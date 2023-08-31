#!/usr/bin/env python3

r"""PushHosts - Push HOSTS file to Windows endpoints.
 __________             .__      ___ ___                 __          
 \______   \__ __  _____|  |__  /   |   \  ____  _______/  |_  ______
  |     ___/  |  \/  ___/  |  \/    ~    \/  _ \/  ___/\   __\/  ___/
  |    |   |  |  /\___ \|   Y  \    Y    (  <_> )___ \  |  |  \___ \ 
  |____|   |____//____  >___|  /\___|_  / \____/____  > |__| /____  >
                      \/     \/       \/            \/            \/ 

 Use RTR API to push HOSTS file to endpoints across CID or host group
 FalconPy v1.0

 CHANGE LOG

 12/06/2023   v1.0    First version
 22/08/2023   v1.1    Add rollback capability and some bug fixes, tested with FalconPy 1.3.0
 31/08/2023   v1.2    Add RTR command to fix permissions to new HOSTS file

"""
# Import dependencies
import datetime
from argparse import ArgumentParser, RawTextHelpFormatter

version = "1.2"

# Define logging function
def log(msg):
    """Print the log message to the terminal."""
    print(datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + '  ' + str(msg))

# Import SDK
try:
    from falconpy import(
        Hosts,
        OAuth2,
        RealTimeResponse,
        RealTimeResponseAdmin,
        HostGroup,
        SensorDownload
    )
except ImportError as err:
    log(err)
    log("Python falconpy library is required.\n"
        "Install with: python3 -m pip install crowdstrike-falconpy"
        )
    raise SystemExit("Python falconpy library is required.\n"
                     "Install with: python3 -m pip install crowdstrike-falconpy"
                     ) from err

# Process command line arguments
parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
req = parser.add_argument_group("required arguments")

req.add_argument("--falcon_client_id",
                 help="CrowdStrike Falcon API Client ID",
                 required=True
                 )

req.add_argument("--falcon_client_secret",
                 help="CrowdStrike Falcon API Client Secret",
                 required=True
                 )

req.add_argument("--hosts_file",
                 help="Hash (sha256) of HOSTS file to deploy. Must be uploaded to 'PUT' files in the console.",
                 required=True
                 )

req.add_argument("--scope",
                 help="Which hosts to change, can be 'cid' or 'hostgroup'",
                 choices=['cid', 'hostgroup'],
                 required=True
                 )

req.add_argument("--scope_id",
                 help="CID or Host Group ID",
                 required=True
                 )

req.add_argument("-b", "--base_url",
                    help="CrowdStrike base URL (only required for GovCloud, pass usgov1)",
                    required=False,
                    default="auto"
                    )

args = parser.parse_args()

if args.scope.lower() not in ["cid", "hostgroup"]:
    log("The scope needs to be 'cid' or 'hostgroup'")
    raise SystemExit("The scope needs to be 'cid' or 'hostgroup'")


# Main routine
def main():  
    log(f"Starting execution of PushHosts v{version}")

    log("Authenticating to API")
    auth = OAuth2(client_id=args.falcon_client_id,
                  client_secret=args.falcon_client_secret,
                  base_url=args.base_url
                  )

    # Check which CID the API client is operating in, as sanity check. Exit if operating CID does not match provided scope_id.
    falcon = SensorDownload(auth_object=auth, base_url=args.base_url)
    current_cid = falcon.get_sensor_installer_ccid()["body"]["resources"][0][:-3]
    if (args.scope.lower() == "cid" and (args.scope_id.lower() != current_cid.lower())):
        log(f"The entered CID [{args.scope_id.upper()}] does not match the API client CID [{current_cid.upper()}].")
        raise SystemExit(f"The entered CID [{args.scope_id.upper()}] does not match the API client CID [{current_cid.upper()}].")


    # Check that hosts file specified exists
    falcon = RealTimeResponseAdmin(auth_object=auth, base_url=args.base_url)

    put_files = falcon.get_put_files_v2(ids=falcon.list_put_files()["body"]["resources"])["body"]["resources"]

    found = False

    for put_file in put_files:
        if put_file['sha256'].lower() == args.hosts_file.lower():
            found = True
            filename = put_file['name']
            log(f"The selected HOSTS file is: {put_file['name']} ({put_file['sha256']}), modified {put_file['modified_timestamp'][:19]} by {put_file['modified_by']}")

    if not found:
        log(f"The entered HOSTS file hash [{args.hosts_file.lower()}] does not exist.")
        raise SystemExit(f"The entered HOSTS file hash [{args.hosts_file.lower()}] does not exist.")     


    # Fetch list of hosts
    if args.scope.lower() == "cid":
        log(f"Getting all hosts from CID [{args.scope_id}]")
        falcon = Hosts(auth_object=auth, base_url=args.base_url)
    else:
        log(f"Getting all hosts from host group ID [{args.scope_id}]")
        falcon = HostGroup(auth_object=auth, base_url=args.base_url)


    offset = ""
    hosts_all = []

    while True:
        batch_size = 5000 # 5000 is max supported by API

        if args.scope.lower() == "cid":
            # Fetch all Windows CID hosts
            response = falcon.query_devices_by_filter_scroll(offset=offset,
                                                             limit=batch_size,
                                                             filter="platform_name:'Windows'"
                                                             )
        else:
            # Fetch all Windows host group ID hosts
            if offset == "":
                response = falcon.query_group_members(limit=batch_size,
                                                      filter="platform_name:'Windows'",
                                                      id=args.scope_id
                                                      )
            else:
                response = falcon.query_group_members(offset=offset,
                                                      limit=batch_size,
                                                      filter="platform_name:'Windows'",
                                                      id=args.scope_id
                                                      )

        offset = response['body']['meta']['pagination']['offset']

        for host_id in response['body']['resources']:
            hosts_all.append(host_id)

        log(f"-- Fetched {len(response['body']['resources'])} hosts, "
            f"{len(hosts_all)}/{response['body']['meta']['pagination']['total']}"
            )

        if len(hosts_all) >= int(response['body']['meta']['pagination']['total']):
            break

    log(f"-- Retrieved a total of {str(len(hosts_all))} hosts")


    # Now that we have the host IDs, we create a batch RTR list of commands to execute it in all hosts

    falcon = RealTimeResponse(auth_object=auth, base_url=args.base_url)
    falcon_admin = RealTimeResponseAdmin(auth_object=auth, base_url=args.base_url)
    

    # Get batch id

    response = falcon.batch_init_sessions(host_ids=hosts_all, queue_offline=True)
    batch_id = response['body']['batch_id']

    if batch_id:
        log(f"Initiated RTR batch with id {batch_id}")
    else:
        raise SystemExit("Unable to initiate RTR session with hosts.")


    # Commands to push HOSTS file

    response = falcon.batch_active_responder_command(batch_id=batch_id,
                                                        base_command="cd",
                                                        command_string=f"cd c:\windows\system32\drivers\etc"
                                                        )
    if response["status_code"] == 201:
        log(f"-- Command: cd c:\windows\system32\drivers\etc")
    else:
        raise SystemExit(f"Error, Response: {response['status_code']} - {response.text}")

    datestring = datetime.datetime.utcnow().strftime("%Y-%m-%d-%H-%M-%S.backup")
    response = falcon.batch_active_responder_command(batch_id=batch_id,
                                                        base_command="mv",
                                                        command_string=f"mv hosts hosts." + datestring
                                                        )
    if response["status_code"] == 201:
        log(f"-- Command: mv hosts hosts." + datestring)
    else:
        raise SystemExit(f"Error, Response: {response['status_code']} - {response.text}")

    response = falcon_admin.batch_admin_command(batch_id=batch_id,
                                                        base_command="put",
                                                        command_string=f"put {filename}"
                                                        )
    if response["status_code"] == 201:
        log(f"-- Command: put {filename}")
    else:
        raise SystemExit(f"Error, Response: {response['status_code']} - {response.text}")

    if filename.lower() != "hosts":
        response = falcon.batch_active_responder_command(batch_id=batch_id,
                                                            base_command="mv",
                                                            command_string=f"mv {filename} hosts"
                                                            )
        if response["status_code"] == 201:
            log(f"-- Command: mv {filename} hosts")
        else:
            raise SystemExit(f"Error, Response: {response['status_code']} - {response.text}")

    response = falcon_admin.batch_admin_command(batch_id=batch_id,
                                                        base_command="run",
                                                        command_string="run ICACLS c:\windows\system32\drivers\etc\hosts /grant Users:RX"
                                                        )
    if response["status_code"] == 201:
        log("-- Command: run ICACLS c:\windows\system32\drivers\etc\hosts /grant Users:RX")
    else:
        raise SystemExit(f"Error, Response: {response['status_code']} - {response.text}")
     


    response = falcon_admin.batch_admin_command(batch_id=batch_id,
                                                        base_command="run",
                                                        command_string="run ipconfig /flushdns"
                                                        )
    if response["status_code"] == 201:
        log("-- Command: run ipconfig /flushdns")
    else:
        raise SystemExit(f"Error, Response: {response['status_code']} - {response.text}")


    log("-- Finished launching RTR commands, please check progress in the RTR audit logs")
    log("End")

if __name__ == "__main__":
    main()
 
