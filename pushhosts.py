#!/usr/bin/env python3

r"""PushHosts - Push HOSTS file to Windows endpoints.
 __________             .__      ___ ___                 __          
 \______   \__ __  _____|  |__  /   |   \  ____  _______/  |_  ______
  |     ___/  |  \/  ___/  |  \/    ~    \/  _ \/  ___/\   __\/  ___/
  |    |   |  |  /\___ \|   Y  \    Y    (  <_> )___ \  |  |  \___ \ 
  |____|   |____//____  >___|  /\___|_  / \____/____  > |__| /____  >
                      \/     \/       \/            \/            \/ 

 Use RTR API to pish HOSTS file to endpoints across CID or host group
 FalconPy v1.0

 CHANGE LOG

 12/06/2023   v0.9    First version

"""
# Import dependencies
import datetime
from argparse import ArgumentParser, RawTextHelpFormatter

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
        HostGroup
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
    log("Starting execution of PushHosts")

    log("Authenticating to API")
    auth = OAuth2(client_id=args.falcon_client_id,
                  client_secret=args.falcon_client_secret,
                  base_url=args.base_url
                  )

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
                                                        command_string=f"put hosts"
                                                        )
    if response["status_code"] == 201:
        log(f"-- Command: put hosts")
    else:
        raise SystemExit(f"Error, Response: {response['status_code']} - {response.text}")



    log("-- Finished launching RTR commands, please check progress in the RTR audit logs")
    log("End")

if __name__ == "__main__":
    main()
