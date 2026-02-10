# APHIDS - CLI 


Welcome to the **APHIDS CLI**  

This acts as the interface for the **APHIDS Core** Docker Container.


> Note: This will not run without docker and the docker container.  
>To get the container run:  `docker pull ghcr.io/darksidesecurity/aphids:latest`

For full APHIDS documentation on the core docker container please see [APHIDS Docs](https://aphids.darksidesecurity.io)

## Quick Start ##

### What You Need (**Dependencies**)

* Aphids CLI (This repo)
* Aphids Core Docker Container
* Input Files - Required Offline
  * config.yaml
  * options.yaml
* Host with Docker running
* Python

### How to get those things ###


* Get the Container

`docker pull ghcr.io/darksidesecurity/aphids:latest`

* Install CLI

`pip install git+https://github.com/darksidesecurity/aphids.git`

* Get the config files
  * Get the files from the repo in the Samples directory.
  * Register for the SaaS platform and get your config file for use with the Hive.

### Running Aphids ###

Make sure you have docker running, the container pulled down, and the app installed. It should be as simple as running:

> ``` aphids-cli -o options.yaml -c config.yaml```

## Help ##
```      
 __________________________________________
|                                          |
|               Aphids CLI                 |
|__________________________________________|
                
                version 1.2.0
                        

usage: aphids.py [-h] [-o options.yaml] [-c [config.yaml]] [-r RUNBOOK] [-at ATTACK_TREE] [-ats ATTACK_TREE_SCOPE] [--target-url TARGET_URL] [--target-host TARGET_HOST] [--target-domain TARGET_DOMAIN]
                 [-k API_KEY] [-u API_URL] [-uw WSAPI_URL] [-e ENGAGEMENT] [-n NETWORK] [-sp /DevCode/MyApplication/] [-v [VERBOSE]] [-t [TOOL_OUTPUT]] [-d [DEBUG]] [-i IMAGE]

OPTIONS:
  -h, --help            show this help message and exit
  -o options.yaml, --options options.yaml
                        Options file path (See Sample options.yaml)
  -c [config.yaml], --config [config.yaml]
                        Configuration file path (See Sample config.yaml)
  -r RUNBOOK, --runbook RUNBOOK
                        [Online Mode Only] Runbook ID for retrieving and populating options. Requires an API Key (-k) and a 'target' argument --target-url|target-host|target-domain
  -at ATTACK_TREE, --attack-tree ATTACK_TREE
                        [Online Mode Only] Attack Tree ID for retrieving and populating options. Requires an API Key (-k) and a 'target' argument --target-url|target-host|target-domain
  -ats ATTACK_TREE_SCOPE, --attack-tree-scope ATTACK_TREE_SCOPE
                        [Online Mode Only] Scope restrictions for attack tree. Currently Supported types are [IP Address, IP CIDR, DOMAIN, DOMAIN with WILDCARD] Ex: *.domain.com, sub.domain.com, 127.0.0.1,
                        127.0.0.1/21
  --target-url TARGET_URL
                        [Online Mode Only] Target URL for runbook. Should be in Full URL format. Example: https://www.darksidesecurity.io
  --target-host TARGET_HOST
                        [Online Mode Only] Target HOST for runbook. Should be in FQDN, IP, or CIDR depending on tool/target requirements.
  --target-domain TARGET_DOMAIN
                        [Online Mode Only] Target DOMAIN for runbook. Should be a resolvable domain, often used for subdomain enumeration.
  -k API_KEY, --api-key API_KEY
                        [Online Mode Only] API Key for interacting with Valis or Continuity
  -u API_URL, --api-url API_URL
                        [Online Mode Only] Hive API Url
  -uw WSAPI_URL, --wsapi-url WSAPI_URL
                        [Online Mode Only] Hive WS API Url
  -e ENGAGEMENT, --engagement ENGAGEMENT
                        [Online Mode Only] Engagement ID from Hive UI
  -n NETWORK, --network NETWORK
                        [Online Mode Only] Specify a network name or domain to prevent dns/ip collisions (use when testing non public internet. Example: domain.local)
  -sp /DevCode/MyApplication/, --static-path /DevCode/MyApplication/
                        A relative or absolute path for running scans on a local directory, this will become the working directory.
  -v [VERBOSE], --verbose [VERBOSE]
                        Enable verbose mode to see module execution in real time.
  -t [TOOL_OUTPUT], --tool-output [TOOL_OUTPUT]
                        Write individual tool output to working directory.
  -d [DEBUG], --debug [DEBUG]
                        Debug mode.
  -i IMAGE, --image IMAGE
                        Custom Container Name for custom built Aphids Core images or testing purposes.

Example: python aphids.py -o options.yaml -c config.yaml
```

## Arguments ##

-h, --help 
> Display the help context

-o, --options options.yaml 
> This is the file the contains the attack modules to run, and their arguments. In addition, this file contains the base configuration and other operational items required for the SaaS platform.

-c, --config config.yaml
> Used for providing identity information to the SaaS platform.

-sp, --static-path /DevCode/MyApplication 
> Use this to map a separate path than your working directory. 
> This is required for options that are performing static analysis on a folder on the host machine.
> 
>WARNING: Output will be written to this directory as well.
>
>Example: `aphids-cli -o options.yaml -c config.yaml -sp /Projects/Development/MyApplicationCode `

-v, --verbose
> ... Not yet implemented

-t, --tool-output 
> Used to clean up any output generated from the scans. Not yet implemented

-d, --debug
> ... Not yet implemented.

-i, --image
> This is to specify an alternate docker image to use in place of the default for the application.
> Specifying a custom docker image can allow you to clone the Aphids-Core repository, modify the existing container and run docker build. Using this method you can fully customize the docker container and still use it with our SaaS platform and this command line interface.
> 
> Example: `aphids-cli -o ~/Downloads/options.yaml -c ~/Downloads/config.yaml -i aphids-custom:latest`

## Description ##

A pip installable python interface for the Aphids Core Docker Container. To run the application you **MUST** have the docker container installed.