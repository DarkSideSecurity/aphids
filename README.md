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
* Input Files
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
                
                version 1.0
                        
    
usage: aphids-cli.py [-h] -o options.yaml [-c [config.yaml]] [-sp /DevCode/MyApplication/] [-v [VERBOSE]] [-t [TOOL_OUTPUT]] [-d [DEBUG]] [-i IMAGE]

OPTIONS:
  -h, --help            show this help message and exit
  -o options.yaml, --options options.yaml
                        Options file path (See Sample options.yaml)
  -c [config.yaml], --config [config.yaml]
                        Configuration file path (See Sample config.yaml)
  -sp /DevCode/MyApplication/, --static-path /DevCode/MyApplication/
                        A relative or absolute path for running scans on a local directory, this will become the working directory.
  -v [VERBOSE], --verbose [VERBOSE]
                        Enable verbose mode to see module execution in real time.
  -t [TOOL_OUTPUT], --tool-output [TOOL_OUTPUT]
                        Write individual tool output to working directory.
  -d [DEBUG], --debug [DEBUG]
                        Debug mode.
  -i IMAGE, --image IMAGE
                        Custom Container Name

Example: python aphids-cli.py -o options.yaml -c config.yaml
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