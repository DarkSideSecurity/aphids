#!/usr/bin/env python

import argparse, sys, yaml
import subprocess
import os
import json
from urllib.parse import urlparse

G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white


class Aphids(object):

    def __init__(self):
        self.map_path = os.getcwd()
        self.container_image = 'ghcr.io/darksidesecurity/aphids:latest'
        self.options = None
        self.config = None
        self.tool_output = None
        self.debug = False
        self.runbook = None

    def banner(self):
        print(f"""
        {W}
 __________________________________________
|                                          |
|               {G}Aphids CLI{W}                 |
|__________________________________________|
                
                version {R}1.2.1{W}
                        
    """)

    @staticmethod
    def disclaimer():
        print('Disclaimer: WARNING - The Aphids client is a scriptable tool wrapper used for executing a variety of security tools. Some of these tools may cause system instability or be illegal. Do not use this application for malicious or illegal purposes, this is intended for research purposes only and we hold no liability for its usage.')

    def parser_error(self, errmsg):
        
        print("Usage: python " + sys.argv[0] + " [options] use -h for help")
        print(R + "Error: " + errmsg + W)
        sys.exit()

    def parse_args(self):
        # parse the arguments
        parser = argparse.ArgumentParser(
            prog=self.banner(),
            epilog='\tExample: \r\npython ' + sys.argv[0] + " -o options.yaml -c config.yaml",
            description='')
        parser.error = self.parser_error
        parser._optionals.title = "OPTIONS"
        parser.add_argument('-o', '--options', help="Options file path (See Sample options.yaml)", required=False, type=argparse.FileType('r'), metavar="options.yaml")
        parser.add_argument('-c', '--config', help='Configuration file path (See Sample config.yaml)', required=False,nargs='?', type=argparse.FileType('r'), metavar="config.yaml")
        parser.add_argument('-r', '--runbook', help="[Online Mode Only] Runbook ID for retrieving and populating options. Requires an API Key (-k) and a 'target' argument --target-url|target-host|target-domain")
        parser.add_argument('-at', '--attack-tree', help="[Online Mode Only] Attack Tree ID for retrieving and populating options. Requires an API Key (-k) and a 'target' argument --target-url|target-host|target-domain")
        parser.add_argument('-ats', '--attack-tree-scope', help="[Online Mode Only] Scope restrictions for attack tree. Currently Supported types are [IP Address, IP CIDR, DOMAIN, DOMAIN with WILDCARD] Ex: *.domain.com, sub.domain.com, 127.0.0.1, 127.0.0.1/21")
        parser.add_argument('--target-url', help="[Online Mode Only] Target URL for runbook. Should be in Full URL format. Example: https://www.darksidesecurity.io")
        parser.add_argument('--target-host', help="[Online Mode Only] Target HOST for runbook. Should be in FQDN, IP, or CIDR depending on tool/target requirements.")
        parser.add_argument('--target-domain', help="[Online Mode Only] Target DOMAIN for runbook. Should be a resolvable domain, often used for subdomain enumeration.")
        parser.add_argument('-k', '--api-key', help="[Online Mode Only] API Key for interacting with Valis or Continuity")
        parser.add_argument('-u', '--api-url', help="[Online Mode Only] Hive API Url", default="https://api.hive.darksidsecurity.io")
        parser.add_argument('-uw', '--wsapi-url', help="[Online Mode Only] Hive WS API Url", default="wss://ws.continuity.hive.darksidsecurity.io")
        parser.add_argument('-e', '--engagement', help="[Online Mode Only] Engagement ID from Hive UI")   
        parser.add_argument('-n', '--network', help="[Online Mode Only] Specify a network name or domain to prevent dns/ip collisions (use when testing non public internet. Example: domain.local)", default="public")   
        parser.add_argument('-sp', '--static-path', help='A relative or absolute path for running scans on a local directory, this will become the working directory.', metavar='/DevCode/MyApplication/')
        parser.add_argument('-v', '--verbose', help='Enable verbose mode to see module execution in real time.', nargs='?', default=False)
        parser.add_argument('-t', '--tool-output', help='Write individual tool output to working directory.', nargs='?', default=True)
        parser.add_argument('-d', '--debug', help='Debug mode.', nargs='?', default=False)
        parser.add_argument('-i', '--image', help='Custom Container Name for custom built Aphids Core images or testing purposes.')
        return parser

    def run(self):
        parser = self.parse_args()
        args = parser.parse_args()
        if args.options:
            self.options = yaml.safe_load(args.options)
        elif args.runbook:
            self.runbook = args.runbook
            self.options = {
                "runbookId": args.runbook,
                "configuration": {
                    "online": "enabled",
                    "network": "public"
                }
            }
        elif args.attack_tree:
            self.options = {
                "attackTreeId": args.attack_tree,
                "configuration":{
                    "online": "enabled",
                    "network": "public"
                }
            }
        else:
            print('**** Missing Required options|runbook|attackTree ****')
            parser.print_help()
            exit(0)
        if args.attack_tree_scope:
            self.options["attackTreeScope"] = args.attack_tree_scope
        if args.network and self.options["configuration"]:
            self.options["configuration"]["network"] = args.network
        if args.engagement and self.options["configuration"]:
            self.options["configuration"]["engagement"] = args.engagement
        if args.target_url or args.target_host or args.target_domain:
            self.options["targets"] = {}
        if args.target_url:
            self.options["targets"]["target_url"] = args.target_url
        if args.target_host:
            self.options["targets"]["target_host"] = args.target_host
        if args.target_domain:
            self.options["targets"]["target_domain"] = args.target_domain
            

        if args.config:
            self.config = yaml.safe_load(args.config)
        elif args.api_key:
            uri = urlparse(args.api_url)
            self.config = {
                "authorization": {
                    "apiKey": args.api_key
                },
                "baseUrl": uri._replace(path="").geturl(),
                "endpoints":{
                    "valis": {
                        "path": "/valis/"
                    },
                    "continuity":{
                        "path": "/continuity/"
                    }
                }
            }
        if args.wsapi_url:
            self.config["baseWsUrl"] = args.wsapi_url
        if args.static_path:
            self.map_path = args.static_path
        if args.image:
            self.container_image = args.image
        self.debug = args.debug
        self.disclaimer()
        self.build_run_docker()
        print(f'\r\n{R}Goodbye.{W}')
        exit(0)
    
    def check_docker(self):
        # if docker version then return true else false        
        pass
    
    def check_container(self):
        # get container list - if self.container_image in list: return true, else return false.
        pass

    def build_run_docker(self):
        docker_cmd = 'docker run --rm -it'
        map_path = f'{self.map_path}:/output/'
        docker_cmd += f' -v {map_path} {self.container_image}'
        docker_cmd = docker_cmd.split(' ')
        if self.options is not None:
            docker_cmd.append('-jo')
            jo = json.dumps(self.options)
            docker_cmd.append(jo)
        if self.config is not None:
            docker_cmd.append('-jc')
            jc = json.dumps(self.config)
            docker_cmd.append(jc)
        # print(docker_cmd)
        print(f'{W}Running container: {G}{self.container_image}{W}')
        raw = ''
        process = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE)
        while True:
            output = process.stdout.readline()
            formatted_output = str(output.strip(), 'UTF-8')
            if formatted_output == '' and process.poll() is not None:
                break
            if output:
                raw += formatted_output
                print(f'\r{formatted_output}')
        rc = process.poll()
        return raw


def cli():
    am = Aphids()
    am.run()
    sys.exit()


if __name__ == "__main__":
    cli()