#!/usr/bin/env python

import argparse, sys, yaml
import subprocess
import os
import json


G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white


class Aphids(object):

    def __init__(self):
        self.map_path = os.getcwd()
        self.container_image = 'ghcr.io/darksidesecurity.io/aphids:latest'
        self.options = None
        self.config = None
        self.tool_output = None
        self.debug = False

    def banner(self):
        print(f"""
        {W}
 __________________________________________
|                                          |
|               {G}Aphids CLI{W}                 |
|__________________________________________|
                
                version {R}1.1.0{W}
                        
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
        parser.add_argument('-o', '--options', help="Options file path (See Sample options.yaml)", required=True, type=argparse.FileType('r'), metavar="options.yaml")
        parser.add_argument('-c', '--config', help='Configuration file path (See Sample config.yaml)', required=False,nargs='?', type=argparse.FileType('r'), metavar="config.yaml")
        parser.add_argument('-sp', '--static-path', help='A relative or absolute path for running scans on a local directory, this will become the working directory.', metavar='/DevCode/MyApplication/')
        parser.add_argument('-v', '--verbose', help='Enable verbose mode to see module execution in real time.', nargs='?', default=False)
        parser.add_argument('-t', '--tool-output', help='Write individual tool output to working directory.', nargs='?', default=True)
        parser.add_argument('-d', '--debug', help='Debug mode.', nargs='?', default=False)
        parser.add_argument('-i', '--image', help='Custom Container Name')
        return parser.parse_args()

    def run(self):
        args = self.parse_args()
        self.options = yaml.safe_load(args.options)
        self.config = yaml.safe_load(args.config)
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
        docker_cmd = 'docker run -it'
        map_path = f'{self.map_path}:/output/'
        docker_cmd += f' -v {map_path} {self.container_image}'
        docker_cmd = docker_cmd.split(' ')
        docker_cmd.append('-jo')
        jo = json.dumps(self.options)
        docker_cmd.append(jo)
        docker_cmd.append('-jc')
        jc = json.dumps(self.config)
        docker_cmd.append(jc)
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