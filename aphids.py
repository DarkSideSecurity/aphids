#!/usr/bin/env python

import argparse, sys, yaml
import subprocess
import os
import json
from importlib.metadata import version as _pkg_version
from urllib.parse import urlparse

try:
    __version__ = _pkg_version("aphids-cli")
except Exception:
    __version__ = "dev"

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
        self.unattended = False
        self.agent_mode = False
        self.agent_name = None
        self.exit_on_idle = 0
        self.ws_url = None
        self.resume_id = None
        self.fail_on_severity = None
        self.fail_on_count = None
        self.sarif_output = None

    def banner(self):
        print(f"""
        {W}
 __________________________________________
|                                          |
|               {G}Aphids CLI{W}                 |
|__________________________________________|
                
                version {R}{__version__}{W}
                        
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
        parser.add_argument('-se', '--scan-execution', help="[Online Mode Only] Scan Execution ID for retrieving pre-configured execution parameters. Requires an API Key (-k). Overrides -r and -at arguments.")
        parser.add_argument('-ats', '--attack-tree-scope', help="[Online Mode Only] Scope restrictions for attack tree. Currently Supported types are [IP Address, IP CIDR, DOMAIN, DOMAIN with WILDCARD] Ex: *.domain.com, sub.domain.com, 127.0.0.1, 127.0.0.1/21")
        parser.add_argument('--target-url', help="[Online Mode Only] Target URL for runbook. Should be in Full URL format. Example: https://www.darksidesecurity.io")
        parser.add_argument('--target-host', help="[Online Mode Only] Target HOST for runbook. Should be in FQDN, IP, or CIDR depending on tool/target requirements.")
        parser.add_argument('--target-domain', help="[Online Mode Only] Target DOMAIN for runbook. Should be a resolvable domain, often used for subdomain enumeration.")
        parser.add_argument('--target-dir', help="[Online Mode Only] Target directory for runbook. Should be a relative path to a directory containing the target files, or simply '.' for the current directory.")
        parser.add_argument('-k', '--api-key', help="[Online Mode Only] API Key for interacting with Valis or Continuity")
        parser.add_argument('-u', '--api-url', help="[Online Mode Only] Hive API Url", default="https://api.hive.darksidsecurity.io")
        parser.add_argument('-uw', '--wsapi-url', help="[Online Mode Only] Hive WS API Url", default="wss://ws.continuity.hive.darksidsecurity.io")
        parser.add_argument('-e', '--engagement', help="[Online Mode Only] Engagement ID from Hive UI")   
        parser.add_argument('-n', '--network', help="[Online Mode Only] Specify a network name or domain to prevent dns/ip collisions (use when testing non public internet. Example: domain.local)", default="public")   
        parser.add_argument('-sp', '--static-path', dest='static_path', help='A relative or absolute path for running scans on a local directory, this will become the working directory.', metavar='/DevCode/MyApplication/')
        parser.add_argument('-v', '--verbose', help='Enable verbose mode to see module execution in real time.', nargs='?', default=False)
        parser.add_argument('-t', '--tool-output', help='Write individual tool output to working directory.', nargs='?', default=True)
        parser.add_argument('-d', '--debug', help='Debug mode.', nargs='?', default=False)
        parser.add_argument('-i', '--image', help='Custom Container Name for custom built Aphids Core images or testing purposes.')
        parser.add_argument('--runtime', dest='runtime', default=None,
            choices=['docker', 'podman', 'nerdctl'],
            help='Container runtime to use (default: auto-detect). Can also be set via APHIDS_CONTAINER_RUNTIME env var.')
        parser.add_argument('--mcp', action='store_true', help='Start as MCP server for AI agent integration. Dispatches tools to containers via the selected runtime.')
        parser.add_argument('--mcp-workspace', dest='mcp_workspace', help='Workspace directory for MCP mode static analysis tools (default: current directory).', default=None)
        parser.add_argument('--mcp-refresh', dest='mcp_refresh', action='store_true', help='Force refresh of cached tool registry in MCP mode.')
        parser.add_argument('--unattended', action='store_true', 
            help='CAUTION: Unattended mode - auto-approves all prompts. A user MUST be present to monitor and stop the scan if incorrect targets or arguments are specified.')
        parser.add_argument('--agent', action='store_true',
            help='Start in persistent agent mode. Connects via WebSocket, registers with the Hive, and waits for scan execution commands.')
        parser.add_argument('--agent-name', dest='agent_name', default=None,
            help='Friendly name for this agent instance (e.g. my-scanner). Auto-generated if not specified.')
        parser.add_argument('--exit-on-idle', dest='exit_on_idle', type=int, default=0,
            help='Auto-exit after N seconds of idle time (0 = never exit). Useful for CI/CD short-lived agents.')
        parser.add_argument('--ws-url', dest='ws_url', default=None,
            help='WebSocket URL override for agent mode (must be wss://). Defaults to config baseWsUrl.')
        parser.add_argument('--resume', dest='resume_id', default=None,
            help='Resume a previously paused/interrupted scan by its group ID or execution ID.')
        parser.add_argument('--fail-on-severity', dest='fail_on_severity', default=None,
            help='Exit with code 3 if findings at or above this severity are found. '
                 'Values: critical, high, medium, low, info. Example: --fail-on-severity high')
        parser.add_argument('--fail-on-count', dest='fail_on_count', type=int, default=None,
            help='Exit with code 3 if total findings exceed this count. Example: --fail-on-count 10')
        parser.add_argument('--sarif', dest='sarif_output', default=None, metavar='FILE',
            help='Write SARIF v2.1.0 output to FILE after scan. Path is relative to output directory. '
                 'Example: --sarif results.sarif')
        return parser

    def run(self):
        parser = self.parse_args()
        args = parser.parse_args()
        # Handle MCP server mode — runs natively on host, dispatches to Docker
        if args.mcp:
            self._run_mcp_mode(args)
            return
        # Handle agent mode — no options required
        if args.agent:
            self.agent_mode = True
            self.agent_name = args.agent_name
            self.exit_on_idle = args.exit_on_idle
            self.ws_url = args.ws_url
            self.debug = args.debug
            # Agent mode requires an API key via -k or config file
            if not args.api_key and not args.config:
                print(f'{R}Error: Agent mode requires an API key. Use -k YOUR_API_KEY{W}')
                exit(1)
        elif args.options:
            self.options = yaml.safe_load(args.options)
        elif args.scan_execution:
            # Scan execution takes priority - it contains all execution parameters
            self.options = {
                "scanExecutionId": args.scan_execution,
                "configuration": {
                    "online": "enabled",
                    "network": "public"
                }
            }
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
        elif not self.agent_mode:
            print('**** Missing Required options|runbook|attackTree|scan-execution|--agent ****')
            parser.print_help()
            exit(0)
        if not self.agent_mode:
            if args.attack_tree_scope:
                self.options["attackTreeScope"] = args.attack_tree_scope
            if args.network and self.options.get("configuration"):
                self.options["configuration"]["network"] = args.network
            if args.engagement and self.options.get("configuration"):
                self.options["configuration"]["engagement"] = args.engagement
            if args.target_url or args.target_host or args.target_domain or args.target_dir:
                self.options["targets"] = {}
            if args.target_url:
                self.options["targets"]["target_url"] = args.target_url
            if args.target_host:
                self.options["targets"]["target_host"] = args.target_host
            if args.target_domain:
                self.options["targets"]["target_domain"] = args.target_domain
            if args.target_dir:
                self.options["targets"]["target_dir"] = args.target_dir
            

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
                },
                "debug": args.debug if args.debug else False
            }
        if args.wsapi_url and self.config:
            self.config["baseWsUrl"] = args.wsapi_url
        if args.static_path:
            self.map_path = args.static_path
        if args.image:
            self.container_image = args.image
        if not self.agent_mode:
            self.debug = args.debug
        self.unattended = args.unattended
        if args.resume_id:
            self.resume_id = args.resume_id
        if args.fail_on_severity:
            self.fail_on_severity = args.fail_on_severity
        if args.fail_on_count is not None:
            self.fail_on_count = args.fail_on_count
        if args.sarif_output:
            self.sarif_output = args.sarif_output
        self.disclaimer()
        rc = self.build_run_container(runtime_name=args.runtime if hasattr(args, 'runtime') else None)
        print(f'\r\n{R}Goodbye.{W}')
        exit(rc if rc else 0)
    
    def _run_mcp_mode(self, args):
        """Start the MCP server shim that dispatches tools to containers."""
        import asyncio
        from mcp_shim import run_mcp_server

        container_image = args.image if args.image else self.container_image
        workspace_dir = os.path.abspath(args.mcp_workspace or os.getcwd())
        api_key = args.api_key if hasattr(args, 'api_key') and args.api_key else os.environ.get('APHIDS_API_KEY')
        api_url = args.api_url if hasattr(args, 'api_url') and args.api_url else os.environ.get('APHIDS_API_URL')
        ws_url = args.wsapi_url if hasattr(args, 'wsapi_url') and args.wsapi_url else os.environ.get('APHIDS_WS_URL')
        refresh = args.mcp_refresh if hasattr(args, 'mcp_refresh') else False
        runtime_name = args.runtime if hasattr(args, 'runtime') else None

        try:
            asyncio.run(run_mcp_server(
                container_image=container_image,
                workspace_dir=workspace_dir,
                api_key=api_key,
                api_url=api_url,
                ws_url=ws_url,
                refresh_tools=refresh,
                runtime_name=runtime_name,
            ))
        except KeyboardInterrupt:
            print(f'\n{W}MCP server stopped.{W}')
        except Exception as ex:
            print(f'{R}MCP server error: {ex}{W}')
            sys.exit(1)

    def check_container(self):
        # get container list - if self.container_image in list: return true, else return false.
        pass

    def build_run_container(self, runtime_name=None):
        from container_runtime import detect_runtime
        try:
            runtime = detect_runtime(runtime_name)
        except RuntimeError as exc:
            print(f'{R}Error: {exc}{W}')
            sys.exit(1)

        # Build container arguments (after image name)
        ctr_args = []
        if self.agent_mode:
            ctr_args.append('--agent')
            if self.agent_name:
                ctr_args.extend(['--agent-name', self.agent_name])
            if self.exit_on_idle:
                ctr_args.extend(['--exit-on-idle', str(self.exit_on_idle)])
            if self.ws_url:
                ctr_args.extend(['--ws-url', self.ws_url])
            if self.debug:
                ctr_args.append('--debug')
        if self.options is not None:
            ctr_args.append('-jo')
            ctr_args.append(json.dumps(self.options))
        if self.config is not None:
            ctr_args.append('-jc')
            ctr_args.append(json.dumps(self.config))
        if self.unattended:
            ctr_args.append('--unattended')
        if self.resume_id:
            ctr_args.extend(['--resume', self.resume_id])
        if self.fail_on_severity:
            ctr_args.extend(['--fail-on-severity', self.fail_on_severity])
        if self.fail_on_count is not None:
            ctr_args.extend(['--fail-on-count', str(self.fail_on_count)])
        if self.sarif_output:
            # SARIF path inside the container maps to /output/
            sarif_path = f'/output/{self.sarif_output}' if not self.sarif_output.startswith('/') else self.sarif_output
            ctr_args.extend(['--sarif', sarif_path])

        cmd = runtime.build_run_cmd(
            self.container_image,
            rm=True,
            interactive=True,
            tty=True,
            volumes=[(self.map_path, '/output/', '')],
            container_args=ctr_args,
        )

        print(f'{W}Running container ({runtime.label}): {G}{self.container_image}{W}')
        try:
            process = subprocess.run(cmd)
            return process.returncode
        except KeyboardInterrupt:
            print(f'\n{W}Goodbye.{W}')
            return 130


def cli():
    am = Aphids()
    am.run()
    sys.exit()


if __name__ == "__main__":
    cli()