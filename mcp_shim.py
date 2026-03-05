"""
Aphids CLI MCP Server Shim

Runs natively on the host as the MCP server process. Receives MCP tool calls
from AI clients (Windsurf, Claude Desktop, Cursor) and dispatches each one
as a container ``run`` command with the correct volume mounts.

Supported container runtimes:
  - Docker   (default)
  - Podman   (rootless, daemonless)
  - nerdctl  (containerd CLI — Rancher Desktop, Lima)

Solves two problems:
  1. Output is returned directly to the LLM via MCP (no volume mount needed).
  2. Static analysis tools get the host workspace mounted read-only at /workspace.

Security:
  - Zero-trust: all inputs validated, paths canonicalized
  - Workspace mounted read-only (:ro)
  - Path traversal protection on target_dir resolution
  - Output dirs are ephemeral and cleaned up after each tool call
  - No secrets persisted to disk
  - Container isolation: each tool call is a fresh container (--rm)
"""

import sys
import os
import re
import json
import uuid
import shutil
import asyncio
import logging
import tempfile
import subprocess
import hashlib
import time
from typing import Any, Dict, List, Optional
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging — structured, enterprise-grade
# ---------------------------------------------------------------------------

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [aphids-mcp] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

logger = logging.getLogger("aphids-mcp")
logger.setLevel(logging.DEBUG)

_stderr_handler = logging.StreamHandler(sys.stderr)
_stderr_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
logger.addHandler(_stderr_handler)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONTAINER_IMAGE = "ghcr.io/darksidesecurity/aphids:latest"
DEFAULT_TOOL_TIMEOUT = 1800  # 30 minutes
MAX_TOOL_TIMEOUT = 7200      # 2 hours
TOOL_REGISTRY_CACHE_TTL = 86400  # 24 hours
CACHE_DIR = os.path.join(str(Path.home()), ".aphids", "cache")
MAX_OUTPUT_SIZE = 500_000    # ~500KB cap on raw output returned to LLM

# Tools that require filesystem access to source code
WORKSPACE_TOOLS = {"run_semgrep", "run_gitleaks", "run_trufflehog"}

# Engagement admin-tool constraints
MAX_ENGAGEMENT_NAME_LEN = 256
MAX_ENGAGEMENTS = 20
_SAFE_NAME_RE = re.compile(r"^[\w\s.\-/()]+$")


def _validate_safe_name(value: str, field: str) -> str:
    """Validate a configuration name field (engagement, scan_group, team)."""
    if not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string")
    value = value.strip()
    if not value:
        raise ValueError(f"'{field}' must not be empty")
    if len(value) > MAX_ENGAGEMENT_NAME_LEN:
        raise ValueError(
            f"'{field}' exceeds max length ({MAX_ENGAGEMENT_NAME_LEN})"
        )
    if "\x00" in value:
        raise ValueError(f"'{field}' contains null bytes")
    if not _SAFE_NAME_RE.match(value):
        raise ValueError(
            f"'{field}' contains invalid characters — "
            "only alphanumeric, spaces, dots, hyphens, slashes, and parentheses allowed"
        )
    return value

# Parameters that reference host filesystem paths
WORKSPACE_PARAMS = {"target_dir", "target"}


# ---------------------------------------------------------------------------
# Security utilities
# ---------------------------------------------------------------------------

def _validate_path_safe(path: str, allowed_base: str) -> str:
    """Resolve and validate a path is within the allowed base directory.

    Prevents path traversal attacks (../../etc/passwd, symlink escapes, etc.)

    Args:
        path: The path to validate (may be relative or absolute)
        allowed_base: The base directory the path must resolve within

    Returns:
        The canonicalized absolute path

    Raises:
        ValueError: If the path escapes the allowed base directory
    """
    # Reject null bytes (common injection vector)
    if "\x00" in path:
        raise ValueError("Path contains null bytes")

    # Reject obviously malicious patterns
    if ".." in path.split(os.sep):
        raise ValueError("Path traversal detected: '..' components not allowed")

    # Resolve to absolute, following symlinks
    base_real = os.path.realpath(allowed_base)
    if os.path.isabs(path):
        resolved = os.path.realpath(path)
    else:
        resolved = os.path.realpath(os.path.join(allowed_base, path))

    # Ensure resolved path is within the allowed base
    if not resolved.startswith(base_real + os.sep) and resolved != base_real:
        raise ValueError(
            f"Path '{path}' resolves outside allowed directory '{allowed_base}'"
        )

    return resolved


def _sanitize_tool_name(name: str) -> str:
    """Validate tool name contains only safe characters."""
    if not re.match(r"^run_[a-zA-Z0-9_-]{1,64}$", name):
        raise ValueError(f"Invalid tool name: {name}")
    return name


def _validate_runtime_available(preferred: Optional[str] = None):
    """Detect and validate a container runtime.

    Returns a ContainerRuntime instance or calls sys.exit(1).
    """
    from container_runtime import detect_runtime
    try:
        return detect_runtime(preferred)
    except RuntimeError as exc:
        logger.error(str(exc))
        sys.exit(1)


def _validate_container_image(image: str) -> str:
    """Validate container image name is safe (no injection)."""
    # Allow: registry/org/name:tag format
    if not re.match(r"^[a-zA-Z0-9._/-]+(:[a-zA-Z0-9._-]+)?$", image):
        raise ValueError(f"Invalid container image name: {image}")
    if len(image) > 256:
        raise ValueError("Container image name too long")
    return image


# ---------------------------------------------------------------------------
# Tool registry cache
# ---------------------------------------------------------------------------

def _get_cache_path() -> str:
    """Get the path to the cached tool registry."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, "tool-registry.json")


def _load_cached_registry(container_image: str) -> Optional[dict]:
    """Load cached tool registry if valid and not expired."""
    cache_path = _get_cache_path()
    if not os.path.isfile(cache_path):
        return None

    try:
        with open(cache_path, "r") as f:
            cached = json.load(f)

        # Check TTL
        cached_at = cached.get("_cached_at", 0)
        if time.time() - cached_at > TOOL_REGISTRY_CACHE_TTL:
            logger.info("Tool registry cache expired")
            return None

        # Check image match
        if cached.get("_container_image") != container_image:
            logger.info("Tool registry cache invalidated (image changed)")
            return None

        logger.info(f"Loaded {cached.get('count', 0)} tools from cache")
        return cached

    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(f"Failed to load tool registry cache: {exc}")
        return None


def _save_registry_cache(registry: dict, container_image: str):
    """Save tool registry to cache."""
    registry["_cached_at"] = time.time()
    registry["_container_image"] = container_image
    cache_path = _get_cache_path()
    try:
        with open(cache_path, "w") as f:
            json.dump(registry, f, indent=2)
        logger.info(f"Cached {registry.get('count', 0)} tools to {cache_path}")
    except OSError as exc:
        logger.warning(f"Failed to save tool registry cache: {exc}")


# ---------------------------------------------------------------------------
# Container dispatch
# ---------------------------------------------------------------------------

def _discover_tools_via_container(container_image: str, runtime) -> dict:
    """Run the container with --mcp-list-tools to get the tool registry."""
    logger.info(f"Discovering tools from container ({runtime.label}): {container_image}")

    cmd = runtime.build_run_cmd(
        container_image,
        rm=True,
        container_args=["--mcp-list-tools"],
    )

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
    except subprocess.TimeoutExpired:
        logger.error("Tool discovery timed out after 120s")
        raise RuntimeError("Tool discovery timed out")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        logger.error(f"Tool discovery failed (exit {result.returncode}): {stderr}")
        raise RuntimeError(f"Tool discovery failed: {stderr}")

    # Parse stdout — skip any non-JSON preamble (banners, warnings)
    stdout = result.stdout.strip()
    json_start = stdout.find("{")
    if json_start < 0:
        logger.error(f"No JSON found in tool discovery output: {stdout[:200]}")
        raise RuntimeError("Tool discovery returned no JSON")

    try:
        registry = json.loads(stdout[json_start:])
    except json.JSONDecodeError as exc:
        logger.error(f"Failed to parse tool registry JSON: {exc}")
        raise RuntimeError(f"Invalid tool registry JSON: {exc}")

    logger.info(f"Discovered {registry.get('count', 0)} tools")
    return registry


def _is_url(value: str) -> bool:
    """Check if a value looks like a URL (not a filesystem path)."""
    return bool(re.match(r"^(https?://|git@|ssh://|s3://|gs://)", value))


def _resolve_workspace_path(
    tool_name: str, arguments: dict, workspace_dir: str
) -> Optional[str]:
    """Determine the host directory to mount as /workspace for this tool call.

    Returns None if the tool doesn't need workspace access (e.g. network tools,
    or tools targeting a URL/remote repo instead of local filesystem).
    """
    if tool_name not in WORKSPACE_TOOLS:
        return None

    # For trufflehog: if target_type is not "filesystem", no workspace needed
    # (it's scanning a remote repo via URL, not local files)
    if tool_name == "run_trufflehog":
        target_type = arguments.get("target_type", "filesystem")
        if target_type != "filesystem":
            logger.debug(
                f"Trufflehog target_type='{target_type}' — no workspace mount needed"
            )
            return None

    # Check if any workspace-related params are present
    for param in WORKSPACE_PARAMS:
        if param in arguments and arguments[param] is not None:
            target = arguments[param]

            # Skip URL-like targets (git repos, S3 buckets, etc.)
            if _is_url(target):
                logger.debug(f"Target '{target}' is a URL — no workspace mount needed")
                return None

            # "." or "./" means the workspace root
            if target in (".", "./", ""):
                return workspace_dir

            # Validate the path is safe and exists
            try:
                resolved = _validate_path_safe(target, workspace_dir)
            except ValueError:
                # If it's an absolute path outside workspace, check if it exists
                # (user might be pointing to a different project)
                if os.path.isabs(target):
                    real_path = os.path.realpath(target)
                    if os.path.isdir(real_path):
                        logger.info(
                            f"Using absolute host path for {param}: {real_path}"
                        )
                        return real_path
                raise

            if os.path.isdir(resolved):
                return resolved
            else:
                raise ValueError(f"Directory not found: {resolved}")

    # Tool needs workspace but no path param provided — use workspace root
    return workspace_dir


def _remap_arguments_for_container(
    tool_name: str, arguments: dict, workspace_mounted: bool
) -> dict:
    """Remap host paths in arguments to container paths.

    When workspace is mounted at /workspace, rewrite target_dir/target
    to point inside the container.
    """
    if not workspace_mounted:
        return arguments

    remapped = dict(arguments)
    for param in WORKSPACE_PARAMS:
        if param in remapped and remapped[param] is not None:
            original = remapped[param]
            if original in (".", "./", ""):
                remapped[param] = "/workspace"
            else:
                # The entire host dir is mounted at /workspace, so the param
                # should just be /workspace (the mount point IS the target)
                remapped[param] = "/workspace"
            logger.debug(f"Remapped {param}: '{original}' -> '{remapped[param]}'")

    return remapped


def dispatch_tool(
    tool_name: str,
    arguments: dict,
    container_image: str,
    workspace_dir: str,
    runtime,
    config: Optional[dict] = None,
    timeout: int = DEFAULT_TOOL_TIMEOUT,
) -> dict:
    """Execute a tool inside a container and return the result.

    This is the core dispatch function. For each tool call:
    1. Creates a temp output directory on the host
    2. Resolves workspace path for static analysis tools
    3. Constructs the container run command with appropriate mounts
    4. Runs the container, captures stdout
    5. Reads any output files from the temp dir
    6. Cleans up and returns the result

    Args:
        tool_name: MCP tool name (e.g. "run_semgrep")
        arguments: Validated tool arguments
        container_image: Container image to use
        workspace_dir: Host workspace directory (cwd or configured)
        runtime: ContainerRuntime instance for the selected runtime
        config: Optional execution config (online mode, API key, etc.)
        timeout: Execution timeout in seconds

    Returns:
        Dict with execution results
    """
    run_id = uuid.uuid4().hex[:12]
    output_dir = tempfile.mkdtemp(prefix=f"aphids-mcp-{run_id}-")

    logger.info(
        f"[{run_id}] Dispatching {tool_name} | "
        f"timeout={timeout}s | output={output_dir}"
    )

    try:
        # Resolve workspace mount
        workspace_host_path = None
        try:
            workspace_host_path = _resolve_workspace_path(
                tool_name, arguments, workspace_dir
            )
        except ValueError as ve:
            logger.error(f"[{run_id}] Workspace resolution failed: {ve}")
            return {
                "success": False,
                "error": f"Workspace error: {ve}",
                "mcp_version": "1.0",
            }

        # Remap arguments for container paths
        container_args = _remap_arguments_for_container(
            tool_name, arguments, workspace_host_path is not None
        )

        # Build volume mounts: (host, container, mode)
        volumes = [(output_dir, "/output", "")]
        if workspace_host_path:
            volumes.append((workspace_host_path, "/workspace", "ro"))
            logger.info(
                f"[{run_id}] Mounting workspace: {workspace_host_path} -> /workspace:ro"
            )

        # Build env vars for online mode
        env_vars = []
        if config and config.get("authorization", {}).get("apiKey"):
            env_vars.append(("APHIDS_API_KEY", config["authorization"]["apiKey"]))
            base_url = config.get("baseUrl", "")
            if base_url:
                env_vars.append(("APHIDS_BASE_URL", base_url))
            ws_url_val = config.get("baseWsUrl", "")
            if ws_url_val:
                env_vars.append(("APHIDS_WS_URL", ws_url_val))

        # Network isolation: static analysis tools scanning local files don't
        # need network. But if workspace isn't mounted (e.g. trufflehog scanning
        # a remote git repo), the tool needs network access.
        network = None
        if tool_name in WORKSPACE_TOOLS and workspace_host_path is not None:
            network = "none"

        # Build container arguments (after image name)
        ctr_args = ["--mcp-exec", tool_name, json.dumps(container_args)]
        if config and config.get("configuration", {}).get("online") == "enabled":
            ctr_args.extend(["--mcp-exec-config", json.dumps(config)])

        # Build the full run command via the runtime abstraction
        cmd = runtime.build_run_cmd(
            container_image,
            rm=True,
            interactive=True,
            volumes=volumes,
            env_vars=env_vars if env_vars else None,
            cap_drop_all=True,
            no_new_privileges=True,
            network=network,
            container_args=ctr_args,
        )

        logger.debug(f"[{run_id}] {runtime.label} command: {' '.join(cmd[:8])}... (truncated)")

        # Execute
        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            logger.error(f"[{run_id}] Tool timed out after {elapsed:.1f}s")
            return {
                "success": False,
                "error": f"Tool '{tool_name}' timed out after {timeout}s",
                "timeout": True,
                "timeout_limit": timeout,
                "mcp_version": "1.0",
            }

        elapsed = time.time() - start_time
        logger.info(
            f"[{run_id}] Container exited (code={proc.returncode}) "
            f"in {elapsed:.1f}s"
        )

        # Log stderr from container (tool discovery messages, debug output)
        if proc.stderr:
            for line in proc.stderr.strip().split("\n")[:50]:
                logger.debug(f"[{run_id}] [container] {line}")

        # Parse stdout — the container outputs JSON result
        stdout = proc.stdout.strip()
        if not stdout:
            logger.error(f"[{run_id}] No stdout from container")
            return {
                "success": False,
                "error": "Container produced no output",
                "exit_code": proc.returncode,
                "stderr": proc.stderr[:1000] if proc.stderr else None,
                "mcp_version": "1.0",
            }

        # Find JSON in stdout — the container prints banner/log lines before
        # the JSON result, so search backwards for the last valid JSON object.
        result = None
        search_pos = len(stdout)
        while search_pos > 0:
            # Find the last newline+{ or start-of-string {
            nl_brace = stdout.rfind("\n{", 0, search_pos)
            if nl_brace >= 0:
                candidate_start = nl_brace + 1
            elif stdout.startswith("{"):
                candidate_start = 0
            else:
                break

            try:
                result = json.loads(stdout[candidate_start:])
                break
            except json.JSONDecodeError:
                search_pos = candidate_start
                result = None

        if result is None:
            logger.error(f"[{run_id}] No valid JSON in stdout: {stdout[:200]}")
            return {
                "success": False,
                "error": "Container output contains no valid JSON",
                "raw_stdout": stdout[:2000],
                "mcp_version": "1.0",
            }

        # If raw_output wasn't included (container didn't read the file),
        # try to read it from the mounted output dir
        if result.get("success") and not result.get("raw_output"):
            output_file = result.get("output_file")
            if output_file:
                # The output_file path is inside the container (/output/...),
                # map it to the host output_dir
                basename = os.path.basename(output_file)
                host_output = os.path.join(output_dir, basename)
                if os.path.isfile(host_output):
                    try:
                        file_size = os.path.getsize(host_output)
                        with open(host_output, "r", errors="replace") as f:
                            raw = f.read(MAX_OUTPUT_SIZE)
                        if file_size > MAX_OUTPUT_SIZE:
                            raw += (
                                f"\n\n... [TRUNCATED — {file_size} bytes total, "
                                f"showing first {MAX_OUTPUT_SIZE}]"
                            )
                        result["raw_output"] = raw
                        logger.debug(
                            f"[{run_id}] Read {len(raw)} chars from {host_output}"
                        )
                    except Exception as read_exc:
                        logger.warning(
                            f"[{run_id}] Failed to read output file: {read_exc}"
                        )

        # Strip the output_file path (it's a container-internal path, not useful to LLM)
        result.pop("output_file", None)

        logger.info(
            f"[{run_id}] {tool_name} completed | "
            f"success={result.get('success')} | "
            f"parsed={result.get('parsed')} | "
            f"elapsed={elapsed:.1f}s"
        )

        return result

    finally:
        # Cleanup: remove temp output directory
        try:
            shutil.rmtree(output_dir, ignore_errors=True)
            logger.debug(f"[{run_id}] Cleaned up {output_dir}")
        except Exception as cleanup_exc:
            logger.warning(f"[{run_id}] Cleanup failed: {cleanup_exc}")


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

async def run_mcp_server(
    container_image: str,
    workspace_dir: str,
    api_key: Optional[str] = None,
    api_url: Optional[str] = None,
    ws_url: Optional[str] = None,
    refresh_tools: bool = False,
    runtime_name: Optional[str] = None,
):
    """Start the MCP server over stdio transport.

    This is the main entry point for ``aphids-cli --mcp``.

    Args:
        container_image: Container image to use for tool execution
        workspace_dir: Host workspace directory (typically cwd)
        api_key: Optional Hive API key for online mode
        api_url: Optional Hive API URL
        ws_url: Optional Hive WebSocket URL
        refresh_tools: Force refresh of tool registry cache
        runtime_name: Container runtime override (docker, podman, nerdctl)
    """
    try:
        import mcp.types as types
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
    except ImportError:
        logger.error(
            "MCP SDK not installed. Run: pip install 'aphids-cli[mcp]' "
            "or pip install mcp"
        )
        sys.exit(1)

    # Detect container runtime (docker, podman, nerdctl)
    runtime = _validate_runtime_available(runtime_name)
    logger.info(f"Using container runtime: {runtime.label} v{runtime.version}")

    # Validate container image
    try:
        container_image = _validate_container_image(container_image)
    except ValueError as ve:
        logger.error(f"Invalid container image: {ve}")
        sys.exit(1)

    # Build config for online mode
    config = None
    if api_key:
        if not api_url:
            api_url = "https://api.hive.darksidesecurity.io"
        if not re.match(r"^https://[a-zA-Z0-9.-]+(:[0-9]+)?$", api_url):
            logger.error(f"Invalid API URL: {api_url}")
            sys.exit(1)
        from datetime import datetime
        session_id = uuid.uuid4().hex[:8]
        session_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        scan_group = os.environ.get("APHIDS_SCAN_GROUP", f"MCP-{session_ts}-{session_id}")
        config = {
            "authorization": {"apiKey": api_key},
            "baseUrl": api_url,
            "baseWsUrl": ws_url or api_url.replace("https://", "wss://"),
            "endpoints": {
                "valis": {"path": "/valis/"},
                "valis-cli": {"path": "/executions-cli/"},
                "continuity": {"path": "/continuity/"},
            },
            "configuration": {
                "online": "enabled",
                "network": "public",
                "team": "users",
                "scan_group": scan_group,
                "team_access": "read",
            },
        }
        logger.info(f"Online mode enabled — API: {api_url} | scan_group: {scan_group}")
    else:
        logger.info("Offline mode — results will not be uploaded to Hive")

    # Discover tools (from cache or container)
    registry = None
    if not refresh_tools:
        registry = _load_cached_registry(container_image)

    if registry is None:
        try:
            registry = _discover_tools_via_container(container_image, runtime)
            _save_registry_cache(registry, container_image)
        except RuntimeError as exc:
            logger.error(f"Failed to discover tools: {exc}")
            sys.exit(1)

    tools = registry.get("tools", [])
    tool_map = {t["name"]: t for t in tools}

    logger.info(
        f"MCP server ready | {len(tools)} tools | "
        f"workspace={workspace_dir} | image={container_image}"
    )

    # -- Admin tool definitions -----------------------------------------------
    _ADMIN_TOOLS = {
        "set_engagement": types.Tool(
            name="set_engagement",
            description=(
                "Set the active engagement configuration for all subsequent "
                "tool runs. Use this to associate scans with a specific Hive "
                "engagement, scan group, or team. At least one parameter must "
                "be provided. Changes take effect immediately for all future "
                "tool calls in this session."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "engagements": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "List of Hive engagement names to associate scans "
                            "with (e.g. ['Q1 2026 External Pentest'])"
                        ),
                    },
                    "scan_group": {
                        "type": "string",
                        "description": (
                            "Scan group name for organizing results "
                            "(e.g. 'Client-ABC-Web-App')"
                        ),
                    },
                    "team": {
                        "type": "string",
                        "description": (
                            "Team name for access control (default: 'users')"
                        ),
                    },
                    "team_access": {
                        "type": "string",
                        "enum": ["read", "write", "admin"],
                        "description": (
                            "Team access level for scan results (default: 'read')"
                        ),
                    },
                },
                "required": [],
            },
        ),
        "get_engagement": types.Tool(
            name="get_engagement",
            description=(
                "Return the current engagement configuration (engagements, "
                "scan_group, team, team_access, online mode). Use this to "
                "verify the active settings before running tools."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
    }

    # -- Data submission tools (findings + assets → Hive graph) ---------------
    _SUBMIT_TOOLS = {
        "submit_findings": types.Tool(
            name="submit_findings",
            description=(
                "Submit vulnerability findings to the Hive graph database. "
                "Use this after running security tools and analyzing the output "
                "to push structured findings into Hive. Each finding needs at "
                "minimum a name and risk level. Include a url (full URL) or host "
                "(IP/hostname) to link the finding to targets in the graph. "
                "Findings are deduplicated by name+url. "
                "Requires online mode (API key configured)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Finding name/title (e.g. 'SQL Injection in login form')",
                                },
                                "risk": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low", "info"],
                                    "description": "Severity level",
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Detailed description of the vulnerability",
                                },
                                "url": {
                                    "type": "string",
                                    "description": "Target URL where the finding was discovered",
                                },
                                "host": {
                                    "type": "string",
                                    "description": "Target host/IP (if no URL)",
                                },
                                "path": {
                                    "type": "string",
                                    "description": "URL path or file path",
                                },
                                "cweid": {
                                    "type": "string",
                                    "description": "CWE ID (e.g. '89')",
                                },
                                "cveid": {
                                    "type": "string",
                                    "description": "CVE ID (e.g. 'CVE-2024-1234')",
                                },
                                "cvss": {
                                    "type": "string",
                                    "description": "CVSS score (e.g. '8.6')",
                                },
                                "evidence": {
                                    "type": "string",
                                    "description": "Evidence/proof (error messages, snippets, etc.)",
                                },
                                "solution": {
                                    "type": "string",
                                    "description": "Remediation guidance",
                                },
                                "confidence": {
                                    "type": "string",
                                    "enum": ["HIGH", "MEDIUM", "LOW"],
                                    "description": "Confidence level of the finding",
                                },
                                "request": {
                                    "type": "string",
                                    "description": "HTTP request that triggered the finding",
                                },
                                "response": {
                                    "type": "string",
                                    "description": "HTTP response containing the evidence",
                                },
                                "reference": {
                                    "type": "string",
                                    "description": "Reference URLs for more information",
                                },
                            },
                            "required": ["name", "risk"],
                        },
                        "description": "Array of vulnerability findings to submit",
                    },
                },
                "required": ["findings"],
            },
        ),
        "submit_assets": types.Tool(
            name="submit_assets",
            description=(
                "Submit discovered assets to the Hive graph database. "
                "Use this after reconnaissance to push URLs, IPs, domains, "
                "ports, hosts, and applications into Hive. Assets are linked "
                "to each other automatically (e.g. URL→site, port→IP, DNS→IP). "
                "Requires online mode (API key configured).\n\n"
                "Required fields per type:\n"
                "  url:   url (full URL string)\n"
                "  ip:    address (IP address)\n"
                "  dns:   name (domain name)\n"
                "  port:  port (port number) + host (IP to link to)\n"
                "  site:  url (hostname only)\n"
                "  host:  name (hostname)\n"
                "  application: name (app name) + host (hostname to link to)"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "assets": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": ["url", "ip", "dns", "port", "site", "host", "application"],
                                    "description": "Asset type — determines which fields are required",
                                },
                                "url": {
                                    "type": "string",
                                    "description": "Full URL (for type: url, e.g. 'https://example.com/path') or hostname (for type: site, e.g. 'example.com')",
                                },
                                "address": {
                                    "type": "string",
                                    "description": "IP address (required for type: ip, e.g. '192.168.1.1')",
                                },
                                "name": {
                                    "type": "string",
                                    "description": "Domain name (required for type: dns), hostname (required for type: host), or app name (required for type: application)",
                                },
                                "port": {
                                    "type": "integer",
                                    "description": "Port number (required for type: port, e.g. 443)",
                                },
                                "protocol": {
                                    "type": "string",
                                    "enum": ["tcp", "udp"],
                                    "description": "Protocol (for type: port, default: tcp)",
                                },
                                "service": {
                                    "type": "string",
                                    "description": "Service name (for type: port, e.g. 'https', 'ssh', 'mysql')",
                                },
                                "state": {
                                    "type": "string",
                                    "enum": ["open", "closed", "filtered"],
                                    "description": "Port state (for type: port, default: open)",
                                },
                                "host": {
                                    "type": "string",
                                    "description": "Associated host or IP — creates a link between this asset and the host/IP node",
                                },
                                "dns_type": {
                                    "type": "string",
                                    "enum": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV"],
                                    "description": "DNS record type (for type: dns, default: A)",
                                },
                                "value": {
                                    "type": "string",
                                    "description": "Resolved value (for type: dns — if an IP, creates dns→IP link)",
                                },
                                "version": {
                                    "type": "string",
                                    "description": "Version string (for type: application, e.g. '2.4.49')",
                                },
                                "cpe": {
                                    "type": "string",
                                    "description": "CPE URI (for type: application, e.g. 'cpe:/a:apache:http_server:2.4.49')",
                                },
                                "os": {
                                    "type": "string",
                                    "description": "Operating system (for type: host, e.g. 'Ubuntu 22.04')",
                                },
                                "title": {
                                    "type": "string",
                                    "description": "Page/site title (for type: url or site)",
                                },
                                "status_code": {
                                    "type": "integer",
                                    "description": "HTTP status code (for type: url or site, e.g. 200)",
                                },
                                "technologies": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Detected technologies (for type: url or site, e.g. ['nginx', 'react'])",
                                },
                            },
                            "required": ["type"],
                        },
                        "description": "Array of assets to submit",
                    },
                },
                "required": ["assets"],
            },
        ),
    }

    # -- Admin tool handlers --------------------------------------------------
    def _handle_submit_data(parser_name: str, arguments: dict) -> dict:
        """Submit findings or assets to the Hive receiver endpoint."""
        nonlocal config

        if config is None or config.get("configuration", {}).get("online") != "enabled":
            return {
                "success": False,
                "error": (
                    "Online mode required. Start the MCP server with an API key: "
                    "aphids-cli --mcp -k YOUR_API_KEY"
                ),
            }

        api_key = config.get("authorization", {}).get("apiKey")
        base_url = config.get("baseUrl", "")
        if not api_key or not base_url:
            return {
                "success": False,
                "error": "API key and base URL required for data submission",
            }

        import urllib.request
        import urllib.error

        # Build the receiver payload.
        # - source.name: validated against alphaNumSpaceHyphenDotRegex (underscores now allowed)
        # - scan: includes name + scanGroup/engagement (downstream parsing extracts them)
        # - team: must be a plain string (receiver calls team.toLowerCase())
        cfg = config.get("configuration", {})
        payload = {
            "source": {"name": parser_name},
            "data": arguments,
            "team": cfg.get("team", "users"),
            "scan": {
                "name": f"MCP {parser_name}",
                "scanGroupName": cfg.get("scan_group", "MCP-Submission"),
            },
        }

        # Add engagement if configured (embedded in scan object for downstream parsing)
        engagements = cfg.get("engagements", [])
        if engagements:
            eng_name = engagements[0] if isinstance(engagements, list) else engagements
            payload["engagement"] = {"name": eng_name}

        receiver_url = f"{base_url}/valis/"
        req_body = json.dumps(payload).encode("utf-8")

        logger.info(
            f"Submitting {parser_name} data to {receiver_url} "
            f"({len(req_body)} bytes)"
        )

        try:
            req = urllib.request.Request(
                receiver_url,
                data=req_body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_body = resp.read().decode("utf-8")
                logger.info(f"Receiver response: {resp.status} {resp_body[:200]}")
                return {
                    "success": True,
                    "message": f"Submitted {parser_name} data to Hive",
                    "status": resp.status,
                    "response": resp_body[:500],
                }
        except urllib.error.HTTPError as he:
            err_body = he.read().decode("utf-8", errors="replace")[:500]
            logger.error(f"Receiver HTTP error {he.code}: {err_body}")
            return {
                "success": False,
                "error": f"Hive API error ({he.code}): {err_body}",
            }
        except Exception as exc:
            logger.error(f"Submission failed: {exc}")
            return {"success": False, "error": f"Submission failed: {str(exc)}"}

    def _handle_set_engagement(arguments: dict) -> dict:
        nonlocal config
        arguments = arguments or {}

        if not arguments:
            return {
                "success": False,
                "error": "At least one parameter required (engagements, scan_group, team, team_access)",
            }

        # Ensure config exists (create minimal if offline mode)
        if config is None:
            config = {
                "configuration": {
                    "online": "disabled",
                    "network": "public",
                    "team": "users",
                    "scan_group": "MCP-Aphids-Scans",
                    "team_access": "read",
                },
            }

        cfg = config["configuration"]
        changes = {}

        try:
            if "engagements" in arguments:
                raw = arguments["engagements"]
                if not isinstance(raw, list):
                    raise ValueError("'engagements' must be an array of strings")
                if len(raw) > MAX_ENGAGEMENTS:
                    raise ValueError(
                        f"'engagements' exceeds max count ({MAX_ENGAGEMENTS})"
                    )
                clean_engs = [_validate_safe_name(e, "engagements[]") for e in raw]
                cfg["engagements"] = clean_engs
                changes["engagements"] = clean_engs

            if "scan_group" in arguments:
                val = _validate_safe_name(arguments["scan_group"], "scan_group")
                cfg["scan_group"] = val
                changes["scan_group"] = val

            if "team" in arguments:
                val = _validate_safe_name(arguments["team"], "team")
                cfg["team"] = val
                changes["team"] = val

            if "team_access" in arguments:
                val = arguments["team_access"]
                if val not in ("read", "write", "admin"):
                    raise ValueError(
                        "'team_access' must be one of: read, write, admin"
                    )
                cfg["team_access"] = val
                changes["team_access"] = val

        except ValueError as ve:
            return {"success": False, "error": str(ve)}

        logger.info(f"Engagement config updated: {changes}")

        return {
            "success": True,
            "message": "Engagement configuration updated",
            "changes": changes,
            "current_config": {
                "engagements": cfg.get("engagements", []),
                "scan_group": cfg.get("scan_group"),
                "team": cfg.get("team"),
                "team_access": cfg.get("team_access"),
                "online": cfg.get("online"),
            },
        }

    def _handle_get_engagement() -> dict:
        if config is None:
            return {
                "success": True,
                "configuration": {
                    "engagements": [],
                    "scan_group": None,
                    "team": None,
                    "team_access": None,
                    "online": "disabled",
                    "network": None,
                },
            }
        cfg = config["configuration"]
        return {
            "success": True,
            "configuration": {
                "engagements": cfg.get("engagements", []),
                "scan_group": cfg.get("scan_group"),
                "team": cfg.get("team"),
                "team_access": cfg.get("team_access"),
                "online": cfg.get("online"),
                "network": cfg.get("network"),
            },
        }

    # Build MCP server
    server = Server("aphids-security-tools")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        admin = list(_ADMIN_TOOLS.values())
        admin.extend(_SUBMIT_TOOLS.values())
        admin.extend(
            types.Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["inputSchema"],
            )
            for t in tools
        )
        return admin

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:

        # Admin tools — handled locally, no Docker dispatch
        if name == "set_engagement":
            result = _handle_set_engagement(arguments)
            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2, default=str),
            )]
        if name == "get_engagement":
            result = _handle_get_engagement()
            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2, default=str),
            )]

        # Data submission tools — POST to Hive receiver, no Docker dispatch
        if name == "submit_findings":
            result = await asyncio.to_thread(
                _handle_submit_data, "sarif", arguments
            )
            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2, default=str),
            )]
        if name == "submit_assets":
            result = await asyncio.to_thread(
                _handle_submit_data, "asset_ingest", arguments
            )
            return [types.TextContent(
                type="text",
                text=json.dumps(result, indent=2, default=str),
            )]

        # Validate tool name
        try:
            name = _sanitize_tool_name(name)
        except ValueError as ve:
            return [types.TextContent(
                type="text",
                text=json.dumps({"success": False, "error": str(ve)}),
            )]

        if name not in tool_map:
            return [types.TextContent(
                type="text",
                text=json.dumps({
                    "success": False,
                    "error": f"Unknown tool: {name}",
                }),
            )]

        arguments = arguments or {}

        # Determine timeout
        tool_timeout = DEFAULT_TOOL_TIMEOUT
        if isinstance(arguments.get("timeout"), int) and arguments["timeout"] > 0:
            tool_timeout = min(arguments["timeout"], MAX_TOOL_TIMEOUT)

        # Dispatch to container in a background thread
        logger.info(f"Tool call: {name} | args: {list(arguments.keys())}")
        try:
            result = await asyncio.to_thread(
                dispatch_tool,
                tool_name=name,
                arguments=arguments,
                container_image=container_image,
                workspace_dir=workspace_dir,
                runtime=runtime,
                config=config,
                timeout=tool_timeout,
            )
        except Exception as exc:
            logger.error(f"Dispatch error for {name}: {exc}")
            result = {
                "success": False,
                "error": f"Dispatch error: {str(exc)}",
                "mcp_version": "1.0",
            }

        return [types.TextContent(
            type="text",
            text=json.dumps(result, indent=2, default=str),
        )]

    # Run stdio transport
    logger.info("Starting MCP stdio transport")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )
