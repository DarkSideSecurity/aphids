"""
Container Runtime Abstraction for Aphids CLI

Supports multiple OCI-compatible container runtimes:
  - Docker       (default)
  - Podman       (rootless, daemonless — Red Hat / Fedora / RHEL)
  - nerdctl      (containerd CLI — Rancher Desktop, Lima, k3s)
  - Lima nerdctl (macOS via Lima VM — Rancher Desktop on macOS)

Selection priority:
  1. Explicit --runtime CLI arg or APHIDS_CONTAINER_RUNTIME env var
  2. Auto-detect: probe each runtime in order and use the first available

All runtimes are OCI-compatible and use the same ``run``, ``version``,
and image-name conventions, but each has small behavioural differences
that this module normalises.
"""

import os
import re
import shutil
import subprocess
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger("aphids-mcp")

# ---------------------------------------------------------------------------
# Supported runtimes — probed in this order during auto-detect
# ---------------------------------------------------------------------------

SUPPORTED_RUNTIMES = ("docker", "podman", "nerdctl")

# Env var / CLI arg override
ENV_VAR = "APHIDS_CONTAINER_RUNTIME"

# Validation: binary name must be one of the known runtimes
_RUNTIME_NAME_RE = re.compile(r"^(docker|podman|nerdctl)$")


# ---------------------------------------------------------------------------
# Runtime metadata — quirks and extra flags per runtime
# ---------------------------------------------------------------------------

_RUNTIME_META = {
    "docker": {
        "label": "Docker",
        "version_fmt": "{{.Server.Version}}",
        "extra_run_flags": [],
        "supports_cap_drop": True,
        "supports_security_opt": True,
    },
    "podman": {
        "label": "Podman",
        # Podman uses Go-template but with slightly different server info
        "version_fmt": "{{.Version.Version}}",
        "extra_run_flags": [],
        "supports_cap_drop": True,
        "supports_security_opt": True,
    },
    "nerdctl": {
        "label": "nerdctl (containerd)",
        "version_fmt": None,  # nerdctl version doesn't support --format
        "extra_run_flags": [],
        "supports_cap_drop": True,
        # nerdctl doesn't support --security-opt no-new-privileges
        "supports_security_opt": False,
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ContainerRuntime:
    """Resolved container runtime with its binary path and metadata."""

    def __init__(self, name: str, binary: str, version: str):
        self.name = name
        self.binary = binary
        self.version = version
        self._meta = _RUNTIME_META.get(name, _RUNTIME_META["docker"])

    @property
    def label(self) -> str:
        return self._meta["label"]

    @property
    def extra_run_flags(self) -> List[str]:
        return list(self._meta["extra_run_flags"])

    @property
    def supports_cap_drop(self) -> bool:
        return self._meta["supports_cap_drop"]

    @property
    def supports_security_opt(self) -> bool:
        return self._meta["supports_security_opt"]

    def build_run_cmd(
        self,
        image: str,
        *,
        rm: bool = True,
        interactive: bool = False,
        tty: bool = False,
        volumes: Optional[List[Tuple[str, str, str]]] = None,
        env_vars: Optional[List[Tuple[str, str]]] = None,
        cap_drop_all: bool = False,
        no_new_privileges: bool = False,
        network: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        container_args: Optional[List[str]] = None,
    ) -> List[str]:
        """Build a ``<runtime> run`` command list.

        Args:
            image: Container image name
            rm: Add --rm flag
            interactive: Add -i flag
            tty: Add -t flag
            volumes: List of (host_path, container_path, mode) tuples
            env_vars: List of (key, value) tuples
            cap_drop_all: Add --cap-drop ALL
            no_new_privileges: Add --security-opt no-new-privileges
            network: Network mode (e.g. "none", "host")
            extra_args: Additional flags before the image name
            container_args: Arguments after the image name

        Returns:
            Complete command as a list of strings
        """
        cmd = [self.binary, "run"]

        if rm:
            cmd.append("--rm")
        if interactive:
            cmd.append("-i")
        if tty:
            cmd.append("-t")

        # Runtime-specific extra flags
        cmd.extend(self.extra_run_flags)

        # Security hardening
        if cap_drop_all and self.supports_cap_drop:
            cmd.extend(["--cap-drop", "ALL"])
        if no_new_privileges and self.supports_security_opt:
            cmd.extend(["--security-opt", "no-new-privileges"])

        # Network
        if network:
            cmd.extend(["--network", network])

        # Volumes
        if volumes:
            for host_path, container_path, mode in volumes:
                mount_spec = f"{host_path}:{container_path}"
                if mode:
                    mount_spec += f":{mode}"
                cmd.extend(["-v", mount_spec])

        # Environment variables
        if env_vars:
            for key, value in env_vars:
                cmd.extend(["-e", f"{key}={value}"])

        # Extra flags
        if extra_args:
            cmd.extend(extra_args)

        # Image
        cmd.append(image)

        # Container arguments (after image)
        if container_args:
            cmd.extend(container_args)

        return cmd

    def build_version_cmd(self) -> List[str]:
        """Build a version check command."""
        cmd = [self.binary, "version"]
        fmt = self._meta.get("version_fmt")
        if fmt:
            cmd.extend(["--format", fmt])
        return cmd

    def __repr__(self) -> str:
        return f"ContainerRuntime(name={self.name!r}, binary={self.binary!r}, version={self.version!r})"


def detect_runtime(preferred: Optional[str] = None) -> ContainerRuntime:
    """Detect and validate a container runtime.

    Args:
        preferred: Explicit runtime name (from CLI arg or env var).
                   If None, checks APHIDS_CONTAINER_RUNTIME env var,
                   then auto-detects.

    Returns:
        A validated ContainerRuntime instance.

    Raises:
        RuntimeError: If no supported runtime is found.
    """
    # 1. Explicit preference
    choice = preferred or os.environ.get(ENV_VAR)

    if choice:
        choice = choice.strip().lower()
        if not _RUNTIME_NAME_RE.match(choice):
            raise RuntimeError(
                f"Unsupported container runtime: '{choice}'. "
                f"Supported: {', '.join(SUPPORTED_RUNTIMES)}"
            )
        rt = _probe_runtime(choice)
        if rt:
            return rt
        raise RuntimeError(
            f"Container runtime '{choice}' was requested but is not "
            f"available. Ensure it is installed and in your PATH."
        )

    # 2. Auto-detect — probe in priority order
    for name in SUPPORTED_RUNTIMES:
        rt = _probe_runtime(name)
        if rt:
            logger.info(f"Auto-detected container runtime: {rt.label} v{rt.version}")
            return rt

    raise RuntimeError(
        "No supported container runtime found. "
        f"Please install one of: {', '.join(SUPPORTED_RUNTIMES)}. "
        "Or set APHIDS_CONTAINER_RUNTIME to specify one explicitly."
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _probe_runtime(name: str) -> Optional[ContainerRuntime]:
    """Check if a runtime binary exists and is responsive."""
    binary = shutil.which(name)
    if not binary:
        return None

    meta = _RUNTIME_META.get(name, _RUNTIME_META["docker"])

    try:
        cmd = [binary, "version"]
        fmt = meta.get("version_fmt")
        if fmt:
            cmd.extend(["--format", fmt])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0:
            version = result.stdout.strip().split("\n")[0]
            # nerdctl outputs multi-line without --format; grab first line
            if not version:
                version = "unknown"
            return ContainerRuntime(name=name, binary=binary, version=version)

        logger.debug(f"{name} check failed (exit {result.returncode}): {result.stderr.strip()}")
        return None

    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        logger.debug(f"{name} version check timed out")
        return None
    except Exception as exc:
        logger.debug(f"{name} probe error: {exc}")
        return None
