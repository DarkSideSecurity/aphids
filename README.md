<div align="center">

# Aphids CLI

**Containerized Security Toolkit for Penetration Testing & Vulnerability Assessment**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io)
[![Container: OCI](https://img.shields.io/badge/container-OCI--compatible-blue.svg)](#container-runtime-support)

*By [Dark Side Security](https://darksidesecurity.io)*

[Documentation](https://aphids.darksidesecurity.io) &middot; [Report a Bug](https://github.com/darksidesecurity/aphids/issues) &middot; [Hive Platform](https://hive.darksidesecurity.io)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Container Runtime Support](#container-runtime-support)
- [Security](#security)
- [API Key Management](#api-key-management)
- [CLI Reference](#cli-reference)
- [Environment Variables](#environment-variables)
- [MCP Client Configuration](#mcp-client-configuration)
- [CI/CD Integration](#cicd-integration)
- [Documentation](#documentation)
- [License](#license)

---

## Overview

Aphids CLI is the command-line interface for the **Aphids** security toolkit. It orchestrates penetration testing and vulnerability assessment tools inside isolated, ephemeral containers — providing a consistent, reproducible, and secure execution environment across any infrastructure.

### Key Capabilities

- **30+ security tools** — network scanning, static analysis, secret detection, web application testing, and more
- **Container-isolated execution** — every tool runs in a fresh, ephemeral container with dropped capabilities and read-only mounts
- **Multi-runtime support** — works with Docker, Podman, and nerdctl (Rancher Desktop / containerd)
- **AI agent integration** — native [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for use with Windsurf, Claude Desktop, Cursor, and other AI coding assistants
- **Hive platform integration** — connect to [Hive](https://hive.darksidesecurity.io) for runbooks, attack trees, scan executions, engagement tracking, and centralized reporting
- **Persistent agent mode** — deploy long-running agents that receive and execute scan commands via WebSocket

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  AI Client  /  Terminal  /  Hive Platform             │
└─────────────────────┬────────────────────────────────┘
                      │
             ┌────────▼────────┐
             │   Aphids CLI    │  Host process (Python)
             │                 │  - Argument parsing
             │  ┌───────────┐  │  - Container runtime detection
             │  │ MCP Shim  │  │  - Tool discovery & dispatch
             │  └───────────┘  │  - Input validation & security
             └────────┬────────┘
                      │  container run (ephemeral, --rm)
             ┌────────▼────────┐
             │  Aphids Core    │  OCI Container
             │                 │  - 30+ security tool wrappers
             │  /workspace:ro  │  - Structured JSON output
             │  /output        │  - Zero host access
             └─────────────────┘
```

**Aphids CLI** runs on the host. It builds and executes container commands against the **Aphids Core** image, which packages all security tools and their dependencies. Each tool invocation is a fresh, isolated container — no state leaks between runs.

---

## Requirements

| Requirement | Details |
|---|---|
| **Python** | 3.10 or later |
| **Container Runtime** | [Docker](https://docs.docker.com/get-docker/), [Podman](https://podman.io/), or [nerdctl](https://github.com/containerd/nerdctl) |
| **Aphids Core Image** | `ghcr.io/darksidesecurity/aphids:latest` |

Pull the container image:

```bash
docker pull ghcr.io/darksidesecurity/aphids:latest
```

---

## Installation

### Standard Install

```bash
pip install git+https://github.com/darksidesecurity/aphids.git
```

### With MCP Support (AI Agent Integration)

The [MCP](https://modelcontextprotocol.io) protocol SDK is an optional dependency. Install it if you plan to use Aphids with AI coding assistants:

```bash
pip install "aphids-cli[mcp] @ git+https://github.com/darksidesecurity/aphids.git"
```

### Development Install

```bash
git clone https://github.com/darksidesecurity/aphids.git
cd aphids
pip install -e ".[mcp,dev]"
pytest
```

### Verify Installation

```bash
aphids-cli --help
```

---

## Quick Start

### Offline Mode

Run scans locally using YAML configuration files. No network or API key required.

```bash
aphids-cli -o options.yaml -c config.yaml
```

### Online Mode (Hive Integration)

Connect to the [Hive](https://hive.darksidesecurity.io) platform for runbooks, attack trees, and centralized reporting. Set your API key via environment variable (see [API Key Management](#api-key-management)):

```bash
export APHIDS_API_KEY="your-api-key"

# Execute a runbook against a target URL
aphids-cli -r RUNBOOK_ID --target-url https://example.com

# Execute an attack tree against a target domain
aphids-cli -at ATTACK_TREE_ID --target-domain example.com

# Run a pre-configured scan execution
aphids-cli -se EXECUTION_ID
```

### MCP Mode (AI Agent Integration)

Start Aphids as an [MCP](https://modelcontextprotocol.io) server. AI clients discover and invoke security tools through the standard MCP protocol.

```bash
# Local-only (offline scans)
aphids-cli --mcp

# With Hive integration (results uploaded to platform)
APHIDS_API_KEY="your-api-key" aphids-cli --mcp
```

The MCP server automatically discovers all available tools from the container image and exposes them to the AI client. It also provides administrative tools (`set_engagement`, `get_engagement`) for dynamic engagement configuration during a session.

### Agent Mode

Deploy a persistent agent that registers with the Hive and waits for scan commands via WebSocket.

```bash
aphids-cli --agent --agent-name prod-scanner-01
```

Agents support auto-exit for ephemeral CI/CD runners:

```bash
aphids-cli --agent --exit-on-idle 300
```

---

## Container Runtime Support

Aphids auto-detects your container runtime in the following priority order:

| Priority | Runtime | Notes |
|:---:|---|---|
| 1 | **Docker** | Default. Most widely available. |
| 2 | **Podman** | Rootless, daemonless. Common on RHEL/Fedora. |
| 3 | **nerdctl** | containerd CLI. Used by Rancher Desktop and Lima. |

Override auto-detection:

```bash
# CLI flag
aphids-cli --runtime podman -o options.yaml

# Environment variable
export APHIDS_CONTAINER_RUNTIME=podman
```

---

## Security

Aphids is designed with a zero-trust, defense-in-depth approach to container execution:

- **Ephemeral containers** — every tool invocation runs in a fresh container (`--rm`). No state persists between runs.
- **Dropped capabilities** — all Linux capabilities are dropped (`--cap-drop ALL`).
- **No privilege escalation** — `--security-opt no-new-privileges` is enforced on Docker and Podman.
- **Read-only workspace** — host directories are mounted read-only (`:ro`). Tools cannot modify your source code.
- **Network isolation** — static analysis tools run with `--network none`. Only tools that require network access are granted it.
- **Input validation** — all tool arguments, file paths, and configuration values are validated and sanitized before execution.
- **Path traversal protection** — workspace paths are canonicalized and checked against the allowed base directory.
- **No secrets on disk** — API keys are passed via environment variables to the container, never written to the filesystem, never logged, and never cached.

---

## API Key Management

> **Never pass your API key directly on the command line.** Command-line arguments are visible in process listings (`ps aux`) and may be recorded in shell history. Always use environment variables or a secrets manager.

### Recommended: Environment Variable

Set `APHIDS_API_KEY` in your shell profile, CI/CD pipeline, or container orchestrator:

```bash
# Shell profile (~/.bashrc, ~/.zshrc)
export APHIDS_API_KEY="your-api-key"

# Then run normally — no -k flag needed
aphids-cli --mcp
aphids-cli -r RUNBOOK_ID --target-url https://example.com
```

For MCP client configurations (Windsurf, Claude Desktop, Cursor), pass the key via the `env` block — this keeps it out of the `args` array and out of process listings:

```json
{
  "env": {
    "APHIDS_API_KEY": "your-api-key"
  }
}
```

### Secret Manager Integration

Aphids does not yet have native secret manager integration, but you can retrieve the key at runtime from any secrets provider using a shell wrapper:

```bash
# AWS Secrets Manager
export APHIDS_API_KEY=$(aws secretsmanager get-secret-value \
  --secret-id aphids/api-key --query SecretString --output text)

# Azure Key Vault
export APHIDS_API_KEY=$(az keyvault secret show \
  --vault-name my-vault --name aphids-api-key --query value -o tsv)

# Google Cloud Secret Manager
export APHIDS_API_KEY=$(gcloud secrets versions access latest \
  --secret=aphids-api-key)

# HashiCorp Vault
export APHIDS_API_KEY=$(vault kv get -field=api_key secret/aphids)
```

> **Roadmap:** Native integration with AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, and HashiCorp Vault is planned for a future release — allowing Aphids to retrieve credentials directly without shell wrappers. Track progress in [GitHub Issues](https://github.com/darksidesecurity/aphids/issues).

---

## CLI Reference

### Scan Configuration

| Flag | Description |
|---|---|
| `-o`, `--options FILE` | Options YAML file defining scan modules and their arguments |
| `-c`, `--config FILE` | Configuration YAML file with identity and auth information |
| `-sp`, `--static-path DIR` | Host directory to mount for static analysis scans |

### Online Mode (Hive)

| Flag | Description |
|---|---|
| `-k`, `--api-key KEY` | API key for Hive authentication (prefer `APHIDS_API_KEY` env var) |
| `-u`, `--api-url URL` | Hive API base URL |
| `-uw`, `--wsapi-url URL` | Hive WebSocket API URL |
| `-r`, `--runbook ID` | Execute a runbook by ID |
| `-at`, `--attack-tree ID` | Execute an attack tree by ID |
| `-ats`, `--attack-tree-scope SCOPE` | Scope restriction for attack trees (IP, CIDR, domain, wildcard) |
| `-se`, `--scan-execution ID` | Execute a pre-configured scan execution by ID |
| `-e`, `--engagement ID` | Associate scans with a Hive engagement |
| `-n`, `--network NAME` | Network name to prevent DNS/IP collisions (default: `public`) |

### Targeting

| Flag | Description |
|---|---|
| `--target-url URL` | Target URL (e.g. `https://example.com`) |
| `--target-host HOST` | Target host — FQDN, IP, or CIDR |
| `--target-domain DOMAIN` | Target domain for subdomain enumeration |
| `--target-dir DIR` | Target directory for file-based scans |

### MCP Mode

| Flag | Description |
|---|---|
| `--mcp` | Start as an MCP server for AI agent integration |
| `--mcp-workspace DIR` | Workspace directory for static analysis tools (default: cwd) |
| `--mcp-refresh` | Force re-discovery of tools from the container image |

### Agent Mode

| Flag | Description |
|---|---|
| `--agent` | Start in persistent agent mode |
| `--agent-name NAME` | Friendly name for this agent instance |
| `--exit-on-idle SECONDS` | Auto-exit after N seconds idle (0 = never). Useful for CI/CD. |
| `--ws-url URL` | WebSocket URL override for agent mode |
| `--resume ID` | Resume a previously interrupted scan by group or execution ID |

### General

| Flag | Description |
|---|---|
| `-i`, `--image IMAGE` | Custom container image (default: `ghcr.io/darksidesecurity/aphids:latest`) |
| `--runtime RUNTIME` | Container runtime: `docker`, `podman`, or `nerdctl` (default: auto-detect) |
| `--unattended` | Auto-approve all prompts. **Use with caution.** |
| `-d`, `--debug` | Enable debug output |

---

## Environment Variables

| Variable | Description |
|---|---|
| `APHIDS_API_KEY` | **Recommended.** Hive API key. Preferred over the `-k` CLI flag. See [API Key Management](#api-key-management). |
| `APHIDS_API_URL` | Hive API base URL (alternative to `-u` flag) |
| `APHIDS_WS_URL` | Hive WebSocket URL (alternative to `--ws-url` flag) |
| `APHIDS_CONTAINER_RUNTIME` | Container runtime override (`docker`, `podman`, `nerdctl`) |
| `APHIDS_DEBUG` | Set to `true` to enable debug logging |

---

## MCP Client Configuration

To use Aphids with an AI coding assistant, add the following to your client's MCP configuration. The `APHIDS_API_KEY` is optional — without it, Aphids runs in offline mode and results are returned directly to the AI client without uploading to the Hive.

### Windsurf

`~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "aphids-security-tools": {
      "command": "aphids-cli",
      "args": ["--mcp"],
      "env": {
        "APHIDS_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Claude Desktop

| OS | Config Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "aphids-security-tools": {
      "command": "aphids-cli",
      "args": ["--mcp", "--mcp-workspace", "/path/to/your/project"],
      "env": {
        "APHIDS_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Cursor

`~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "aphids-security-tools": {
      "command": "aphids-cli",
      "args": ["--mcp"],
      "env": {
        "APHIDS_API_KEY": "your-api-key"
      }
    }
  }
}
```

---

## CI/CD Integration

Aphids supports two integration strategies for CI/CD pipelines:

| Approach | Best For | Requirements |
|---|---|---|
| **Container direct** | Simple scans, fastest startup, no Python needed | Docker on the runner |
| **CLI install** | Runbooks, attack trees, scan executions, Hive reporting | Python 3.10+ on the runner |

Both approaches return structured JSON to stdout and set a non-zero exit code on failure, so your pipeline can gate merges on scan results regardless of which method you use.

When `APHIDS_API_KEY` is set, results are **automatically uploaded** to the Hive platform for centralized tracking, deduplication, and team visibility — in addition to being printed to the pipeline console.

### GitHub Actions

#### Container Direct

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  aphids-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Aphids scan
        run: |
          docker run --rm \
            -e APHIDS_API_KEY="${{ secrets.APHIDS_API_KEY }}" \
            -v "${{ github.workspace }}:/workspace:ro" \
            ghcr.io/darksidesecurity/aphids:latest \
            -o /workspace/options.yaml
```

#### CLI with Hive Integration

```yaml
name: Security Scan (Hive)
on: [push, pull_request]

jobs:
  aphids-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Aphids CLI
        run: pip install git+https://github.com/darksidesecurity/aphids.git

      - name: Run scan execution
        env:
          APHIDS_API_KEY: ${{ secrets.APHIDS_API_KEY }}
        run: aphids-cli -se ${{ vars.SCAN_EXECUTION_ID }}
```

### GitLab CI

#### Container Direct

```yaml
aphids-scan:
  image: docker:latest
  services:
    - docker:dind
  variables:
    APHIDS_API_KEY: $APHIDS_API_KEY  # Set in CI/CD → Variables (masked)
  script:
    - docker run --rm
        -e APHIDS_API_KEY="${APHIDS_API_KEY}"
        -v "${CI_PROJECT_DIR}:/workspace:ro"
        ghcr.io/darksidesecurity/aphids:latest
        -o /workspace/options.yaml
```

#### CLI with Hive Integration

```yaml
aphids-scan:
  image: python:3.12-slim
  variables:
    APHIDS_API_KEY: $APHIDS_API_KEY
  before_script:
    - pip install git+https://github.com/darksidesecurity/aphids.git
  script:
    - aphids-cli -se $SCAN_EXECUTION_ID
```

### Jenkins

```groovy
pipeline {
    agent any
    environment {
        APHIDS_API_KEY = credentials('aphids-api-key')
    }
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    docker run --rm \
                        -e APHIDS_API_KEY="${APHIDS_API_KEY}" \
                        -v "${WORKSPACE}:/workspace:ro" \
                        ghcr.io/darksidesecurity/aphids:latest \
                        -o /workspace/options.yaml
                '''
            }
        }
    }
}
```

### Pipeline Output

Aphids returns structured JSON results to stdout. In online mode, results are simultaneously uploaded to the Hive. A typical pipeline run:

```
[+] Scan ID: f8e30a94-851c-446d-9c0d-f55784270d02
[-] Executing module: trufflehog
[-] Completed module run for trufflehog. Processing results.
[-] Executing module: semgrep
[-] Completed module run for semgrep. Processing results.
[*] Results uploaded to Hive.
[*] Done. 2 modules executed, 14 findings.
```

| Exit Code | Meaning |
|:---:|---|
| `0` | Scan completed successfully |
| `1` | Scan completed with errors or findings above threshold |
| `2` | Configuration or authentication error |

> **Tip:** For pull request workflows, run Aphids on every PR to catch secrets, dependency vulnerabilities, and code issues before merge. Use scan executions (`-se`) for consistent, repeatable configurations managed from the Hive UI.

---

## Documentation

Full documentation is available at **[aphids.darksidesecurity.io](https://aphids.darksidesecurity.io)**.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

<div align="center">

**[Dark Side Security](https://darksidesecurity.io)** — Offensive Security, Automated.

</div>