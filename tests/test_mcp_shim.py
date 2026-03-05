"""
Comprehensive tests for the Aphids CLI MCP Server Shim.

Tests cover:
  - Security: path traversal, input validation, container image validation
  - Docker dispatch: command construction, workspace mounting, output handling
  - Tool registry: caching, discovery, invalidation
  - MCP protocol: tool listing, tool calling, error handling
  - Edge cases: timeouts, missing Docker, malformed JSON, empty output
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock, call

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_shim


class TestPathValidation(unittest.TestCase):
    """Test _validate_path_safe — the core security function."""

    def setUp(self):
        self.base_dir = tempfile.mkdtemp(prefix="aphids-test-")
        self.sub_dir = os.path.join(self.base_dir, "project")
        os.makedirs(self.sub_dir)
        self.nested_dir = os.path.join(self.sub_dir, "src", "main")
        os.makedirs(self.nested_dir)

    def tearDown(self):
        shutil.rmtree(self.base_dir, ignore_errors=True)

    def test_valid_relative_path(self):
        result = mcp_shim._validate_path_safe("project", self.base_dir)
        self.assertEqual(result, os.path.realpath(self.sub_dir))

    def test_valid_nested_relative_path(self):
        result = mcp_shim._validate_path_safe(
            "project/src/main", self.base_dir
        )
        self.assertEqual(result, os.path.realpath(self.nested_dir))

    def test_valid_dot_path(self):
        result = mcp_shim._validate_path_safe(".", self.base_dir)
        self.assertEqual(result, os.path.realpath(self.base_dir))

    def test_path_traversal_dotdot(self):
        with self.assertRaises(ValueError) as ctx:
            mcp_shim._validate_path_safe("../../../etc/passwd", self.base_dir)
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_path_traversal_encoded(self):
        with self.assertRaises(ValueError) as ctx:
            mcp_shim._validate_path_safe("..", self.base_dir)
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_path_traversal_nested(self):
        with self.assertRaises(ValueError) as ctx:
            mcp_shim._validate_path_safe("project/../../..", self.base_dir)
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_null_byte_injection(self):
        with self.assertRaises(ValueError) as ctx:
            mcp_shim._validate_path_safe("project\x00.txt", self.base_dir)
        self.assertIn("null", str(ctx.exception).lower())

    def test_absolute_path_outside_base(self):
        with self.assertRaises(ValueError):
            mcp_shim._validate_path_safe("/etc/passwd", self.base_dir)

    def test_absolute_path_inside_base(self):
        result = mcp_shim._validate_path_safe(self.sub_dir, self.base_dir)
        self.assertEqual(result, os.path.realpath(self.sub_dir))

    def test_symlink_escape(self):
        """Symlink pointing outside base should be caught."""
        link_path = os.path.join(self.base_dir, "evil_link")
        os.symlink("/etc", link_path)
        with self.assertRaises(ValueError):
            mcp_shim._validate_path_safe("evil_link", self.base_dir)


class TestToolNameValidation(unittest.TestCase):
    """Test _sanitize_tool_name."""

    def test_valid_tool_name(self):
        self.assertEqual(mcp_shim._sanitize_tool_name("run_nmap"), "run_nmap")

    def test_valid_tool_with_hyphen(self):
        self.assertEqual(
            mcp_shim._sanitize_tool_name("run_jwt-tool"), "run_jwt-tool"
        )

    def test_invalid_no_prefix(self):
        with self.assertRaises(ValueError):
            mcp_shim._sanitize_tool_name("nmap")

    def test_invalid_injection(self):
        with self.assertRaises(ValueError):
            mcp_shim._sanitize_tool_name("run_nmap; rm -rf /")

    def test_invalid_empty(self):
        with self.assertRaises(ValueError):
            mcp_shim._sanitize_tool_name("")

    def test_invalid_too_long(self):
        with self.assertRaises(ValueError):
            mcp_shim._sanitize_tool_name("run_" + "a" * 100)

    def test_invalid_special_chars(self):
        with self.assertRaises(ValueError):
            mcp_shim._sanitize_tool_name("run_$(whoami)")


class TestContainerImageValidation(unittest.TestCase):
    """Test _validate_container_image."""

    def test_valid_default_image(self):
        img = "ghcr.io/darksidesecurity/aphids:latest"
        self.assertEqual(mcp_shim._validate_container_image(img), img)

    def test_valid_simple_image(self):
        self.assertEqual(
            mcp_shim._validate_container_image("aphids-core:v1.0"),
            "aphids-core:v1.0",
        )

    def test_invalid_injection(self):
        with self.assertRaises(ValueError):
            mcp_shim._validate_container_image("aphids; rm -rf /")

    def test_invalid_backtick(self):
        with self.assertRaises(ValueError):
            mcp_shim._validate_container_image("aphids`whoami`")

    def test_invalid_too_long(self):
        with self.assertRaises(ValueError):
            mcp_shim._validate_container_image("a" * 300)


class TestWorkspaceResolution(unittest.TestCase):
    """Test _resolve_workspace_path."""

    def setUp(self):
        self.workspace = tempfile.mkdtemp(prefix="aphids-ws-")
        self.project_dir = os.path.join(self.workspace, "myproject")
        os.makedirs(self.project_dir)

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_non_workspace_tool_returns_none(self):
        result = mcp_shim._resolve_workspace_path(
            "run_nmap", {"target": "192.168.1.1"}, self.workspace
        )
        self.assertIsNone(result)

    def test_workspace_tool_dot_target(self):
        result = mcp_shim._resolve_workspace_path(
            "run_semgrep", {"target_dir": "."}, self.workspace
        )
        self.assertEqual(result, self.workspace)

    def test_workspace_tool_relative_path(self):
        result = mcp_shim._resolve_workspace_path(
            "run_semgrep", {"target_dir": "myproject"}, self.workspace
        )
        self.assertEqual(result, os.path.realpath(self.project_dir))

    def test_workspace_tool_no_param_uses_root(self):
        result = mcp_shim._resolve_workspace_path(
            "run_semgrep", {}, self.workspace
        )
        self.assertEqual(result, self.workspace)

    def test_workspace_tool_traversal_blocked(self):
        with self.assertRaises(ValueError):
            mcp_shim._resolve_workspace_path(
                "run_gitleaks", {"target_dir": "../../etc"}, self.workspace
            )

    def test_trufflehog_target_param(self):
        result = mcp_shim._resolve_workspace_path(
            "run_trufflehog", {"target": "."}, self.workspace
        )
        self.assertEqual(result, self.workspace)

    def test_trufflehog_git_target_type_no_workspace(self):
        """Trufflehog with target_type=git should NOT mount workspace."""
        result = mcp_shim._resolve_workspace_path(
            "run_trufflehog",
            {"target": "https://github.com/org/repo", "target_type": "git"},
            self.workspace,
        )
        self.assertIsNone(result)

    def test_trufflehog_github_target_type_no_workspace(self):
        result = mcp_shim._resolve_workspace_path(
            "run_trufflehog",
            {"target": "https://github.com/org/repo", "target_type": "github"},
            self.workspace,
        )
        self.assertIsNone(result)

    def test_trufflehog_s3_target_type_no_workspace(self):
        result = mcp_shim._resolve_workspace_path(
            "run_trufflehog",
            {"target": "s3://bucket/path", "target_type": "s3"},
            self.workspace,
        )
        self.assertIsNone(result)

    def test_url_target_no_workspace(self):
        """URL-like targets should not trigger workspace mount."""
        result = mcp_shim._resolve_workspace_path(
            "run_trufflehog",
            {"target": "https://github.com/org/repo"},
            self.workspace,
        )
        self.assertIsNone(result)

    def test_git_ssh_target_no_workspace(self):
        result = mcp_shim._resolve_workspace_path(
            "run_trufflehog",
            {"target": "git@github.com:org/repo.git", "target_type": "git"},
            self.workspace,
        )
        self.assertIsNone(result)


class TestArgumentRemapping(unittest.TestCase):
    """Test _remap_arguments_for_container."""

    def test_no_remap_when_no_workspace(self):
        args = {"target": "192.168.1.1", "ports": "80,443"}
        result = mcp_shim._remap_arguments_for_container(
            "run_nmap", args, False
        )
        self.assertEqual(result, args)

    def test_remap_target_dir(self):
        args = {"target_dir": "/home/user/project", "name": "test"}
        result = mcp_shim._remap_arguments_for_container(
            "run_semgrep", args, True
        )
        self.assertEqual(result["target_dir"], "/workspace")
        self.assertEqual(result["name"], "test")

    def test_remap_dot_target(self):
        args = {"target_dir": "."}
        result = mcp_shim._remap_arguments_for_container(
            "run_gitleaks", args, True
        )
        self.assertEqual(result["target_dir"], "/workspace")

    def test_remap_preserves_other_args(self):
        args = {"target_dir": ".", "name": "myapp", "version": "1.0"}
        result = mcp_shim._remap_arguments_for_container(
            "run_semgrep", args, True
        )
        self.assertEqual(result["name"], "myapp")
        self.assertEqual(result["version"], "1.0")

    def test_original_args_not_mutated(self):
        args = {"target_dir": "/home/user/project"}
        original = dict(args)
        mcp_shim._remap_arguments_for_container("run_semgrep", args, True)
        self.assertEqual(args, original)


class TestContainerDispatch(unittest.TestCase):
    """Test dispatch_tool container command construction and result handling."""

    def setUp(self):
        self.workspace = tempfile.mkdtemp(prefix="aphids-ws-")
        self.runtime = _make_mock_runtime()

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    @patch("mcp_shim.subprocess.run")
    def test_basic_network_tool_dispatch(self, mock_run):
        """Network tool: no workspace mount, no --network none."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "success": True,
                "tool": "nmap",
                "raw_output": "scan results...",
                "parsed": True,
                "parsed_data": [{"host": "192.168.1.1"}],
                "mcp_version": "1.0",
            }),
            stderr="",
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1", "ports": "80"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["tool"], "nmap")

        # Verify container command
        cmd = mock_run.call_args[0][0]
        self.assertIn(self.runtime.binary, cmd)
        self.assertIn("--rm", cmd)
        self.assertIn("--cap-drop", cmd)
        self.assertIn("ALL", cmd)
        self.assertNotIn("--network", cmd)  # Network tools need network
        self.assertNotIn("/workspace:ro", " ".join(cmd))

    @patch("mcp_shim.subprocess.run")
    def test_static_analysis_tool_dispatch(self, mock_run):
        """Static analysis tool: workspace mounted :ro, network disabled."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "success": True,
                "tool": "semgrep",
                "raw_output": "findings...",
                "parsed": True,
                "parsed_data": [],
                "mcp_version": "1.0",
            }),
            stderr="",
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_semgrep",
            arguments={"target_dir": "."},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertTrue(result["success"])

        # Verify workspace mount and network isolation
        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        self.assertIn("/workspace:ro", cmd_str)
        self.assertIn("--network", cmd)
        self.assertIn("none", cmd)

    @patch("mcp_shim.subprocess.run")
    def test_trufflehog_remote_target_has_network(self, mock_run):
        """Trufflehog scanning a remote git repo should have network access."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "success": True,
                "tool": "trufflehog",
                "raw_output": "secrets...",
                "parsed": True,
                "parsed_data": [],
                "mcp_version": "1.0",
            }),
            stderr="",
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_trufflehog",
            arguments={"target": "https://github.com/org/repo", "target_type": "git"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertTrue(result["success"])

        # Verify NO network isolation (remote target needs network)
        cmd = mock_run.call_args[0][0]
        self.assertNotIn("--network", cmd)
        # Verify NO workspace mount
        cmd_str = " ".join(cmd)
        self.assertNotIn("/workspace", cmd_str)

    @patch("mcp_shim.subprocess.run")
    def test_timeout_handling(self, mock_run):
        """Tool timeout returns proper error."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=30)

        result = mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
            timeout=30,
        )

        self.assertFalse(result["success"])
        self.assertTrue(result.get("timeout"))
        self.assertIn("timed out", result["error"])

    @patch("mcp_shim.subprocess.run")
    def test_empty_stdout_handling(self, mock_run):
        """Container producing no output returns error."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="segfault"
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertFalse(result["success"])
        self.assertIn("no output", result["error"].lower())

    @patch("mcp_shim.subprocess.run")
    def test_non_json_stdout_handling(self, mock_run):
        """Container producing non-JSON output returns error."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="This is not JSON", stderr=""
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertFalse(result["success"])
        self.assertIn("no valid JSON", result["error"])

    @patch("mcp_shim.subprocess.run")
    def test_output_file_cleanup(self, mock_run):
        """Temp output directory is cleaned up after dispatch."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"success": True, "tool": "nmap", "mcp_version": "1.0"}),
            stderr="",
        )

        # Track created temp dirs
        original_mkdtemp = tempfile.mkdtemp
        created_dirs = []

        def tracking_mkdtemp(**kwargs):
            d = original_mkdtemp(**kwargs)
            created_dirs.append(d)
            return d

        with patch("mcp_shim.tempfile.mkdtemp", side_effect=tracking_mkdtemp):
            mcp_shim.dispatch_tool(
                tool_name="run_nmap",
                arguments={"target": "192.168.1.1"},
                container_image="aphids-core:latest",
                workspace_dir=self.workspace,
                runtime=self.runtime,
            )

        # Verify cleanup
        for d in created_dirs:
            self.assertFalse(os.path.exists(d), f"Temp dir not cleaned up: {d}")

    @patch("mcp_shim.subprocess.run")
    def test_output_file_not_exposed_to_llm(self, mock_run):
        """output_file (container-internal path) should be stripped from result."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "success": True,
                "tool": "nmap",
                "output_file": "/output/aphids-nmap-output-abc123.xml",
                "raw_output": "scan data",
                "mcp_version": "1.0",
            }),
            stderr="",
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertNotIn("output_file", result)

    @patch("mcp_shim.subprocess.run")
    def test_security_caps_dropped(self, mock_run):
        """All capabilities should be dropped."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"success": True, "tool": "nmap", "mcp_version": "1.0"}),
            stderr="",
        )

        mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        cmd = mock_run.call_args[0][0]
        cap_idx = cmd.index("--cap-drop")
        self.assertEqual(cmd[cap_idx + 1], "ALL")

        sec_idx = cmd.index("--security-opt")
        self.assertEqual(cmd[sec_idx + 1], "no-new-privileges")

    @patch("mcp_shim.subprocess.run")
    def test_online_mode_env_vars(self, mock_run):
        """Online mode passes API key as env var, not in command args."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"success": True, "tool": "nmap", "mcp_version": "1.0"}),
            stderr="",
        )

        config = {
            "authorization": {"apiKey": "test-key-123"},
            "baseUrl": "https://api.hive.test.io",
            "baseWsUrl": "wss://ws.hive.test.io",
            "configuration": {"online": "enabled"},
        }

        mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
            config=config,
        )

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        self.assertIn("-e", cmd)
        self.assertIn("APHIDS_API_KEY=test-key-123", cmd_str)
        self.assertIn("APHIDS_BASE_URL=https://api.hive.test.io", cmd_str)

    @patch("mcp_shim.subprocess.run")
    def test_json_with_ansi_banner_preamble(self, mock_run):
        """Real-world case: ANSI banner with { chars before the JSON result."""
        banner = (
            '\x1b[33moperator\x1b[93m@\x1b[31maphids\x1b[91m# \x1b[0m'
            '\x1b[32m[+]\x1b[92m Running...\x1b[0m\n'
            '\x1b[34m[*]\x1b[94m Starting scan with parameters: '
            '{"target": "scanme.nmap.org", "ports": "80"}\x1b[0m\n'
        )
        json_result = json.dumps({
            "success": True,
            "tool": "nmap",
            "raw_output": "scan data",
            "parsed": True,
            "mcp_version": "1.0",
        })
        mock_run.return_value = MagicMock(
            returncode=0, stdout=banner + json_result, stderr=""
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "scanme.nmap.org"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["tool"], "nmap")
        self.assertEqual(result["raw_output"], "scan data")

    @patch("mcp_shim.subprocess.run")
    def test_json_with_preamble(self, mock_run):
        """JSON output preceded by non-JSON text should still parse."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='Some banner text\nWarning: blah\n{"success": true, "tool": "nmap", "mcp_version": "1.0"}',
            stderr="",
        )

        result = mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids-core:latest",
            workspace_dir=self.workspace,
            runtime=self.runtime,
        )

        self.assertTrue(result["success"])


class TestToolRegistryCache(unittest.TestCase):
    """Test tool registry caching."""

    def setUp(self):
        self.original_cache_dir = mcp_shim.CACHE_DIR
        self.temp_cache = tempfile.mkdtemp(prefix="aphids-cache-")
        mcp_shim.CACHE_DIR = self.temp_cache

    def tearDown(self):
        mcp_shim.CACHE_DIR = self.original_cache_dir
        shutil.rmtree(self.temp_cache, ignore_errors=True)

    def test_cache_miss_returns_none(self):
        result = mcp_shim._load_cached_registry("aphids:latest")
        self.assertIsNone(result)

    def test_cache_save_and_load(self):
        registry = {
            "tools": [{"name": "run_nmap", "description": "test"}],
            "count": 1,
        }
        mcp_shim._save_registry_cache(registry, "aphids:latest")

        loaded = mcp_shim._load_cached_registry("aphids:latest")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["count"], 1)

    def test_cache_invalidation_on_image_change(self):
        registry = {"tools": [], "count": 0}
        mcp_shim._save_registry_cache(registry, "aphids:v1")

        loaded = mcp_shim._load_cached_registry("aphids:v2")
        self.assertIsNone(loaded)

    def test_cache_expiry(self):
        registry = {"tools": [], "count": 0, "_cached_at": time.time() - 100000}
        cache_path = mcp_shim._get_cache_path()
        with open(cache_path, "w") as f:
            json.dump(registry, f)

        loaded = mcp_shim._load_cached_registry("aphids:latest")
        self.assertIsNone(loaded)


def _make_mock_runtime(name="docker", binary="docker"):
    """Create a mock ContainerRuntime for testing."""
    from container_runtime import ContainerRuntime
    return ContainerRuntime(name=name, binary=binary, version="test")


class TestRuntimeAvailability(unittest.TestCase):
    """Test _validate_runtime_available."""

    @patch("container_runtime.detect_runtime")
    def test_runtime_detected(self, mock_detect):
        mock_detect.return_value = _make_mock_runtime()
        rt = mcp_shim._validate_runtime_available()
        self.assertEqual(rt.name, "docker")

    @patch("container_runtime.detect_runtime")
    def test_runtime_not_found(self, mock_detect):
        mock_detect.side_effect = RuntimeError("No runtime found")
        with self.assertRaises(SystemExit):
            mcp_shim._validate_runtime_available()


class TestToolDiscoveryViaContainer(unittest.TestCase):
    """Test _discover_tools_via_container."""

    @patch("mcp_shim.subprocess.run")
    def test_successful_discovery(self, mock_run):
        registry = {
            "tools": [
                {"name": "run_nmap", "description": "nmap scanner"},
                {"name": "run_semgrep", "description": "semgrep scanner"},
            ],
            "count": 2,
        }
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(registry), stderr=""
        )

        rt = _make_mock_runtime()
        result = mcp_shim._discover_tools_via_container("aphids:latest", rt)
        self.assertEqual(result["count"], 2)

    @patch("mcp_shim.subprocess.run")
    def test_discovery_with_preamble(self, mock_run):
        registry = {"tools": [], "count": 0}
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=f"Loading wrappers...\n{json.dumps(registry)}",
            stderr="",
        )

        rt = _make_mock_runtime()
        result = mcp_shim._discover_tools_via_container("aphids:latest", rt)
        self.assertEqual(result["count"], 0)

    @patch("mcp_shim.subprocess.run")
    def test_discovery_failure(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="Error: image not found"
        )

        rt = _make_mock_runtime()
        with self.assertRaises(RuntimeError):
            mcp_shim._discover_tools_via_container("aphids:nonexistent", rt)

    @patch("mcp_shim.subprocess.run")
    def test_discovery_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=120)

        rt = _make_mock_runtime()
        with self.assertRaises(RuntimeError):
            mcp_shim._discover_tools_via_container("aphids:latest", rt)


class TestUrlDetection(unittest.TestCase):
    """Test _is_url helper."""

    def test_https_url(self):
        self.assertTrue(mcp_shim._is_url("https://github.com/org/repo"))

    def test_http_url(self):
        self.assertTrue(mcp_shim._is_url("http://example.com"))

    def test_git_ssh(self):
        self.assertTrue(mcp_shim._is_url("git@github.com:org/repo.git"))

    def test_ssh_url(self):
        self.assertTrue(mcp_shim._is_url("ssh://git@github.com/org/repo"))

    def test_s3_url(self):
        self.assertTrue(mcp_shim._is_url("s3://my-bucket/path"))

    def test_gs_url(self):
        self.assertTrue(mcp_shim._is_url("gs://my-bucket/path"))

    def test_filesystem_path(self):
        self.assertFalse(mcp_shim._is_url("/home/user/project"))

    def test_relative_path(self):
        self.assertFalse(mcp_shim._is_url("./my-project"))

    def test_dot(self):
        self.assertFalse(mcp_shim._is_url("."))

    def test_empty(self):
        self.assertFalse(mcp_shim._is_url(""))


class TestSecurityEdgeCases(unittest.TestCase):
    """Additional security-focused edge case tests."""

    def setUp(self):
        self.workspace = tempfile.mkdtemp(prefix="aphids-sec-")

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_path_with_spaces(self):
        dir_with_spaces = os.path.join(self.workspace, "my project")
        os.makedirs(dir_with_spaces)
        result = mcp_shim._validate_path_safe("my project", self.workspace)
        self.assertEqual(result, os.path.realpath(dir_with_spaces))

    def test_path_with_unicode(self):
        dir_unicode = os.path.join(self.workspace, "proyecto")
        os.makedirs(dir_unicode)
        result = mcp_shim._validate_path_safe("proyecto", self.workspace)
        self.assertEqual(result, os.path.realpath(dir_unicode))

    def test_empty_path(self):
        """Empty string should not traverse."""
        result = mcp_shim._validate_path_safe("", self.workspace)
        self.assertEqual(result, os.path.realpath(self.workspace))

    @patch("mcp_shim.subprocess.run")
    def test_workspace_not_mounted_for_network_tools(self, mock_run):
        """Network tools should never get workspace mounted."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"success": True, "tool": "nmap", "mcp_version": "1.0"}),
            stderr="",
        )

        rt = _make_mock_runtime()
        mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids:latest",
            workspace_dir=self.workspace,
            runtime=rt,
        )

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        self.assertNotIn("/workspace", cmd_str)

    @patch("mcp_shim.subprocess.run")
    def test_container_rm_flag_always_present(self, mock_run):
        """Container should always be ephemeral (--rm)."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"success": True, "tool": "nmap", "mcp_version": "1.0"}),
            stderr="",
        )

        rt = _make_mock_runtime()
        mcp_shim.dispatch_tool(
            tool_name="run_nmap",
            arguments={"target": "192.168.1.1"},
            container_image="aphids:latest",
            workspace_dir=self.workspace,
            runtime=rt,
        )

        cmd = mock_run.call_args[0][0]
        self.assertIn("--rm", cmd)


# Need subprocess imported for TimeoutExpired
import subprocess


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
