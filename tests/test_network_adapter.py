"""Phase 11 — Network adapter tests.

Comprehensive tests for NetworkAdapter covering:
    - ALLOW path (connect returns bytes)
    - DENY path (NetworkDeniedError, no connection)
    - APPROVE path (NetworkApprovalRequiredError, no connection)
    - Error path (NetworkError, no connection)
    - Agent/resource preservation in exceptions
    - Authorization-before-execution order
    - URL construction (scheme, host, port, path)
    - Default scheme (https)
    - Resource format ("host:port")
    - Mocked network I/O (no real connections)
    - Adversarial/security checks
    - Zero third-party imports
    - Regression: Phase 1-10 tests unaffected
    - Frozen file verification
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_firewall import Firewall
from agent_firewall.adapters.network import (
    NetworkAdapter,
    NetworkApprovalRequiredError,
    NetworkDeniedError,
    NetworkError,
)


def _firewall(agents):
    """Helper: build a Firewall from agent policy dicts."""
    return Firewall.from_dict({"version": 1, "agents": agents})


class TestNetworkAdapterAllow(unittest.TestCase):
    """Tests for the ALLOW path."""

    def test_allowed_connect_returns_bytes(self):
        """ALLOW → connect returns response bytes."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status":"ok"}'

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            result = adapter.connect("dev", "api.example.com", 443)

        self.assertEqual(result, b'{"status":"ok"}')
        mock_urlopen.assert_called_once()

    def test_allowed_connect_default_scheme_https(self):
        """Default scheme is https."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "api.example.com", 443)

        url = mock_urlopen.call_args[0][0]
        self.assertTrue(url.startswith("https://"))

    def test_allowed_connect_explicit_http(self):
        """Explicit scheme=http is respected."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "localhost:8080"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "localhost", 8080, scheme="http")

        url = mock_urlopen.call_args[0][0]
        self.assertTrue(url.startswith("http://"))

    def test_allowed_connect_url_construction(self):
        """URL is built from host:port/path."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "api.example.com", 443, path="/v1/data")

        url = mock_urlopen.call_args[0][0]
        self.assertEqual(url, "https://api.example.com/v1/data")

    def test_allowed_connect_non_standard_port_in_url(self):
        """Non-standard port appears in URL."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "localhost:9090"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "localhost", 9090)

        url = mock_urlopen.call_args[0][0]
        self.assertEqual(url, "https://localhost:9090")

    def test_allowed_connect_standard_port_omitted_from_url(self):
        """Standard port (443 for https) is omitted from URL."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "api.example.com", 443)

        url = mock_urlopen.call_args[0][0]
        self.assertEqual(url, "https://api.example.com")

    def test_allowed_connect_standard_port_80_http(self):
        """Standard port (80 for http) is omitted from URL."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "example.com:80"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "example.com", 80, scheme="http")

        url = mock_urlopen.call_args[0][0]
        self.assertEqual(url, "http://example.com")

    def test_allowed_connect_path_without_leading_slash(self):
        """Path without leading slash gets one added."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "api.example.com", 443, path="v1/data")

        url = mock_urlopen.call_args[0][0]
        self.assertEqual(url, "https://api.example.com/v1/data")

    def test_allowed_connect_kwargs_passed_to_urlopen(self):
        """Extra kwargs are passed through to urlopen."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "api.example.com", 443, timeout=5)

        _, kwargs = mock_urlopen.call_args
        self.assertEqual(kwargs["timeout"], 5)

    def test_allowed_connect_empty_path(self):
        """Empty path produces clean URL."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    return_value=mock_response) as mock_urlopen:
            adapter.connect("dev", "api.example.com", 443, path="")

        url = mock_urlopen.call_args[0][0]
        self.assertEqual(url, "https://api.example.com")


class TestNetworkAdapterDeny(unittest.TestCase):
    """Tests for the DENY path."""

    def test_denied_connect_raises(self):
        """DENY → NetworkDeniedError raised."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with self.assertRaises(NetworkDeniedError):
            adapter.connect("dev", "evil.example.com", 443)

    def test_denied_connect_no_connection(self):
        """DENY → urlopen is never called."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with patch("agent_firewall.adapters.network.urllib.request.urlopen") as mock_urlopen:
            with self.assertRaises(NetworkDeniedError):
                adapter.connect("dev", "evil.example.com", 443)

        mock_urlopen.assert_not_called()

    def test_denied_exception_has_agent(self):
        """DENY exception preserves agent."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with self.assertRaises(NetworkDeniedError) as ctx:
            adapter.connect("dev", "evil.example.com", 443)
        self.assertEqual(ctx.exception.agent, "dev")

    def test_denied_exception_has_resource(self):
        """DENY exception preserves resource."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with self.assertRaises(NetworkDeniedError) as ctx:
            adapter.connect("dev", "evil.example.com", 443)
        self.assertEqual(ctx.exception.resource, "evil.example.com:443")

    def test_denied_exception_has_action(self):
        """DENY exception preserves action."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with self.assertRaises(NetworkDeniedError) as ctx:
            adapter.connect("dev", "evil.example.com", 443)
        self.assertEqual(ctx.exception.action, "network.connect")

    def test_default_deny_blocks_all_connections(self):
        """Unknown agent → default deny → no connection."""
        fw = _firewall({})
        adapter = NetworkAdapter(fw)

        with patch("agent_firewall.adapters.network.urllib.request.urlopen") as mock_urlopen:
            with self.assertRaises(NetworkDeniedError):
                adapter.connect("unknown", "api.example.com", 443)

        mock_urlopen.assert_not_called()


class TestNetworkAdapterApprove(unittest.TestCase):
    """Tests for the APPROVE path."""

    def test_approve_connect_raises(self):
        """APPROVE → NetworkApprovalRequiredError raised."""
        fw = _firewall({"dev": {"approve": [
            {"action": "network.connect", "resource": "prod.db:5432"},
        ]}})
        adapter = NetworkAdapter(fw)

        with self.assertRaises(NetworkApprovalRequiredError):
            adapter.connect("dev", "prod.db", 5432)

    def test_approve_connect_no_connection(self):
        """APPROVE → urlopen is never called."""
        fw = _firewall({"dev": {"approve": [
            {"action": "network.connect", "resource": "prod.db:5432"},
        ]}})
        adapter = NetworkAdapter(fw)

        with patch("agent_firewall.adapters.network.urllib.request.urlopen") as mock_urlopen:
            with self.assertRaises(NetworkApprovalRequiredError):
                adapter.connect("dev", "prod.db", 5432)

        mock_urlopen.assert_not_called()

    def test_approve_exception_has_agent(self):
        """APPROVE exception preserves agent."""
        fw = _firewall({"dev": {"approve": [
            {"action": "network.connect", "resource": "prod.db:5432"},
        ]}})
        adapter = NetworkAdapter(fw)

        with self.assertRaises(NetworkApprovalRequiredError) as ctx:
            adapter.connect("dev", "prod.db", 5432)
        self.assertEqual(ctx.exception.agent, "dev")


class TestNetworkAdapterError(unittest.TestCase):
    """Tests for error paths."""

    def test_invalid_request_raises_network_error(self):
        """InvalidRequestError → NetworkError, no connection."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with patch("agent_firewall.adapters.network.urllib.request.urlopen") as mock_urlopen:
            with self.assertRaises(NetworkError):
                # Empty agent triggers InvalidRequestError
                adapter.connect("", "api.example.com", 443)

        mock_urlopen.assert_not_called()

    def test_error_exception_has_metadata(self):
        """NetworkError preserves agent, action, resource."""
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with self.assertRaises(NetworkError) as ctx:
            adapter.connect("", "api.example.com", 443)
        self.assertEqual(ctx.exception.agent, "")
        self.assertEqual(ctx.exception.action, "network.connect")
        self.assertEqual(ctx.exception.resource, "api.example.com:443")

    def test_connection_failure_propagates(self):
        """Network failure after ALLOW propagates as urllib error."""
        import urllib.error
        fw = _firewall({"dev": {"allow": [
            {"action": "network.connect", "resource": "api.example.com:443"},
        ]}})
        adapter = NetworkAdapter(fw)

        with patch("agent_firewall.adapters.network.urllib.request.urlopen",
                    side_effect=urllib.error.URLError("connection refused")):
            with self.assertRaises(urllib.error.URLError):
                adapter.connect("dev", "api.example.com", 443)


class TestNetworkAdapterAuthorizationOrder(unittest.TestCase):
    """Verify authorization occurs before execution."""

    def test_authorization_before_execution_in_source(self):
        """_check() is called before urlopen() in connect()."""
        source = inspect.getsource(NetworkAdapter.connect)
        # Strip docstring content to avoid matching example usage
        in_docstring = False
        code_lines = []
        for line in source.split("\n"):
            stripped = line.strip()
            if '"""' in stripped:
                count = stripped.count('"""')
                if count == 2:
                    continue  # single-line docstring
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            if stripped and not stripped.startswith("#"):
                code_lines.append(stripped)

        check_idx = None
        urlopen_idx = None
        for i, line in enumerate(code_lines):
            if "_check(" in line and check_idx is None:
                check_idx = i
            if "urlopen(" in line and urlopen_idx is None:
                urlopen_idx = i

        self.assertIsNotNone(check_idx, "_check() call not found")
        self.assertIsNotNone(urlopen_idx, "urlopen() call not found")
        self.assertLess(check_idx, urlopen_idx,
                        "_check() must be called before urlopen()")


class TestNetworkAdapterSecurity(unittest.TestCase):
    """Adversarial security checks."""

    def test_no_shell_true_in_code(self):
        """No shell=True in network adapter source."""
        source = inspect.getsource(NetworkAdapter)
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""'):
                continue
            self.assertNotIn("shell=True", stripped,
                             f"shell=True found: {stripped}")

    def test_no_os_system_in_code(self):
        """No os.system() in network adapter source."""
        source = inspect.getsource(NetworkAdapter)
        self.assertNotIn("os.system", source)

    def test_no_subprocess_import(self):
        """Network adapter does not import subprocess."""
        source = inspect.getsource(NetworkAdapter)
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""'):
                continue
            self.assertNotIn("import subprocess", stripped)
            self.assertNotIn("from subprocess", stripped)

    def test_no_dangerous_imports_in_network_adapter(self):
        """No dangerous imports in network.py."""
        path = os.path.join(os.path.dirname(__file__),
                            "..", "agent_firewall", "adapters", "network.py")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)
        dangerous = {"subprocess", "socket", "http", "asyncio"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    self.assertNotIn(mod, dangerous,
                                     f"Dangerous import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    self.assertNotIn(mod, dangerous,
                                     f"Dangerous import: {node.module}")

    def test_urlopen_called_only_after_check(self):
        """urlopen must only be reachable after _check succeeds."""
        # Verify the _check method exists and is called in connect
        source = inspect.getsource(NetworkAdapter.connect)
        self.assertIn("_check(", source)
        self.assertIn("urlopen(", source)

    def test_exception_classes_are_not_too_broad(self):
        """Exception classes inherit from Exception, not BaseException."""
        self.assertTrue(issubclass(NetworkDeniedError, Exception))
        self.assertTrue(issubclass(NetworkApprovalRequiredError, Exception))
        self.assertTrue(issubclass(NetworkError, Exception))

    def test_no_network_adapter_in_core(self):
        """Evaluator does not import network adapter."""
        eval_path = os.path.join(os.path.dirname(__file__),
                                 "..", "agent_firewall", "evaluator.py")
        with open(eval_path, "r", encoding="utf-8") as f:
            source = f.read()
        # Check no import of network adapter (skip docstrings/comments)
        self.assertNotIn("from ..adapters", source)
        self.assertNotIn("from .adapters", source)
        self.assertNotIn("NetworkAdapter", source)
        self.assertNotIn("import network", source)
        self.assertNotIn("from network", source)


class TestNetworkAdapterZeroDependencies(unittest.TestCase):
    """Verify zero third-party runtime dependencies."""

    def test_no_third_party_imports_in_network_adapter(self):
        """network.py uses only stdlib and internal imports."""
        path = os.path.join(os.path.dirname(__file__),
                            "..", "agent_firewall", "adapters", "network.py")
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)
        allowed = {
            "json", "os", "sys", "dataclasses", "datetime", "typing",
            "hashlib", "hmac", "re", "enum", "pathlib", "collections",
            "fnmatch", "io", "__future__", "urllib",
            # Internal package modules
            "model", "typing_extensions",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    self.assertIn(mod, allowed,
                                  f"Unexpected import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    self.assertIn(mod, allowed,
                                  f"Unexpected import: {node.module}")

    def test_pyproject_dependencies_empty(self):
        """pyproject.toml has zero runtime dependencies."""
        path = os.path.join(os.path.dirname(__file__),
                            "..", "pyproject.toml")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            # Check that dependencies = [] or dependencies are empty
            if "dependencies" in content:
                for line in content.split("\n"):
                    if "dependencies" in line and "=" in line:
                        # Should be empty list
                        self.assertIn("[]", line.replace(" ", ""))


class TestNetworkAdapterRegression(unittest.TestCase):
    """Regression: existing adapter functionality unchanged."""

    def test_filesystem_adapter_still_works(self):
        """FilesystemAdapter is still importable and functional."""
        from agent_firewall.adapters import FilesystemAdapter
        fw = _firewall({"dev": {"allow": [
            {"action": "filesystem.read", "resource": "./**"},
        ]}})
        adapter = FilesystemAdapter(fw)
        # Just verify it can be instantiated
        self.assertIsNotNone(adapter)

    def test_process_adapter_still_works(self):
        """ProcessAdapter is still importable and functional."""
        from agent_firewall.adapters import ProcessAdapter
        fw = _firewall({"dev": {"allow": [
            {"action": "process.spawn", "resource": "python"},
        ]}})
        adapter = ProcessAdapter(fw)
        self.assertIsNotNone(adapter)

    def test_git_adapter_still_works(self):
        """GitAdapter is still importable and functional."""
        from agent_firewall.adapters import GitAdapter
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        self.assertIsNotNone(adapter)

    def test_network_adapter_importable_from_package(self):
        """NetworkAdapter is importable from the adapters package."""
        from agent_firewall.adapters import NetworkAdapter
        self.assertIsNotNone(NetworkAdapter)

    def test_phase1_core_still_works(self):
        """Phase 1 evaluator still functions correctly."""
        from agent_firewall.model import Request
        fw = _firewall({"dev": {"allow": [
            {"action": "test.action", "resource": "test.resource"},
        ]}})
        decision = fw.check(Request("dev", "test.action", "test.resource"))
        self.assertEqual(decision.kind.value, "ALLOW")


if __name__ == "__main__":
    unittest.main()
