"""Tests for Phase 8 filesystem adapter.

Uses relative paths only (the core rejects absolute paths).
All test files are created in a temporary subdirectory that is
cleaned up after each test class.
"""

import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind
from agent_firewall.adapters.filesystem import (
    FilesystemAdapter,
    FilesystemApprovalRequiredError,
    FilesystemDeniedError,
    FilesystemError,
)

# Test workspace — relative directory for all test files
_TEST_DIR = "_test_adapter_workspace"


def _setup():
    os.makedirs(_TEST_DIR, exist_ok=True)


def _teardown():
    if os.path.exists(_TEST_DIR):
        shutil.rmtree(_TEST_DIR, ignore_errors=True)


def _filepath(name: str) -> str:
    """Return a relative path inside the test workspace."""
    return os.path.join(_TEST_DIR, name)


def _write_file(name: str, content: bytes = b"hello world") -> str:
    """Create a file in the test workspace and return its relative path."""
    path = _filepath(name)
    with open(path, "wb") as f:
        f.write(content)
    return path


def _firewall(*, allow=None, deny=None, approve=None, agents=None) -> Firewall:
    """Build a Firewall with a simple policy."""
    if agents is not None:
        agent_data = agents
    else:
        agent_data = {
            "dev": {
                "allow": allow or [],
                "deny": deny or [],
                "approve": approve or [],
            }
        }
    return Firewall.from_dict({"version": 1, "agents": agent_data})


# ══════════════════════════════════════════════════════════════════════════════
# Allowed operations
# ══════════════════════════════════════════════════════════════════════════════

class AllowedReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_read_returns_bytes(self):
        path = _write_file("read_test.txt", b"test content")
        fw = _firewall(allow=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        result = adapter.read("dev", path)
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, b"test content")

    def test_read_empty_file(self):
        path = _write_file("empty.txt", b"")
        fw = _firewall(allow=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        result = adapter.read("dev", path)
        self.assertEqual(result, b"")

    def test_read_binary_content(self):
        content = bytes(range(256))
        path = _write_file("binary.dat", content)
        fw = _firewall(allow=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        result = adapter.read("dev", path)
        self.assertEqual(result, content)


class AllowedWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_write_creates_file(self):
        path = _filepath("write_new.txt")
        fw = _firewall(allow=[{"action": "filesystem.write", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        adapter.write("dev", path, b"new content")
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"new content")
        os.unlink(path)

    def test_write_overwrites_file(self):
        path = _write_file("overwrite.txt", b"old content")
        fw = _firewall(allow=[{"action": "filesystem.write", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        adapter.write("dev", path, b"new content")
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"new content")

    def test_write_empty_bytes(self):
        path = _write_file("empty_write.txt", b"old")
        fw = _firewall(allow=[{"action": "filesystem.write", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        adapter.write("dev", path, b"")
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"")


class AllowedDeleteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_delete_removes_file(self):
        path = _write_file("to_delete.txt", b"bye")
        fw = _firewall(allow=[{"action": "filesystem.delete", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        adapter.delete("dev", path)
        self.assertFalse(os.path.exists(path))


# ══════════════════════════════════════════════════════════════════════════════
# Denied operations
# ══════════════════════════════════════════════════════════════════════════════

class DeniedReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_read_denied(self):
        path = _write_file("secret.txt", b"secret")
        fw = _firewall(deny=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError) as ctx:
            adapter.read("dev", path)
        self.assertIn("filesystem.read", str(ctx.exception))

    def test_read_file_unchanged_after_deny(self):
        path = _write_file("unchanged.txt", b"secret")
        fw = _firewall(deny=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError):
            adapter.read("dev", path)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"secret")


class DeniedWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_write_denied(self):
        path = _filepath("not_created.txt")
        fw = _firewall(deny=[{"action": "filesystem.write", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError) as ctx:
            adapter.write("dev", path, b"should not exist")
        self.assertIn("filesystem.write", str(ctx.exception))
        self.assertFalse(os.path.exists(path))

    def test_write_file_unchanged_after_deny(self):
        path = _write_file("original.txt", b"original")
        fw = _firewall(deny=[{"action": "filesystem.write", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError):
            adapter.write("dev", path, b"should not overwrite")
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"original")


class DeniedDeleteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_delete_denied(self):
        path = _write_file("keep_me.txt", b"keep")
        fw = _firewall(deny=[{"action": "filesystem.delete", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError) as ctx:
            adapter.delete("dev", path)
        self.assertIn("filesystem.delete", str(ctx.exception))
        self.assertTrue(os.path.exists(path))


# ══════════════════════════════════════════════════════════════════════════════
# Approval-required operations
# ══════════════════════════════════════════════════════════════════════════════

class ApprovalRequiredTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_read_approval_required(self):
        path = _write_file("approval_read.txt", b"needs approval")
        fw = _firewall(approve=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemApprovalRequiredError) as ctx:
            adapter.read("dev", path)
        self.assertIn("filesystem.read", str(ctx.exception))

    def test_write_approval_required(self):
        path = _filepath("approval_write.txt")
        fw = _firewall(approve=[{"action": "filesystem.write", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemApprovalRequiredError):
            adapter.write("dev", path, b"should not write")
        self.assertFalse(os.path.exists(path))

    def test_delete_approval_required(self):
        path = _write_file("approval_delete.txt", b"needs approval")
        fw = _firewall(approve=[{"action": "filesystem.delete", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemApprovalRequiredError):
            adapter.delete("dev", path)
        self.assertTrue(os.path.exists(path))


# ══════════════════════════════════════════════════════════════════════════════
# Default deny / unknown agent
# ══════════════════════════════════════════════════════════════════════════════

class DefaultDenyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_read_unknown_agent(self):
        path = _write_file("unknown_read.txt", b"secret")
        fw = _firewall()
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError):
            adapter.read("unknown", path)

    def test_write_unknown_agent(self):
        path = _filepath("unknown_write.txt")
        fw = _firewall()
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError):
            adapter.write("unknown", path, b"data")
        self.assertFalse(os.path.exists(path))

    def test_delete_unknown_agent(self):
        path = _write_file("unknown_delete.txt", b"data")
        fw = _firewall()
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError):
            adapter.delete("unknown", path)
        self.assertTrue(os.path.exists(path))


# ══════════════════════════════════════════════════════════════════════════════
# Identity and resource preservation
# ══════════════════════════════════════════════════════════════════════════════

class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_agent_preserved_in_denied_request(self):
        path = _write_file("agent_test.txt", b"test")
        fw = _firewall(deny=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError) as ctx:
            adapter.read("special_agent", path)
        self.assertEqual(ctx.exception.agent, "special_agent")

    def test_resource_preserved_in_denied_request(self):
        path = _write_file("resource_test.txt", b"test")
        fw = _firewall(deny=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError) as ctx:
            adapter.read("dev", path)
        self.assertEqual(ctx.exception.resource, path)

    def test_reason_populated(self):
        path = _write_file("reason_test.txt", b"test")
        fw = _firewall(deny=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError) as ctx:
            adapter.read("dev", path)
        self.assertIsInstance(ctx.exception.reason, str)


# ══════════════════════════════════════════════════════════════════════════════
# Firewall error handling
# ══════════════════════════════════════════════════════════════════════════════

class FirewallErrorTests(unittest.TestCase):
    def test_invalid_request_raises(self):
        fw = _firewall(allow=[{"action": "filesystem.read", "resource": "./src/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemError):
            adapter.read("dev", "/etc/passwd")

    def test_error_does_not_execute(self):
        fw = _firewall(allow=[{"action": "filesystem.read", "resource": "./src/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemError):
            adapter.read("dev", "/nonexistent/path")


# ══════════════════════════════════════════════════════════════════════════════
# Pre-existence / TOCTOU
# ══════════════════════════════════════════════════════════════════════════════

class TOCTOUTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_delete_nonexistent_file(self):
        path = _filepath("does_not_exist.txt")
        fw = _firewall(allow=[{"action": "filesystem.delete", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FileNotFoundError):
            adapter.delete("dev", path)


# ══════════════════════════════════════════════════════════════════════════════
# Security / adversarial tests
# ══════════════════════════════════════════════════════════════════════════════

class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _setup()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    def test_no_network_imports(self):
        import agent_firewall.adapters.filesystem as fs_mod
        with open(fs_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        for d in ["import socket", "import http", "import urllib", "import requests"]:
            self.assertNotIn(d, src)

    def test_no_subprocess_imports(self):
        import agent_firewall.adapters.filesystem as fs_mod
        with open(fs_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import subprocess", src)

    def test_no_llm_imports(self):
        import agent_firewall.adapters.filesystem as fs_mod
        with open(fs_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import openai", src)
        self.assertNotIn("import anthropic", src)

    def test_no_symlink_resolution(self):
        import agent_firewall.adapters.filesystem as fs_mod
        with open(fs_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("resolve()", src)
        self.assertNotIn("readlink", src)
        self.assertNotIn("os.path.realpath", src)

    def test_zero_third_party_imports(self):
        import agent_firewall.adapters.filesystem as fs_mod
        with open(fs_mod.__file__, "r", encoding="utf-8") as f:
            tree = __import__("ast").parse(f.read())
        known = {"json", "os", "sys", "dataclasses", "datetime", "typing",
                 "hashlib", "hmac", "re", "enum", "pathlib", "collections",
                 "fnmatch", "io", "__future__"}
        internal = {"evaluator", "model", "policy", "normalize",
                     "adapters", "filesystem"}
        allowed = known | internal
        third_party = []
        for node in __import__("ast").walk(tree):
            if isinstance(node, __import__("ast").Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in allowed:
                        third_party.append(mod)
            elif isinstance(node, __import__("ast").ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in allowed:
                        third_party.append(mod)
        self.assertEqual(third_party, [], f"Third-party imports: {third_party}")

    def test_adapter_uses_firewall_check(self):
        import agent_firewall.adapters.filesystem as fs_mod
        with open(fs_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("self._firewall.check(", src)

    def test_adapter_does_not_modify_policy(self):
        fw = _firewall(allow=[{"action": "filesystem.read", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        path = _write_file("policy_test.txt", b"test")
        adapter.read("dev", path)
        self.assertEqual(len(fw.policy.agents["dev"].allow), 1)

    def test_deny_does_not_execute_write(self):
        path = _filepath("deny_write.txt")
        fw = _firewall(deny=[{"action": "filesystem.write", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError):
            adapter.write("dev", path, b"malicious")
        self.assertFalse(os.path.exists(path))

    def test_deny_does_not_execute_delete(self):
        path = _write_file("deny_delete.txt", b"protected")
        fw = _firewall(deny=[{"action": "filesystem.delete", "resource": "_test_adapter_workspace/**"}])
        adapter = FilesystemAdapter(fw)
        with self.assertRaises(FilesystemDeniedError):
            adapter.delete("dev", path)
        self.assertTrue(os.path.exists(path))


# ══════════════════════════════════════════════════════════════════════════════
# Regression tests
# ══════════════════════════════════════════════════════════════════════════════

class RegressionTests(unittest.TestCase):
    def test_evaluator_still_works(self):
        from agent_firewall.evaluator import evaluate
        p = Firewall.from_dict({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read"}]}},
        }).policy
        d = evaluate(Request(agent="dev", action="fs.read"), p)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_firewall_check_still_works(self):
        fw = _firewall(allow=[{"action": "filesystem.read"}])
        d = fw.check(Request(agent="dev", action="filesystem.read"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)


if __name__ == "__main__":
    unittest.main()
