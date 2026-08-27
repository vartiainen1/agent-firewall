"""Tests for Phase 9 process adapter.

Covers:
    - allowed operations (spawn with/without args)
    - denied operations
    - approval-required operations
    - default-deny (unknown agent)
    - agent identity preservation
    - resource preservation
    - firewall error handling
    - subprocess invocation style (list-based, no shell)
    - security/adversarial checks
    - zero third-party dependencies
    - regression coverage
"""

import ast
import inspect
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_firewall import Firewall, Request
from agent_firewall.model import DecisionKind
from agent_firewall.adapters.process import (
    ProcessAdapter,
    ProcessApprovalRequiredError,
    ProcessDeniedError,
    ProcessError,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

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

class AllowedSpawnTests(unittest.TestCase):
    """spawn() succeeds when ALLOW."""

    def test_spawn_returns_completed_process(self):
        fw = _firewall(allow=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        result = adapter.spawn("dev", "python", ["-c", "print('hello')"])
        self.assertIsInstance(result, subprocess.CompletedProcess)

    def test_spawn_stdout_captured_when_requested(self):
        fw = _firewall(allow=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        result = adapter.spawn("dev", "python", ["-c", "print('test123')"],
                               capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "test123")

    def test_spawn_without_args(self):
        fw = _firewall(allow=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        result = adapter.spawn("dev", "python", ["--version"],
                               capture_output=True, text=True)
        self.assertIn("Python", result.stdout)

    def test_spawn_returncode_zero(self):
        fw = _firewall(allow=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        result = adapter.spawn("dev", "python", ["-c", "import sys; sys.exit(0)"])
        self.assertEqual(result.returncode, 0)

    def test_spawn_returncode_nonzero(self):
        fw = _firewall(allow=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        result = adapter.spawn("dev", "python", ["-c", "import sys; sys.exit(42)"])
        self.assertEqual(result.returncode, 42)


# ══════════════════════════════════════════════════════════════════════════════
# Denied operations
# ══════════════════════════════════════════════════════════════════════════════

class DeniedSpawnTests(unittest.TestCase):
    """spawn() raises ProcessDeniedError when DENY."""

    def test_spawn_denied(self):
        fw = _firewall(deny=[{"action": "process.spawn", "resource": "sudo"}])
        adapter = ProcessAdapter(fw)
        with self.assertRaises(ProcessDeniedError) as ctx:
            adapter.spawn("dev", "sudo")
        self.assertIn("process.spawn", str(ctx.exception))
        self.assertIn("sudo", str(ctx.exception))

    def test_spawn_denied_with_args(self):
        fw = _firewall(deny=[{"action": "process.spawn", "resource": "sudo"}])
        adapter = ProcessAdapter(fw)
        with self.assertRaises(ProcessDeniedError):
            adapter.spawn("dev", "sudo", ["rm", "-rf", "/"])

    def test_spawn_denied_does_not_execute(self):
        """Verify process is NOT started when denied."""
        fw = _firewall(deny=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        original_run = subprocess.run
        called = [False]
        def tracking_run(*args, **kwargs):
            called[0] = True
            return original_run(*args, **kwargs)
        subprocess.run = tracking_run
        try:
            with self.assertRaises(ProcessDeniedError):
                adapter.spawn("dev", "python", ["-c", "import sys; sys.exit(1)"])
            self.assertFalse(called[0], "subprocess.run was called despite DENY")
        finally:
            subprocess.run = original_run


# ══════════════════════════════════════════════════════════════════════════════
# Approval-required operations
# ══════════════════════════════════════════════════════════════════════════════

class ApprovalRequiredTests(unittest.TestCase):
    """spawn() raises ProcessApprovalRequiredError when APPROVE."""

    def test_spawn_approval_required(self):
        fw = _firewall(approve=[{"action": "process.spawn", "resource": "deploy"}])
        adapter = ProcessAdapter(fw)
        with self.assertRaises(ProcessApprovalRequiredError) as ctx:
            adapter.spawn("dev", "deploy")
        self.assertIn("process.spawn", str(ctx.exception))

    def test_spawn_approval_does_not_execute(self):
        fw = _firewall(approve=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        original_run = subprocess.run
        called = [False]
        def tracking_run(*args, **kwargs):
            called[0] = True
            return original_run(*args, **kwargs)
        subprocess.run = tracking_run
        try:
            with self.assertRaises(ProcessApprovalRequiredError):
                adapter.spawn("dev", "python")
            self.assertFalse(called[0], "subprocess.run was called despite APPROVE")
        finally:
            subprocess.run = original_run


# ══════════════════════════════════════════════════════════════════════════════
# Default deny / unknown agent
# ══════════════════════════════════════════════════════════════════════════════

class DefaultDenyTests(unittest.TestCase):
    """Unknown agents are denied."""

    def test_spawn_unknown_agent(self):
        fw = _firewall()
        adapter = ProcessAdapter(fw)
        with self.assertRaises(ProcessDeniedError):
            adapter.spawn("unknown", "python")


# ══════════════════════════════════════════════════════════════════════════════
# Identity and resource preservation
# ══════════════════════════════════════════════════════════════════════════════

class IdentityTests(unittest.TestCase):
    """Agent identity and resource are preserved in requests."""

    def test_agent_preserved_in_denied_request(self):
        fw = _firewall(deny=[{"action": "process.spawn", "resource": "sudo"}])
        adapter = ProcessAdapter(fw)
        with self.assertRaises(ProcessDeniedError) as ctx:
            adapter.spawn("special_agent", "sudo")
        self.assertEqual(ctx.exception.agent, "special_agent")

    def test_resource_preserved_in_denied_request(self):
        fw = _firewall(deny=[{"action": "process.spawn", "resource": "sudo"}])
        adapter = ProcessAdapter(fw)
        with self.assertRaises(ProcessDeniedError) as ctx:
            adapter.spawn("dev", "sudo")
        self.assertEqual(ctx.exception.resource, "sudo")

    def test_reason_populated(self):
        fw = _firewall(deny=[{"action": "process.spawn", "resource": "sudo"}])
        adapter = ProcessAdapter(fw)
        with self.assertRaises(ProcessDeniedError) as ctx:
            adapter.spawn("dev", "sudo")
        self.assertIsInstance(ctx.exception.reason, str)


# ══════════════════════════════════════════════════════════════════════════════
# Firewall error handling
# ══════════════════════════════════════════════════════════════════════════════

class FirewallErrorTests(unittest.TestCase):
    """Firewall errors raise ProcessError, never ALLOW."""

    def test_invalid_request_raises(self):
        fw = _firewall(allow=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        # Absolute path for process.spawn is a valid resource string;
        # it triggers default-deny, not InvalidRequestError.
        with self.assertRaises(ProcessDeniedError):
            adapter.spawn("dev", "/usr/bin/python")

    def test_error_does_not_execute(self):
        """Verify adapter never calls subprocess.run when any error occurs."""
        # Use a broken firewall that always raises
        class BrokenFirewall:
            def check(self, request):
                raise RuntimeError("simulated failure")
        adapter = ProcessAdapter(BrokenFirewall())
        original_run = subprocess.run
        called = [False]
        def tracking_run(*args, **kwargs):
            called[0] = True
            return original_run(*args, **kwargs)
        subprocess.run = tracking_run
        try:
            with self.assertRaises(ProcessError):
                adapter.spawn("dev", "python")
            self.assertFalse(called[0], "subprocess.run was called despite error")
        finally:
            subprocess.run = original_run


# ══════════════════════════════════════════════════════════════════════════════
# Security / adversarial tests
# ══════════════════════════════════════════════════════════════════════════════

class SecurityTests(unittest.TestCase):
    """Security and adversarial checks."""

    def test_no_shell_true_in_code(self):
        """adapter must never pass shell=True to subprocess.run."""
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            lines = f.readlines()
        in_docstring = False
        for line in lines:
            s = line.strip()
            if s.startswith('"""') or s.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            if s.startswith("#"):
                continue
            self.assertNotIn("shell=True", s,
                             f"shell=True found in code: {s}")

    def test_no_os_system(self):
        """adapter must never use os.system."""
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("os.system", src)

    def test_uses_subprocess_run(self):
        """adapter must use subprocess.run for execution."""
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("subprocess.run(", src)

    def test_list_based_invocation(self):
        """adapter builds a list command, not a string."""
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("cmd = [executable]", src)

    def test_shell_kwarg_stripped(self):
        """adapter removes shell kwarg to prevent shell=True."""
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn('kwargs.pop("shell", None)', src)

    def test_no_network_imports(self):
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        for d in ["import socket", "import http", "import urllib", "import requests"]:
            self.assertNotIn(d, src)

    def test_no_llm_imports(self):
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("import openai", src)
        self.assertNotIn("import anthropic", src)

    def test_zero_third_party_imports(self):
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        known = {
            "json", "os", "sys", "dataclasses", "datetime", "typing",
            "hashlib", "hmac", "re", "enum", "pathlib", "collections",
            "fnmatch", "io", "__future__", "subprocess",
        }
        internal = {"evaluator", "model", "policy", "normalize",
                     "adapters", "process"}
        allowed = known | internal
        third_party = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in allowed:
                        third_party.append(mod)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod not in allowed:
                        third_party.append(mod)
        self.assertEqual(third_party, [], f"Third-party imports: {third_party}")

    def test_adapter_uses_firewall_check(self):
        import agent_firewall.adapters.process as proc_mod
        with open(proc_mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("self._firewall.check(", src)

    def test_adapter_does_not_modify_policy(self):
        fw = _firewall(allow=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        adapter.spawn("dev", "python", ["--version"],
                       capture_output=True)
        self.assertEqual(len(fw.policy.agents["dev"].allow), 1)

    def test_deny_does_not_execute(self):
        """Process must not start when denied."""
        fw = _firewall(deny=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        original_run = subprocess.run
        called = [False]
        def tracking_run(*args, **kwargs):
            called[0] = True
            return original_run(*args, **kwargs)
        subprocess.run = tracking_run
        try:
            with self.assertRaises(ProcessDeniedError):
                adapter.spawn("dev", "python", ["-c", "import sys; sys.exit(1)"])
            self.assertFalse(called[0])
        finally:
            subprocess.run = original_run

    def test_approve_does_not_execute(self):
        """Process must not start when approval required."""
        fw = _firewall(approve=[{"action": "process.spawn", "resource": "python"}])
        adapter = ProcessAdapter(fw)
        original_run = subprocess.run
        called = [False]
        def tracking_run(*args, **kwargs):
            called[0] = True
            return original_run(*args, **kwargs)
        subprocess.run = tracking_run
        try:
            with self.assertRaises(ProcessApprovalRequiredError):
                adapter.spawn("dev", "python")
            self.assertFalse(called[0])
        finally:
            subprocess.run = original_run

    def test_authorization_before_execution(self):
        """Firewall check must happen before subprocess.run in spawn()."""
        source = inspect.getsource(ProcessAdapter.spawn)
        # Find the actual code lines (skip docstring)
        lines = source.split("\n")
        in_docstring = False
        code_lines = []
        for line in lines:
            s = line.strip()
            if s.startswith('"""') or s.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            code_lines.append(s)
        code_text = "\n".join(code_lines)
        check_pos = code_text.find("self._check(")
        run_pos = code_text.find("subprocess.run(")
        self.assertGreater(check_pos, 0, "_check not found in spawn()")
        self.assertGreater(run_pos, 0, "subprocess.run not found in spawn()")
        self.assertLess(check_pos, run_pos,
                        "_check must be called before subprocess.run in spawn()")


# ══════════════════════════════════════════════════════════════════════════════
# Regression tests
# ══════════════════════════════════════════════════════════════════════════════

class RegressionTests(unittest.TestCase):
    """Verify adapter doesn't break existing behavior."""

    def test_evaluator_still_works(self):
        from agent_firewall.evaluator import evaluate
        p = Firewall.from_dict({
            "version": 1,
            "agents": {"dev": {"allow": [{"action": "fs.read"}]}},
        }).policy
        d = evaluate(Request(agent="dev", action="fs.read"), p)
        self.assertEqual(d.kind, DecisionKind.ALLOW)

    def test_firewall_check_still_works(self):
        fw = _firewall(allow=[{"action": "process.spawn"}])
        d = fw.check(Request(agent="dev", action="process.spawn"))
        self.assertEqual(d.kind, DecisionKind.ALLOW)


if __name__ == "__main__":
    unittest.main()
