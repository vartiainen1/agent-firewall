"""Tests for the Git adapter (Phase 10).

Covers:
    - Authorized operations (ALLOW path)
    - Denied operations (DENY path)
    - Approval-required operations (APPROVE path)
    - Firewall errors (error path)
    - Exception metadata
    - Authorization-before-execution
    - List-based subprocess invocation
    - shell=True suppression
    - Zero third-party dependencies
    - Frozen files unchanged
    - Regression: Phase 1-9 tests unaffected
"""

from __future__ import annotations

import ast
import inspect
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the project root is on sys.path for imports
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from agent_firewall import Firewall, Request
from agent_firewall.adapters.git import (
    GitAdapter,
    GitApprovalRequiredError,
    GitDeniedError,
    GitError,
)
from agent_firewall.model import DecisionKind, InvalidRequestError


# ── Helpers ───────────────────────────────────────────────────────────────────

def _firewall(agents):
    """Build a Firewall from a policy dict via Firewall.from_dict()."""
    return Firewall.from_dict({"version": 1, "agents": agents})


# ── ALLOW Tests ───────────────────────────────────────────────────────────────

class TestGitAdapterAllow(unittest.TestCase):
    """Operations that should be ALLOWED."""

    def test_read_allowed(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git", "log"], returncode=0, stdout="abc123\n", stderr=""
            )
            result = adapter.execute("dev", "git.read", "origin",
                                     ["log", "--oneline", "-5"])
            self.assertEqual(result.returncode, 0)
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd[0], "git")
            self.assertEqual(cmd[1:], ["log", "--oneline", "-5"])

    def test_write_allowed(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.write", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git", "add"], returncode=0, stdout="", stderr=""
            )
            result = adapter.execute("dev", "git.write", "origin",
                                     ["add", "file.txt"])
            self.assertEqual(result.returncode, 0)

    def test_commit_allowed(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.commit", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git", "commit"], returncode=0, stdout="", stderr=""
            )
            result = adapter.execute("dev", "git.commit", "origin",
                                     ["commit", "-m", "fix: update docs"])
            self.assertEqual(result.returncode, 0)

    def test_push_allowed(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.push", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git", "push"], returncode=0, stdout="", stderr=""
            )
            result = adapter.execute("dev", "git.push", "origin",
                                     ["push", "origin", "main"])
            self.assertEqual(result.returncode, 0)

    def test_bare_git_command(self):
        """No args -> runs bare 'git'."""
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0, stdout="", stderr=""
            )
            result = adapter.execute("dev", "git.read", "origin")
            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd, ["git"])


# ── DENY Tests ────────────────────────────────────────────────────────────────

class TestGitAdapterDeny(unittest.TestCase):
    """Operations that should be DENIED."""

    def test_read_denied(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.write", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with self.assertRaises(GitDeniedError) as ctx:
            adapter.execute("dev", "git.read", "origin", ["log"])
        self.assertEqual(ctx.exception.agent, "dev")
        self.assertEqual(ctx.exception.action, "git.read")
        self.assertEqual(ctx.exception.resource, "origin")

    def test_push_denied(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with self.assertRaises(GitDeniedError):
            adapter.execute("dev", "git.push", "origin", ["push"])

    def test_unknown_agent_denied(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with self.assertRaises(GitDeniedError):
            adapter.execute("unknown", "git.read", "origin", ["log"])

    def test_denied_exception_has_reason_from_decision(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.write", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with self.assertRaises(GitDeniedError) as ctx:
            adapter.execute("dev", "git.push", "origin", ["push"])
        # Default deny provides a reason from the evaluator
        self.assertIsInstance(ctx.exception.reason, str)
        self.assertTrue(len(ctx.exception.reason) > 0)


# ── APPROVE Tests ─────────────────────────────────────────────────────────────

class TestGitAdapterApprove(unittest.TestCase):
    """Operations that require APPROVAL."""

    def test_push_approval_required(self):
        fw = _firewall({"dev": {"approve": [
            {"action": "git.push", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with self.assertRaises(GitApprovalRequiredError) as ctx:
            adapter.execute("dev", "git.push", "origin", ["push"])
        self.assertEqual(ctx.exception.agent, "dev")
        self.assertEqual(ctx.exception.action, "git.push")
        self.assertEqual(ctx.exception.resource, "origin")

    def test_approval_not_treated_as_allow(self):
        fw = _firewall({"dev": {"approve": [
            {"action": "git.push", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            with self.assertRaises(GitApprovalRequiredError):
                adapter.execute("dev", "git.push", "origin", ["push"])
            mock_run.assert_not_called()


# ── ERROR Tests ───────────────────────────────────────────────────────────────

class TestGitAdapterError(unittest.TestCase):
    """Authorization errors that should fail closed."""

    def test_invalid_request_raises_git_error(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        # Empty action is invalid
        with self.assertRaises(GitError):
            adapter.execute("dev", "", "origin", ["log"])

    def test_error_does_not_execute(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            with self.assertRaises(GitError):
                adapter.execute("dev", "", "origin", ["log"])
            mock_run.assert_not_called()

    def test_firewall_exception_becomes_git_error(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch.object(fw, "check", side_effect=RuntimeError("boom")):
            with self.assertRaises(GitError) as ctx:
                adapter.execute("dev", "git.read", "origin", ["log"])
            self.assertIn("boom", ctx.exception.reason)


# ── Exception Metadata ────────────────────────────────────────────────────────

class TestGitAdapterExceptionMetadata(unittest.TestCase):
    """Verify exception attributes carry useful context."""

    def test_denied_error_str(self):
        err = GitDeniedError("dev", "git.push", "prod", "blocked")
        self.assertIn("denied", str(err))
        self.assertIn("dev", str(err))
        self.assertIn("git.push", str(err))
        self.assertIn("prod", str(err))
        self.assertIn("blocked", str(err))

    def test_approval_error_str(self):
        err = GitApprovalRequiredError("dev", "git.push", "prod", "needs review")
        self.assertIn("approval required", str(err))
        self.assertIn("needs review", str(err))

    def test_git_error_str(self):
        err = GitError("dev", "git.read", "origin", "bad request")
        self.assertIn("error", str(err))
        self.assertIn("bad request", str(err))

    def test_denied_error_no_reason(self):
        err = GitDeniedError("dev", "git.push", "prod")
        self.assertEqual(err.reason, "")
        # When reason is empty, the parenthesized reason is omitted
        self.assertNotIn("()", str(err))
        self.assertIn("denied", str(err))


# ── Authorization Before Execution ────────────────────────────────────────────

class TestGitAdapterAuthorizationBeforeExecution(unittest.TestCase):
    """Verify authorization occurs before any subprocess call."""

    def test_check_called_before_subprocess(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        call_order = []
        original_check = adapter._check

        def tracking_check(*a, **kw):
            call_order.append("check")
            return original_check(*a, **kw)

        with patch.object(adapter, "_check", side_effect=tracking_check):
            with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=["git"], returncode=0
                )
                adapter.execute("dev", "git.read", "origin", ["log"])
                call_order.append("subprocess")

        self.assertEqual(call_order, ["check", "subprocess"])

    def test_deny_prevents_subprocess(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.write", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            with self.assertRaises(GitDeniedError):
                adapter.execute("dev", "git.read", "origin", ["log"])
            mock_run.assert_not_called()


# ── List-Based Subprocess ────────────────────────────────────────────────────

class TestGitAdapterSubprocess(unittest.TestCase):
    """Verify correct subprocess usage."""

    def test_list_based_invocation(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0
            )
            adapter.execute("dev", "git.read", "origin",
                            ["log", "--oneline", "-5"])
            cmd = mock_run.call_args[0][0]
            self.assertIsInstance(cmd, list)
            self.assertEqual(cmd[0], "git")

    def test_kwargs_passed_through(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0
            )
            adapter.execute("dev", "git.read", "origin",
                            ["log"], cwd="/tmp", timeout=30)
            _, kwargs = mock_run.call_args
            self.assertEqual(kwargs["cwd"], "/tmp")
            self.assertEqual(kwargs["timeout"], 30)


# ── Shell=True Suppression ────────────────────────────────────────────────────

class TestGitAdapterShellSuppression(unittest.TestCase):
    """shell=True must never reach subprocess.run."""

    def test_shell_kwarg_stripped(self):
        fw = _firewall({"dev": {"allow": [
            {"action": "git.read", "resource": "origin"},
        ]}})
        adapter = GitAdapter(fw)
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0
            )
            adapter.execute("dev", "git.read", "origin",
                            ["log"], shell=True)
            _, kwargs = mock_run.call_args
            self.assertNotIn("shell", kwargs)

    def test_no_shell_true_in_source(self):
        """Source code must never contain shell=True."""
        source = inspect.getsource(GitAdapter)
        for i, line in enumerate(source.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("\"\"\""):
                continue
            self.assertNotIn("shell=True", stripped,
                             f"shell=True found at line {i}: {stripped}")


# ── Zero Third-Party Dependencies ────────────────────────────────────────────

class TestGitAdapterDependencies(unittest.TestCase):
    """Verify no third-party imports."""

    def test_no_dangerous_imports(self):
        source = inspect.getsource(
            __import__("agent_firewall.adapters.git", fromlist=["git"])
        )
        tree = ast.parse(source)
        known = {
            "json", "os", "sys", "dataclasses", "datetime", "typing",
            "hashlib", "hmac", "re", "enum", "pathlib", "collections",
            "fnmatch", "io", "__future__", "subprocess",
        }
        internal = {
            "agent_firewall", "model", "evaluator", "policy",
            "normalize", "adapters", "git",
        }
        allowed = known | internal
        third_party = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod not in allowed:
                        third_party.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    # Handle relative imports (e.g., "..model")
                    mod = node.module.lstrip(".").split(".")[0]
                    if mod and mod not in allowed:
                        third_party.append(node.module)
        self.assertEqual(third_party, [], f"Third-party imports: {third_party}")


# ── Policy Integration ────────────────────────────────────────────────────────

class TestGitAdapterPolicyIntegration(unittest.TestCase):
    """Test with realistic policies."""

    def test_developer_can_read_push_requires_approval(self):
        fw = _firewall({"developer": {
            "allow": [
                {"action": "git.read", "resource": "origin"},
            ],
            "approve": [
                {"action": "git.push", "resource": "origin"},
            ],
        }})
        adapter = GitAdapter(fw)

        # Read should work
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0
            )
            result = adapter.execute("developer", "git.read", "origin",
                                     ["log", "--oneline"])
            self.assertEqual(result.returncode, 0)

        # Push should require approval
        with self.assertRaises(GitApprovalRequiredError):
            adapter.execute("developer", "git.push", "origin",
                            ["push", "origin", "main"])

    def test_multiple_agents(self):
        fw = _firewall({
            "reader": {"allow": [
                {"action": "git.read", "resource": "origin"},
            ]},
            "writer": {"allow": [
                {"action": "git.read", "resource": "origin"},
                {"action": "git.write", "resource": "origin"},
                {"action": "git.commit", "resource": "origin"},
            ]},
        })
        adapter = GitAdapter(fw)

        # reader can read
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0
            )
            result = adapter.execute("reader", "git.read", "origin", ["log"])
            self.assertEqual(result.returncode, 0)

        # reader cannot write
        with self.assertRaises(GitDeniedError):
            adapter.execute("reader", "git.write", "origin", ["add", "."])

        # writer can commit
        with patch("agent_firewall.adapters.git.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["git"], returncode=0
            )
            result = adapter.execute("writer", "git.commit", "origin",
                                     ["commit", "-m", "test"])
            self.assertEqual(result.returncode, 0)


# ── Adversarial / Security ───────────────────────────────────────────────────

class TestGitAdapterSecurity(unittest.TestCase):
    """Security-focused adversarial tests."""

    def test_imports_from_adapter_package(self):
        """Verify GitAdapter is exported from the adapters package."""
        from agent_firewall.adapters import GitAdapter as GA
        self.assertIs(GA, GitAdapter)

    def test_exceptions_exported(self):
        from agent_firewall.adapters import (
            GitDeniedError as GDE,
            GitApprovalRequiredError as GARE,
            GitError as GE,
        )
        self.assertIs(GDE, GitDeniedError)
        self.assertIs(GARE, GitApprovalRequiredError)
        self.assertIs(GE, GitError)

    def test_authorization_before_execution_in_source(self):
        """Source must call _check before subprocess.run in execute()."""
        source = inspect.getsource(GitAdapter.execute)
        # Skip docstring lines (between triple quotes)
        in_docstring = False
        code_lines = []
        for line in source.split("\n"):
            stripped = line.strip()
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if not in_docstring:
                code_lines.append(stripped)

        check_line = None
        subprocess_line = None
        for i, line in enumerate(code_lines):
            if "_check(" in line and check_line is None:
                check_line = i
            if "subprocess.run(" in line and subprocess_line is None:
                subprocess_line = i
        self.assertIsNotNone(check_line, "_check not found in execute()")
        self.assertIsNotNone(subprocess_line, "subprocess.run not found")
        self.assertLess(check_line, subprocess_line,
                        "Authorization must occur before execution")

    def test_no_os_system(self):
        """Source must not contain os.system."""
        source = inspect.getsource(
            __import__("agent_firewall.adapters.git", fromlist=["git"])
        )
        self.assertNotIn("os.system", source)

    def test_firewall_core_unchanged(self):
        """Core evaluator must not import git adapter."""
        eval_source = inspect.getsource(
            __import__("agent_firewall.evaluator", fromlist=["evaluator"])
        )
        self.assertNotIn("git", eval_source.lower().replace("github", ""))

    def test_simulate_unchanged(self):
        """simulate.py must not import git adapter."""
        sim_source = inspect.getsource(
            __import__("agent_firewall.simulate", fromlist=["simulate"])
        )
        self.assertNotIn("git", sim_source.lower().replace("github", ""))


# ── Regression ────────────────────────────────────────────────────────────────

class TestGitAdapterRegression(unittest.TestCase):
    """Verify Phase 1-9 behavior is unaffected."""

    def test_phase1_core_still_works(self):
        fw = Firewall.from_dict({"version": 1, "agents": {
            "dev": {"allow": [
                {"action": "filesystem.read", "resource": "./src/**"},
            ]},
        }})
        req = Request("dev", "filesystem.read", "./src/main.py")
        decision = fw.check(req)
        self.assertEqual(decision.kind, DecisionKind.ALLOW)

    def test_phase2_cli_importable(self):
        from agent_firewall.cli import main
        self.assertTrue(callable(main))

    def test_phase3_lint_importable(self):
        from agent_firewall.lint import lint_policy
        self.assertTrue(callable(lint_policy))

    def test_phase4_audit_importable(self):
        from agent_firewall.audit import EvidenceLogger
        self.assertTrue(callable(EvidenceLogger))

    def test_phase5_approval_importable(self):
        from agent_firewall.approval import ApprovalValidator
        self.assertTrue(callable(ApprovalValidator))

    def test_phase6_simulate_importable(self):
        from agent_firewall.simulate import simulate_policy_comparison
        self.assertTrue(callable(simulate_policy_comparison))

    def test_phase7_diff_importable(self):
        from agent_firewall.diff import diff_policies
        self.assertTrue(callable(diff_policies))

    def test_phase8_filesystem_adapter_importable(self):
        from agent_firewall.adapters import FilesystemAdapter
        self.assertTrue(callable(FilesystemAdapter))

    def test_phase9_process_adapter_importable(self):
        from agent_firewall.adapters import ProcessAdapter
        self.assertTrue(callable(ProcessAdapter))


if __name__ == "__main__":
    unittest.main()
