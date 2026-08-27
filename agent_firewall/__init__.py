"""agent-firewall: a small, deterministic authorization primitive.

Public surface (DESIGN 42). Keep it small: the core is Request + Policy and
the evaluation functions in this package. The `Firewall` facade holds one
immutable policy snapshot and answers `check()` for convenience.
"""

try:
    from importlib.metadata import version as _get_version
    __version__ = _get_version("agent-firewall")
except Exception:
    __version__ = "0.1.0"

from .approval import Approval, ApprovalError, ApprovalValidator
from .audit import EvidenceLogger, EvidenceRecord
from .evaluator import evaluate
from .diff import RuleDiff, diff_policies
from .orchestrator import OrchestratorBridge, TaskAuthorization
from .sandbox import (
    SandboxAdapter,
    SandboxApprovalRequiredError,
    SandboxDeniedError,
    SandboxError,
    SandboxResult,
)
from .integrity import (
    CapabilityExpirationList,
    ChainedEvidenceRecord,
    ChainVerification,
    EvidenceChain,
    ExpiringCapability,
    PolicyIntegrity,
    PolicyIntegrityVerifier,
    RevocationEntry,
    RevocationList,
    check_with_revocation,
)
from .simulate import SimulationResult, simulate_policy_comparison
from .analysis import (
    BroadPermission,
    CapabilityNode,
    ConflictEntry,
    PolicyAnalyzer,
    PrivilegeMismatch,
    ReachabilityResult,
    UnusedCapability,
)
from .suggestions import (
    InvalidSuggestionError,
    PolicySuggestion,
    PolicySuggestionEngine,
    SuggestionError,
    export_suggestions,
    proposed_policy,
)
from .validator import SuggestionValidationResult, SuggestionValidator
from .model import (
    Decision,
    DecisionKind,
    InvalidPolicyError,
    InvalidRequestError,
    Request,
    Rule,
    UnsupportedPolicyVersionError,
)
from .policy import SUPPORTED_VERSION, AgentPolicy, Policy, policy_from_dict, policy_from_file

__all__ = [
    "AgentPolicy",
    "Approval",
    "ApprovalError",
    "ApprovalValidator",
    "Decision",
    "DecisionKind",
    "EvidenceLogger",
    "EvidenceRecord",
    "Firewall",
    "OrchestratorBridge",
    "RuleDiff",
    "SandboxAdapter",
    "SandboxApprovalRequiredError",
    "SandboxDeniedError",
    "SandboxError",
    "SandboxResult",
    "CapabilityExpirationList",
    "ChainedEvidenceRecord",
    "ChainVerification",
    "EvidenceChain",
    "ExpiringCapability",
    "PolicyIntegrity",
    "PolicyIntegrityVerifier",
    "RevocationEntry",
    "RevocationList",
    "check_with_revocation",
    "BroadPermission",
    "CapabilityNode",
    "ConflictEntry",
    "PolicyAnalyzer",
    "PrivilegeMismatch",
    "ReachabilityResult",
    "SimulationResult",
    "TaskAuthorization",
    "UnusedCapability",
    "InvalidPolicyError",
    "InvalidRequestError",
    "InvalidSuggestionError",
    "Policy",
    "PolicySuggestion",
    "PolicySuggestionEngine",
    "Request",
    "Rule",
    "SUPPORTED_VERSION",
    "SuggestionError",
    "UnsupportedPolicyVersionError",
    "export_suggestions",
    "policy_from_dict",
    "policy_from_file",
    "proposed_policy",
    "SuggestionValidationResult",
    "SuggestionValidator",
]


class Firewall:
    """Holds one immutable policy snapshot and answers authorization checks.

    ``check(request)`` returns a Decision. It is side-effect free and never
    authorizes a malformed request (that raises InvalidRequestError instead).
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @classmethod
    def from_dict(cls, data, generation: int = 1) -> "Firewall":
        return cls(policy_from_dict(data, generation=generation))

    @classmethod
    def from_file(cls, path: str, generation: int = 1) -> "Firewall":
        return cls(policy_from_file(path, generation=generation))

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def snapshot(self) -> Policy:
        return self._policy

    def check(self, request: Request) -> Decision:
        return evaluate(request, self._policy)

    def is_allowed(self, request: Request) -> bool:
        return self.check(request).allowed