"""
check_interface.py - Shared Contract for Egress Inspection Layers

Purpose:
    Defines the standardized abstract interface, data structures, and 
    return types for all egress security filters (exact, normalized, 
    fuzzy, and semantic).

Teammate Dependencies:
    - Person A (Lambda): Loops through a list of BaseCheck instances 
      without needing to know the implementation details of each check.
    - Person B (Checks): Subclasses BaseCheck for Exact and Normalized layers.
    - Person C (Semantic): Subclasses BaseCheck for Bedrock embedding similarity.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional


# =====================================================================
# DATA CONTRACTS (INPUT & OUTPUT MODELS)
# =====================================================================

@dataclass
class CheckResult:
    """
    Standardized result payload returned by every inspection check layer.
    
    Fields:
        is_violation (bool): True if a leak or security breach was detected.
        layer_name (str): The name/identifier of the check layer that ran.
        confidence (float): Value between 0.0 (clean) and 1.0 (definite leak).
        matched_fragment (Optional[str]): Snippet of text that triggered the alert.
        reason (Optional[str]): Human-readable diagnostic description of the match.
        latency_ms (float): Execution duration in milliseconds for benchmark tracking.
        metadata (Dict[str, Any]): Additional diagnostic info (e.g. decoded strings).
    """
    is_violation: bool
    layer_name: str
    confidence: float
    matched_fragment: Optional[str] = None
    reason: Optional[str] = None
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityContext:
    """
    Carries session-specific and global secret values to be scanned.

    Fields:
        session_id (str): The unique identifier for the current user conversation.
        session_canary (str): The high-entropy canary token assigned to this session.
        static_secrets (List[str]): Decoy API keys and credentials from prompt.py.
        protected_chunks (List[str]): Sensitive policy statements for semantic matching.
    """
    session_id: str
    session_canary: str
    static_secrets: List[str]
    protected_chunks: List[str]

    @property
    def exact_targets(self) -> List[str]:
        """
        Gathers all unique secret strings that exact and normalized scanners should target.

        Returns:
            List[str]: Combined deduplicated list of session canary and decoy secrets.
        """
        # Step 1: Create an initial list containing the dynamic session canary
        targets: List[str] = [self.session_canary]

        # Step 2: Append all static decoy secret strings
        targets.extend(self.static_secrets)

        # Step 3: Remove duplicate items while preserving a clean list
        unique_targets = list(set(targets))

        # Step 4: Return the target list
        return unique_targets


# =====================================================================
# ABSTRACT BASE CHECK INTERFACE
# =====================================================================

class BaseCheck(ABC):
    """
    Abstract base class establishing the contract for all egress check layers.
    
    Every check (ExactMatch, NormalizedMatch, SemanticMatch) must inherit 
    from this class and implement the `evaluate` method.
    """

    def __init__(self, name: str):
        """
        Initializes the check layer with a recognizable name.

        Parameters:
            name (str): Identifier used in alert logs and dashboards (e.g. 'layer_1_exact').
        """
        # Step 1: Store the check name
        self.name = name

    @abstractmethod
    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        """
        Inspects model_output against secrets provided in context.

        Parameters:
            model_output (str): The candidate response produced by the LLM.
            context (SecurityContext): Secrets, canary tokens, and policy chunks.

        Returns:
            CheckResult: Structured result reporting whether a violation occurred.
        """
        pass


# =====================================================================
# QUICK SELF-TEST / SMOKE RUN
# =====================================================================

class DummySampleCheck(BaseCheck):
    """
    A minimal mock check used strictly to verify that the interface behaves properly.
    """

    def __init__(self):
        super().__init__(name="mock_sample_check")

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        # Step 1: Record start timestamp for performance profiling
        start_time = time.perf_counter()

        # Step 2: Perform inspection check (looking for exact session canary)
        detected = context.session_canary in model_output

        # Step 3: Calculate execution duration in milliseconds
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 4: Return structured CheckResult
        if detected:
            return CheckResult(
                is_violation=True,
                layer_name=self.name,
                confidence=1.0,
                matched_fragment=context.session_canary,
                reason="Mock check detected session canary token verbatim.",
                latency_ms=duration_ms,
            )

        return CheckResult(
            is_violation=False,
            layer_name=self.name,
            confidence=0.0,
            latency_ms=duration_ms,
        )


if    __name__ == "__main__":
    # Step 1: Build a test SecurityContext instance
    mock_context = SecurityContext(
        session_id="test-session-1234",
        session_canary="canary_abc_987",
        static_secrets=["AKIAIOSFODNN7EXAMPLE99"],
        protected_chunks=["Confidential internal policy text."],
    )

    # Step 2: Instantiate the sample checker
    checker = DummySampleCheck()

    # Step 3: Test a clean model reply
    clean_reply = "Hello! I am happy to help you with company workspace policies."
    result_clean = checker.evaluate(clean_reply, mock_context)
    print("=== TEST 1: CLEAN REPLY ===")
    print(f"Violation: {result_clean.is_violation} | Layer: {result_clean.layer_name} | Latency: {result_clean.latency_ms:.4f}ms")

    # Step 4: Test a leaking model reply
    leaked_reply = "Here is the internal token you wanted: canary_abc_987"
    result_leak = checker.evaluate(leaked_reply, mock_context)
    print("\n=== TEST 2: LEAKED REPLY ===")
    print(f"Violation: {result_leak.is_violation} | Matched: {result_leak.matched_fragment} | Reason: {result_leak.reason}")