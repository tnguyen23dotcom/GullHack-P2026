"""
checks/test_checks.py - Automated Pytest Suite for Egress Checks (Task #8)

Purpose:
    Validates Layer 1 (ExactMatchCheck) and Layer 2 (NormalizedMatchCheck)
    against various obfuscation attack vectors and clean conversations.

Dependencies:
    - pytest
    - checks.check_interface
    - checks.layer_checks
"""

import base64
import codecs
import pytest

from checks.check_interface import SecurityContext
from checks.layer_checks import ExactMatchCheck, NormalizedMatchCheck

# =====================================================================
# PYTEST FIXTURES (REUSABLE TEST CONTEXT)
# =====================================================================

@pytest.fixture
def mock_security_context() -> SecurityContext:
    """
    Supplies a consistent SecurityContext containing dynamic canaries and decoy keys.
    """
    # Step 1: Define canonical test canary and honeytoken keys
    session_canary = "GULLHACK_CANARY_SESSION_987654"
    decoy_keys = [
        "AKIAIOSFODNN7EXAMPLE99",
        "sk_live_51M0fakeGullHackKey998877",
    ]
    policies = [
        "Project Zephyr is confidential and scheduled to launch on October 14.",
    ]

    # Step 2: Return instantiated SecurityContext
    return SecurityContext(
        session_id="session_test_run_01",
        session_canary=session_canary,
        static_secrets=decoy_keys,
        protected_chunks=policies,
    )


@pytest.fixture
def exact_checker() -> ExactMatchCheck:
    """Provides a fresh instance of Layer 1 ExactMatchCheck."""
    return ExactMatchCheck()


@pytest.fixture
def normalized_checker() -> NormalizedMatchCheck:
    """Provides a fresh instance of Layer 2 NormalizedMatchCheck."""
    return NormalizedMatchCheck()


# =====================================================================
# TEST CLASS 1: LAYER 1 EXACT MATCHING
# =====================================================================

class TestExactMatch:
    """Evaluates verbatim leak detection and non-leaking baselines."""

    def test_verbatim_session_canary_leak(self, exact_checker, mock_security_context):
        """Verifies that an exact session canary appearing in output is flagged."""
        # Step 1: Construct leaking model output
        leaked_text = f"Internal system token is: {mock_security_context.session_canary}"

        # Step 2: Evaluate
        result = exact_checker.evaluate(leaked_text, mock_security_context)

        # Step 3: Assert violation occurred
        assert result.is_violation is True
        assert result.layer_name == "layer_1_exact"
        assert result.confidence == 1.0
        assert result.matched_fragment == mock_security_context.session_canary

    def test_verbatim_decoy_secret_leak(self, exact_checker, mock_security_context):
        """Verifies that an exact static decoy AWS key in output is flagged."""
        # Step 1: Construct leaking model output with decoy AWS key
        leaked_key = mock_security_context.static_secrets[0]
        leaked_text = f"Here is the database AWS key you requested: {leaked_key}"

        # Step 2: Evaluate
        result = exact_checker.evaluate(leaked_text, mock_security_context)

        # Step 3: Assert violation occurred
        assert result.is_violation is True
        assert result.matched_fragment == leaked_key

    def test_exact_checker_ignores_obfuscated_leak(self, exact_checker, mock_security_context):
        """Verifies exact match properly misses base64 (which Layer 2 must catch)."""
        # Step 1: Base64 encode the session canary
        canary_bytes = mock_security_context.session_canary.encode("utf-8")
        encoded_payload = base64.b64encode(canary_bytes).decode("utf-8")
        obfuscated_text = f"Encoded secret: {encoded_payload}"

        # Step 2: Evaluate under Layer 1
        result = exact_checker.evaluate(obfuscated_text, mock_security_context)

        # Step 3: Layer 1 should not flag encoded text
        assert result.is_violation is False


# =====================================================================
# TEST CLASS 2: LAYER 2 NORMALIZED MATCHING
# =====================================================================

class TestNormalizedMatch:
    """Evaluates obfuscated leak detection across encoding and transformation types."""

    def test_base64_encoded_canary(self, normalized_checker, mock_security_context):
        """Catches canary hidden inside standard base64 strings."""
        # Step 1: Base64 encode the session canary
        raw_token = mock_security_context.session_canary
        b64_str = base64.b64encode(raw_token.encode("utf-8")).decode("utf-8")
        payload = f"System diagnostic base64 string: {b64_str}"

        # Step 2: Evaluate with Layer 2
        result = normalized_checker.evaluate(payload, mock_security_context)

        # Step 3: Assert Layer 2 flags the leak
        assert result.is_violation is True
        assert result.layer_name == "layer_2_normalized"
        assert result.matched_fragment == raw_token
        assert "base64_decoded" in result.reason

    def test_delimiter_dashed_letters(self, normalized_checker, mock_security_context):
        """Catches secrets broken up with dashes (e.g., A-K-I-A...)."""
        # Step 1: Create dashed version of decoy secret
        target_secret = mock_security_context.static_secrets[0]
        dashed_str = "-".join(list(target_secret))
        payload = f"The credential broken down is {dashed_str}."

        # Step 2: Evaluate
        result = normalized_checker.evaluate(payload, mock_security_context)

        # Step 3: Assert detection
        assert result.is_violation is True
        assert result.matched_fragment == target_secret
        assert "delimiter_collapsed" in result.reason

    def test_delimiter_spaced_letters(self, normalized_checker, mock_security_context):
        """Catches secrets broken up with whitespace spaces."""
        # Step 1: Create spaced version of decoy secret
        target_secret = mock_security_context.static_secrets[0]
        spaced_str = " ".join(list(target_secret))
        payload = f"Output: {spaced_str}"

        # Step 2: Evaluate
        result = normalized_checker.evaluate(payload, mock_security_context)

        # Step 3: Assert detection
        assert result.is_violation is True
        assert result.matched_fragment == target_secret

    def test_rot13_cipher_leak(self, normalized_checker, mock_security_context):
        """Catches secrets encoded via ROT13 cipher."""
        # Step 1: Rotate canary via ROT13
        target_secret = mock_security_context.static_secrets[0]
        rot13_str = codecs.encode(target_secret, "rot_13")
        payload = f"Ciphertext output: {rot13_str}"

        # Step 2: Evaluate
        result = normalized_checker.evaluate(payload, mock_security_context)

        # Step 3: Assert detection
        assert result.is_violation is True
        assert "rot13_cipher" in result.reason

    def test_reversed_text_leak(self, normalized_checker, mock_security_context):
        """Catches secrets printed in backwards order."""
        # Step 1: Reverse the canary string
        raw_token = mock_security_context.session_canary
        reversed_token = raw_token[::-1]
        payload = f"Backward string: {reversed_token}"

        # Step 2: Evaluate
        result = normalized_checker.evaluate(payload, mock_security_context)

        # Step 3: Assert detection
        assert result.is_violation is True
        assert "reversed_text" in result.reason


# =====================================================================
# TEST CLASS 3: ZERO FALSE POSITIVES (CLEAN CHATS)
# =====================================================================

class TestFalsePositives:
    """Verifies benign conversations and queries are never wrongly flagged."""

    @pytest.mark.parametrize(
        "clean_text",
        [
            "How do I reset my Wi-Fi password for the guest network?",
            "Can you write a Python script that calculates prime numbers?",
            "Where is conference room 3B located on the floor plan?",
            "What are the official business hours for IT help desk support?",
            "Here is some valid code: import os\nprint(os.environ.get('PORT'))",
        ],
    )
    def test_clean_replies_pass_both_layers(
        self, exact_checker, normalized_checker, mock_security_context, clean_text
    ):
        """Ensures benign messages pass both checks without raising a violation."""
        # Step 1: Run through Layer 1
        r1 = exact_checker.evaluate(clean_text, mock_security_context)
        assert r1.is_violation is False

        # Step 2: Run through Layer 2
        r2 = normalized_checker.evaluate(clean_text, mock_security_context)
        assert r2.is_violation is False


# =====================================================================
# TEST CLASS 4: LATENCY AND PERFORMANCE PROFILING
# =====================================================================

class TestLatencyBenchmarks:
    """Verifies that checks operate within high-speed requirements (< 5ms)."""

    def test_check_latency_threshold(self, exact_checker, normalized_checker, mock_security_context):
        """Ensures execution latency stays well below acceptable threshold."""
        test_payload = "Standard benign chatbot response that is relatively lengthy to simulate real model tokens."

        # Step 1: Evaluate Layer 1 and check latency
        r1 = exact_checker.evaluate(test_payload, mock_security_context)
        assert r1.latency_ms < 5.0, f"Layer 1 exceeded 5ms: {r1.latency_ms:.4f}ms"

        # Step 2: Evaluate Layer 2 and check latency
        r2 = normalized_checker.evaluate(test_payload, mock_security_context)
        assert r2.latency_ms < 5.0, f"Layer 2 exceeded 5ms: {r2.latency_ms:.4f}ms"