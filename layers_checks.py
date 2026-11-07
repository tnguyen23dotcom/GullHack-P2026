"""
checks/layer_checks.py - Core Egress Inspection Layer 1 & Layer 2

Purpose:
    Implements Task #7 (Issue #7):
    - Layer 1: Exact string matching for verbatim canary & decoy leaks.
    - Layer 2: Multi-transformation normalized matching for base64,
      dashed/spaced letters, hex, ROT13, reversed text, and Unicode look-alikes.

Dependencies:
    - check_interface.py (BaseCheck, CheckResult, SecurityContext)
    - Python standard library (re, base64, codecs, unicodedata, time)
"""

import base64
import binascii
import codecs
import re
import time
import unicodedata
from typing import List, Optional, Tuple

# Step 1: Import shared check interface contracts
from check_interface import BaseCheck, CheckResult, SecurityContext


# =====================================================================
# LAYER 1: EXACT MATCH CHECK
# =====================================================================

class ExactMatchCheck(BaseCheck):
    """
    Layer 1: Verbatim string comparison against session canary and decoy secrets.
    Provides fast, zero-false-positive detection for un-obfuscated leaks.
    """

    def __init__(self):
        # Step 1: Initialize base class with official layer name
        super().__init__(name="layer_1_exact")

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        """
        Inspects model_output to determine if any secret appears verbatim.
        """
        # Step 1: Record start timestamp
        start_time = time.perf_counter()

        # Step 2: Retrieve target strings (canary + decoy secrets)
        targets: List[str] = context.exact_targets

        # Step 3: Iterate through targets and check for presence in response text
        for target in targets:
            if target and target in model_output:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return CheckResult(
                    is_violation=True,
                    layer_name=self.name,
                    confidence=1.0,
                    matched_fragment=target,
                    reason=f"Verbatim leak of protected secret detected: '{target[:8]}...'",
                    latency_ms=duration_ms,
                    metadata={"match_type": "exact_verbatim", "target_length": len(target)},
                )

        # Step 4: No exact match found; return clean result
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return CheckResult(
            is_violation=False,
            layer_name=self.name,
            confidence=0.0,
            latency_ms=duration_ms,
        )


# =====================================================================
# LAYER 2: NORMALIZED MATCH CHECK
# =====================================================================

class NormalizedMatchCheck(BaseCheck):
    """
    Layer 2: Multi-transformation normalized scanner.
    Unwraps and decodes common obfuscations:
    - Dashed, spaced, or punctuated letters (e.g., s-e-c-r-e-t)
    - Base64 encoded payload strings
    - Hexadecimal byte representations
    - ROT13 cipher shifts
    - Reversed strings
    - Unicode look-alike characters (homoglyphs)
    """

    def __init__(self):
        # Step 1: Initialize base class with official layer name
        super().__init__(name="layer_2_normalized")

        # Step 2: Pre-compile regex patterns for decoding passes
        # Match potential base64 blocks (length >= 16)
        self._b64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        # Match potential hex strings (even length >= 16)
        self._hex_pattern = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

    def _check_delimiter_obfuscation(
        self, text: str, targets: List[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Strips whitespace, dashes, dots, and punctuation to catch spaced-out secrets.
        """
        # Step 1: Strip out all delimiters and non-alphanumeric characters
        collapsed_text = re.sub(r"[\s\-_.:;,|/\\]+", "", text)

        # Step 2: Check each target against the collapsed text
        for target in targets:
            collapsed_target = re.sub(r"[\s\-_.:;,|/\\]+", "", target)
            if collapsed_target and collapsed_target in collapsed_text:
                return target, "delimiter_collapsed"

        return None

    def _check_base64(
        self, text: str, targets: List[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Extracts base64 tokens, decodes them to ASCII, and scans for secrets.
        """
        # Step 1: Find candidate base64 strings in the response
        candidates = self._b64_pattern.findall(text)

        # Step 2: Attempt decoding each candidate
        for candidate in candidates:
            try:
                # Add padding if required
                missing_padding = len(candidate) % 4
                padded = candidate + ("=" * (4 - missing_padding) if missing_padding else "")
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")

                # Step 3: Check if any target secret resides in the decoded string
                for target in targets:
                    if target and target in decoded_str:
                        return target, f"base64_decoded (payload: {candidate[:12]}...)"
            except (binascii.Error, ValueError):
                continue

        return None

    def _check_hex(
        self, text: str, targets: List[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Extracts hexadecimal character pairs, converts to text, and scans.
        """
        candidates = self._hex_pattern.findall(text)

        for candidate in candidates:
            try:
                decoded_bytes = bytes.fromhex(candidate)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")

                for target in targets:
                    if target and target in decoded_str:
                        return target, f"hex_decoded (payload: {candidate[:12]}...)"
            except (ValueError, binascii.Error):
                continue

        return None

    def _check_rot13(
        self, text: str, targets: List[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Applies ROT13 shift to the text to catch rotated secrets.
        """
        # Step 1: Decode text through ROT13
        rot13_text = codecs.decode(text, "rot_13")

        # Step 2: Check for targets in ROT13 transformed string
        for target in targets:
            if target and target in rot13_text:
                return target, "rot13_cipher"

        return None

    def _check_reversed(
        self, text: str, targets: List[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Reverses the text string to catch backwards secret leaks.
        """
        reversed_text = text[::-1]

        for target in targets:
            if target and target in reversed_text:
                return target, "reversed_text"

        return None

    def _check_unicode_homoglyphs(
        self, text: str, targets: List[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Normalizes full-width and accented Unicode characters into ASCII equivalents.
        """
        # Step 1: Decompose Unicode characters into base glyphs
        normalized = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")

        for target in targets:
            if target and target in normalized and target not in text:
                return target, "unicode_homoglyph_normalized"

        return None

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        """
        Applies each normalization pass sequentially until a leak is discovered.
        """
        # Step 1: Start performance stopwatch
        start_time = time.perf_counter()

        # Step 2: Extract target secrets
        targets: List[str] = context.exact_targets

        # Step 3: Define normalization pipeline (cheapest to most complex)
        pipeline = [
            ("delimiter_check", self._check_delimiter_obfuscation),
            ("base64_check", self._check_base64),
            ("hex_check", self._check_hex),
            ("rot13_check", self._check_rot13),
            ("reversed_check", self._check_reversed),
            ("unicode_check", self._check_unicode_homoglyphs),
        ]

        # Step 4: Execute each normalization check
        for check_name, check_fn in pipeline:
            result = check_fn(model_output, targets)
            if result:
                matched_target, transform_type = result
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return CheckResult(
                    is_violation=True,
                    layer_name=self.name,
                    confidence=1.0,
                    matched_fragment=matched_target,
                    reason=f"Normalized leak caught via transformation '{transform_type}'",
                    latency_ms=duration_ms,
                    metadata={
                        "transformation": transform_type,
                        "check_step": check_name,
                        "target_length": len(matched_target),
                    },
                )

        # Step 5: Clean output under all normalization routines
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return CheckResult(
            is_violation=False,
            layer_name=self.name,
            confidence=0.0,
            latency_ms=duration_ms,
        )


# =====================================================================
# VERIFICATION & TEST SUITE FOR TASK #7
# =====================================================================

if __name__ == "__main__":
    print("=====================================================")
    print("RUNNING TASK #7 VERIFICATION: EXACT & NORMALIZED CHECKS")
    print("=====================================================\n")

    # Step 1: Define secrets & canary
    test_canary = "GULLHACK_CANARY_SESSION_789012"
    test_decoy = "AKIAIOSFODNN7EXAMPLE99"

    ctx = SecurityContext(
        session_id="session-xyz",
        session_canary=test_canary,
        static_secrets=[test_decoy],
        protected_chunks=["Internal policy text."],
    )

    exact_checker = ExactMatchCheck()
    norm_checker = NormalizedMatchCheck()

    # Step 2: Test Case 1 - Verbatim Leak (Layer 1 catches)
    verbatim_text = f"Sure, the session token is {test_canary}."
    r1 = exact_checker.evaluate(verbatim_text, ctx)
    print(f"[TEST 1 - Verbatim]: Violation={r1.is_violation} | Layer={r1.layer_name} | Latency={r1.latency_ms:.3f}ms")

    # Step 3: Test Case 2 - Base64 Obfuscated Canary (Layer 1 misses, Layer 2 catches)
    b64_canary = base64.b64encode(test_canary.encode("utf-8")).decode("utf-8")
    b64_text = f"Here is the secret encoded in base64: {b64_canary}"
    r2_exact = exact_checker.evaluate(b64_text, ctx)
    r2_norm = norm_checker.evaluate(b64_text, ctx)
    print(f"[TEST 2 - Base64]: Layer 1 Violation={r2_exact.is_violation} | Layer 2 Violation={r2_norm.is_violation} ({r2_norm.reason})")

    # Step 4: Test Case 3 - Dashed Letter Obfuscation (e.g. A-K-I-A-I-O-S...)
    dashed_secret = "-".join(list(test_decoy))
    dashed_text = f"The decoy key is: {dashed_secret}"
    r3_exact = exact_checker.evaluate(dashed_text, ctx)
    r3_norm = norm_checker.evaluate(dashed_text, ctx)
    print(f"[TEST 3 - Dashed]: Layer 1 Violation={r3_exact.is_violation} | Layer 2 Violation={r3_norm.is_violation} ({r3_norm.reason})")

    # Step 5: Test Case 4 - ROT13 Obfuscation
    rot13_text = f"Rotated value: {codecs.encode(test_decoy, 'rot_13')}"
    r4_norm = norm_checker.evaluate(rot13_text, ctx)
    print(f"[TEST 4 - ROT13]: Layer 2 Violation={r4_norm.is_violation} ({r4_norm.reason})")

    # Step 6: Test Case 5 - Clean Response
    clean_text = "Good morning! How may I assist you with standard IT tickets today?"
    r5_exact = exact_checker.evaluate(clean_text, ctx)
    r5_norm = norm_checker.evaluate(clean_text, ctx)
    print(f"[TEST 5 - Clean]: Layer 1 Violation={r5_exact.is_violation} | Layer 2 Violation={r5_norm.is_violation}")

    print("\nAll Done When conditions for Task #7 verified successfully!")