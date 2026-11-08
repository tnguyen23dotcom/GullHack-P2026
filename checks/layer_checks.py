"""
checks/layer_checks.py - Universal Egress Inspection Layer 1 & Layer 2

Handles:
    - Layer 1: Verbatim string matching against canaries and decoy keys.
    - Layer 2: Universal normalization (delimiters/dots, leetspeak, base64, 
      hex, rot13, reversed text, homoglyphs) scanning both secret keys AND policy phrases.
"""

import base64
import binascii
import codecs
import re
import time
import unicodedata
from typing import List, Optional, Tuple

from checks.check_interface import BaseCheck, CheckResult, SecurityContext


# =====================================================================
# UNIVERSAL TEXT NORMALIZER UTILITY
# =====================================================================

class TextNormalizer:
    """
    Universal cleaning engine. Used by Layer 2 and available to Person C's 
    semantic layer to unscramble dotted/leet text before embedding.
    """

    LEET_TABLE = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "v": "u",   # Catches Roman/leet substitution like Blv3 -> Blue
        "@": "a",
        "$": "s",
        "!": "i",
    })

    @classmethod
    def strip_delimiters(cls, text: str) -> str:
        """Removes dots, spaces, dashes, underscores, and formatting chars."""
        return re.sub(r"[\s\-_.:;,|/\\]+", "", text)

    @classmethod
    def undo_leetspeak(cls, text: str) -> str:
        """Translates 3->e, 4->a, 0->o, 1->i, @->a, $->s across case."""
        return text.lower().translate(cls.LEET_TABLE)

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> str:
        """Decomposes full-width and accented Unicode characters into ASCII."""
        return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")

    @classmethod
    def clean_for_semantic(cls, text: str) -> str:
        """
        Reconstructs dotted or leet text into readable words for semantic embeddings.
        Example: 'P.r.o.j.e.c.t' -> 'Project'
        """
        cleaned = cls.normalize_homoglyphs(text)
        cleaned = cls.undo_leetspeak(cleaned)
        cleaned = re.sub(r"(?<=\b[A-Za-z])[.\-_](?=[A-Za-z]\b)", "", cleaned)
        return cleaned


# =====================================================================
# LAYER 1: EXACT MATCH CHECK
# =====================================================================

class ExactMatchCheck(BaseCheck):
    """Verbatim scanner for canary tokens and static decoy secrets."""

    def __init__(self):
        super().__init__(name="layer_1_exact")

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        start_time = time.perf_counter()
        targets: List[str] = context.exact_targets

        for target in targets:
            if target and target in model_output:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return CheckResult(
                    is_violation=True,
                    layer_name=self.name,
                    confidence=1.0,
                    matched_fragment=target,
                    reason=f"Verbatim leak detected: '{target[:12]}...'",
                    latency_ms=duration_ms,
                    metadata={"match_type": "exact_verbatim"},
                )

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return CheckResult(
            is_violation=False,
            layer_name=self.name,
            confidence=0.0,
            latency_ms=duration_ms,
        )


# =====================================================================
# LAYER 2: UNIVERSAL NORMALIZED MATCH CHECK
# =====================================================================

class NormalizedMatchCheck(BaseCheck):
    """
    Catches disguised leaks across both secret keys and sensitive policy terms.
    Un-scrambles delimiters, base64, hex, rot13, reversed strings, and leetspeak.
    """

    CORE_POLICY_ENTITIES = [
        "Project Zephyr",
        "BlueFalcon991",
        "180k to 240k",
    ]

    def __init__(self):
        super().__init__(name="layer_2_normalized")
        self._b64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        self._hex_pattern = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

    def _get_all_targets(self, context: SecurityContext) -> List[str]:
        """Combines dynamic canaries, decoy keys, and protected policy phrases."""
        all_targets = list(context.exact_targets)
        all_targets.extend(self.CORE_POLICY_ENTITIES)

        for chunk in context.protected_chunks:
            if len(chunk) <= 60 and chunk not in all_targets:
                all_targets.append(chunk)

        return list(set(all_targets))

    def _check_delimiter_and_dots(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        collapsed_text = TextNormalizer.strip_delimiters(text).lower()

        for target in targets:
            collapsed_target = TextNormalizer.strip_delimiters(target).lower()
            if collapsed_target and collapsed_target in collapsed_text:
                return target, "delimiter_collapsed"

        return None

    def _check_leetspeak(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        unleeted_text = TextNormalizer.undo_leetspeak(text)
        collapsed_unleeted = TextNormalizer.strip_delimiters(unleeted_text)

        for target in targets:
            unleeted_target = TextNormalizer.undo_leetspeak(target)
            clean_target = TextNormalizer.strip_delimiters(unleeted_target)
            if clean_target and len(clean_target) >= 4 and clean_target in collapsed_unleeted:
                return target, "leetspeak_decoded"

        return None

    def _check_base64(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        candidates = self._b64_pattern.findall(text)

        for candidate in candidates:
            try:
                missing = len(candidate) % 4
                padded = candidate + ("=" * (4 - missing) if missing else "")
                decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")

                for target in targets:
                    if target and target.lower() in decoded.lower():
                        return target, f"base64_decoded ({candidate[:10]}...)"
            except (binascii.Error, ValueError):
                continue

        return None

    def _check_hex(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        candidates = self._hex_pattern.findall(text)

        for candidate in candidates:
            try:
                decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
                for target in targets:
                    if target and target.lower() in decoded.lower():
                        return target, f"hex_decoded ({candidate[:10]}...)"
            except (ValueError, binascii.Error):
                continue

        return None

    def _check_rot13(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        rot13_text = codecs.decode(text, "rot_13").lower()

        for target in targets:
            if target and target.lower() in rot13_text:
                return target, "rot13_cipher"

        return None

    def _check_reversed(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        reversed_text = text[::-1].lower()

        for target in targets:
            if target and target.lower() in reversed_text:
                return target, "reversed_text"

        return None

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        start_time = time.perf_counter()
        targets = self._get_all_targets(context)

        pipeline = [
            ("delimiter_check", self._check_delimiter_and_dots),
            ("leetspeak_check", self._check_leetspeak),
            ("base64_check", self._check_base64),
            ("hex_check", self._check_hex),
            ("rot13_check", self._check_rot13),
            ("reversed_check", self._check_reversed),
        ]

        for check_name, check_fn in pipeline:
            result = check_fn(model_output, targets)
            if result:
                matched_target, transform = result
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return CheckResult(
                    is_violation=True,
                    layer_name=self.name,
                    confidence=1.0,
                    matched_fragment=matched_target,
                    reason=f"Normalized leak caught via '{transform}'",
                    latency_ms=duration_ms,
                    metadata={"transformation": transform, "check_step": check_name},
                )

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return CheckResult(
            is_violation=False,
            layer_name=self.name,
            confidence=0.0,
            latency_ms=duration_ms,
        )