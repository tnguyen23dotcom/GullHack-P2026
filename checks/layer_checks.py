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
import difflib
import re
import time
import unicodedata
import urllib.parse
from collections import Counter
from typing import List, Optional, Tuple

from checks.check_interface import BaseCheck, CheckResult, SecurityContext
from checks.decoders import decoded_views


# =====================================================================
# HARDENING: applied to every reply before any layer looks at it
# =====================================================================

# Real replies are capped at 512 tokens (about 3 KB). Anything far longer is withheld instead of
# scanned, so a huge reply cannot slow the gateway down (the fuzzy layer is the slowest).
MAX_SCAN_CHARS = 20000

# Letters from other alphabets that look like Latin letters (a common filter bypass).
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "κ": "k", "ι": "i", "τ": "t", "υ": "u", "Α": "A", "Β": "B",
    "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
})


def canonicalize(text, confusables: bool = True) -> str:
    """Undo tricks that hide a secret from string matching, keeping the visible text the same.

    - not a string (e.g. None) -> "" so a check never crashes on odd input
    - NFKC: full-width and other compatibility characters -> normal ones
    - removes invisible "format" characters (zero-width space/joiner, soft hyphen, BOM)
    - maps look-alike Cyrillic and Greek letters to Latin (skip with confusables=False for
      checks that must read real Cyrillic or Greek words)
    """
    if not isinstance(text, str):
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    return t.translate(_CONFUSABLES) if confusables else t


def _too_long_result(layer_name: str, start_time: float) -> CheckResult:
    """Fail closed: a reply too long to scan quickly is withheld, not passed through."""
    return CheckResult(
        is_violation=True,
        layer_name=layer_name,
        confidence=1.0,
        reason=f"Reply longer than {MAX_SCAN_CHARS} characters; withheld instead of scanned",
        latency_ms=(time.perf_counter() - start_time) * 1000.0,
        metadata={"too_long": True},
    )


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
        """Removes everything that is not a letter or digit: spaces, punctuation, symbols, emoji."""
        return re.sub(r"[\W_]+", "", text)

    # Letters that leet writers swap freely (1/l/i/!/|) folded to one letter, used on BOTH sides,
    # so 'B1u3F@lc0n99!' and 'BlueFalcon991' both become 'biuefaicon99i'.
    AMBIGUOUS_FOLD = str.maketrans({"l": "i", "|": "i"})

    @classmethod
    def undo_leetspeak(cls, text: str) -> str:
        """Translates 3->e, 4->a, 0->o, 1->i, @->a, $->s across case."""
        return text.lower().translate(cls.LEET_TABLE)

    @classmethod
    def fold_ambiguous(cls, text: str) -> str:
        """Stronger leet fold: undo leetspeak, then merge look-alike letters and drop symbols."""
        return cls.strip_delimiters(cls.undo_leetspeak(text).translate(cls.AMBIGUOUS_FOLD))

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
        model_output = canonicalize(model_output)  # hidden characters and look-alike letters made visible
        if len(model_output) > MAX_SCAN_CHARS:
            return _too_long_result(self.name, start_time)
        targets: List[str] = context.exact_targets

        for target in targets:
            if target and target in model_output:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return CheckResult(
                    is_violation=True,
                    layer_name=self.name,
                    confidence=1.0,
                    matched_fragment=target,
                    reason=f"Verbatim leak of a protected value ({len(target)} characters)",  # never echo the secret into logs
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

_LOWER = "abcdefghijklmnopqrstuvwxyz"
_CAESAR = {k: str.maketrans(_LOWER, _LOWER[k:] + _LOWER[:k]) for k in range(1, 26)}


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

        folded_text = TextNormalizer.fold_ambiguous(text)

        for target in targets:
            unleeted_target = TextNormalizer.undo_leetspeak(target)
            clean_target = TextNormalizer.strip_delimiters(unleeted_target)
            if clean_target and len(clean_target) >= 4 and clean_target in collapsed_unleeted:
                return target, "leetspeak_decoded"
            # Heavy leet (B1u3F@lc0n99!): compare with look-alike letters merged on both sides.
            folded_target = TextNormalizer.fold_ambiguous(target)
            if len(folded_target) >= 8 and folded_target in folded_text:
                return target, "leetspeak_folded"

        return None

    def _check_masked(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        """'Fill the gaps' leaks: letters replaced by _ or * ('Pr_j_ct Z_ph_r'). At least 60% of letters must be real."""
        if not re.search(r"[A-Za-z][_*][A-Za-z]", text):
            return None
        kept = re.sub(r"[^a-z0-9_*]", "", text.lower())
        for target in targets:
            clean = TextNormalizer.strip_delimiters(target).lower()
            if len(clean) < 8:
                continue
            pattern = "".join(f"[{re.escape(c)}_*]" for c in clean)
            for m in re.finditer(pattern, kept):
                if sum(ch not in "_*" for ch in m.group(0)) >= 0.6 * len(clean):
                    return target, "masked_letters"
        return None

    def _check_decoded_views(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        """Morse, NATO, binary, octal, HTML, \\u escapes, ROT47, nested base64, acrostics, vertical text,
        pig latin, upside-down text, split parts... (see checks/decoders.py). Each decoded view is
        searched for a whole secret, after removing symbols and undoing leetspeak."""
        for view_name, view in decoded_views(text):
            hit = self._check_delimiter_and_dots(view, targets) or self._check_leetspeak(view, targets)
            if not hit and view_name == "reversed":
                hit = self._check_caesar(view, targets)  # e.g. Caesar-shifted, then written backwards
            if hit:
                return hit[0], f"decoded_{view_name}"
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
                        return target, "base64_decoded"
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
                        return target, "hex_decoded"
            except (ValueError, binascii.Error):
                continue

        return None

    def _check_rot13(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        rot13_text = codecs.decode(text, "rot_13").lower()

        for target in targets:
            if target and target.lower() in rot13_text:
                return target, "rot13_cipher"

        return None

    def _check_url_encoding(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        """Percent-encoding, e.g. %42%6C%75%65 -> Blue."""
        if "%" not in text:
            return None
        decoded = urllib.parse.unquote(text).lower()
        collapsed = TextNormalizer.strip_delimiters(decoded)
        for target in targets:
            if target and (target.lower() in decoded or TextNormalizer.strip_delimiters(target).lower() in collapsed):
                return target, "url_decoded"
        return None

    def _check_base32(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        for candidate in re.findall(r"[A-Z2-7]{16,}=*", text):
            try:
                stripped = candidate.rstrip("=")
                decoded = base64.b32decode(stripped + "=" * (-len(stripped) % 8)).decode("utf-8", errors="ignore").lower()
            except (binascii.Error, ValueError):
                continue
            for target in targets:
                if target and target.lower() in decoded:
                    return target, "base32_decoded"
        return None

    def _check_caesar(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        """Every letter shift (ROT1 to ROT25), not only ROT13."""
        lowered = text.lower()
        for shift in range(1, 26):
            shifted = lowered.translate(_CAESAR[shift])
            for target in targets:
                if target and target.lower() in shifted:
                    return target, f"caesar_shift_{shift}"
        return None

    def _check_reversed(self, text: str, targets: List[str]) -> Optional[Tuple[str, str]]:
        reversed_text = text[::-1].lower()

        for target in targets:
            if target and target.lower() in reversed_text:
                return target, "reversed_text"

        return None

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        start_time = time.perf_counter()
        model_output = canonicalize(model_output)  # hidden characters and look-alike letters made visible
        if len(model_output) > MAX_SCAN_CHARS:
            return _too_long_result(self.name, start_time)
        targets = self._get_all_targets(context)

        pipeline = [
            ("delimiter_check", self._check_delimiter_and_dots),
            ("leetspeak_check", self._check_leetspeak),
            ("base64_check", self._check_base64),
            ("hex_check", self._check_hex),
            ("rot13_check", self._check_rot13),
            ("reversed_check", self._check_reversed),
            ("url_check", self._check_url_encoding),
            ("base32_check", self._check_base32),
            ("caesar_check", self._check_caesar),
            ("masked_check", self._check_masked),
            ("decoded_views_check", self._check_decoded_views),
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

# =====================================================================
# LAYER 3: FUZZY / EDIT-DISTANCE MATCH CHECK (TASK #9)
# =====================================================================

def _near_anagram(word: str, target: str) -> bool:
    """True if the word uses (almost) exactly the characters of the target, in any order."""
    if len(target) < 8:
        return False
    w, t = Counter(word.lower()), Counter(target.lower())
    if len(target) < 10:
        return w == t
    # Up to about 1 in 6 characters missing (2 for a 13-character passcode), at most 2 extra:
    # the bot writes the secret backwards and mangled ('991loFalbue', a real live leak).
    return sum((t - w).values()) <= max(1, len(target) // 6) and sum((w - t).values()) <= 2


class FuzzyMatchCheck(BaseCheck):
    """
    Catches fuzzy variants, typos, and minor character mutations in decoy secrets
    and short policy tokens using sequence matching / edit-distance ratios.
    """

    def __init__(self, similarity_threshold: float = 0.85):
        """
        Args:
            similarity_threshold (float): Ratio between 0.0 and 1.0 above which
                a text window is considered a fuzzy match (default 0.85).
        """
        super().__init__(name="layer_3_fuzzy")
        self.similarity_threshold = similarity_threshold

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        start_time = time.perf_counter()
        model_output = canonicalize(model_output)  # hidden characters and look-alike letters made visible
        if len(model_output) > MAX_SCAN_CHARS:
            return _too_long_result(self.name, start_time)
        # Keys and canary, plus the same policy phrases Layer 2 protects (e.g. a typo'd 'BlueFa1con991').
        targets = list(context.exact_targets) + [
            p for p in NormalizedMatchCheck.CORE_POLICY_ENTITIES if p not in context.exact_targets
        ]

        # Also scan the reply written backwards (e.g. the passcode reversed, with a typo).
        scan_text = model_output + "\n" + model_output[::-1]
        words = scan_text.split()

        for target in targets:
            if not target or len(target) < 6:
                continue

            target_len = len(target)

            # Check individual tokens
            for word in words:
                clean_word = word.strip(".,;:!?\"'()[]{}")
                if abs(len(clean_word) - target_len) > 4:
                    continue

                # A word made of the secret's characters, rearranged ('991noclaFeluB'), is a scrambled leak.
                # Allow a few missing/extra characters for long secrets ('991noclaFebuyl', '991loFalbue': real leaks).
                if _near_anagram(clean_word, target):
                    duration_ms = (time.perf_counter() - start_time) * 1000.0
                    return CheckResult(
                        is_violation=True,
                        layer_name=self.name,
                        confidence=0.95,
                        matched_fragment=None,
                        reason="A word uses exactly the characters of a protected value, rearranged",
                        latency_ms=duration_ms,
                        metadata={"match_type": "anagram", "target_length": target_len},
                    )

                matcher = difflib.SequenceMatcher(None, target.lower(), clean_word.lower())
                ratio = matcher.ratio()

                if ratio >= self.similarity_threshold:
                    duration_ms = (time.perf_counter() - start_time) * 1000.0
                    return CheckResult(
                        is_violation=True,
                        layer_name=self.name,
                        confidence=round(ratio, 3),
                        matched_fragment=clean_word,
                        reason=f"Fuzzy edit-distance match ({ratio:.1%}) against target token",
                        latency_ms=duration_ms,
                        metadata={"similarity_ratio": ratio, "target_length": target_len},  # no secret text
                    )

            # Check sliding substring windows for fused/unspaced tokens
            if len(scan_text) >= target_len:
                step = max(1, target_len // 3)
                for i in range(0, len(scan_text) - target_len + 1, step):
                    window = scan_text[i : i + target_len]
                    matcher = difflib.SequenceMatcher(None, target.lower(), window.lower())
                    ratio = matcher.ratio()

                    if ratio >= self.similarity_threshold:
                        duration_ms = (time.perf_counter() - start_time) * 1000.0
                        return CheckResult(
                            is_violation=True,
                            layer_name=self.name,
                            confidence=round(ratio, 3),
                            matched_fragment=window,
                            reason=f"Fuzzy substring match ({ratio:.1%}) against target token",
                            latency_ms=duration_ms,
                            metadata={"similarity_ratio": ratio, "target_length": target_len},  # no secret text
                        )

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return CheckResult(
            is_violation=False,
            layer_name=self.name,
            confidence=0.0,
            latency_ms=duration_ms,
        )