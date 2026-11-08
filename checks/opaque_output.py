"""
Layer 2c - Opaque output check: withhold replies that carry UNREADABLE ENCODED DATA.

Why: Layers 2 and 2b only catch encodings they know how to decode. An attacker can always pick a new
one (base85, a cipher, a list of character codes...). An IT help-desk bot almost never needs to send
long runs of codes or random-looking strings, so instead of decoding every scheme, this layer
fails closed: if a reply contains a block of opaque data, the reply is withheld.

It does NOT look at the secrets at all, so it cannot leak them, and it works for encodings nobody
has seen yet. The cost is that a harmless reply full of codes (e.g. a long hash) is also withheld;
that trade-off is measured on the harmless replies in eval/.

Flags a reply when ANY of these is found:
  1. a run of >= 10 code-like tokens (numbers, 0x41, \\x41, =41, %41, &#65;, 01000001, U+0041...)
  2. one stretch of >= 8 back-to-back escape sequences (\\x73\\x6b..., =42=6C..., %25%34...)
  3. a random-looking token of >= 20 characters (mixes upper case, lower case, digits or symbols,
     and is not a URL, path, e-mail or normal hyphenated word)
  4. >= 8 consecutive very short lines (<= 4 characters) - text written vertically or in chunks
  5. >= 5 characters from symbol alphabets used to spell text (braille, flag letters, Ogham, runes)
  6. a run of >= 10 one-character tokens (s p a c e d  o u t)
"""

import re
import time
import unicodedata

from checks.check_interface import BaseCheck, CheckResult, SecurityContext

MAX_SCAN_CHARS = 20000

_CODE_TOKEN = re.compile(
    r"^(?:0x[0-9a-f]{1,4}|\\x[0-9a-f]{2}|=[0-9a-f]{2}|%[0-9a-f]{2}|&#x?[0-9a-f]{1,6};?|u\+[0-9a-f]{4}|\\u[0-9a-f]{4}"
    r"|[01]{8})$", re.IGNORECASE)
_DECIMAL = re.compile(r"^\d{2,3}$")  # plain numbers count only in the printable-character range 32-255
_ESCAPE_RUN = re.compile(r"(?:\\x[0-9a-f]{2}|=[0-9a-f]{2}|%[0-9a-f]{2}|&#x?[0-9a-f]{1,6};|\\u[0-9a-f]{4}){8,}", re.IGNORECASE)
_TOKEN_SPLIT = re.compile(r"[\s,;()\[\]{}\"'`|]+")
_SYMBOL_ALPHABETS = [(0x2800, 0x28FF), (0x1F1E6, 0x1F1FF), (0x1680, 0x169F), (0x16A0, 0x16FF)]


def _looks_random(token: str) -> bool:
    """A long token that mixes character classes like base64/base85/keys, not a URL or a normal word."""
    core = token.replace("*", "").strip(".,:;!?()[]{}<>\"'")
    if len(core) < 20 or "://" in core or "@" in core or "/" in core.strip("/") and core.count("/") >= 2:
        return False
    if re.fullmatch(r"[A-Za-z]+(?:[-_./:][A-Za-z]+)*", core):  # long-but-normal words like 'well-known-feature'
        return False
    classes = sum([any(c.islower() for c in core), any(c.isupper() for c in core), any(c.isdigit() for c in core),
                   any(not c.isalnum() for c in core)])
    switches = sum(1 for a, b in zip(core, core[1:]) if a.isdigit() != b.isdigit() or a.isupper() != b.isupper())
    return classes >= 3 and switches >= len(core) // 4


def opaque_reason(text: str):
    """Return a short reason string if the text contains opaque encoded data, else None."""
    if not text:
        return None
    tokens = [t for t in _TOKEN_SPLIT.split(text) if t]
    run = best = 0
    for t in tokens:
        t = t.rstrip(".:")
        is_code = _CODE_TOKEN.match(t) or (_DECIMAL.match(t) and 32 <= int(t) <= 255)
        run = run + 1 if is_code else 0
        best = max(best, run)
    if best >= 10:
        return "run of character codes"
    if _ESCAPE_RUN.search(text):
        return "run of escape sequences"
    if any(_looks_random(t) for t in tokens):
        return "random-looking encoded string"
    lines = [ln.strip() for ln in text.splitlines()]
    run = 0
    for ln in lines:
        run = run + 1 if 0 < len(ln) <= 4 else (run if not ln else 0)
        if run >= 8:
            return "text written vertically or in chunks"
    if sum(any(lo <= ord(c) <= hi for lo, hi in _SYMBOL_ALPHABETS) for c in text) >= 5:
        return "symbol alphabet (braille, flag letters, runes)"
    run = 0
    for t in tokens:
        run = run + 1 if len(t) == 1 else 0
        if run >= 10:
            return "spaced-out single characters"
    return None


class OpaqueOutputCheck(BaseCheck):
    """Fails closed on replies that contain unreadable encoded data (any encoding, known or not)."""

    def __init__(self):
        super().__init__(name="layer_2c_opaque_output")

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        start = time.perf_counter()
        text = unicodedata.normalize("NFC", model_output or "")
        reason = "reply too long to scan safely" if len(text) > MAX_SCAN_CHARS else opaque_reason(text)
        return CheckResult(
            is_violation=reason is not None,
            layer_name=self.name,
            confidence=0.8 if reason else 0.0,
            matched_fragment=None,  # never copy the data into logs
            reason=f"Reply contains opaque encoded data ({reason})" if reason else None,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            metadata={"opaque_rule": reason} if reason else {},
        )
