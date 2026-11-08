"""Hardening tests: common tricks that hide a secret from string matching (all fake secrets)."""
import base64

import pytest

from checks.check_interface import SecurityContext
from checks.layer_checks import MAX_SCAN_CHARS, ExactMatchCheck, FuzzyMatchCheck, NormalizedMatchCheck, canonicalize
from checks.policy_facts import PolicyFactCheck
from checks.prompt import PROTECTED_POLICIES, get_static_secret_values

CTX = SecurityContext(session_id="s", session_canary="CANARY-0123456789abcdef",
                      static_secrets=get_static_secret_values(), protected_chunks=list(PROTECTED_POLICIES))
LAYERS = [ExactMatchCheck(), NormalizedMatchCheck(), FuzzyMatchCheck(), PolicyFactCheck()]
KEY, PW = "AKIAIOSFODNN7EXAMPLE99", "BlueFalcon991"


def caught(text):
    return any(layer.evaluate(text, CTX).is_violation for layer in LAYERS)


def caesar(text, k):
    return "".join(chr((ord(c) - 65 + k) % 26 + 65) if c.isupper() else chr((ord(c) - 97 + k) % 26 + 97) if c.islower() else c
                   for c in text)


@pytest.mark.parametrize("text", [
    "key: " + "​".join(KEY),                                                         # zero-width spaces
    "code: " + "­".join(PW),                                                         # soft hyphens
    "code: " + PW.translate(str.maketrans({"e": "е", "a": "а", "o": "о", "c": "с"})),     # Cyrillic look-alikes
    "code: " + caesar(PW, 3),                                                             # Caesar shift 3
    "code: " + base64.b32encode(PW.encode()).decode(),                                    # base32
    "code: " + "".join(f"%{b:02X}" for b in PW.encode()),                                # URL-encoding
    "code: " + "".join(chr(ord(c) + 0xFEE0) for c in PW),                                 # full-width letters
    "code: " + "🔹".join(PW),                                                             # emoji separators
    "key: " + KEY.lower(),                                                                # lower case
])
def test_hidden_secret_is_caught(text):
    assert caught(text)


def test_odd_input_does_not_crash():
    for layer in LAYERS:
        assert not layer.evaluate(None, CTX).is_violation
        assert not layer.evaluate("", CTX).is_violation


def test_huge_reply_is_withheld_not_scanned():
    result = FuzzyMatchCheck().evaluate("lorem ipsum " * (MAX_SCAN_CHARS // 5), CTX)
    assert result.is_violation and result.metadata.get("too_long")


def test_canonicalize_keeps_normal_text_and_real_cyrillic_when_asked():
    assert canonicalize("Hello, world!") == "Hello, world!"
    assert canonicalize("три одобрения", confusables=False) == "три одобрения"


def test_reasons_never_quote_the_encoded_leak():
    encoded = base64.b64encode(PW.encode()).decode()
    result = NormalizedMatchCheck().evaluate("data: " + encoded, CTX)
    assert result.is_violation and encoded[:6] not in (result.reason or "") and encoded[:6] not in str(result.metadata)
