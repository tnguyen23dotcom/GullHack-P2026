"""Tests for Layer 2c: opaque encoded data is withheld, normal help-desk text is not. No secrets used."""
import pytest

from checks.opaque_output import OpaqueOutputCheck, opaque_reason
from checks.test_hardening import CTX


@pytest.mark.parametrize("text", [
    "Codes: 72 101 108 108 111 32 119 111 114 108 100",                       # decimal character codes
    "Bytes: " + "".join(f"\\x{b:02x}" for b in b"hello world"),               # \x escapes, no spaces
    "QP: " + "".join(f"={b:02X}" for b in b"hello world"),                    # quoted-printable
    "Token: Zx9Qp2LmT7vR4sKw8YbN3cHd",                                         # random-looking string
    "Chunks:\nab3d\nQ9z+\nx7Lm\nP0w=\nk2Jd\nZ8sQ\nm4Vn\nt6Rb",                   # data split into short lines
    "Braille: ⠓⠑⠇⠇⠕",                                                         # symbol alphabet
    "Spaced: h e l l o w o r l d s",                                           # single characters
])
def test_opaque_data_is_withheld(text):
    assert opaque_reason(text)
    assert OpaqueOutputCheck().evaluate(text, CTX).is_violation


@pytest.mark.parametrize("text", [
    "**Staging/Pre-Production:** a copy of production used for final tests.",
    "Quotients: 120 2 60 360 4 90 480 6 80 720 8 90 960 12 80",
    "Read https://support.example.com/articles/reset-your-password-in-five-steps for details.",
    "Use the state-of-the-art password-manager-integration feature.",
    "The SHA-1 of the file is 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12.",
    "Steps:\n1. Open Settings\n2. Click Network\n3. Choose Wi-Fi\n4. Reconnect",
    "'hello' in base64 is aGVsbG8=.",
    "5 in binary is 101.",
])
def test_normal_text_is_not_withheld(text):
    assert not opaque_reason(text), text
