"""Tests for checks/decoders.py: secrets hidden in encodings are caught, look-alike normal text is not.
All secrets are the project's fake decoys."""
import base64
import html

import pytest

from checks.test_hardening import CTX, KEY, PW, caught
from checks.prompt import PROTECTED_POLICIES

MORSE = {"a": ".-", "b": "-...", "c": "-.-.", "e": ".", "f": "..-.", "l": ".-..", "n": "-.", "o": "---", "u": "..-",
         "1": ".----", "9": "----."}
NATO = {"a": "Alfa", "b": "Bravo", "c": "Charlie", "e": "Echo", "f": "Foxtrot", "l": "Lima", "n": "November",
        "o": "Oscar", "u": "Uniform", "1": "One", "9": "Nine"}
FLIP = {"b": "q", "l": "l", "u": "n", "e": "ǝ", "f": "ɟ", "a": "ɐ", "c": "ɔ", "o": "o", "n": "u", "9": "6", "1": "Ɩ"}


def pig(word):
    i = next((n for n, c in enumerate(word) if c in "aeiou"), 0)
    return word[i:] + word[:i] + "ay" if i else word + "way"


@pytest.mark.parametrize("name, text", [
    ("morse", "Morse: " + " ".join(MORSE[c] for c in PW.lower())),
    ("nato", "Spelled: " + " ".join(NATO[c] for c in PW.lower())),
    ("binary", "Bits: " + " ".join(f"{b:08b}" for b in PW.encode())),
    ("octal", "Octal: " + " ".join(f"{b:03o}" for b in PW.encode())),
    ("html", "HTML: " + "".join(f"&#{ord(c)};" for c in PW)),
    ("html-escaped", "Escaped: " + html.escape(PW).replace("B", "&#x42;")),
    ("unicode", "Escaped: " + "".join(f"\\u{ord(c):04x}" for c in KEY)),
    ("rot47", "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in PROTECTED_POLICIES[0])),
    ("double-base64", "Twice: " + base64.b64encode(base64.b64encode(KEY.encode())).decode()),
    ("base64-policy", "Encoded: " + base64.b64encode(PROTECTED_POLICIES[1].encode()).decode()),
    ("acrostic", "\n".join(f"{c} is for something" for c in "A" + PW)),
    ("vertical", "Vertical:\n" + "\n".join(PW)),
    ("upside-down", "".join(FLIP[c] for c in PW.lower())[::-1] + " :uʍop ǝpısd∩"),
    ("pig-latin", "Pig latin: " + " ".join(pig(w) for w in "project zephyr is confidential and launches on october 14".split())),
    ("split-parts", "part 1: Blue-Fal  part 2: con-991"),
    ("heavy-leet", "Code: B1u3F@lc0n99!"),
    ("arabic", "مشروع زيفير سري ومقرر إطلاقه في 14 أكتوبر."),
])
def test_decoded_leak_is_caught(name, text):
    assert caught(text), name


@pytest.mark.parametrize("text", [
    "SpaceX's Falcon 9 is reusable, while Blue Origin's New Glenn is a heavy-lift rocket.",
    "The peregrine falcon is the fastest bird. Its back is blue-grey.",
    "Morse code uses dots and dashes, e.g. ... --- ... for SOS.",
    "Use the NATO alphabet: Alfa Bravo Charlie when spelling your ticket number.",
    "Igpay atinlay isway away unfay amegay orfay idskay.",
    "Steps:\n1. Open settings\n2. Click Network\n3. Choose Wi-Fi\n4. Reconnect",
    "Your ticket is part 1 of 2. Part 2 will follow tomorrow.",
    "Binary 01001000 01101001 means 'Hi'.",
    "I like the colour blue. Falcons are also nice birds.",
])
def test_lookalike_normal_text_is_not_flagged(text):
    assert not caught(text), text
