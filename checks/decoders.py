"""
checks/decoders.py - "Decoded views" of a reply, shared by Layer 2 (normalized) and Layer 2b (facts).

Why: a leak can be hidden in many reversible encodings. Instead of each layer knowing every trick,
this module turns one reply into a list of candidate decodings ("views"). Each layer then looks for
secrets in every view. A view that is just noise is harmless: the layers still need a full secret
(Layer 2) or two policy facts together (Layer 2b) before flagging anything.

Covered: base64 (also nested), base32, hex, binary, octal, URL and HTML entities, \\uXXXX escapes,
ROT47, Morse code, the NATO alphabet, upside-down text, words written backwards, pig latin,
acrostics (first letter of each line), vertical text (one letter per line), and secrets split into
"part 1 / part 2". Every decoder is bounded so a long reply cannot make this slow.
"""

import base64
import binascii
import html
import re
import urllib.parse
from typing import List, Tuple

MAX_VIEW_INPUT = 20000

_MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h", "..": "i",
    ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}
_NATO = {w: w[0] for w in ("alfa alpha bravo charlie delta echo foxtrot golf hotel india juliett juliet kilo lima mike "
                           "november oscar papa quebec romeo sierra tango uniform victor whiskey xray x-ray yankee zulu").split()}
_NATO.update({"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7",
              "eight": "8", "nine": "9", "niner": "9"})
# Upside-down letters back to normal (read after reversing the string).
_FLIP = str.maketrans({"ɐ": "a", "q": "b", "ɔ": "c", "p": "d", "ǝ": "e", "ɟ": "f", "Ⅎ": "f", "ƃ": "g", "ɥ": "h", "ı": "i",
                       "ɾ": "j", "ʞ": "k", "ɯ": "m", "u": "n", "d": "p", "b": "q", "ɹ": "r", "ʇ": "t", "n": "u", "ʌ": "v",
                       "ʍ": "w", "ʎ": "y", "6": "9", "9": "6", "Ɩ": "1", "ᄅ": "2", "Ɛ": "3", "ㄣ": "4", "ϛ": "5", "ㄥ": "7"})
_VOWELS = set("aeiou")


def _b64(candidate: str) -> str:
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        return base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return ""


def _nested_base64(text: str) -> List[str]:
    """Decode base64 blobs, and blobs inside the decoded text, up to 3 levels deep."""
    out, frontier = [], [text]
    for _ in range(3):
        nxt = []
        for t in frontier:
            for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", t)[:20]:
                decoded = _b64(blob)
                if decoded and decoded.isprintable():
                    out.append(decoded)
                    nxt.append(decoded)
        frontier = nxt
    return out


def _numbers_to_text(groups: List[str], base: int) -> str:
    try:
        return bytes(int(g, base) for g in groups).decode("utf-8", errors="ignore")
    except ValueError:
        return ""


def _morse(text: str) -> str:
    words = []
    for chunk in re.findall(r"(?:[.\-]{1,6}[ /]{0,3}){3,}", text):
        letters = [_MORSE.get(tok, "") for tok in re.split(r"[ ]+", chunk.replace("/", " / ")) if tok and tok != "/"]
        words.append("".join(letters))
    return " ".join(words)


def _nato(text: str) -> str:
    tokens = re.findall(r"[a-z\-]+", text.lower())
    out, run = [], []
    for tok in tokens + [""]:
        if tok in _NATO:
            run.append(_NATO[tok])
        else:
            if len(run) >= 4:
                out.append("".join(run))
            run = []
    return " ".join(out)


def _pig_latin_variants(text: str) -> List[str]:
    """Undo pig latin: strip 'way'/'ay' and move the last 1-3 letters back to the front."""
    words = text.lower().split()
    if sum(w.strip(".,").endswith("ay") for w in words) < 3:
        return []
    views = []
    for k in (1, 2, 3):
        decoded = []
        for w in words:
            core = w.strip(".,")
            if core.endswith("way") and core[:1] in _VOWELS:
                decoded.append(core[:-3])
            elif core.endswith("ay") and len(core) > 2 + k:
                stem = core[:-2]
                decoded.append(stem[-k:] + stem[:-k])
            else:
                decoded.append(core)
        views.append(" ".join(decoded))
    return views


def decoded_views(text: str) -> List[Tuple[str, str]]:
    """Return (decoder name, decoded text) pairs. The original text is NOT included."""
    if not isinstance(text, str) or not text or len(text) > MAX_VIEW_INPUT:
        return []
    views: List[Tuple[str, str]] = []
    add = lambda name, value: views.append((name, value)) if value and value != text else None  # noqa: E731

    add("url", urllib.parse.unquote(text) if "%" in text else "")
    add("html_entities", html.unescape(text) if "&" in text else "")
    add("unicode_escapes", re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text) if "\\u" in text else "")
    for i, decoded in enumerate(_nested_base64(text)):
        add(f"base64_{i}", decoded)
    bits = re.findall(r"\b[01]{8}\b", text)
    add("binary", _numbers_to_text(bits, 2) if len(bits) >= 4 else "")
    octal = re.findall(r"\b[0-3][0-7]{2}\b", text)
    add("octal", _numbers_to_text(octal, 8) if len(octal) >= 4 and len(octal) * 4 >= len(text.split()) else "")
    hex_pairs = re.findall(r"\b(?:[0-9a-fA-F]{2}[ :]?){8,}\b", text)
    add("hex", " ".join(_numbers_to_text(re.findall(r"[0-9a-fA-F]{2}", h), 16) for h in hex_pairs))
    add("rot47", "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text))
    add("morse", _morse(text))
    add("nato", _nato(text))
    add("upside_down", text[::-1].translate(_FLIP))
    add("words_reversed", " ".join(w[::-1] for w in text.split()))
    for i, v in enumerate(_pig_latin_variants(text)):
        add(f"pig_latin_{i}", v)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 4:
        add("acrostic", "".join(ln[0] for ln in lines))
        # Vertical text: runs of one-character lines joined into a word.
        add("vertical", re.sub(r"(?:(?<=\n)|^)(\S)\n(?=\S\n|\S$)", r"\1", "\n".join(lines)).replace("\n", " "))
    add("parts_joined", re.sub(r"(?i)\b(?:part|piece|chunk|segment)\s*\d+\s*[:\-]?", "", text) if re.search(r"(?i)\b(?:part|piece|chunk|segment)\s*\d", text) else "")
    return views
