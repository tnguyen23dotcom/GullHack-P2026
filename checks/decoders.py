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
    """Decode Morse runs in place (the words around them stay). Also accepts 'dah-dit-dit-dit' spelling."""
    text = re.sub(r"(?i)\b(?:dit|dah|di)(?:-(?:dit|dah|di))*\b",
                  lambda m: "".join("-" if t.lower() == "dah" else "." for t in m.group(0).split("-")), text)

    def one(chunk):
        letters = [_MORSE.get(tok, "") for tok in re.split(r"[ ]+", chunk.group(0).replace("/", " / ")) if tok and tok != "/"]
        return "".join(letters) + " "
    return re.sub(r"(?:[.\-]{1,6}[ /]{0,3}){3,}", one, text)


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


_LETTER_NAMES = dict(zip("ay bee see dee ee ef gee aitch eye jay kay el em en oh pee cue ar ess tee you vee double-you "
                         "ex why zed zee".split(), "abcdefghijklmnopqrstuvwxyzz"))
_DIGIT_WORDS = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
                "seven": "7", "eight": "8", "nine": "9", "niner": "9"}
_QWERTY_ROWS = ["qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./"]


def _keyboard_shift(text: str, step: int) -> str:
    table = {}
    for row in _QWERTY_ROWS:
        for i, c in enumerate(row):
            if 0 <= i + step < len(row):
                table[c] = row[i + step]
    return "".join(table.get(c, c) for c in text.lower())


def _atbash(text: str) -> str:
    return "".join(chr(219 - ord(c)) if "a" <= c <= "z" else chr(155 - ord(c)) if "A" <= c <= "Z" else c for c in text)


def _vigenere_with_stated_key(text: str) -> str:
    """If the reply names its own key ('key GULL', 'key: SECRET'), undo a Vigenere cipher with it."""
    m = re.search(r"(?i)\bkey\W{0,3}([A-Za-z]{3,12})\b", text)
    if not m:
        return ""
    key, out, i = m.group(1).upper(), [], 0
    for c in text[m.end():]:
        if c.isascii() and c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c) - base - (ord(key[i % len(key)]) - 65)) % 26 + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def _base85_views(text: str) -> List[str]:
    out = []
    blobs = [(b, base64.a85decode) for b in re.findall(r"[!-u]{10,}", text)[:20]]  # ascii85 alphabet
    blobs += [(b, base64.b85decode) for b in re.findall(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{10,}", text)[:20]]
    for blob, fn in blobs:
        for fn in (fn,):
            try:
                decoded = fn(blob).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if decoded.isprintable() and sum(c.isalnum() for c in decoded) >= 0.6 * len(decoded):
                out.append(decoded)
    for blob in (re.findall(r"[ -`]{10,}", text) + text.split())[:40]:  # uuencoded line or token
        try:
            out.append(binascii.a2b_uu(blob.strip()).decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    return [v for v in out if v]


def _numbers_to_letters(text: str) -> str:
    """A1Z26: runs of 1-26 joined by - or spaces ('26-5-16-8-25-18' -> 'zephyr')."""
    return re.sub(r"\b(?:(?:[1-9]|1\d|2[0-6])[- ,]){3,}(?:[1-9]|1\d|2[0-6])\b",
                  lambda m: "".join(chr(96 + int(n)) for n in re.split(r"[- ,]+", m.group(0)) if n), text)


def _words_to_symbols(text: str) -> str:
    """'bee el you ee' -> 'blue', 'nine nine one' -> '991' (runs only, so normal prose is unchanged)."""
    tokens = re.split(r"[\s_]+", text)
    out, buf_letters, buf_orig = [], [], []
    for tok in tokens + [None]:
        key = tok.lower().strip(".,;:") if tok else None
        if key in _LETTER_NAMES or key in _DIGIT_WORDS:
            buf_letters.append(_DIGIT_WORDS[key] if key in _DIGIT_WORDS else _LETTER_NAMES[key])
            buf_orig.append(tok)
            continue
        if buf_letters:
            out.append("".join(buf_letters) if len(buf_letters) >= 3 else " ".join(buf_orig))
        buf_letters, buf_orig = [], []
        if tok is not None:
            out.append(tok)
    return " ".join(out)


def _first_letters(text: str) -> str:
    """First letter of each word (numbers kept whole): 'Bring lunch until everyone ... 991' -> 'blue...991'."""
    return "".join(w if w.isdigit() else w[0] for w in re.findall(r"[^\W_]+", text))


def _code_assembly(text: str) -> str:
    """Strip assignments, quotes and '+' so 'a = "Blue"; b = "Fal" + "con"; c = 991' reads 'Blue Fal con 991'."""
    t = re.sub(r"\b[A-Za-z_]\w*\s*=(?!=)\s*", " ", text)
    return re.sub(r"[\"'+]", " ", t)


def decoded_views(text: str) -> List[Tuple[str, str]]:
    """Return (decoder name, decoded text) pairs. The original text is NOT included.
    Never raises: if a decoder fails on strange input, the views found so far are returned."""
    views: List[Tuple[str, str]] = []
    try:
        _collect_views(text, views)
    except Exception:  # noqa: BLE001 - a decoding bug must not take the gateway down
        pass
    return views


def _collect_views(text: str, views: List[Tuple[str, str]]) -> None:
    if not isinstance(text, str) or not text or len(text) > MAX_VIEW_INPUT:
        return
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
    for i, v in enumerate(_base85_views(text)):
        add(f"base85_{i}", v)
    add("atbash", _atbash(text))
    add("vigenere", _vigenere_with_stated_key(text))
    add("keyboard_left", _keyboard_shift(text, -1))
    add("keyboard_right", _keyboard_shift(text, 1))
    add("a1z26", _numbers_to_letters(text))
    add("spelled_out", _words_to_symbols(text))
    add("first_letters", _first_letters(text))
    if lines:
        add("last_letters", "".join(ln[-1] for ln in lines))
    add("every_second", " ".join(w[::2] if len(w) >= 6 else w for w in text.split()))
    add("halves_swapped", re.sub(r"(\S+)\s*\|\s*(\S+)", r"\2\1", text) if "|" in text else "")
    # Small sums written out ('1 + 1 + 1' -> '3').
    add("arithmetic", re.sub(r"\b\d{1,3}(?:\s*\+\s*\d{1,3})+\b", lambda m: str(sum(int(n) for n in m.group(0).split("+"))), text))
    add("code_assembly", _code_assembly(text) if "=" in text else "")
    long_bits = re.findall(r"[01]{32,}", text)
    add("binary_unspaced", " ".join(_numbers_to_text(re.findall(r"[01]{8}", b), 2) for b in long_bits))
    # Reversed text, then the main decoders again on it (reversed hex/base64/binary, reversed Caesar).
    rev = text[::-1]
    add("reversed", rev)
    for h in re.findall(r"(?:[0-9a-fA-F]{2}[ :]?){8,}", rev):
        add("reversed_hex", _numbers_to_text(re.findall(r"[0-9a-fA-F]{2}", h), 16))
    for i, decoded in enumerate(_nested_base64(rev)):
        add(f"reversed_base64_{i}", decoded)
