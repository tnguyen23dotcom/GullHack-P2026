"""Split the protected system prompt into small chunks (issue #12).

Why chunks? The semantic check (#13) compares each sentence of a chatbot reply with
pieces of the protected prompt. If we embedded the whole prompt as one vector, a reply
that leaks just one rule would look only slightly similar to it. One rule per chunk
makes a leak of any single rule easy to see.

Rules used here (kept simple on purpose):
  - skip blank lines and "#" headings
  - skip the line holding the per-session canary placeholder: the exact-match layer
    already catches the canary, and a random token has no meaning to embed
  - remove bullet markers like "- " or "1. "
  - split each line into sentences; glue very short sentences onto the previous one
"""
import hashlib
import re

CANARY_PLACEHOLDER = "{{CANARY}}"  # TODO(#6): confirm this is the placeholder Person B uses
MIN_WORDS = 4                      # a sentence shorter than this is glued to its neighbour

# Split after . ! ? when followed by whitespace. Good enough for our rule-style prompt.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_BULLET = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+")


def prompt_sha256(text):
    """Fingerprint of the prompt, so we can tell if saved embeddings are out of date."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sentences(line):
    """Split one line into sentences, merging very short ones into the previous one."""
    pieces = [s.strip() for s in _SENTENCE_END.split(line) if s.strip()]
    merged = []
    for piece in pieces:
        if merged and len(piece.split()) < MIN_WORDS:
            merged[-1] += " " + piece
        else:
            merged.append(piece)
    # A short first piece (for example "Hi.") has nothing before it: glue it forward.
    if len(merged) > 1 and len(merged[0].split()) < MIN_WORDS:
        merged[1] = merged[0] + " " + merged[1]
        merged = merged[1:]
    return merged


def chunk_prompt(text):
    """Return a list of chunks: {"id": "chunk-001", "line": <line number>, "text": "..."}."""
    chunks = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue  # blank line or heading
        if CANARY_PLACEHOLDER in line:
            continue  # the exact-match layer handles the canary
        line = _BULLET.sub("", line)
        for sentence in _sentences(line):
            chunks.append({"id": f"chunk-{len(chunks) + 1:03d}", "line": line_number, "text": sentence})
    return chunks
