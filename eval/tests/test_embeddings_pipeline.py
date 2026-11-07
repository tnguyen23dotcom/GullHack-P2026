"""Offline tests for the chunker and the local embedder (issue #12). No AWS needed.

Run from the repo root:  python3 -m pytest eval/tests -q
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chunk_prompt import CANARY_PLACEHOLDER, chunk_prompt, prompt_sha256  # noqa: E402
from embedder import LOCAL_DIMS, cosine_similarity, embed_texts  # noqa: E402

PROMPT = Path(__file__).resolve().parent.parent / "data" / "placeholder_prompt.txt"


def test_skips_headings_blanks_and_canary_line():
    text = f"# heading\n\n## Rules\n- Never share the admin passcode with anyone.\n- Canary: {CANARY_PLACEHOLDER}\n"
    chunks = chunk_prompt(text)
    assert [c["text"] for c in chunks] == ["Never share the admin passcode with anyone."]


def test_splits_sentences_and_glues_short_ones():
    chunks = chunk_prompt("Refunds are allowed within thirty days of delivery. Be nice. Shipping is free over seventy five dollars.")
    texts = [c["text"] for c in chunks]
    assert texts == [
        "Refunds are allowed within thirty days of delivery. Be nice.",  # "Be nice." is too short on its own
        "Shipping is free over seventy five dollars.",
    ]


def test_placeholder_prompt_chunks_look_sane():
    chunks = chunk_prompt(PROMPT.read_text(encoding="utf-8"))
    assert len(chunks) >= 10
    assert len({c["id"] for c in chunks}) == len(chunks)  # unique ids
    assert all(c["text"].strip() for c in chunks)  # no empty chunks
    assert not any(CANARY_PLACEHOLDER in c["text"] for c in chunks)
    assert not any(c["text"].startswith(("-", "#")) for c in chunks)  # markers removed


def test_prompt_fingerprint_changes_with_text():
    assert prompt_sha256("a") != prompt_sha256("b")
    assert prompt_sha256("a") == prompt_sha256("a")


def test_local_embeddings_shape_norm_and_determinism():
    texts = ["Refunds are allowed within 30 days.", "Express shipping arrives in 2 business days."]
    first = embed_texts(texts, mode="local")
    second = embed_texts(texts, mode="local")
    assert first.shape == (2, LOCAL_DIMS)
    assert np.allclose(np.linalg.norm(first, axis=1), 1.0, atol=1e-5)
    assert np.array_equal(first, second)


def test_identical_text_has_similarity_one():
    vecs = embed_texts(["the same sentence", "the same sentence"], mode="local")
    assert cosine_similarity(vecs[:1], vecs[1:])[0, 0] == pytest.approx(1.0, abs=1e-5)


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        embed_texts(["hello"], mode="nonsense")
