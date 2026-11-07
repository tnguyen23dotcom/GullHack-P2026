"""Semantic check core (issue #13): does a chatbot reply say what the protected prompt says?

How it works: split the reply into sentences, embed each one, compare it with the embedding of
every prompt chunk (cosine similarity) and keep the highest score. A high score means the reply
probably repeats, translates or paraphrases part of the protected prompt.

This file does NOT follow Person B's check interface yet, because we do not have it. When we
do, a thin adapter will call score_reply() and compare the score with the tuned threshold.
"""
import re
from pathlib import Path

import numpy as np

from embedder import DEFAULT_REGION, cosine_similarity, embed_texts, embeddings_filename

DATA = Path(__file__).parent / "data"
MIN_CHARS = 12  # fragments shorter than this ("Sure!", a single letter) carry no meaning
_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")  # split after . ! ? or at line breaks


def split_reply(reply):
    """Split a reply into sentences, dropping very short fragments."""
    parts = [part.strip() for part in _SPLIT.split(reply)]
    return [part for part in parts if len(part) >= MIN_CHARS]


def load_chunk_embeddings(mode):
    """Load the saved prompt-chunk vectors made by build_embeddings.py in the same mode."""
    path = DATA / "embeddings" / embeddings_filename(mode)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Build it first: python3 eval/build_embeddings.py --mode {mode}")
    saved = np.load(path)
    return saved["vectors"], [str(i) for i in saved["ids"]], str(saved["model"])


def score_reply(reply, chunk_vectors, chunk_ids, mode="local", region=DEFAULT_REGION):
    """Highest similarity between any reply sentence and any prompt chunk.

    Returns {"score": float, "sentence": best reply sentence or None, "chunk_id": best chunk or None}.
    A reply with no usable sentences scores 0.0.
    """
    sentences = split_reply(reply)
    if not sentences:
        return {"score": 0.0, "sentence": None, "chunk_id": None}
    sentence_vectors = embed_texts(sentences, mode=mode, region=region)
    similarity = cosine_similarity(sentence_vectors, chunk_vectors)  # rows: sentences, columns: chunks
    row, col = np.unravel_index(np.argmax(similarity), similarity.shape)
    return {"score": float(similarity[row, col]), "sentence": sentences[row], "chunk_id": chunk_ids[col]}


def is_leak(result, threshold):
    """Flag the reply when its best similarity reaches the threshold."""
    return result["score"] >= threshold
