"""Offline tests for the semantic check core, the threshold sweep and the simulated replies.

Run from the repo root:  python3 -m pytest eval/tests -q
"""
import base64
import codecs
import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import embedder  # noqa: E402
import make_simulated_replies as sim  # noqa: E402
from chunk_prompt import chunk_prompt  # noqa: E402
from embedder import embed_texts  # noqa: E402
from semantic_check import split_reply, score_reply  # noqa: E402
from tune_threshold import recommend, sweep  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"


# ---------- semantic check core ----------
def test_split_reply_splits_sentences_and_lines_and_drops_fragments():
    reply = "Sure! Refunds are allowed within 30 days.\nShipping is free over $75. Ok."
    assert split_reply(reply) == ["Refunds are allowed within 30 days.", "Shipping is free over $75."]


def test_score_reply_finds_a_copied_chunk_and_ignores_unrelated_text():
    chunks = chunk_prompt((DATA / "placeholder_prompt.txt").read_text(encoding="utf-8"))
    ids = [c["id"] for c in chunks]
    vectors = embed_texts([c["text"] for c in chunks], mode="local")
    copied = score_reply(chunks[3]["text"] + " Thanks for asking.", vectors, ids, mode="local")
    assert copied["chunk_id"] == chunks[3]["id"]
    assert copied["score"] == pytest.approx(1.0, abs=1e-4)
    unrelated = score_reply("Bananas are yellow fruits from tropical places.", vectors, ids, mode="local")
    assert unrelated["score"] < 0.5


def test_reply_with_no_usable_sentences_scores_zero():
    vectors = embed_texts(["Refunds are allowed within 30 days."], mode="local")
    assert score_reply("Ok.", vectors, ["chunk-001"], mode="local")["score"] == 0.0


# ---------- threshold sweep ----------
def test_sweep_and_recommend_on_toy_scores():
    attacks = {"verbatim": [0.9, 0.8], "paraphrase": [0.6, 0.4]}
    normal = [0.5, 0.2, 0.1]
    rows = sweep(attacks, normal, [0.3, 0.5, 0.7])
    by_threshold = {r["threshold"]: r for r in rows}
    assert by_threshold[0.3]["detection"] == {"verbatim": 1.0, "paraphrase": 1.0}
    assert by_threshold[0.3]["false_positive"] == pytest.approx(1 / 3)
    assert by_threshold[0.7]["detection"] == {"verbatim": 1.0, "paraphrase": 0.0}
    assert by_threshold[0.7]["false_positive"] == 0.0
    assert recommend(rows, max_fp=0.0, focus_types=["verbatim", "paraphrase"])["threshold"] == 0.7
    assert recommend(rows, max_fp=-1.0, focus_types=["verbatim"]) is None  # nothing qualifies


# ---------- local-model mode (no model download: the model call is faked) ----------
def test_local_model_mode_normalizes_whatever_the_model_returns(monkeypatch):
    monkeypatch.setattr(embedder, "_local_model_embed", lambda texts: np.array([[3.0, 4.0]] * len(texts), dtype=np.float32))
    vectors = embed_texts(["a", "b"], mode="local-model")
    assert np.allclose(vectors, [[0.6, 0.8], [0.6, 0.8]])
    assert embedder.embeddings_filename("local-model") == "paraphrase-multilingual-MiniLM-L12-v2.npz"
    assert embedder.embeddings_filename("bedrock") == "amazon.titan-embed-text-v2_0.npz"


# ---------- simulated replies ----------
def test_simulated_replies_match_the_prompt_sets_and_the_saved_file_is_current():
    built = sim.build_replies()
    saved = json.loads((DATA / "simulated_replies.json").read_text(encoding="utf-8"))
    assert saved == built  # re-run make_simulated_replies.py if this fails
    attacks = json.loads((DATA / "attacks.json").read_text(encoding="utf-8"))
    normals = json.loads((DATA / "normal_chats.json").read_text(encoding="utf-8"))
    assert [r["id"] for r in saved] == [i["id"] for i in attacks + normals]
    assert all(r["reply"].strip() for r in saved)


def test_encoded_replies_decode_back_to_the_prompt():
    prompt = sim.load_prompt()
    by_id = {r["id"]: r["reply"] for r in sim.build_replies()}
    assert base64.b64decode(by_id["enc-01"]).decode("utf-8") == prompt
    assert bytes.fromhex(by_id["enc-02"]).decode("utf-8") == prompt
    assert codecs.decode(by_id["enc-03"], "rot13") == prompt
    assert by_id["enc-04"][::-1] == prompt
    assert [base64.b64decode(line).decode("utf-8") for line in by_id["enc-05"].splitlines()] == sim.SECRETS


def test_obfuscated_replies_keep_the_original_letters():
    prompt = sim.load_prompt()
    bullets = sim.prompt_bullets(prompt)
    by_id = {r["id"]: r["reply"] for r in sim.build_replies()}

    def squash(text):  # remove the characters the obfuscation adds
        return text.replace("-", "").replace(" ", "").replace("\n", "").replace(".", "")

    assert squash(by_id["obf-01"]) == squash("\n".join(bullets[:3]))
    assert squash(by_id["obf-02"]) == squash("\n".join(bullets[5:8]))
    assert squash(by_id["obf-05"]) == squash("\n".join(bullets[5:8]))
    assert by_id["obf-03"].replace("\n", "") == sim.SECRETS[0]
    assert not any(ch in by_id["obf-04"] for ch in "eao")  # leetspeak removed every e, a and o
