"""Offline tests for the semantic helpers, the threshold sweep and the simulated replies.

Tests that need Person B's prompt.py / check_interface.py skip themselves when those files are
not available (see eval/b_contract.py).
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
from embedder import embed_texts  # noqa: E402
from semantic_check import score_reply, split_reply  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"


# ---------- sentence splitting and scoring helpers ----------
def test_split_reply_splits_sentences_and_lines_and_drops_fragments():
    reply = "Sure! Refunds are allowed within 30 days.\nShipping is free over $75. Ok."
    assert split_reply(reply) == ["Refunds are allowed within 30 days.", "Shipping is free over $75."]


def test_score_reply_finds_a_copied_chunk_and_ignores_unrelated_text():
    chunks = ["Project Zephyr launches in October.", "Code needs three approvals before release."]
    vectors = embed_texts(chunks, mode="local")
    copied = score_reply(chunks[1] + " Thanks for asking.", vectors, ["c1", "c2"], mode="local")
    assert copied["chunk_id"] == "c2"
    assert copied["score"] == pytest.approx(1.0, abs=1e-4)
    assert score_reply("Bananas are yellow fruits from tropical places.", vectors, ["c1", "c2"], mode="local")["score"] < 0.5


# ---------- local-model mode (no model download: the model call is faked) ----------
def test_local_model_mode_normalizes_whatever_the_model_returns(monkeypatch):
    monkeypatch.setattr(embedder, "_local_model_embed", lambda texts: np.array([[3.0, 4.0]] * len(texts), dtype=np.float32))
    assert np.allclose(embed_texts(["a", "b"], mode="local-model"), [[0.6, 0.8], [0.6, 0.8]])
    assert embedder.embeddings_filename("local-model") == "paraphrase-multilingual-MiniLM-L12-v2.npz"
    assert embedder.embeddings_filename("bedrock") == "amazon.titan-embed-text-v2_0.npz"


# ---------- threshold sweep (needs B's files because tune_threshold imports them) ----------
def test_sweep_and_midpoint_recommendation():
    tt = pytest.importorskip("tune_threshold", reason="needs Person B's files (see eval/b_contract.py)")
    attacks = {"verbatim": [0.9, 0.8], "paraphrase": [0.6, 0.4]}
    normal = [0.5, 0.2, 0.1]
    rows = tt.sweep(attacks, normal, [0.3, 0.5, 0.7])
    by_threshold = {r["threshold"]: r for r in rows}
    assert by_threshold[0.3]["false_positive"] == pytest.approx(1 / 3)
    assert by_threshold[0.7]["detection"] == {"verbatim": 1.0, "paraphrase": 0.0}
    assert tt.recommend(rows, max_fp=0.0, focus_types=["verbatim", "paraphrase"])["threshold"] == 0.7
    assert tt.recommend(rows, max_fp=-1.0, focus_types=["verbatim"]) is None  # nothing qualifies

    # Three thresholds perform the same: the recommendation is the middle one, not the edge.
    plateau = tt.sweep({"verbatim": [0.95]}, [0.4], [0.6, 0.7, 0.8])
    assert [r["threshold"] for r in tt.best_range(plateau, 0.0, ["verbatim"])] == [0.6, 0.7, 0.8]
    assert tt.recommend(plateau, 0.0, ["verbatim"])["threshold"] == 0.7


# ---------- simulated replies (built from B's real prompt) ----------
@pytest.fixture
def sim():
    return pytest.importorskip("make_simulated_replies", reason="needs Person B's files (see eval/b_contract.py)")


def test_simulated_replies_match_the_prompt_sets_and_the_saved_file_is_current(sim):
    built = sim.build_replies()
    saved = json.loads((DATA / "simulated_replies.json").read_text(encoding="utf-8"))
    assert saved == built  # re-run make_simulated_replies.py if this fails
    attacks = json.loads((DATA / "attacks.json").read_text(encoding="utf-8"))
    normals = json.loads((DATA / "normal_chats.json").read_text(encoding="utf-8"))
    assert [r["id"] for r in saved] == [i["id"] for i in attacks + normals]
    assert all(r["reply"].strip() for r in saved)


def test_encoded_replies_decode_back_to_the_prompt(sim):
    prompt = sim.load_prompt()
    by_id = {r["id"]: r["reply"] for r in sim.build_replies()}
    assert base64.b64decode(by_id["enc-01"]).decode("utf-8") == prompt
    assert bytes.fromhex(by_id["enc-02"]).decode("utf-8") == prompt
    assert codecs.decode(by_id["enc-03"], "rot13") == prompt
    assert by_id["enc-04"][::-1] == prompt
    assert [base64.b64decode(line).decode("utf-8") for line in by_id["enc-05"].splitlines()] == sim.secrets()


def test_obfuscated_replies_keep_the_original_letters(sim):
    pol = sim.policies()
    by_id = {r["id"]: r["reply"] for r in sim.build_replies()}

    def squash(text):  # remove the characters the obfuscation adds
        return text.replace("-", "").replace(" ", "").replace("\n", "").replace(".", "")

    assert squash(by_id["obf-01"]) == squash("\n".join(pol[:3]))
    assert squash(by_id["obf-02"]) == squash("\n".join(pol))
    assert squash(by_id["obf-05"]) == squash("\n".join(pol))
    assert by_id["obf-03"].replace("\n", "") == sim.secrets()[0]
    assert not any(ch in by_id["obf-04"] for ch in "eao")  # leetspeak removed every e, a and o


def test_translation_paraphrase_and_normal_replies_hold_no_keys_or_canary(sim):
    """These replies must not contain exact secrets: they test what exact matching cannot catch."""
    targets = sim.secrets() + [sim.SIM_CANARY]
    for r in sim.build_replies():
        if r["type"] in ("translation", "paraphrase", "normal"):
            assert not any(t in r["reply"] for t in targets), r["id"]
