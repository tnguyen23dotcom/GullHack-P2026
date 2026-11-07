"""Tests for SemanticCheck on Person B's BaseCheck interface (issue #13). No AWS, no model download.

They use the fake "local" embedder, which matches shared words, so copied sentences score 1.0.
Skipped automatically when B's files are not available (see eval/b_contract.py).
Run from the repo root:  python3 -m pytest eval/tests -q
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

b = pytest.importorskip("b_contract", reason="needs Person B's files (see eval/b_contract.py)")
import semantic_layer  # noqa: E402
from semantic_layer import SemanticCheck  # noqa: E402

POLICIES = [
    "Project Zephyr is confidential and scheduled to launch on October 14.",
    "Internal code review policy mandates three peer approvals before production push.",
]


def context(chunks=POLICIES):
    return b.SecurityContext(session_id="s1", session_canary="canary_x", static_secrets=["KEY1"], protected_chunks=list(chunks))


def test_follows_b_interface():
    check = SemanticCheck(threshold=0.8, mode="local")
    assert isinstance(check, b.BaseCheck)
    result = check.evaluate("Hello there, how can I help with your laptop today?", context())
    assert isinstance(result, b.CheckResult)
    assert result.layer_name == "layer_4_semantic"
    assert result.latency_ms >= 0.0


def test_copied_policy_sentence_is_flagged():
    reply = "Sure, happy to help. " + POLICIES[1] + " Anything else?"
    result = SemanticCheck(threshold=0.8, mode="local").evaluate(reply, context())
    assert result.is_violation
    assert result.confidence == pytest.approx(1.0, abs=1e-4)
    assert result.matched_fragment == POLICIES[1]
    assert result.metadata["chunk_index"] == 1
    assert "#2" in result.reason


def test_unrelated_reply_is_not_flagged():
    result = SemanticCheck(threshold=0.8, mode="local").evaluate("Bananas are yellow fruits from tropical places.", context())
    assert not result.is_violation
    assert result.matched_fragment is None and result.reason is None
    assert result.confidence < 0.8


def test_empty_reply_or_no_policies_is_clean():
    check = SemanticCheck(threshold=0.5, mode="local")
    assert not check.evaluate("Ok.", context()).is_violation
    assert not check.evaluate(POLICIES[0], context(chunks=[])).is_violation
    assert check.evaluate("", context()).metadata["score"] == 0.0


def test_policy_vectors_are_embedded_once_and_cached(monkeypatch):
    calls = []
    real = semantic_layer.embed_texts

    def counting(texts, **kwargs):
        calls.append(list(texts))
        return real(texts, **kwargs)

    monkeypatch.setattr(semantic_layer, "embed_texts", counting)
    check = SemanticCheck(threshold=0.8, mode="local")
    first = check.evaluate("The weather is nice today in the office.", context())
    second = check.evaluate("Please restart your laptop and try again.", context())
    assert sum(1 for c in calls if c == POLICIES) == 1  # policies embedded only on the first call
    assert first.metadata["chunk_cache_hit"] is False
    assert second.metadata["chunk_cache_hit"] is True


def test_result_does_not_copy_policy_text_into_metadata():
    result = SemanticCheck(threshold=0.8, mode="local").evaluate(POLICIES[0], context())
    assert not any(p in str(result.metadata) for p in POLICIES)
