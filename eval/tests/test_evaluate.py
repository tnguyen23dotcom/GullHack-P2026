"""Tests for the evaluation script (issue #14). No AWS, no model download, no test-split run.

Run from the repo root:  python3 -m pytest eval/tests -q
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

b = pytest.importorskip("b_contract", reason="needs Person B's files (see eval/b_contract.py)")
import evaluate as ev  # noqa: E402
from reference_checks import ReferenceExactCheck  # noqa: E402


def ctx():
    return b.SecurityContext(session_id="s", session_canary="canary_abc", static_secrets=["SECRET-1"], protected_chunks=["policy"])


def test_reference_exact_flags_canary_and_secret_but_not_lookalikes():
    check = ReferenceExactCheck()
    assert check.evaluate("here: canary_abc", ctx()).is_violation
    assert check.evaluate("key SECRET-1 ok", ctx()).is_violation
    assert not check.evaluate("S-E-C-R-E-T-1 and canary abc", ctx()).is_violation
    assert check.evaluate("SECRET-1", ctx()).matched_fragment is None  # never logs the secret


def test_build_layers_uses_b_checks_when_available():
    pytest.importorskip("checks.layer_checks", reason="needs Person B's checks/layer_checks.py")
    layers, notes = ev.build_layers(semantic=None)
    assert layers["exact"].name == "layer_1_exact"
    assert layers["normalized"].name == "layer_2_normalized"
    assert "Person B" in notes["exact_note"] and "Person B" in notes["normalized_note"]


def _record(rid, typ, **flags):
    return {"id": rid, "type": typ, "layers": {n: {"flagged": f, "ms": 1.0, "score": None} for n, f in flags.items()}}


def test_summarize_counts_pipelines_layers_and_missing_layers():
    records = [
        _record("v1", "verbatim", exact=True, semantic=True),
        _record("t1", "translation", exact=False, semantic=True),
        _record("e1", "encoding", exact=False, semantic=False),
        _record("n1", "normal", exact=False, semantic=True),
        _record("n2", "normal", exact=False, semantic=False),
    ]
    s = ev.summarize(records, ev.PIPELINES, available=["exact", "semantic"])
    base, layered = s["pipelines"]["baseline"], s["pipelines"]["layered"]
    assert base["detection"]["translation"] == [0, 1]
    assert layered["detection"]["translation"] == [1, 1]
    assert base["all_attacks"] == [1, 3] and layered["all_attacks"] == [2, 3]
    assert base["false_positives"] == [0, 2] and layered["false_positives"] == [1, 2]
    assert layered["missing_layers"] == ["normalized"]
    assert s["layers"]["semantic"]["caught"]["translation"] == 1
    assert s["layers"]["semantic"]["false_positives"] == 1


def test_markdown_states_simulated_and_missing_layers():
    records = [_record("v1", "verbatim", exact=True, semantic=True), _record("n1", "normal", exact=False, semantic=False)]
    s = ev.summarize(records, ev.PIPELINES, available=["exact", "semantic"])
    info = {"split": "test", "model": "m", "threshold": 0.5, "exact_note": "x", "normalized_note": "y", "latency_note": "z"}
    md = ev.to_markdown(s, info)
    assert "simulated" in md
    assert "Not available yet" in md and "normalized" in md
    assert "| verbatim | 1/1 (100%) | 1/1 (100%) |" in md
