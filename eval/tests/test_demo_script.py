"""The demo file must stay in sync with the simulated replies it is built from. No AWS needed.

Run from the repo root:  python3 -m pytest eval/tests -q
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import make_demo_script  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"


def test_saved_demo_file_is_current():
    saved = json.loads((DATA / "demo_script.json").read_text(encoding="utf-8"))
    assert saved == make_demo_script.build_demo()  # re-run make_demo_script.py if this fails


def test_demo_items_are_unique_and_labelled():
    items = make_demo_script.build_demo()["items"]
    assert len({i["user_message"] for i in items}) == len(items)
    assert all(i["expected"] in ("block", "allow") for i in items)
    assert all((i["expected"] == "block") == (i["caught_by"] is not None) for i in items)
