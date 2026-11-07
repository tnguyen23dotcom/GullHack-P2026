"""Sanity checks for the attack and normal-chat sets (issue #11).

Run from the repo root:  python3 eval/validate_sets.py
Exits with a non-zero code if anything is wrong, so pytest or CI can use it too.

Each item looks like: {"id": "enc-03", "type": "encoding", "split": "test", "prompt": "..."}
The tune/test split is fixed up front: tune the semantic threshold on "tune" only,
and report final numbers on "test" only.
"""
import json
import sys
from collections import Counter
from pathlib import Path

DATA = Path(__file__).parent / "data"
ATTACK_TYPES = ["verbatim", "translation", "encoding", "obfuscation", "paraphrase"]
FIELDS = {"id", "type", "split", "prompt"}


def load(name):
    with open(DATA / name, encoding="utf-8") as f:
        return json.load(f)


def main():
    errors = []
    attacks = load("attacks.json")
    normals = load("normal_chats.json")

    # Every item must have exactly the agreed fields and a non-empty prompt.
    for item in attacks + normals:
        if set(item) != FIELDS:
            errors.append(f"{item.get('id')}: fields are {sorted(item)}, expected {sorted(FIELDS)}")
        if not str(item.get("prompt", "")).strip():
            errors.append(f"{item.get('id')}: empty prompt")
        if item.get("split") not in ("tune", "test"):
            errors.append(f"{item.get('id')}: split must be 'tune' or 'test'")

    # Ids must be unique across both files.
    ids = [i["id"] for i in attacks + normals]
    for dup, n in Counter(ids).items():
        if n > 1:
            errors.append(f"duplicate id: {dup}")

    # Attacks: 5 types, 5 variants each, both splits present for every type.
    if {a["type"] for a in attacks} != set(ATTACK_TYPES):
        errors.append(f"attack types are {sorted({a['type'] for a in attacks})}")
    for t in ATTACK_TYPES:
        of_type = [a for a in attacks if a["type"] == t]
        splits = {a["split"] for a in of_type}
        if len(of_type) != 5:
            errors.append(f"{t}: {len(of_type)} variants, expected 5")
        if splits != {"tune", "test"}:
            errors.append(f"{t}: needs both tune and test items, has {sorted(splits)}")

    # Normal chats: about 25, all type 'normal', both splits present.
    if len(normals) != 25:
        errors.append(f"normal chats: {len(normals)}, expected 25")
    if any(n["type"] != "normal" for n in normals):
        errors.append("every normal chat must have type 'normal'")
    if {n["split"] for n in normals} != {"tune", "test"}:
        errors.append("normal chats need both tune and test items")

    # Report.
    print(f"attacks: {len(attacks)}  split: {dict(Counter(a['split'] for a in attacks))}")
    print(f"normal:  {len(normals)}  split: {dict(Counter(n['split'] for n in normals))}")
    if errors:
        print("\nPROBLEMS:")
        for e in errors:
            print(" -", e)
        sys.exit(1)
    print("OK: sets look valid.")


if __name__ == "__main__":
    main()
