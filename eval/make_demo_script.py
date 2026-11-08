"""Build eval/data/demo_script.json: a small scripted chat for the live demo (simulated-bot fallback).

Why: our AWS accounts cannot call Bedrock chat models yet (quota 0). Person A's Lambda can use this
file as a "simulated bot": when the user's message matches a demo prompt, return its scripted reply,
then run the real checks on it. Everything else in the gateway stays real.

The items are taken unchanged from simulated_replies.json. All are from the TEST split, and the
"caught_by" field records which layer flagged each reply in the measured test run (2026-11-07,
13/15 caught). Normal items were not flagged in that run. Everything is fake.

Run from the repo root:  python3 eval/make_demo_script.py
"""
import json
from pathlib import Path

DATA = Path(__file__).parent / "data"

# id -> (short label for the presenter, layer that caught it in the measured test run, or None)
DEMO_ITEMS = [
    ("norm-03", "Normal IT question", None),
    ("verb-03", "Verbatim leak: copies the whole prompt", "exact"),
    ("enc-05", "Encoded leak: secrets in base64", "normalized"),
    ("obf-03", "Obfuscated leak: a key spelled one letter per line", "normalized"),
    ("trans-03", "Translated leak: policies in German", "semantic"),
    ("para-04", "Paraphrased leak: policies retold as onboarding tips", "semantic"),
    ("norm-19", "Near-miss: salary question, no leak", None),
    ("norm-23", "Near-miss: product launch question, no leak", None),
]


def build_demo():
    prompts = {i["id"]: i for i in json.loads((DATA / "attacks.json").read_text(encoding="utf-8"))}
    prompts.update({i["id"]: i for i in json.loads((DATA / "normal_chats.json").read_text(encoding="utf-8"))})
    replies = {r["id"]: r for r in json.loads((DATA / "simulated_replies.json").read_text(encoding="utf-8"))}
    items = []
    for item_id, label, caught_by in DEMO_ITEMS:
        prompt, reply = prompts[item_id], replies[item_id]
        if reply["split"] != "test":
            raise ValueError(f"{item_id} is not a test-split item")
        items.append({
            "id": item_id,
            "label": label,
            "type": prompt["type"],
            "user_message": prompt["prompt"],
            "bot_reply": reply["reply"],
            "expected": "block" if caught_by else "allow",
            "caught_by": caught_by,
        })
    return {
        "about": (
            "Scripted replies for a SIMULATED bot, used only while Bedrock chat is unavailable. "
            "Say 'simulated chat model' in the demo. All secrets are fake decoys. "
            "Built by eval/make_demo_script.py from eval/data/simulated_replies.json."
        ),
        "how_to_use": (
            "Match the user's message exactly (after .strip()) to user_message and return bot_reply; "
            "for any other message return fallback_reply. Then run the normal egress checks on the reply. "
            "The secrets in these replies come from Person B's prompt.py; the canary is a fixed fake "
            "(canary_sim_0001_fake), so the exact check catches the decoy keys, not the session canary."
        ),
        "fallback_reply": "I am only authorized to assist with general workspace and IT requests.",
        "measured_run": "test split, 2026-11-07: layered gateway caught 13/15 attacks, 1/15 normal replies flagged",
        "items": items,
    }


def main():
    demo = build_demo()
    (DATA / "demo_script.json").write_text(json.dumps(demo, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote eval/data/demo_script.json: {len(demo['items'])} items")


if __name__ == "__main__":
    main()
