"""Send our prompts to the REAL gateway and save the chatbot's replies (live test).

Why: so far the detectors were measured on replies we wrote ourselves (simulated). This script
asks the live chatbot (Person A's API Gateway + Lambda + Bedrock, with Person B's prompt) the same
questions and saves exactly what it answers, so we can measure on real replies.

Run it ONLY while the gateway's checks are a pass-through, so we get the raw replies.
Each prompt uses its own new session, so answers do not influence each other.

Cost: one small model call per prompt (30 for the test split). Default is a DRY RUN: it only
prints what it would send. Add --send to really call the gateway.

Examples (run from the repo root):
  python3 eval/live_collect.py --url https://<api-id>.execute-api.us-east-1.amazonaws.com/chat
  python3 eval/live_collect.py --url https://<api-id>.execute-api.us-east-1.amazonaws.com/chat --send

Output: eval/data/live_replies_<split>.json. Every reply then needs a human label ("did it
really leak?") in eval/data/live_labels_<split>.json before evaluate.py --replies live can score it.
"""
import argparse
import json
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

DATA = Path(__file__).parent / "data"


def load_prompts(split):
    items = []
    for source in ("attacks.json", "normal_chats.json"):
        items += [i for i in json.loads((DATA / source).read_text(encoding="utf-8")) if i["split"] == split]
    return items


def ask_gateway(url, message, session_id, timeout=60.0):
    """POST one chat message. Returns (http_status, reply_or_None, error_or_None, round_trip_ms)."""
    body = json.dumps({"session_id": session_id, "message": message}).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
            status = response.status
    except urllib.error.HTTPError as err:
        ms = (time.perf_counter() - start) * 1000.0
        return err.code, None, err.read().decode("utf-8", "replace")[:300], ms
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
        return None, None, str(err)[:300], (time.perf_counter() - start) * 1000.0
    ms = (time.perf_counter() - start) * 1000.0
    return status, payload.get("reply"), payload.get("error"), ms


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="the gateway's POST /chat URL")
    parser.add_argument("--split", choices=["test", "tune"], default="test")
    parser.add_argument("--send", action="store_true", help="really call the gateway (costs a little); without it, dry run")
    parser.add_argument("--pause", type=float, default=1.0, help="seconds to wait between calls (default 1)")
    args = parser.parse_args()

    prompts = load_prompts(args.split)
    print(f"{len(prompts)} prompts from the {args.split} split -> {args.url}")
    if not args.send:
        for item in prompts:
            print(f"  would send {item['id']:<9} {item['prompt'][:70]}")
        print("DRY RUN: nothing was sent. Add --send to call the gateway.")
        return

    run_id = uuid.uuid4().hex[:8]
    results = []
    for n, item in enumerate(prompts, start=1):
        session_id = f"eval-live-{run_id}-{item['id']}"
        status, reply, error, ms = ask_gateway(args.url, item["prompt"], session_id)
        results.append({
            "id": item["id"], "type": item["type"], "split": item["split"],
            "status": status, "reply": reply, "error": error, "round_trip_ms": round(ms, 1),
        })
        flag = "ok" if status == 200 and reply is not None else f"FAILED ({status}: {error})"
        print(f"  {n:>2}/{len(prompts)} {item['id']:<9} {ms:>7.0f} ms  {flag}")
        time.sleep(args.pause)

    out = DATA / f"live_replies_{args.split}.json"
    out.write_text(json.dumps({"run_id": run_id, "url_host": args.url.split("/")[2], "replies": results},
                              indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ok = sum(1 for r in results if r["status"] == 200 and r["reply"] is not None)
    print(f"wrote {out.relative_to(DATA.parent.parent)}: {ok}/{len(results)} replies received")
    print("Next: label each reply (did it really leak?) in eval/data/live_labels_" + args.split + ".json")


if __name__ == "__main__":
    main()
