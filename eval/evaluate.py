"""Evaluation (issue #14): baseline (exact match only) versus the layered gateway.

For every simulated reply in the chosen split, every layer is run once and its result and time
are recorded. A pipeline flags a reply when ANY of its layers flags it. We report:
  - detection per attack type (caught / total) for each pipeline
  - false-positive rate on normal replies for each pipeline
  - which layer caught what
  - time added per layer (mean and slowest, in milliseconds, after a warm-up call)

Pipelines:
  baseline = [exact]
  layered  = [exact, normalized (Person B, when available), semantic (ours)]

Honesty rules built in:
  - the semantic threshold comes from locked_settings.json (chosen on the tune split only);
  - the default split is "test"; "tune" exists only to check the script on data already seen;
  - replies are SIMULATED, and the output says so;
  - layers that do not exist yet are reported as "not available", never guessed.

Examples (run from the repo root, with Person B's files available; see eval/b_contract.py):
  python3 eval/evaluate.py --mode local --split tune    # FAKE embedder: checks the script only, writes nothing
  python3 eval/evaluate.py --mode local-model           # final numbers: test split, writes eval/results/
  python3 eval/evaluate.py --mode local-model --replies live   # labelled live replies from live_collect.py
"""
import argparse
import importlib
import json
import re
import statistics
from pathlib import Path

from b_contract import PROTECTED_POLICIES, SecurityContext, get_static_secret_values
from embedder import DEFAULT_REGION, model_name
from make_simulated_replies import SIM_CANARY
from reference_checks import ReferenceExactCheck
from semantic_layer import SemanticCheck

EVAL = Path(__file__).parent
DATA = EVAL / "data"
ATTACK_TYPES = ["verbatim", "translation", "encoding", "obfuscation", "paraphrase"]


def load_b_checks():
    """Person B's exact and normalized checks (#7) as (exact, normalized, module name), or (None, None, None).

    B's current file is checks/layer_checks.py (a package module). Older copies named
    layers_checks.py / layer_checks.py are tried only if it is missing, because the old
    top-level layers_checks.py on main predates B's policy-phrase fix (#10).
    """
    for module_name in ("checks.layer_checks", "layer_checks", "layers_checks"):
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue
        return module.ExactMatchCheck(), module.NormalizedMatchCheck(), module_name
    return None, None, None


def build_layers(semantic):
    """The layers in gateway order (cheapest first), plus notes on where each came from.

    The exact layer is B's when available, else our reference check (so a baseline always exists).
    The normalized layer is B's or None (reported as not available, never guessed).
    """
    b_exact, b_normalized, b_module = load_b_checks()
    layers = {"exact": b_exact or ReferenceExactCheck(), "normalized": b_normalized, "semantic": semantic}
    notes = {
        "exact_note": f"Person B's ExactMatchCheck ({b_module}.py)." if b_exact
        else "reference exact-match check in eval/ (Person B's exact check not available).",
        "normalized_note": f"Person B's NormalizedMatchCheck ({b_module}.py)." if b_normalized
        else "**not available yet** (Person B, issue #7).",
    }
    return layers, notes


PIPELINES = {"baseline": ["exact"], "layered": ["exact", "normalized", "semantic"]}


def _is_leak(record):
    """Ground truth. Simulated replies: every attack reply leaks, no normal reply does.
    Live replies: a person's label says whether the reply really leaked."""
    return record.get("is_leak", record["type"] != "normal")


def run_layers(replies, layers, context):
    """Run every available layer on every reply. Returns one record per reply.

    context is one SecurityContext, or a function item -> SecurityContext (live replies each
    come from their own session, with their own canary).
    """
    records = []
    for item in replies:
        ctx = context(item) if callable(context) else context
        results = {}
        for name, check in layers.items():
            if check is None:
                continue
            r = check.evaluate(item["reply"], ctx)
            results[name] = {"flagged": bool(r.is_violation), "ms": float(r.latency_ms), "score": r.metadata.get("score")}
        records.append({"id": item["id"], "type": item["type"], "is_leak": _is_leak(item), "layers": results})
    return records


def summarize(records, pipelines, available):
    """Detection per type, false positives, per-layer catches and latency, from the records.

    Detection is counted over replies that really leak; false positives over replies that do not
    (normal chats, and on live data also attacks the bot refused).
    """
    def flagged_by(record, layer_names):
        return any(record["layers"][n]["flagged"] for n in layer_names if n in record["layers"])

    attacks = [r for r in records if _is_leak(r)]
    normals = [r for r in records if not _is_leak(r)]
    summary = {
        "pipelines": {}, "layers": {}, "counts": {"attacks": len(attacks), "normal": len(normals)},
        "leaks_per_type": {t: [sum(1 for r in attacks if r["type"] == t), sum(1 for r in records if r["type"] == t)]
                           for t in ATTACK_TYPES},
    }
    for pipe, layer_names in pipelines.items():
        per_type = {}
        for t in ATTACK_TYPES:
            of_type = [r for r in attacks if r["type"] == t]
            per_type[t] = [sum(flagged_by(r, layer_names) for r in of_type), len(of_type)]
        summary["pipelines"][pipe] = {
            "detection": per_type,
            "all_attacks": [sum(flagged_by(r, layer_names) for r in attacks), len(attacks)],
            "false_positives": [sum(flagged_by(r, layer_names) for r in normals), len(normals)],
            "missing_layers": [n for n in layer_names if n not in available],
        }
    for name in available:
        times = [r["layers"][name]["ms"] for r in records]
        summary["layers"][name] = {
            "caught": {t: sum(r["layers"][name]["flagged"] for r in attacks if r["type"] == t) for t in ATTACK_TYPES},
            "false_positives": sum(r["layers"][name]["flagged"] for r in normals),
            "mean_ms": statistics.mean(times) if times else 0.0,
            "max_ms": max(times) if times else 0.0,
        }
    return summary


def _cell(pair):
    caught, total = pair
    return f"{caught}/{total} ({caught / total:.0%})" if total else "n/a"


def to_markdown(summary, info):
    pipes = list(summary["pipelines"])
    lines = [
        f"# Evaluation results ({info['split']} split)",
        "",
        info.get("replies_note") or (
            f"- Replies: **simulated** ({summary['counts']['attacks']} attacks, {summary['counts']['normal']} normal), "
            "not a live chat model."),
        f"- Semantic layer: `{info['model']}`, threshold {info['threshold']} (locked on the tune split).",
        f"- Exact layer: {info['exact_note']}",
        f"- Normalized layer: {info['normalized_note']}",
        f"- Latency: {info['latency_note']}",
    ]
    if info.get("source") == "live":
        lines += ["", "## How often the live bot leaked", "", "| Attack type | Replies that leaked |", "| --- | --- |"]
        lines += [f"| {t} | {_cell(summary['leaks_per_type'][t])} |" for t in ATTACK_TYPES]
        lines += ["", "Detection below is counted only over replies that really leaked (n/a = no leak to catch). "
                  "False positives count every reply that did not leak, including refused attacks."]
    lines += [
        "",
        "## Detection per attack type",
        "",
        "| Attack type | " + " | ".join(p.capitalize() for p in pipes) + " |",
        "| --- |" + " --- |" * len(pipes),
    ]
    for t in ATTACK_TYPES:
        lines.append(f"| {t} | " + " | ".join(_cell(summary["pipelines"][p]["detection"][t]) for p in pipes) + " |")
    lines.append("| **all attacks** | " + " | ".join(f"**{_cell(summary['pipelines'][p]['all_attacks'])}**" for p in pipes) + " |")
    lines.append("| false positives (replies with no leak, flagged) | " + " | ".join(_cell(summary["pipelines"][p]["false_positives"]) for p in pipes) + " |")
    lines += ["", "## Per layer", "", "| Layer | " + " | ".join(ATTACK_TYPES) + " | false positives | mean ms | slowest ms |",
              "| --- |" + " --- |" * (len(ATTACK_TYPES) + 3)]
    for name, s in summary["layers"].items():
        lines.append(f"| {name} | " + " | ".join(str(s["caught"][t]) for t in ATTACK_TYPES)
                     + f" | {s['false_positives']} | {s['mean_ms']:.2f} | {s['max_ms']:.2f} |")
    missing = sorted({m for p in summary["pipelines"].values() for m in p["missing_layers"]})
    if missing:
        lines += ["", f"Not available yet, so not included: {', '.join(missing)}. The layered numbers are a lower bound."]
    return "\n".join(lines) + "\n"


LIVE_CANARY = re.compile(r"CANARY-[0-9a-f]{16}")  # the Lambda's per-session canary format


def make_context(canary, session_id):
    return SecurityContext(
        session_id=session_id,
        session_canary=canary,
        static_secrets=get_static_secret_values(),
        protected_chunks=list(PROTECTED_POLICIES),
    )


def live_context(item):
    """Each live reply came from its own session, whose canary the gateway knows but we do not.
    If the reply contains a canary in the Lambda's format, use it (the gateway would know it);
    an encoded canary cannot be recovered this way, so that one case may be undercounted."""
    found = LIVE_CANARY.search(item["reply"] or "")
    return make_context(found.group(0) if found else "CANARY-not-in-reply", f"live-{item['id']}")


def load_live_replies(split):
    """Live replies merged with a person's labels. Refuses to score unlabelled or failed replies."""
    raw = json.loads((DATA / f"live_replies_{split}.json").read_text(encoding="utf-8"))
    labels_path = DATA / f"live_labels_{split}.json"
    if not labels_path.exists():
        raise SystemExit(f"Label the replies first: eval/data/{labels_path.name} (id -> {{\"leaked\": true|false}}).")
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    replies, skipped = [], []
    for r in raw["replies"]:
        if r["status"] != 200 or r["reply"] is None:
            skipped.append(r["id"])
            continue
        if r["id"] not in labels or not isinstance(labels[r["id"]].get("leaked"), bool):
            raise SystemExit(f"Missing or unclear label for {r['id']} in {labels_path.name}.")
        replies.append({**r, "is_leak": labels[r["id"]]["leaked"]})
    mean_ms = statistics.mean(r["round_trip_ms"] for r in raw["replies"] if r["status"] == 200)
    note = (f"- Replies: **live** from the deployed gateway (run {raw['run_id']}, model behind it: Amazon Nova 2 Lite), "
            f"{len(replies)} received; leak labels by a person. Gateway round trip without checks: {mean_ms:.0f} ms on average."
            + (f" Failed calls not scored: {', '.join(skipped)}." if skipped else ""))
    return replies, note


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["local", "local-model", "bedrock"], default="local-model")
    parser.add_argument("--split", choices=["test", "tune"], default="test")
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--replies", choices=["simulated", "live"], default="simulated",
                        help="simulated replies (default) or labelled live replies from live_collect.py")
    args = parser.parse_args()

    locked = json.loads((EVAL / "locked_settings.json").read_text(encoding="utf-8"))
    fake = args.mode == "local"
    if not fake and model_name(args.mode) != locked["embedding_model"]:
        raise SystemExit(
            f"The locked threshold was tuned for {locked['embedding_model']}, not {model_name(args.mode)}. "
            "Tune and lock this model on the tune split first."
        )

    if args.replies == "live":
        replies, replies_note = load_live_replies(args.split)
        context = live_context
    else:
        replies = [r for r in json.loads((DATA / "simulated_replies.json").read_text(encoding="utf-8")) if r["split"] == args.split]
        replies_note = None
        context = make_context(SIM_CANARY, f"eval-{args.split}")
    semantic = SemanticCheck(threshold=locked["semantic_threshold"], mode=args.mode, region=args.region)
    layers, layer_notes = build_layers(semantic)
    available = [n for n, c in layers.items() if c is not None]

    # Warm-up: the first semantic call loads the model and embeds the policies (a "cold start").
    # Time it separately so the per-reply numbers show the steady-state cost.
    cold = semantic.evaluate("Warm-up sentence for timing only.", make_context(SIM_CANARY, "warm-up")).latency_ms

    records = run_layers(replies, layers, context)
    summary = summarize(records, PIPELINES, available)
    info = {
        "source": args.replies,
        "replies_note": replies_note,
        "split": args.split,
        "model": model_name(args.mode),
        "threshold": locked["semantic_threshold"],
        **layer_notes,
        "latency_note": f"measured on this machine's CPU, per reply, after a warm-up call; the semantic cold start "
                        f"(model load and policy embedding) took {cold:.0f} ms and is not in the per-reply numbers.",
    }
    markdown = to_markdown(summary, info)
    print(markdown)

    if fake:
        print("FAKE embedder: these numbers only check the script. Nothing was written.")
        return
    if args.split == "tune":
        print("Tune split: data already used for tuning. Nothing was written; final numbers come from the test split.")
        return
    out_dir = EVAL / "results"
    out_dir.mkdir(exist_ok=True)
    live = "_live" if args.replies == "live" else ""
    stem = f"results_{args.split}{live}_{model_name(args.mode).replace(':', '_')}"
    (out_dir / f"{stem}.md").write_text(markdown, encoding="utf-8")
    (out_dir / f"{stem}.json").write_text(json.dumps({"info": info, "summary": summary, "records": records}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote eval/results/{stem}.md and .json")


if __name__ == "__main__":
    main()
