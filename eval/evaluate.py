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
"""
import argparse
import json
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


def load_b_normalized_check():
    """Person B's normalized check (#7), or None while it is not pushed.

    TODO(#7): when B pushes the normalized check, import it here and return an instance,
    and swap ReferenceExactCheck for B's exact check in build_layers().
    """
    return None


def build_layers(semantic):
    """The layers in gateway order (cheapest first). A missing layer is None."""
    return {"exact": ReferenceExactCheck(), "normalized": load_b_normalized_check(), "semantic": semantic}


PIPELINES = {"baseline": ["exact"], "layered": ["exact", "normalized", "semantic"]}


def run_layers(replies, layers, context):
    """Run every available layer on every reply. Returns one record per reply."""
    records = []
    for item in replies:
        results = {}
        for name, check in layers.items():
            if check is None:
                continue
            r = check.evaluate(item["reply"], context)
            results[name] = {"flagged": bool(r.is_violation), "ms": float(r.latency_ms), "score": r.metadata.get("score")}
        records.append({"id": item["id"], "type": item["type"], "layers": results})
    return records


def summarize(records, pipelines, available):
    """Detection per type, false positives, per-layer catches and latency, from the records."""
    def flagged_by(record, layer_names):
        return any(record["layers"][n]["flagged"] for n in layer_names if n in record["layers"])

    attacks = [r for r in records if r["type"] != "normal"]
    normals = [r for r in records if r["type"] == "normal"]
    summary = {"pipelines": {}, "layers": {}, "counts": {"attacks": len(attacks), "normal": len(normals)}}
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
        f"- Replies: **simulated** ({summary['counts']['attacks']} attacks, {summary['counts']['normal']} normal), "
        "not a live chat model.",
        f"- Semantic layer: `{info['model']}`, threshold {info['threshold']} (locked on the tune split).",
        f"- Exact layer: {info['exact_note']}",
        f"- Normalized layer: {info['normalized_note']}",
        f"- Latency: {info['latency_note']}",
        "",
        "## Detection per attack type",
        "",
        "| Attack type | " + " | ".join(p.capitalize() for p in pipes) + " |",
        "| --- |" + " --- |" * len(pipes),
    ]
    for t in ATTACK_TYPES:
        lines.append(f"| {t} | " + " | ".join(_cell(summary["pipelines"][p]["detection"][t]) for p in pipes) + " |")
    lines.append("| **all attacks** | " + " | ".join(f"**{_cell(summary['pipelines'][p]['all_attacks'])}**" for p in pipes) + " |")
    lines.append("| false positives (normal replies flagged) | " + " | ".join(_cell(summary["pipelines"][p]["false_positives"]) for p in pipes) + " |")
    lines += ["", "## Per layer", "", "| Layer | " + " | ".join(ATTACK_TYPES) + " | false positives | mean ms | slowest ms |",
              "| --- |" + " --- |" * (len(ATTACK_TYPES) + 3)]
    for name, s in summary["layers"].items():
        lines.append(f"| {name} | " + " | ".join(str(s["caught"][t]) for t in ATTACK_TYPES)
                     + f" | {s['false_positives']} | {s['mean_ms']:.2f} | {s['max_ms']:.2f} |")
    missing = sorted({m for p in summary["pipelines"].values() for m in p["missing_layers"]})
    if missing:
        lines += ["", f"Not available yet, so not included: {', '.join(missing)}. The layered numbers are a lower bound."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["local", "local-model", "bedrock"], default="local-model")
    parser.add_argument("--split", choices=["test", "tune"], default="test")
    parser.add_argument("--region", default=DEFAULT_REGION)
    args = parser.parse_args()

    locked = json.loads((EVAL / "locked_settings.json").read_text(encoding="utf-8"))
    fake = args.mode == "local"
    if not fake and model_name(args.mode) != locked["embedding_model"]:
        raise SystemExit(
            f"The locked threshold was tuned for {locked['embedding_model']}, not {model_name(args.mode)}. "
            "Tune and lock this model on the tune split first."
        )

    replies = [r for r in json.loads((DATA / "simulated_replies.json").read_text(encoding="utf-8")) if r["split"] == args.split]
    context = SecurityContext(
        session_id=f"eval-{args.split}",
        session_canary=SIM_CANARY,
        static_secrets=get_static_secret_values(),
        protected_chunks=list(PROTECTED_POLICIES),
    )
    semantic = SemanticCheck(threshold=locked["semantic_threshold"], mode=args.mode, region=args.region)
    layers = build_layers(semantic)
    available = [n for n, c in layers.items() if c is not None]

    # Warm-up: the first semantic call loads the model and embeds the policies (a "cold start").
    # Time it separately so the per-reply numbers show the steady-state cost.
    cold = semantic.evaluate("Warm-up sentence for timing only.", context).latency_ms

    records = run_layers(replies, layers, context)
    summary = summarize(records, PIPELINES, available)
    info = {
        "split": args.split,
        "model": model_name(args.mode),
        "threshold": locked["semantic_threshold"],
        "exact_note": "reference exact-match check in eval/ (Person B's exact check not pushed yet).",
        "normalized_note": "Person B's check" if layers["normalized"] else "**not available yet** (Person B, issue #7).",
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
    stem = f"results_{args.split}_{model_name(args.mode).replace(':', '_')}"
    (out_dir / f"{stem}.md").write_text(markdown, encoding="utf-8")
    (out_dir / f"{stem}.json").write_text(json.dumps({"info": info, "summary": summary, "records": records}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote eval/results/{stem}.md and .json")


if __name__ == "__main__":
    main()
