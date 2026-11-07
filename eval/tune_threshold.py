"""Pick the semantic threshold using the TUNE split only (issue #13).

What it does: runs the real SemanticCheck (the same code the gateway would run) on every
simulated reply in the tune split, records its best-similarity score, then tries many
thresholds and prints the detection rate per attack type and the false-positive rate.

How the threshold is chosen: among thresholds that keep false positives at or below --max-fp,
take those with the best detection on verbatim, translation and paraphrase, and pick the one
in the MIDDLE of that range. The middle leaves a safety margin on both sides; the edge of the
range would sit right next to an attack score or a normal score.

The TEST split is never read here. It is kept for the final numbers (issues #14 and #15).
Replies are SIMULATED (see make_simulated_replies.py), so say so when you report results.

Examples (run from the repo root):
  python3 eval/tune_threshold.py --mode local         # FAKE embedder: only tests the pipeline
  python3 eval/tune_threshold.py --mode local-model   # real local model (pip install sentence-transformers)
  python3 eval/tune_threshold.py --mode bedrock       # Bedrock: embeds every reply sentence, costs a little
"""
import argparse
import json
from pathlib import Path

from b_contract import PROTECTED_POLICIES, SecurityContext, get_static_secret_values
from embedder import DEFAULT_REGION, model_name
from make_simulated_replies import SIM_CANARY
from semantic_layer import SemanticCheck

DATA = Path(__file__).parent / "data"
ATTACK_TYPES = ["verbatim", "translation", "encoding", "obfuscation", "paraphrase"]
FOCUS_TYPES = ["verbatim", "translation", "paraphrase"]  # what the semantic layer is meant to catch
THRESHOLDS = [round(0.30 + 0.025 * i, 3) for i in range(27)]  # 0.300 ... 0.950


def _rate(scores, threshold):
    """Share of scores at or above the threshold (0.0 when there are no scores)."""
    return sum(s >= threshold for s in scores) / len(scores) if scores else 0.0


def sweep(scores_by_type, normal_scores, thresholds):
    """For each threshold: detection rate per attack type and false-positive rate."""
    return [
        {
            "threshold": t,
            "detection": {typ: _rate(scores, t) for typ, scores in scores_by_type.items()},
            "false_positive": _rate(normal_scores, t),
        }
        for t in thresholds
    ]


def _focus(row, focus_types):
    return sum(row["detection"][t] for t in focus_types) / len(focus_types)


def best_range(rows, max_fp, focus_types):
    """All thresholds with false positives <= max_fp that share the best focus detection, sorted."""
    allowed = [r for r in rows if r["false_positive"] <= max_fp]
    if not allowed:
        return []
    top = max(_focus(r, focus_types) for r in allowed)
    return sorted((r for r in allowed if _focus(r, focus_types) == top), key=lambda r: r["threshold"])


def recommend(rows, max_fp, focus_types):
    """The threshold in the middle of the best range, or None if nothing qualifies."""
    candidates = best_range(rows, max_fp, focus_types)
    return candidates[len(candidates) // 2] if candidates else None


def tune_context():
    """The same kind of SecurityContext the gateway builds, with B's real policies and decoys."""
    return SecurityContext(
        session_id="tune-sweep",
        session_canary=SIM_CANARY,
        static_secrets=get_static_secret_values(),
        protected_chunks=list(PROTECTED_POLICIES),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["local", "local-model", "bedrock"], default="local")
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--max-fp", type=float, default=0.10, help="largest false-positive rate you accept (default 0.10)")
    args = parser.parse_args()

    replies = [r for r in json.loads((DATA / "simulated_replies.json").read_text(encoding="utf-8")) if r["split"] == "tune"]
    check = SemanticCheck(threshold=1.0, mode=args.mode, region=args.region)  # threshold unused: we read the raw score
    context = tune_context()
    print(f"embedding model: {model_name(args.mode)}   protected policies: {len(context.protected_chunks)}   "
          f"tune replies: {len(replies)} (test split NOT used)")
    if args.mode == "local":
        print("WARNING: FAKE embedder. It matches shared words, not meaning. Pipeline test only.")

    scores_by_type = {t: [] for t in ATTACK_TYPES}
    normal_scores, per_reply = [], []
    for item in replies:
        score = check.evaluate(item["reply"], context).metadata["score"]
        per_reply.append((item["id"], score))
        (normal_scores if item["type"] == "normal" else scores_by_type[item["type"]]).append(score)

    print("\nscore per reply (tune split):")
    for reply_id, score in per_reply:
        print(f"  {reply_id:<9} {score:.3f}")

    print("\nbest-similarity score per group (min / mean / max):")
    for name, scores in list(scores_by_type.items()) + [("normal", normal_scores)]:
        if scores:
            print(f"  {name:<12} {min(scores):.3f} / {sum(scores) / len(scores):.3f} / {max(scores):.3f}   (n={len(scores)})")

    rows = sweep(scores_by_type, normal_scores, THRESHOLDS)
    print("\nthreshold sweep (detection per attack type, false-positive rate on normal replies):")
    print(f"{'thresh':>7} " + " ".join(f"{t[:7]:>8}" for t in ATTACK_TYPES) + f" {'false+':>8}")
    for r in rows:
        cells = " ".join(f"{r['detection'][t] * 100:>7.0f}%" for t in ATTACK_TYPES)
        print(f"{r['threshold']:>7.3f} {cells} {r['false_positive'] * 100:>7.0f}%")

    candidates = best_range(rows, args.max_fp, FOCUS_TYPES)
    best = recommend(rows, args.max_fp, FOCUS_TYPES)
    if best is None:
        print(f"\nNo threshold keeps false positives at or below {args.max_fp:.0%} on the tune split.")
        return
    print(
        f"\nbest range: {candidates[0]['threshold']:.3f} to {candidates[-1]['threshold']:.3f} "
        f"(same detection, false positives <= {args.max_fp:.0%})"
    )
    print(
        f"RECOMMENDED threshold (middle of the best range, tune split only): {best['threshold']:.3f}  "
        f"[focus-type detection {_focus(best, FOCUS_TYPES):.0%}, false positives {best['false_positive']:.0%}, "
        f"model {model_name(args.mode)}]"
    )
    print("Confirm it on the test split later (issues #14 and #15). Do not change it after seeing test results.")


if __name__ == "__main__":
    main()
