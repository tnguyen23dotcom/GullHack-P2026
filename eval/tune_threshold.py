"""Pick the semantic threshold using the TUNE split only (issue #13).

What it does: for every simulated reply in the tune split it finds the highest similarity between
any reply sentence and any prompt chunk. Then it tries many thresholds and prints, for each one,
the detection rate per attack type and the false-positive rate on normal replies.

The TEST split is never read here. It is kept for the final numbers (issues #14 and #15).
Replies are SIMULATED (see make_simulated_replies.py), so say so when you report results.

Examples (run from the repo root; build the chunk embeddings first, in the same mode):
  python3 eval/tune_threshold.py --mode local         # FAKE embedder: only tests the pipeline
  python3 eval/tune_threshold.py --mode local-model   # real local model (pip install sentence-transformers)
  python3 eval/tune_threshold.py --mode bedrock       # Bedrock: embeds every reply sentence, costs a little
"""
import argparse
import json
from pathlib import Path

from embedder import DEFAULT_REGION
from semantic_check import load_chunk_embeddings, score_reply

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


def recommend(rows, max_fp, focus_types):
    """Best threshold: highest average detection on focus_types with false positives <= max_fp.

    Ties go to the higher threshold (the more cautious one). Returns None if nothing qualifies.
    """
    allowed = [r for r in rows if r["false_positive"] <= max_fp]
    if not allowed:
        return None
    return max(allowed, key=lambda r: (sum(r["detection"][t] for t in focus_types) / len(focus_types), r["threshold"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["local", "local-model", "bedrock"], default="local")
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--max-fp", type=float, default=0.10, help="largest false-positive rate you accept (default 0.10)")
    args = parser.parse_args()

    chunk_vectors, chunk_ids, model = load_chunk_embeddings(args.mode)
    replies = [r for r in json.loads((DATA / "simulated_replies.json").read_text(encoding="utf-8")) if r["split"] == "tune"]
    print(f"embedding model: {model}   tune replies: {len(replies)} (test split NOT used)")
    if args.mode == "local":
        print("WARNING: FAKE embedder. It matches shared words, not meaning. Pipeline test only.")

    scores_by_type = {t: [] for t in ATTACK_TYPES}
    normal_scores = []
    for item in replies:
        result = score_reply(item["reply"], chunk_vectors, chunk_ids, mode=args.mode, region=args.region)
        (normal_scores if item["type"] == "normal" else scores_by_type[item["type"]]).append(result["score"])

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

    best = recommend(rows, args.max_fp, FOCUS_TYPES)
    if best is None:
        print(f"\nNo threshold keeps false positives at or below {args.max_fp:.0%} on the tune split.")
    else:
        focus = sum(best["detection"][t] for t in FOCUS_TYPES) / len(FOCUS_TYPES)
        print(
            f"\nRECOMMENDED threshold (tune split only): {best['threshold']:.3f}  "
            f"[focus-type detection {focus:.0%}, false positives {best['false_positive']:.0%}, model {model}]"
        )
        print("Confirm it on the test split later (issues #14 and #15). Do not change it after seeing test results.")


if __name__ == "__main__":
    main()
