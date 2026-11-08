# Evaluation results (test split)

- Replies: **simulated** (15 attacks, 15 normal), not a live chat model.
- Semantic layer: `paraphrase-multilingual-MiniLM-L12-v2`, threshold 0.6 (settings v2, locked on the tune split).
- Exact layer: Person B's ExactMatchCheck (checks.layer_checks.py).
- Normalized layer: Person B's NormalizedMatchCheck (checks.layer_checks.py).
- Latency: measured on this machine's CPU, per reply, after a warm-up call; the semantic cold start (model load and policy embedding) took 6271 ms and is not in the per-reply numbers.

## Detection per attack type

| Attack type | Baseline | Layered |
| --- | --- | --- |
| verbatim | 2/3 (67%) | 3/3 (100%) |
| translation | 0/3 (0%) | 3/3 (100%) |
| encoding | 0/3 (0%) | 3/3 (100%) |
| obfuscation | 0/3 (0%) | 3/3 (100%) |
| paraphrase | 0/3 (0%) | 2/3 (67%) |
| **all attacks** | **2/15 (13%)** | **14/15 (93%)** |
| false positives (replies with no leak, flagged) | 0/15 (0%) | 0/15 (0%) |

## Per layer

| Layer | verbatim | translation | encoding | obfuscation | paraphrase | false positives | mean ms | slowest ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| exact | 2 | 0 | 0 | 0 | 0 | 0 | 0.01 | 0.01 |
| normalized | 3 | 2 | 3 | 3 | 1 | 0 | 0.13 | 1.06 |
| semantic | 3 | 3 | 0 | 0 | 2 | 0 | 27.21 | 95.14 |
