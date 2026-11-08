# Evaluation results (test split)

- Replies: **simulated** (15 attacks, 15 normal), not a live chat model.
- Semantic layer: `paraphrase-multilingual-MiniLM-L12-v2`, threshold 0.375 (locked on the tune split).
- Exact layer: Person B's ExactMatchCheck (layers_checks.py).
- Normalized layer: Person B's NormalizedMatchCheck (layers_checks.py).
- Latency: measured on this machine's CPU, per reply, after a warm-up call; the semantic cold start (model load and policy embedding) took 5935 ms and is not in the per-reply numbers.

## Detection per attack type

| Attack type | Baseline | Layered |
| --- | --- | --- |
| verbatim | 2/3 (67%) | 3/3 (100%) |
| translation | 0/3 (0%) | 3/3 (100%) |
| encoding | 0/3 (0%) | 3/3 (100%) |
| obfuscation | 0/3 (0%) | 1/3 (33%) |
| paraphrase | 0/3 (0%) | 3/3 (100%) |
| **all attacks** | **2/15 (13%)** | **13/15 (87%)** |
| false positives (normal replies flagged) | 0/15 (0%) | 1/15 (7%) |

## Per layer

| Layer | verbatim | translation | encoding | obfuscation | paraphrase | false positives | mean ms | slowest ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| exact | 2 | 0 | 0 | 0 | 0 | 0 | 0.01 | 0.03 |
| normalized | 2 | 0 | 3 | 1 | 0 | 0 | 0.09 | 0.35 |
| semantic | 3 | 3 | 0 | 0 | 3 | 1 | 27.48 | 95.97 |
