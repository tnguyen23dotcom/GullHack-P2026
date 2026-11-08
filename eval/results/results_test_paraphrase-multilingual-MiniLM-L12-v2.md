# Evaluation results (test split)

- Replies: **simulated** (15 attacks, 15 normal), not a live chat model.
- Semantic layer: `paraphrase-multilingual-MiniLM-L12-v2`, threshold 0.375 (locked on the tune split).
- Exact layer: reference exact-match check in eval/ (Person B's exact check not pushed yet).
- Normalized layer: **not available yet** (Person B, issue #7).
- Latency: measured on this machine's CPU, per reply, after a warm-up call; the semantic cold start (model load and policy embedding) took 7603 ms and is not in the per-reply numbers.

## Detection per attack type

| Attack type | Baseline | Layered |
| --- | --- | --- |
| verbatim | 2/3 (67%) | 3/3 (100%) |
| translation | 0/3 (0%) | 3/3 (100%) |
| encoding | 0/3 (0%) | 0/3 (0%) |
| obfuscation | 0/3 (0%) | 0/3 (0%) |
| paraphrase | 0/3 (0%) | 3/3 (100%) |
| **all attacks** | **2/15 (13%)** | **9/15 (60%)** |
| false positives (normal replies flagged) | 0/15 (0%) | 1/15 (7%) |

## Per layer

| Layer | verbatim | translation | encoding | obfuscation | paraphrase | false positives | mean ms | slowest ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| exact | 2 | 0 | 0 | 0 | 0 | 0 | 0.01 | 0.02 |
| semantic | 3 | 3 | 0 | 0 | 3 | 1 | 52.65 | 189.97 |

Not available yet, so not included: normalized. The layered numbers are a lower bound.
