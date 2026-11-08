# Evaluation results (big split)

- Replies: **big held-out set** built after all settings were locked: 99 valid items (59 leaks, 40 normal). Translation and paraphrase leaks were written by us.amazon.nova-2-lite-v1:0; verbatim, encoding and obfuscation leaks by code (known techniques); normal replies by the same model with Person B's prompt. Left out as invalid: big-indi-03.
- Semantic layer: `paraphrase-multilingual-MiniLM-L12-v2`, threshold 0.6 (settings v2, locked on the tune split).
- Exact layer: Person B's ExactMatchCheck (checks.layer_checks.py).
- Normalized layer: Person B's NormalizedMatchCheck (checks.layer_checks.py).
- Other layers: Fuzzy (#9): Person B's FuzzyMatchCheck; policy facts (layer 2b): Person B's PolicyFactCheck.
- Latency: measured on this machine's CPU, per reply, after a warm-up call; the semantic cold start (model load and policy embedding) took 6508 ms and is not in the per-reply numbers.

## Detection per attack type

| Attack type | Baseline | Layered | Full |
| --- | --- | --- | --- |
| verbatim | 3/5 (60%) | 5/5 (100%) | 5/5 (100%) |
| translation | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |
| encoding | 0/13 (0%) | 4/13 (31%) | 4/13 (31%) |
| obfuscation | 0/12 (0%) | 5/12 (42%) | 6/12 (50%) |
| paraphrase | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |
| indirect | 0/9 (0%) | 9/9 (100%) | 9/9 (100%) |
| **all attacks** | **3/59 (5%)** | **43/59 (73%)** | **44/59 (75%)** |
| false positives (replies with no leak, flagged) | 0/40 (0%) | 1/40 (2%) | 2/40 (5%) |

## Per layer

| Layer | verbatim | translation | encoding | obfuscation | paraphrase | indirect | false positives | mean ms | slowest ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| exact | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0.13 | 0.49 |
| normalized | 5 | 6 | 3 | 5 | 9 | 9 | 0 | 0.68 | 3.40 |
| fuzzy | 5 | 6 | 0 | 2 | 9 | 9 | 0 | 15.91 | 57.98 |
| facts | 2 | 9 | 1 | 2 | 10 | 8 | 2 | 0.21 | 0.77 |
| semantic | 2 | 9 | 1 | 0 | 10 | 9 | 1 | 43.62 | 140.82 |
