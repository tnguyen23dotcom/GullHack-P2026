# Evaluation results (fresh split)

- Replies: **fresh held-out set** built after all settings were locked: 59 valid items (31 leaks, 28 normal). Translation and paraphrase leaks were written by us.amazon.nova-2-lite-v1:0; verbatim, encoding and obfuscation leaks by code (known techniques); normal replies by the same model with Person B's prompt. Left out as invalid: fresh-para-02.
- Semantic layer: `paraphrase-multilingual-MiniLM-L12-v2`, threshold 0.6 (settings v2, locked on the tune split).
- Exact layer: Person B's ExactMatchCheck (checks.layer_checks.py).
- Normalized layer: Person B's NormalizedMatchCheck (checks.layer_checks.py).
- Other layers: Fuzzy (#9): Person B's FuzzyMatchCheck; policy facts (layer 2b): Person B's PolicyFactCheck.
- Latency: measured on this machine's CPU, per reply, after a warm-up call; the semantic cold start (model load and policy embedding) took 6153 ms and is not in the per-reply numbers.

## Detection per attack type

| Attack type | Baseline | Layered | Full |
| --- | --- | --- | --- |
| verbatim | 3/6 (50%) | 6/6 (100%) | 6/6 (100%) |
| translation | 0/6 (0%) | 6/6 (100%) | 6/6 (100%) |
| encoding | 0/6 (0%) | 6/6 (100%) | 6/6 (100%) |
| obfuscation | 1/6 (17%) | 5/6 (83%) | 5/6 (83%) |
| paraphrase | 0/5 (0%) | 5/5 (100%) | 5/5 (100%) |
| spontaneous | 0/2 (0%) | 2/2 (100%) | 2/2 (100%) |
| **all attacks** | **4/31 (13%)** | **30/31 (97%)** | **30/31 (97%)** |
| false positives (replies with no leak, flagged) | 0/28 (0%) | 0/28 (0%) | 1/28 (4%) |

## Per layer

| Layer | verbatim | translation | encoding | obfuscation | paraphrase | spontaneous | false positives | mean ms | slowest ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| exact | 3 | 0 | 0 | 1 | 0 | 0 | 0 | 0.14 | 0.45 |
| normalized | 6 | 4 | 5 | 5 | 4 | 2 | 0 | 0.73 | 3.40 |
| fuzzy | 5 | 3 | 1 | 2 | 4 | 2 | 0 | 18.20 | 71.61 |
| facts | 3 | 5 | 2 | 1 | 5 | 1 | 1 | 0.26 | 0.88 |
| semantic | 3 | 6 | 1 | 1 | 5 | 1 | 0 | 54.43 | 209.10 |
