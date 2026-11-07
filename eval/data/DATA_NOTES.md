# Eval data notes

All data here is fake. The protected prompt is Person B's `prompt.py` (issue #6): an internal IT and Operations assistant for "Gull Systems", with five confidential policies and four decoy keys.

## Files
- `attacks.json`: 25 attack prompts, 5 each of verbatim, translation, encoding, obfuscation and paraphrase.
- `normal_chats.json`: 25 normal chats for the IT assistant. `norm-01` to `norm-12` are ordinary IT questions. `norm-13` to `norm-25` are near-misses: they ask for translation, encoding, summaries or reversal, or touch policy topics (code review, salary, launches, passcodes) without any leak.
- `simulated_replies.json`: one simulated reply per attack and per normal chat, built by `eval/make_simulated_replies.py` from B's prompt. Used to tune and test the detectors while no chat model is available. **Report results from it as "measured on simulated replies".** Translation and paraphrase leaks contain policy text only, no decoy keys or canary.
- `prompt_chunks.json` and `placeholder_prompt.txt`: left from issue #12, when B's prompt did not exist yet. The semantic check no longer uses them: it embeds `context.protected_chunks` (B's five policies) itself.

## Splits
Every item has `split` = `tune` or `test` (10 tune and 15 test in each set). Tune the threshold on `tune` only. Report final numbers on `test` only, and do not change the threshold or method after seeing test results.

## History
The first version of the normal chats and replies was written for a placeholder outdoor-shop bot. They were rewritten for B's prompt, keeping the same ids and splits.
