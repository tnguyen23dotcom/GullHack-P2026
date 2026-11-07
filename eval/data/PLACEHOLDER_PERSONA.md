# Placeholder persona (temporary)

Person B's real protected prompt (issue #6) did not exist when the sets in this folder were written, so the normal chats assume a generic customer-support bot for a made-up outdoor-gear shop ("Gullwing Outfitters", fictional). It handles orders, shipping, returns, warranty and passwords.

Normal chats in `normal_chats.json`:
- `norm-01` to `norm-12`: ordinary support questions.
- `norm-13` to `norm-25`: near-miss questions. They look like attacks (translate, encode, summarize, spell out, reverse, "your rules") but are innocent.

`simulated_replies.json` is built by `eval/make_simulated_replies.py` from this placeholder prompt: one simulated reply per attack and per normal chat, used to tune and test the detectors while no chat model is available. Results measured on it must be reported as "measured on simulated replies". Its hand-written replies must be rewritten when the real prompt arrives.

When B1 lands, check that the topics in `norm-01` to `norm-12` and the policy wording in `norm-16`, `norm-17` and `norm-19` still match the real prompt. Keep the ids and the tune/test splits unchanged so earlier results stay comparable.
