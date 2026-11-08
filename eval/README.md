# Person C: Semantic check and evaluation

This is your own README on the `person-c-eval` branch. It lists your tasks, the tools you need, and the rules to follow.

- **Branch:** `person-c-eval`
- **Your folder:** `eval/` (this README lives here). You own the attack and normal-chat sets, the embeddings, the semantic check and the evaluation script.
- **Your issues:** #11 to #16, plus the shared rehearsal issue #23
- **Project overview:** see the README on `main`

## Your tasks at a glance

| Issue | Hours | Task | Priority |
| --- | --- | --- | --- |
| #11 | 0-2 | Write the attack set and normal-chat set | High |
| #12 | 2-5 | Chunk the protected prompt and build embeddings | High |
| #13 | 5-9 | Semantic check and threshold | Critical |
| #14 | 9-12 | Baseline vs layered evaluation script | Critical |
| #15 | 12-14 | Run the evaluation and record the rates | Critical |
| #16 | 14-16 | Results slide | High |

## Task details

### #11 Write the attack set and normal-chat set

- **Time window:** hours 0-2 of the 16-hour build
- **Priority:** High. Both the evaluation and the demo need the attack set.
- **Tools needed:** A text or JSON file; an AI chatbot to help brainstorm variants
- **Depends on:** None
- **Done when:** About 5 variants of each of 5 attack types and about 25 normal chats are in the repo
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/11

### #12 Chunk the protected prompt and build embeddings

- **Time window:** hours 2-5 of the 16-hour build
- **Priority:** High. The semantic check cannot work without the embeddings.
- **Tools needed:** Bedrock embeddings, boto3, numpy
- **Depends on:** B1 (the prompt), Bedrock access
- **Done when:** Prompt chunks have stored embeddings
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/12

### #13 Semantic check and threshold

- **Time window:** hours 5-9 of the 16-hour build
- **Priority:** Critical. This is the core of the project and it decides the hour-9 gate.
- **Tools needed:** numpy for cosine similarity; a small script to sweep thresholds
- **Depends on:** C1, C2
- **Done when:** Paraphrase and translation leaks are flagged on the test set
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/13

### #14 Baseline vs layered evaluation script

- **Time window:** hours 9-12 of the 16-hour build
- **Priority:** Critical. The measured before and after comparison is the strongest proof.
- **Tools needed:** Python; pytest or a plain script; optionally pandas
- **Depends on:** A3, C1, C3
- **Done when:** One script reports detection rate per attack type, false-positive rate and latency for both setups
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/14

### #15 Run the evaluation and record the rates

- **Time window:** hours 12-14 of the 16-hour build
- **Priority:** Critical. These are the numbers the whole pitch is built on.
- **Tools needed:** The evaluation script; a spreadsheet or Markdown table for results
- **Depends on:** C4
- **Done when:** Final numbers are recorded for the slide
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/15

### #16 Results slide

- **Time window:** hours 14-16 of the 16-hour build
- **Priority:** High. Presents the measured results to the judges.
- **Tools needed:** Google Slides or PowerPoint
- **Depends on:** C5
- **Done when:** The slide shows baseline versus layered detection and the false-positive rate
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/16

## Shared task for everyone

### #23 Rehearse the demo twice

- **Time window:** hours 14-16 of the 16-hour build
- **Priority:** High. A rehearsed demo is what the judges actually see.
- **Tools needed:** A timer, a laptop on the venue Wi-Fi, and a pre-recorded backup video of the demo in case something fails live
- **Depends on:** All other tasks, especially the demo script (D5) and the results slide (C6)
- **Done when:** The demo runs in two minutes without edits.
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/23

## What you depend on, and what others depend on you for

- **You need from B:** the protected prompt (B1) to chunk and embed (C2), and the check interface so your semantic check plugs in.
- **You need from A:** Bedrock model access in the AWS account, and a working gateway (A3) for the evaluation (C4).
- **You give to B and D:** the attack set (C1) for tests and the demo, and the final numbers (C5) for the slides.

## Tools to set up first (everyone)

- A single AWS account for the team, with the AWS CLI configured for anyone who deploys
- Amazon Bedrock model access enabled in the account for the chat model and an embeddings model (do this first; it can take time)
- Git and access to this GitHub repo (accept the collaborator invite)
- Python 3 with `boto3` and `pytest`
- Terraform or AWS SAM, whichever Person A picks

## Working on this branch

1. Get the repo: `git clone https://github.com/tnguyen23dotcom/GullHack-P2026.git`, then `git checkout person-c-eval`.
2. Before you start, and every few hours, bring in the latest work: `git fetch origin` then `git merge origin/main`.
3. Give your AI agent the task text from this README or the issue, and tell it to stay inside `eval/`.
4. Read `git diff` before you commit. You are responsible for what the agent wrote.
5. Commit small and often, with the issue number in the message (for example `Fix #1: add API Gateway and Lambda`), and push your branch.
6. When a task is done, open a pull request into `main` that says `Closes #<issue number>`. A teammate reviews and merges it.

## Rules to avoid

- **Don't push straight to `main`.** Work on your branch and open a pull request. One agent's mistake on `main` breaks everyone.
- **Don't edit files outside your own folder** without telling the owner first. Agents that "helpfully" refactor other people's code cause merge conflicts.
- **Never commit secrets.** No AWS keys, tokens, `.env` files, or `*.tfstate` files. Tell your AI agent this too, because agents sometimes write credentials into config files.
- **Don't give your AI agent admin AWS access.** Use the team account with limited permissions, and read the Terraform plan (or SAM changeset) before anything is applied. An agent can create real resources that cost money.
- **Don't let your AI agent change shared interfaces** (the check interface, API URLs, table names) without agreeing with the team first.
- **Don't force-push** (`git push --force`) and don't rewrite history on a branch someone else uses.
- **Don't commit generated or heavy files:** `node_modules/`, build output, `.terraform/`, large data files.
- **Don't use real data.** Decoy secrets and fake data only. No real credentials, personal data or private information anywhere in the project.
- **Don't attack anything except our own chatbot.** Attack prompts are harmless text-extraction tests against our own bot.
- **Don't sit blocked in silence.** If a task depends on someone else's work that isn't ready, say so in the issue or the team chat.
