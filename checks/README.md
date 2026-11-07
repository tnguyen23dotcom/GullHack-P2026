# Person B: Checks

This is your own README on the `person-b-checks` branch. It lists your tasks, the tools you need, and the rules to follow.

- **Branch:** `person-b-checks`
- **Your folder:** `checks/` (this README lives here). You own the decoy-secret system prompt and the exact, normalized and fuzzy check modules.
- **Your issues:** #6 to #10, plus the shared rehearsal issue #23
- **Project overview:** see the README on `main`

## Your tasks at a glance

| Issue | Hours | Task | Priority |
| --- | --- | --- | --- |
| #6 | 0-2 | System prompt with decoy secrets; shared check interface | High |
| #7 | 2-5 | Exact and normalized checks | High |
| #8 | 5-9 | Tests on attack variants | Medium |
| #9 | 9-12 | Fuzzy check (stretch) | Low |
| #10 | 12-14 | Fix misses found in measuring | Medium |

## Task details

### #6 System prompt with decoy secrets; shared check interface

- **Time window:** hours 0-2 of the 16-hour build
- **Priority:** High. Unblocks Persons A and C, who need the prompt and the interface.
- **Tools needed:** Python, a text editor; fake keys written by hand
- **Depends on:** None
- **Done when:** A prompt with fake secrets exists and every check follows one common interface
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/6

### #7 Exact and normalized checks

- **Time window:** hours 2-5 of the 16-hour build
- **Priority:** High. Core detection for verbatim and encoded leaks.
- **Tools needed:** Python standard library (base64, codecs, unicodedata, re)
- **Depends on:** B1
- **Done when:** Verbatim, base64 and dashed-letter leaks are flagged
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/7

### #8 Tests on attack variants

- **Time window:** hours 5-9 of the 16-hour build
- **Priority:** Medium. Catches regressions; not needed for the demo itself.
- **Tools needed:** pytest
- **Depends on:** B2, C1
- **Done when:** Automated tests cover each attack type for the core checks
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/8

### #9 Fuzzy check (stretch)

- **Time window:** hours 9-12 of the 16-hour build
- **Priority:** Low. Stretch goal; skip it if the schedule is behind.
- **Tools needed:** rapidfuzz or difflib
- **Depends on:** B1
- **Done when:** Partial and lightly edited leaks are flagged, if time allows
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/9

### #10 Fix misses found in measuring

- **Time window:** hours 12-14 of the 16-hour build
- **Priority:** Medium. Improves the final numbers after the first measurement.
- **Tools needed:** Python, the evaluation output from C
- **Depends on:** C4, C5
- **Done when:** Leaks missed in the evaluation are fixed or documented
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/10

## Shared task for everyone

### #23 Rehearse the demo twice

- **Time window:** hours 14-16 of the 16-hour build
- **Priority:** High. A rehearsed demo is what the judges actually see.
- **Tools needed:** A timer, a laptop on the venue Wi-Fi, and a pre-recorded backup video of the demo in case something fails live
- **Depends on:** All other tasks, especially the demo script (D5) and the results slide (C6)
- **Done when:** The demo runs in two minutes without edits.
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/23

## What you depend on, and what others depend on you for

- **You give to A and C first:** the shared check interface and the protected prompt (B1). Write the interface down in this README before hour 2 so everyone builds against it.
- **You need from C:** the attack set (C1) for your tests (B3), and the evaluation output (C4, C5) to fix misses (B5).
- **C's semantic check must follow your interface**, so it plugs into A's Lambda the same way as your checks.

## Tools to set up first (everyone)

- A single AWS account for the team, with the AWS CLI configured for anyone who deploys
- Amazon Bedrock model access enabled in the account for the chat model and an embeddings model (do this first; it can take time)
- Git and access to this GitHub repo (accept the collaborator invite)
- Python 3 with `boto3` and `pytest`
- Terraform or AWS SAM, whichever Person A picks

## Working on this branch

1. Get the repo: `git clone https://github.com/tnguyen23dotcom/GullHack-P2026.git`, then `git checkout person-b-checks`.
2. Before you start, and every few hours, bring in the latest work: `git fetch origin` then `git merge origin/main`.
3. Give your AI agent the task text from this README or the issue, and tell it to stay inside `checks/`.
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
