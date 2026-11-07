# Person A: Cloud infrastructure

This is your own README on the `person-a-infra` branch. It lists your tasks, the tools you need, and the rules to follow.

- **Branch:** `person-a-infra`
- **Your folder:** `infra/` (this README lives here). You own Terraform or SAM files and the gateway Lambda handler.
- **Your issues:** #1 to #5, plus the shared rehearsal issue #23
- **Project overview:** see the README on `main`

## Your tasks at a glance

| Issue | Hours | Task | Priority |
| --- | --- | --- | --- |
| #1 | 0-2 | IaC skeleton; chat through API Gateway, Lambda and Bedrock | Critical |
| #2 | 2-5 | DynamoDB tables and per-session canaries | High |
| #3 | 5-9 | Wire the checks into the Lambda | High |
| #4 | 9-12 | SNS email alerts and session blocklist | High |
| #5 | 12-14 | One-command deploy and billing alarm | Medium |

## Task details

### #1 IaC skeleton; chat through API Gateway, Lambda and Bedrock

- **Time window:** hours 0-2 of the 16-hour build
- **Priority:** Critical. Everything else depends on a working gateway, so it must not slip.
- **Tools needed:** Terraform or AWS SAM, AWS CLI, Python Lambda, Bedrock model access
- **Depends on:** Bedrock model access enabled in the AWS account
- **Done when:** A chat request returns a model reply through the gateway
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/1

### #2 DynamoDB tables and per-session canaries

- **Time window:** hours 2-5 of the 16-hour build
- **Priority:** High. Per-session canaries are core to detection and to finding which session leaked.
- **Tools needed:** DynamoDB, boto3, Python `secrets` for random tokens
- **Depends on:** A1
- **Done when:** Each new session gets its own canary stored in DynamoDB, and alert records can be written
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/2

### #3 Wire the checks into the Lambda

- **Time window:** hours 5-9 of the 16-hour build
- **Priority:** High. Nothing is detected until the checks run inside the gateway.
- **Tools needed:** Python, the check interface from B1, pytest
- **Depends on:** B1 (check interface), B2 (checks)
- **Done when:** Every reply passes through the checks before returning, and flagged replies are withheld
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/3

### #4 SNS email alerts and session blocklist

- **Time window:** hours 9-12 of the 16-hour build
- **Priority:** High. The alert and the block are part of the live demo.
- **Tools needed:** SNS, EventBridge, DynamoDB
- **Depends on:** A3
- **Done when:** A flagged leak sends an email and the session is blocked on its next request
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/4

### #5 One-command deploy and billing alarm

- **Time window:** hours 12-14 of the 16-hour build
- **Priority:** Medium. Shows judges the build is reproducible and protects against surprise cost.
- **Tools needed:** Terraform or SAM, CloudWatch billing alarm, a short Makefile or deploy script
- **Depends on:** A1 to A4
- **Done when:** The whole system deploys from a clean account with one command, and a billing alarm is set
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/5

## Shared task for everyone

### #23 Rehearse the demo twice

- **Time window:** hours 14-16 of the 16-hour build
- **Priority:** High. A rehearsed demo is what the judges actually see.
- **Tools needed:** A timer, a laptop on the venue Wi-Fi, and a pre-recorded backup video of the demo in case something fails live
- **Depends on:** All other tasks, especially the demo script (D5) and the results slide (C6)
- **Done when:** The demo runs in two minutes without edits.
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/23

## What you depend on, and what others depend on you for

- **You need from B:** the check interface and the protected prompt (B1), then the checks (B2), so you can wire them into the Lambda (A3).
- **You give to D:** the chat API endpoint (A1) and a read endpoint for alerts (A4). Tell D the URLs as soon as they exist.
- **You give to C:** a working gateway (A3) so the evaluation can run against it.

## Tools to set up first (everyone)

- A single AWS account for the team, with the AWS CLI configured for anyone who deploys
- Amazon Bedrock model access enabled in the account for the chat model and an embeddings model (do this first; it can take time)
- Git and access to this GitHub repo (accept the collaborator invite)
- Python 3 with `boto3` and `pytest`
- Terraform or AWS SAM, whichever Person A picks

## Working on this branch

1. Get the repo: `git clone https://github.com/tnguyen23dotcom/GullHack-P2026.git`, then `git checkout person-a-infra`.
2. Before you start, and every few hours, bring in the latest work: `git fetch origin` then `git merge origin/main`.
3. Give your AI agent the task text from this README or the issue, and tell it to stay inside `infra/`.
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
