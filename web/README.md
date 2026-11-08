# Person D: Dashboard, demo and docs

This is your own README on the `person-d-web` branch. It lists your tasks, the tools you need, and the rules to follow.

- **Branch:** `person-d-web`
- **Your folder:** `web/` (this README lives here). You own the chat page, the dashboard, the demo script and the slides.
- **Your issues:** #17 to #22, plus the shared rehearsal issue #23
- **Project overview:** see the README on `main`

## Your tasks at a glance

| Issue | Hours | Task | Priority |
| --- | --- | --- | --- |
| #17 | 0-2 | Repo, README and GitHub issues | Low |
| #18 | 2-5 | Chat UI | High |
| #19 | 5-9 | Dashboard with mock data | Medium |
| #20 | 9-12 | Connect the dashboard to live alerts | Medium |
| #21 | 12-14 | Demo script | High |
| #22 | 14-16 | Technology-choices slide | High |

## Task details

### #17 Repo, README and GitHub issues

- **Time window:** hours 0-2 of the 16-hour build
- **Priority:** Low. Already done in setup.
- **Tools needed:** GitHub
- **Depends on:** None
- **Done when:** Repo has the README and one issue per task (done in setup)
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/17

### #18 Chat UI

- **Time window:** hours 2-5 of the 16-hour build
- **Priority:** High. The demo needs a chat page for the attacks.
- **Tools needed:** Plain HTML, CSS and JavaScript; S3 and CloudFront
- **Depends on:** A1 (the API endpoint)
- **Done when:** Users can chat with the bot from a web page hosted on S3 and CloudFront
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/18

### #19 Dashboard with mock data

- **Time window:** hours 5-9 of the 16-hour build
- **Priority:** Medium. Lets the dashboard be built before live alerts exist.
- **Tools needed:** Plain HTML and JavaScript; optionally Chart.js
- **Depends on:** None
- **Done when:** The dashboard shows a leak feed from sample data
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/19

### #20 Connect the dashboard to live alerts

- **Time window:** hours 9-12 of the 16-hour build
- **Priority:** Medium. A live feed makes the demo stronger, but a results table works without it.
- **Tools needed:** fetch calls to an API Gateway endpoint that reads DynamoDB
- **Depends on:** A4; Person A must expose a read endpoint for alerts
- **Done when:** A flagged leak appears on the dashboard
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/20

### #21 Demo script

- **Time window:** hours 12-14 of the 16-hour build
- **Priority:** High. A rehearsed script keeps the demo to two minutes.
- **Tools needed:** A shared document; a screen recorder for a backup video
- **Depends on:** A3, A4
- **Done when:** A two-minute script covers five attacks, baseline vs layered, and the session block
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/21

### #22 Technology-choices slide

- **Time window:** hours 14-16 of the 16-hour build
- **Priority:** High. Judges score clear reasons behind technology choices.
- **Tools needed:** Google Slides or PowerPoint; the architecture table in the README
- **Depends on:** None
- **Done when:** The slide explains each service and why it was chosen
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/22

## Shared task for everyone

### #23 Rehearse the demo twice

- **Time window:** hours 14-16 of the 16-hour build
- **Priority:** High. A rehearsed demo is what the judges actually see.
- **Tools needed:** A timer, a laptop on the venue Wi-Fi, and a pre-recorded backup video of the demo in case something fails live
- **Depends on:** All other tasks, especially the demo script (D5) and the results slide (C6)
- **Done when:** The demo runs in two minutes without edits.
- **Issue:** https://github.com/tnguyen23dotcom/GullHack-P2026/issues/23

## What you depend on, and what others depend on you for

- **You need from A:** the chat API endpoint (A1) for the chat UI, and a read endpoint for alerts (A4) for the live dashboard (D4). Ask A for the URLs.
- **You need from C:** the final numbers (C5) for the results slide, and from everyone the facts for the demo script.
- **You give to everyone:** the demo script (D5) so the team can rehearse it (issue #23).

## API endpoints from Person A

- **Chat API (A1):** `POST https://94v13m7mj1.execute-api.us-east-1.amazonaws.com/chat` with a JSON body `{"session_id": "...", "message": "..."}`. If the API is redeployed, get the current URL from Person A or run `terraform output` in `infra/terraform`.
- **Alerts read endpoint (A4):** not deployed yet.

## Tools to set up first (everyone)

- A single AWS account for the team, with the AWS CLI configured for anyone who deploys
- Amazon Bedrock model access enabled in the account for the chat model and an embeddings model (do this first; it can take time)
- Git and access to this GitHub repo (accept the collaborator invite)
- Python 3 with `boto3` and `pytest`
- Terraform or AWS SAM, whichever Person A picks

## Working on this branch

1. Get the repo: `git clone https://github.com/tnguyen23dotcom/GullHack-P2026.git`, then `git checkout person-d-web`.
2. Before you start, and every few hours, bring in the latest work: `git fetch origin` then `git merge origin/main`.
3. Give your AI agent the task text from this README or the issue, and tell it to stay inside `web/`.
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
