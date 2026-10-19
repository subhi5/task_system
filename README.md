# Task System — Plane dashboard

A self-hosted dashboard on top of [Plane](https://plane.so): tasks (table / board / timeline), versions and modules, a weekly/monthly report, private sticky notes, a per-version file & link library with tags, a task detail panel (rich description, attachments, comments), dashboard accounts with roles (admin, project admin, employee), and an MCP endpoint so each person can work from Claude.

Single Node.js file, no `npm install` (Node 18+).

## Run locally
```
copy config.example.json config.json   # then put your Plane workspace slug and API key in it
node server.js adduser <username> <password ≥ 8 chars> admin "Your Name"
node server.js                           # http://127.0.0.1:8787/
```
On Windows you can double-click `Start Web Task.bat`.

Deployment, roles and Claude/MCP tokens: see [DEPLOY.md](DEPLOY.md).

## Where the data lives
- **Plane** — tasks, modules, versions, members, plus the dashboard's planning fields: project category, sections, status and drag order; version state; module department and order (kept in Plane's hidden `external_source` / `external_id` fields).
- **`db/`** (in git — keep this repo **private**) — what Plane cannot hold: tasks and module leads given to dashboard-only people, private sticky notes, the uploaded-file list and the files. Double-click `Save data to GitHub.bat` to commit and push it; it refuses while the repo is public.
- **`data/` and `config.json`** (never in git) — accounts with password hashes, the session key and the Plane API key. Back these up separately.
