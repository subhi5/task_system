# Dashboard server

## Run locally
```
node server.js            # http://127.0.0.1:8787/
node server.js adduser <username> <password ≥ 8 chars> [admin|employee] [Full Name]
node server.js passwd  <username> <new password>
```
Workspaces and their Plane API keys live in `config.json` (server only). Accounts and the session key live in `data/`; neither is ever sent to the browser or to git — back them up. Dashboard-only data lives in `db/database.json` (+ `db/files/`), kept in git. Planning fields (categories, status, order, version state, module department) live in Plane.

## On a VPS
1. Copy `server.js`, `Web Task.html`, `config.json`, `data/`, `db/` to the server (Node 18+ only, no `npm install`).
2. In `config.json` set `"host": "127.0.0.1"`, `"secureCookie": true`, `"trustProxy": true`.
3. Put HTTPS in front (Caddy shown; nginx works the same):
   ```
   dash.example.com {
       reverse_proxy 127.0.0.1:8787
   }
   ```
4. Keep it running with systemd or `pm2 start server.js --name dashboard`.
5. Open only ports 80/443 on the firewall. Never expose 8787 directly.

## Claude access tokens (MCP)
Members → Dashboard accounts → key icon → **Create token**. The token is shown once; copy the setup command it gives:
```
claude mcp add --transport http swb-dashboard https://dash.example.com/mcp --header "Authorization: Bearer dash_…"
```
- Employee token: list/create/update/comment/assign tasks in their projects; modules and versions read-only.
- Project admin token (an employee ticked under "Project admin for"): in those projects also create modules and versions and move tasks between them; `list_projects` marks them `you_manage: true`.
- Admin token: all of that in every project.
- No token can manage accounts or workspaces. Revoking a token, or disabling the account, cuts it off at once.

## Security notes
- Rotate the Plane API keys once before going live (they were stored in older copies of the HTML).
- Delete `Web Task - Copy.html` and the `*.backup*.html` files from anything you deploy.
- 6 wrong passwords lock a username+IP pair for 10 minutes; resetting a password signs that person out everywhere.
- Plane allows 60 requests/minute per key, so the server shares identical reads for 20 seconds.
