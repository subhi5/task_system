// Dashboard server: serves the page, handles logins and roles, and proxies Plane with the API key kept here.
// Also an MCP endpoint (/mcp) so each person can drive their tasks from Claude with a personal access token.
// Run: node server.js   |   Users: node server.js adduser <username> <password> [admin|employee] [Full Name]
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const ROOT = __dirname;
const DATA_DIR = process.env.DASH_DATA || path.join(ROOT, 'data');
const CONFIG_FILE = process.env.DASH_CONFIG || path.join(ROOT, 'config.json');
// data/ (never in git): accounts with password hashes and the session key.
// db/ (kept in git): what Plane cannot hold. Project/version/module planning fields live in Plane itself.
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
const DB_DIR = process.env.DASH_DB || path.join(ROOT, 'db');
const DB_FILE = path.join(DB_DIR, 'database.json');
const FILES_DIR = path.join(DB_DIR, 'files'); // uploaded project/version files, stored by id only
const PAGE_FILE = path.join(ROOT, 'Web Task.html');

const SESSION_MS = 12 * 3600 * 1000;
const CACHE_MS = 20000; // Plane allows 60 req/min per key, so identical reads are shared
const MODULE_TAG_SRC = 'swb-dash-tag'; // same marker the page uses to tie a module to a version
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const UUID_RE = new RegExp(`^${UUID}$`, 'i');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(DB_DIR, { recursive: true });

function readJson(file, fallback) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fallback; }
}
function writeJson(file, value) {
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
    fs.renameSync(tmp, file); // atomic: a crash never leaves a half-written file
}

const config = Object.assign({ port: 8787, host: '127.0.0.1', secureCookie: false, trustProxy: false, planeBase: 'https://api.plane.so', workspaces: [] }, readJson(CONFIG_FILE, {}));
if (process.env.PORT) config.port = Number(process.env.PORT);
if (process.env.HOST) config.host = process.env.HOST;
const saveConfig = () => writeJson(CONFIG_FILE, config);

let secret = '';
try { secret = fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch (e) { /* first run */ }
if (!secret) { secret = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SECRET_FILE, secret); }

let users = readJson(USERS_FILE, []);
const saveUsers = () => writeJson(USERS_FILE, users);
// The database: built once from the older data/*.json files, then one file for everything here.
function loadDb() {
    const db = readJson(DB_FILE, null);
    if (db) return db;
    const old = (name) => readJson(path.join(DATA_DIR, name), {});
    const fresh = { assignments: old('assignments.json'), moduleLeads: old('module-leads.json'), notes: old('notes.json'), files: old('files.json') };
    const oldFiles = path.join(DATA_DIR, 'files');
    if (fs.existsSync(oldFiles) && !fs.existsSync(FILES_DIR)) fs.renameSync(oldFiles, FILES_DIR);
    writeJson(DB_FILE, fresh);
    return fresh;
}
const db = loadDb();
['assignments', 'moduleLeads', 'notes', 'files'].forEach(k => { db[k] = db[k] || {}; });
const saveDb = () => writeJson(DB_FILE, db);
const assignments = db.assignments; // { slug: { issueId: [userId] } } — tasks given to dashboard-only people
const moduleLeads = db.moduleLeads; // { slug: { moduleId: userId } } — module leads who have no Plane account
const fileIndex = db.files; // { slug: [file record] }
const notes = db.notes; // { userId: [note] } — private sticky notes, not tied to any task
const saveAssignments = saveDb;
const NOTE_COLORS = ['yellow', 'pink', 'green', 'blue', 'purple', 'orange'];
const clampNum = (v, lo, hi, d) => { const n = Number(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : d; };
function setNotes(user, list) {
    if (!Array.isArray(list) || list.length > 150) throw fail(400, 'Too many notes (150 max)');
    if (list.some(n => !n || typeof n !== 'object')) throw fail(400, 'Bad note');
    const clean = list.map(n => ({
        id: String((n && n.id) || '').slice(0, 40) || crypto.randomUUID(),
        x: clampNum(n.x, 0, 20000, 40), y: clampNum(n.y, 0, 20000, 40),
        w: clampNum(n.w, 140, 900, 220), h: clampNum(n.h, 100, 900, 180),
        color: NOTE_COLORS.includes(n.color) ? n.color : 'yellow',
        text: String(n.text || '').slice(0, 3000), // 150 notes × 3000 chars (Arabic is 2 bytes each) stays under the 1 MB body limit
        updatedAt: String(n.updatedAt || new Date().toISOString()).slice(0, 30)
    }));
    if (clean.length) notes[user.id] = clean; else delete notes[user.id];
    saveDb();
    return clean;
}

// ---------- Passwords and sessions ----------
async function hashPassword(password, salt) {
    return (await scrypt(password, salt, 64)).toString('hex');
}
async function setPassword(user, password) {
    user.salt = crypto.randomBytes(16).toString('hex');
    user.hash = await hashPassword(password, user.salt);
}
async function checkPassword(user, password) {
    const a = Buffer.from(await hashPassword(password, user.salt), 'hex');
    const b = Buffer.from(user.hash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sign = (data) => crypto.createHmac('sha256', secret).update(data).digest('base64url');
function makeToken(user) {
    const body = Buffer.from(JSON.stringify({ uid: user.id, exp: Date.now() + SESSION_MS, pv: user.hash.slice(0, 12) })).toString('base64url');
    return `${body}.${sign(body)}`;
}
function readCookie(req, name) {
    const hit = String(req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
    return hit ? hit.slice(name.length + 1) : '';
}
function sessionUser(req) {
    const [body, mac] = readCookie(req, 'dash_session').split('.');
    if (!body || !mac) return null;
    const want = Buffer.from(sign(body));
    const got = Buffer.from(mac);
    if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
    try {
        const p = JSON.parse(Buffer.from(body, 'base64url').toString());
        const user = users.find(u => u.id === p.uid);
        // pv ties the session to the current password, so a reset signs the person out everywhere
        return user && user.active && p.exp > Date.now() && p.pv === user.hash.slice(0, 12) ? user : null;
    } catch (e) { return null; }
}
const cookieHeader = (value, maxAge) =>
    `dash_session=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${config.secureCookie ? '; Secure' : ''}`;

// Personal access tokens: only a SHA-256 of each token is stored; the token itself is shown once.
const tokenHash = (t) => crypto.createHash('sha256').update(t).digest('hex');
const lastUseSaved = new Map();
function bearerUser(req) {
    const m = String(req.headers.authorization || '').match(/^Bearer\s+(dash_[A-Za-z0-9_-]{20,})$/);
    if (!m) return null;
    const h = tokenHash(m[1]);
    for (const u of users) {
        const tok = (u.tokens || []).find(t => t.hash === h);
        if (!tok) continue;
        if (!u.active) return null;
        tok.lastUsedAt = new Date().toISOString();
        if (Date.now() - (lastUseSaved.get(tok.id) || 0) > 600000) { lastUseSaved.set(tok.id, Date.now()); saveUsers(); }
        return u;
    }
    return null;
}
const tokenPub = (t) => ({ id: t.id, name: t.name, prefix: t.prefix, createdAt: t.createdAt, lastUsedAt: t.lastUsedAt || null });

const failedLogins = new Map(); // ip|username -> { n, until }
function loginBlocked(key) {
    const f = failedLogins.get(key);
    return !!f && f.n >= 6 && f.until > Date.now();
}
function noteLogin(key, ok) {
    if (ok) { failedLogins.delete(key); return; }
    if (failedLogins.size > 1000) for (const [k, v] of failedLogins) if (v.until <= Date.now()) failedLogins.delete(k);
    const f = failedLogins.get(key);
    failedLogins.set(key, { n: (f && f.until > Date.now() ? f.n : 0) + 1, until: Date.now() + 10 * 60 * 1000 });
}

// ---------- Helpers ----------
const pub = (u) => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: u.active, access: u.access || {}, manage: u.manage || {}, createdAt: u.createdAt, tokenCount: (u.tokens || []).length });
// Project admin: an employee who may also create and change versions and modules in the projects listed in user.manage.
const managesProject = (user, slug, pid) => user.role === 'admin' || !!(user.manage && user.manage[slug] && user.manage[slug].includes(String(pid || '').toLowerCase()));
const managesAny = (user) => user.role === 'admin' || Object.values(user.manage || {}).some(ids => ids.length);
// Keep manage ⊆ access: you cannot manage a project you cannot see.
function cleanManage(raw, access) {
    const out = {};
    Object.entries(cleanAccess(raw)).forEach(([slug, ids]) => {
        const ok = ids.filter(id => ((access || {})[slug] || []).includes(id));
        if (ok.length) out[slug] = ok;
    });
    return out;
}
const wsByLink = (slug) => config.workspaces.find(w => w.slug === slug);
function userSlugs(user) {
    return config.workspaces.map(w => w.slug).filter(slug => user.role === 'admin' || (user.access && user.access[slug]));
}
function sendJson(res, status, obj, extra) {
    res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {}));
    res.end(JSON.stringify(obj));
}
function readBody(req, limit) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', (c) => {
            size += c.length;
            if (size > (limit || 1e6)) { reject(Object.assign(new Error('Request too large'), { status: 413 })); req.destroy(); return; }
            chunks.push(c);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}
async function readJsonBody(req) {
    const buf = await readBody(req);
    if (!buf.length) return {};
    try { return JSON.parse(buf.toString('utf8')); } catch (e) { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}
const fail = (status, message) => Object.assign(new Error(message), { status });
const clientIp = (req) => (config.trustProxy && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress);

function cleanAccess(raw) {
    const out = {};
    if (!raw || typeof raw !== 'object') return out;
    Object.entries(raw).forEach(([slug, ids]) => {
        if (!wsByLink(slug) || !Array.isArray(ids)) return;
        out[slug] = [...new Set(ids.filter(id => typeof id === 'string' && UUID_RE.test(id)).map(id => id.toLowerCase()))];
    });
    return out;
}

// ---------- Plane proxy ----------
// What an employee may do: read their projects and create, edit and comment on tasks. Modules and versions are admin-only.
function employeeRule(user, slug, method, rest) {
    const access = user.access && user.access[slug];
    if (!access) return null;
    if (method === 'GET' && rest === '/members/') return 'members';
    if (method === 'GET' && rest === '/projects/') return 'projects';
    const m = rest.match(new RegExp(`^/projects/(${UUID})(/.*)?$`, 'i'));
    if (!m || !access.includes(m[1].toLowerCase())) return null;
    const sub = (m[2] || '/').replace(/\/{2,}/g, '/');
    if (method === 'GET') return /^\/(project-members|project-members-lite|members|members-lite)(\/|$)/.test(sub) ? null : 'pass';
    if ((method === 'POST' || method === 'PATCH') && /^\/(issues|work-items)\//.test(sub)) return 'pass';
    if (['POST', 'PATCH', 'DELETE'].includes(method) && managesProject(user, slug, m[1]) && /^\/(cycles|modules|issues|work-items)(\/|$)/.test(sub)) return 'pass';
    return null;
}

const cache = new Map();
const cacheGen = new Map(); // slug -> write counter
const inflight = new Map();
async function callPlane(ws, method, rest, search, body) {
    for (let attempt = 0; ; attempt++) {
        let r;
        try {
            r = await fetch(`${config.planeBase}/api/v1/workspaces/${ws.slug}${rest}${search}`, {
                method,
                headers: { 'X-API-Key': ws.apiKey, 'Content-Type': 'application/json' },
                body: body && body.length ? body : undefined,
                signal: AbortSignal.timeout(20000)
            });
        } catch (e) {
            if (method === 'GET' && attempt === 0) continue; // the first connection to Plane sometimes times out
            throw fail(502, 'Plane did not answer — try again in a moment');
        }
        if (r.status === 429 && method === 'GET' && attempt === 0) {
            await new Promise(ok => setTimeout(ok, Math.min(5000, 1000 * (Number(r.headers.get('retry-after')) || 2))));
            continue;
        }
        return { status: r.status, ctype: r.headers.get('content-type') || 'application/json', body: await r.text() };
    }
}
async function planeCached(ws, rest, search) {
    const key = ws.slug + rest + search;
    const hit = cache.get(key);
    if (hit && hit.t > Date.now()) return hit.res;
    if (inflight.has(key)) return inflight.get(key);
    const gen = cacheGen.get(ws.slug) || 0;
    const p = callPlane(ws, 'GET', rest, search).then(res => {
        if (res.status === 200 && gen === (cacheGen.get(ws.slug) || 0)) {
            if (cache.size > 500) for (const [k, v] of cache) if (v.t <= Date.now()) cache.delete(k); // drop expired entries
            cache.set(key, { t: Date.now() + CACHE_MS, res });
        }
        return res;
    }).finally(() => inflight.delete(key));
    inflight.set(key, p);
    return p;
}
function trimForEmployee(rule, user, slug, res) {
    if (res.status !== 200) return res;
    let data;
    try { data = JSON.parse(res.body); } catch (e) { return res; }
    const list = Array.isArray(data) ? data : (data && Array.isArray(data.results) ? data.results : null);
    if (!list) return res;
    let out = list;
    if (rule === 'projects') out = list.filter(p => user.access[slug].includes(String(p.id).toLowerCase()));
    if (rule === 'members') out = list.map(m => Object.assign({}, m, { email: '', avatar: '', avatar_url: null }));
    return Object.assign({}, res, { body: JSON.stringify(Array.isArray(data) ? out : Object.assign({}, data, { results: out, count: out.length, total_results: out.length })) });
}

// New Plane projects start with versions and modules off: switch them on as soon as the dashboard sees them.
const FEATURES_ON = Buffer.from(JSON.stringify({ cycle_view: true, module_view: true }));
const featuresDone = new Set();
const enableFeatures = (ws, pid) => callPlane(ws, 'PATCH', `/projects/${pid}/`, '', FEATURES_ON).then(r => { if (r.status >= 300) throw fail(r.status, 'enable failed'); return r; });
function enableFeaturesIn(ws, res) {
    if (res.status !== 200) return res;
    let data;
    try { data = JSON.parse(res.body); } catch (e) { return res; }
    const list = listOf(data);
    const off = list.filter(p => p && p.id && (p.cycle_view === false || p.module_view === false) && !featuresDone.has(p.id));
    if (!off.length) return res;
    off.forEach(p => { featuresDone.add(p.id); enableFeatures(ws, p.id).catch(() => featuresDone.delete(p.id)); p.cycle_view = true; p.module_view = true; });
    for (const k of cache.keys()) if (k.startsWith(ws.slug + '/projects/')) cache.delete(k);
    return Object.assign({}, res, { body: JSON.stringify(data) });
}

// One gate for every Plane call, from the page or from Claude: same rules, same cache.
async function planeAs(user, slug, method, rest, search, body) {
    const ws = wsByLink(slug);
    if (!ws) throw fail(404, 'Unknown workspace');
    if (!userSlugs(user).includes(slug)) throw fail(403, 'Not allowed for your account');
    if (!/^\/[A-Za-z0-9_\-/.]*$/.test(rest) || rest.includes('..') || !/^(\?[A-Za-z0-9_\-.=&%,+:]*)?$/.test(search)) throw fail(400, 'Bad path');
    let rule = 'pass';
    if (user.role !== 'admin') {
        rule = employeeRule(user, slug, method, rest);
        if (!rule) throw fail(403, 'Not allowed for your account');
    }
    let out;
    if (method === 'GET') {
        out = await planeCached(ws, rest, search);
        if (rest === '/projects/') out = enableFeaturesIn(ws, out);
    } else {
        out = await callPlane(ws, method, rest, search, body);
        if (method === 'POST' && rest === '/projects/' && out.status < 300) {
            try { const p = JSON.parse(out.body); if (p && p.id) { await enableFeatures(ws, p.id); p.cycle_view = true; p.module_view = true; out = Object.assign({}, out, { body: JSON.stringify(p) }); } } catch (e) { /* best effort */ }
        }
        const feat = method === 'POST' && out.status === 400 && /not enabled/i.test(out.body) && rest.match(new RegExp(`^/projects/(${UUID})/(cycles|modules)/$`, 'i'));
        if (feat) { // fallback if a project was switched off later: turn it back on and retry
            await enableFeatures(ws, feat[1]);
            out = await callPlane(ws, method, rest, search, body);
        }
        if (out.status < 300) { cacheGen.set(slug, (cacheGen.get(slug) || 0) + 1); for (const k of cache.keys()) if (k.startsWith(slug + '/')) cache.delete(k); }
    }
    return user.role !== 'admin' ? trimForEmployee(rule, user, slug, out) : out;
}
// ---------- Project / version file library ----------
const FILE_MAX = 200 * 1024 * 1024;
const PREVIEW_TYPES = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };
const canSeeProject = (user, slug, pid) => userSlugs(user).includes(slug)
    && (user.role === 'admin' || !!(user.access && user.access[slug] && user.access[slug].includes(String(pid).toLowerCase())));
const cleanName = (n) => String(n || '').replace(/[\\/:*?"<>|\r\n\t]+/g, '_').replace(/^\.+/, '').trim().slice(0, 200) || 'file';
// Tags: up to 8 short labels per item, chosen by the people using the library (e.g. Code, Circuit, Mechanical).
function cleanTags(raw) {
    const list = Array.isArray(raw) ? raw : String(raw || '').split(',');
    const seen = new Set();
    return list.map(t => String(t || '').replace(/[\u0000-\u001f,<>]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 30))
        .filter(t => t && !seen.has(t.toLowerCase()) && seen.add(t.toLowerCase())).slice(0, 8);
}
// Links live next to the files: a web page, a repo, a cloud folder… (http/https only).
function saveLink(user, slug, pid, b) {
    if (!wsByLink(slug) || !UUID_RE.test(pid)) throw fail(400, 'Bad request');
    if (!canSeeProject(user, slug, pid)) throw fail(403, 'Not allowed for your account');
    const link = String(b.url || '').trim();
    let u;
    try { u = new URL(link); } catch (e) { throw fail(400, 'That is not a valid link'); }
    if (!/^https?:$/.test(u.protocol) || link.length > 2000) throw fail(400, 'Only http(s) links can be saved');
    const versionId = String(b.versionId || '').toLowerCase();
    if (versionId && !UUID_RE.test(versionId)) throw fail(400, 'Bad version');
    const rec = {
        id: crypto.randomUUID(), type: 'link', url: u.href, projectId: pid.toLowerCase(),
        versionId: versionId || null, versionName: String(b.versionName || '').slice(0, 120),
        name: String(b.name || '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, 200) || u.hostname,
        size: 0, note: String(b.note || '').slice(0, 300), tags: cleanTags(b.tags),
        uploaderId: user.id, uploaderName: user.name, createdAt: new Date().toISOString()
    };
    fileIndex[slug] = (fileIndex[slug] || []).concat(rec);
    saveDb();
    return rec;
}
// Anyone who can see the project may retag or re-note an item; renaming stays with the admin or the uploader.
function updateFileItem(user, slug, id, b) {
    const f = (fileIndex[slug] || []).find(x => x.id === id);
    if (!f || !canSeeProject(user, slug, f.projectId)) throw fail(404, 'File not found');
    if ('tags' in b) f.tags = cleanTags(b.tags);
    if ('note' in b) f.note = String(b.note || '').slice(0, 300);
    if ('name' in b) {
        if (!managesProject(user, slug, f.projectId) && f.uploaderId !== user.id) throw fail(403, 'Only an admin, the project admin or the uploader can rename this');
        f.name = f.type === 'link' ? (String(b.name || '').trim().slice(0, 200) || f.name) : cleanName(b.name);
    }
    saveDb();
    return f;
}
function listFiles(user, slug) {
    if (!userSlugs(user).includes(slug)) throw fail(403, 'Not allowed for your account');
    return (fileIndex[slug] || []).filter(f => canSeeProject(user, slug, f.projectId));
}
// Streams the body to disk (never held in memory) and stops at FILE_MAX.
async function saveUpload(req, user, slug, pid, url) {
    if (!wsByLink(slug) || !UUID_RE.test(pid)) throw fail(400, 'Bad request');
    if (!canSeeProject(user, slug, pid)) throw fail(403, 'Not allowed for your account');
    const versionId = String(url.searchParams.get('version') || '').toLowerCase();
    if (versionId && !UUID_RE.test(versionId)) throw fail(400, 'Bad version');
    fs.mkdirSync(FILES_DIR, { recursive: true });
    const id = crypto.randomUUID();
    const dest = path.join(FILES_DIR, id);
    let size = 0;
    await new Promise((resolve, reject) => {
        const out = fs.createWriteStream(dest);
        const stop = (err) => { req.unpipe(out); out.destroy(); fs.rm(dest, { force: true }, () => {}); reject(err); };
        req.on('data', (c) => { size += c.length; if (size > FILE_MAX) { req.destroy(); stop(fail(413, 'File is larger than 200 MB')); } });
        req.on('error', stop);
        out.on('error', stop);
        out.on('finish', resolve);
        req.pipe(out);
    });
    if (!size) { fs.rmSync(dest, { force: true }); throw fail(400, 'The file is empty'); }
    const rec = {
        id, projectId: pid.toLowerCase(),
        versionId: versionId || null, versionName: String(url.searchParams.get('versionName') || '').slice(0, 120),
        name: cleanName(url.searchParams.get('name')), size,
        note: String(url.searchParams.get('note') || '').slice(0, 300),
        tags: cleanTags(url.searchParams.get('tags')),
        uploaderId: user.id, uploaderName: user.name, createdAt: new Date().toISOString()
    };
    fileIndex[slug] = (fileIndex[slug] || []).concat(rec);
    saveDb();
    return rec;
}
function sendStoredFile(req, res, user, slug, id, inline) {
    const f = (fileIndex[slug] || []).find(x => x.id === id);
    if (!f || !canSeeProject(user, slug, f.projectId) || f.type === 'link') throw fail(404, 'File not found');
    const file = path.join(FILES_DIR, f.id);
    if (!fs.existsSync(file)) throw fail(404, 'File is missing on the server');
    const ext = (f.name.split('.').pop() || '').toLowerCase();
    const preview = inline && PREVIEW_TYPES[ext]; // only PDFs and plain images open in the browser; everything else downloads
    const ascii = f.name.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, "'");
    res.writeHead(200, {
        'Content-Type': preview || 'application/octet-stream',
        'Content-Length': fs.statSync(file).size,
        'Content-Disposition': `${preview ? 'inline' : 'attachment'}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(f.name)}`,
        'Cache-Control': 'private, no-store'
    });
    require('stream').pipeline(fs.createReadStream(file), res, () => {}); // closes the file on error or abort
}
function deleteStoredFile(user, slug, id) {
    const f = (fileIndex[slug] || []).find(x => x.id === id);
    if (!f || !canSeeProject(user, slug, f.projectId)) throw fail(404, 'File not found');
    if (!managesProject(user, slug, f.projectId) && f.uploaderId !== user.id) throw fail(403, 'Only an admin, the project admin or the person who uploaded it can delete this file');
    fileIndex[slug] = fileIndex[slug].filter(x => x !== f);
    saveDb();
    fs.rm(path.join(FILES_DIR, f.id), { force: true }, () => {});
}

// ---------- Work-item attachments ----------
// Plane hands out a presigned storage upload; the browser cannot post there (CORS), so the server does it.
const ATTACH_MAX = 25 * 1024 * 1024;
const attachPath = (pid, iid) => `/projects/${pid}/work-items/${iid}/attachments/`;
async function uploadAttachment(req, user, slug, pid, iid, url) {
    if (!userSlugs(user).includes(slug) || (user.role !== 'admin' && !employeeRule(user, slug, 'POST', attachPath(pid, iid)))) throw fail(403, 'Not allowed for your account');
    const name = String(url.searchParams.get('name') || '').replace(/[\\/:*?"<>|\r\n]+/g, '_').slice(0, 180) || 'file';
    const type = String(url.searchParams.get('type') || 'application/octet-stream').slice(0, 120);
    const bytes = await readBody(req, ATTACH_MAX);
    if (!bytes.length) throw fail(400, 'The file is empty');
    const created = await planeAs(user, slug, 'POST', attachPath(pid, iid), '', Buffer.from(JSON.stringify({ name, type, size: bytes.length })));
    let info;
    try { info = JSON.parse(created.body); } catch (e) { info = null; }
    if (created.status >= 300 || !info || !info.upload_data || !info.asset_id) throw fail(created.status >= 400 ? created.status : 502, (info && (info.error || info.detail)) || 'Plane refused the upload');
    const up = info.upload_data;
    const form = new FormData();
    Object.entries(up.fields || {}).forEach(([k, v]) => form.append(k, v));
    form.append('file', new Blob([bytes], { type }), name);
    // The storage (MinIO behind nginx) only takes the POST at the bucket path with a trailing slash.
    const put = await fetch(String(up.url).replace(/\/?$/, '/'), { method: 'POST', body: form, redirect: 'manual' });
    if (!put.ok) throw fail(502, `Storage refused the file (${put.status})`);
    const done = await planeAs(user, slug, 'PATCH', attachPath(pid, iid) + info.asset_id + '/', '', Buffer.from('{}'));
    if (done.status >= 300) throw fail(502, `Plane did not confirm the upload (${done.status})`);
    return Object.assign({ id: info.asset_id, name, type, size: bytes.length }, info.attachment || {});
}
// Plane answers a download with a redirect to a short-lived storage link; pass that redirect on.
async function attachmentLink(user, slug, pid, iid, aid) {
    const ws = wsByLink(slug);
    if (!ws) throw fail(404, 'Unknown workspace');
    if (!userSlugs(user).includes(slug)) throw fail(403, 'Not allowed for your account');
    if (user.role !== 'admin' && !employeeRule(user, slug, 'GET', attachPath(pid, iid))) throw fail(403, 'Not allowed for your account');
    const r = await fetch(`${config.planeBase}/api/v1/workspaces/${ws.slug}${attachPath(pid, iid)}${aid}/`, { headers: { 'X-API-Key': ws.apiKey }, redirect: 'manual' });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) return loc;
    throw fail(r.status === 404 ? 404 : 502, 'That file is not available');
}

async function planeProxy(req, res, user, slug, rest, search) {
    const out = await planeAs(user, slug, req.method, rest, search, req.method === 'GET' ? null : await readBody(req));
    res.writeHead(out.status, { 'Content-Type': out.ctype, 'Cache-Control': 'no-store' });
    res.end(out.status === 204 ? undefined : out.body);
}

function setAssignment(user, slug, issueId, projectId, userIds) {
    projectId = String(projectId || '').toLowerCase();
    if (!wsByLink(slug) || !UUID_RE.test(projectId) || !UUID_RE.test(String(issueId))) throw fail(400, 'Bad request');
    if (user.role !== 'admin' && !(user.access && user.access[slug] && user.access[slug].includes(projectId))) throw fail(403, 'Not allowed for your account');
    const ids = [...new Set(Array.isArray(userIds) ? userIds : [])];
    for (const id of ids) {
        const u = users.find(x => x.id === id);
        if (!u || u.role !== 'employee' || !u.active || !(u.access && u.access[slug] && u.access[slug].includes(projectId))) throw fail(400, 'That person is not on this project');
    }
    assignments[slug] = assignments[slug] || {};
    if (ids.length) assignments[slug][issueId] = ids; else delete assignments[slug][issueId];
    saveAssignments();
    return ids;
}
function setModuleLead(user, slug, moduleId, projectId, userId) {
    moduleId = String(moduleId || '').toLowerCase();
    projectId = String(projectId || '').toLowerCase();
    if (!wsByLink(slug) || !UUID_RE.test(moduleId) || !UUID_RE.test(projectId)) throw fail(400, 'Bad request');
    if (!managesProject(user, slug, projectId)) throw fail(403, 'Only an admin or this project\'s admin can change its module leads');
    if (userId) {
        const u = users.find(x => x.id === userId);
        if (!u || u.role !== 'employee' || !u.active || !(u.access && u.access[slug] && u.access[slug].includes(projectId))) throw fail(400, 'That person is not on this project');
    }
    moduleLeads[slug] = moduleLeads[slug] || {};
    if (userId) moduleLeads[slug][moduleId] = userId; else delete moduleLeads[slug][moduleId];
    saveDb();
    return userId || null;
}
const teamOf = (slug) => users.filter(u => u.role === 'employee' && u.active && u.access && u.access[slug]).map(u => ({ id: u.id, name: u.name }));

// ---------- Routes ----------
async function login(req, res) {
    const { username, password } = await readJsonBody(req);
    const name = String(username || '').trim().toLowerCase();
    const key = `${clientIp(req)}|${name}`;
    if (loginBlocked(key)) throw fail(429, 'Too many attempts — wait 10 minutes.');
    const user = users.find(u => u.username === name);
    const ok = !!user && user.active && typeof password === 'string' && await checkPassword(user, password);
    noteLogin(key, ok);
    if (!ok) { await new Promise(r => setTimeout(r, 400)); throw fail(401, 'Wrong username or password'); }
    sendJson(res, 200, me(user), { 'Set-Cookie': cookieHeader(makeToken(user), SESSION_MS / 1000) });
}
const me = (user) => ({ user: { id: user.id, username: user.username, name: user.name, role: user.role, manage: user.role === 'admin' ? {} : (user.manage || {}) }, workspaces: userSlugs(user), planeWeb: config.planeWeb || 'https://app.plane.so' });

async function adminRoutes(req, res, user, p) {
    if (user.role !== 'admin') throw fail(403, 'Admins only');
    let m;
    if (p === '/admin/users' && req.method === 'GET') return sendJson(res, 200, users.map(pub));
    if (p === '/admin/users' && req.method === 'POST') {
        const b = await readJsonBody(req);
        const username = String(b.username || '').trim().toLowerCase();
        if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw fail(400, 'Username: 3–32 letters, digits, dot, dash or underscore');
        if (users.some(u => u.username === username)) throw fail(409, 'That username is taken');
        if (typeof b.password !== 'string' || b.password.length < 8) throw fail(400, 'Password must be at least 8 characters');
        if (!['admin', 'employee'].includes(b.role)) throw fail(400, 'Role must be admin or employee');
        const u = { id: crypto.randomUUID(), username, name: String(b.name || username).trim().slice(0, 80), role: b.role, active: true, access: cleanAccess(b.access), tokens: [], createdAt: new Date().toISOString() };
        u.manage = b.role === 'employee' ? cleanManage(b.manage, u.access) : {};
        await setPassword(u, b.password);
        users.push(u);
        saveUsers();
        return sendJson(res, 201, pub(u));
    }
    if ((m = p.match(/^\/admin\/users\/([0-9a-f-]{36})\/tokens$/i))) {
        const target = users.find(u => u.id === m[1]);
        if (!target) throw fail(404, 'No such user');
        if (req.method === 'GET') return sendJson(res, 200, (target.tokens || []).map(tokenPub));
        if (req.method === 'POST') {
            const b = await readJsonBody(req);
            const name = String(b.name || 'Claude').trim().slice(0, 60) || 'Claude';
            const token = 'dash_' + crypto.randomBytes(32).toString('base64url');
            const t = { id: crypto.randomUUID(), name, prefix: token.slice(0, 12), hash: tokenHash(token), createdAt: new Date().toISOString(), lastUsedAt: null };
            target.tokens = (target.tokens || []).concat(t);
            saveUsers();
            return sendJson(res, 201, Object.assign(tokenPub(t), { token }));
        }
    }
    if ((m = p.match(/^\/admin\/users\/([0-9a-f-]{36})\/tokens\/([0-9a-f-]{36})$/i)) && req.method === 'DELETE') {
        const target = users.find(u => u.id === m[1]);
        if (!target) throw fail(404, 'No such user');
        target.tokens = (target.tokens || []).filter(t => t.id !== m[2]);
        saveUsers();
        res.writeHead(204);
        return res.end();
    }
    if ((m = p.match(/^\/admin\/users\/([0-9a-f-]{36})$/i))) {
        const target = users.find(u => u.id === m[1]);
        if (!target) throw fail(404, 'No such user');
        if (req.method === 'PATCH') {
            const b = await readJsonBody(req);
            const nextRole = b.role !== undefined ? b.role : target.role;
            const nextActive = b.active !== undefined ? !!b.active : target.active;
            if (!['admin', 'employee'].includes(nextRole)) throw fail(400, 'Role must be admin or employee');
            if (target.id === user.id && (nextRole !== 'admin' || !nextActive)) throw fail(400, 'You cannot demote or disable your own account');
            if (b.password !== undefined && (typeof b.password !== 'string' || b.password.length < 8)) throw fail(400, 'Password must be at least 8 characters');
            if (b.name !== undefined) target.name = String(b.name).trim().slice(0, 80) || target.name;
            target.role = nextRole;
            target.active = nextActive;
            if (b.access) {
                const patch = cleanAccess(b.access);
                target.access = Object.assign({}, target.access);
                Object.entries(patch).forEach(([slug, ids]) => { if (ids.length) target.access[slug] = ids; else delete target.access[slug]; });
            }
            if (b.manage) {
                const patch = cleanAccess(b.manage);
                target.manage = Object.assign({}, target.manage);
                Object.entries(patch).forEach(([slug, ids]) => { if (ids.length) target.manage[slug] = ids; else delete target.manage[slug]; });
            }
            target.manage = target.role === 'employee' ? cleanManage(target.manage, target.access) : {}; // never manage what you cannot see
            if (b.password) await setPassword(target, b.password);
            saveUsers();
            return sendJson(res, 200, pub(target));
        }
        if (req.method === 'DELETE') {
            if (target.id === user.id) throw fail(400, 'You cannot delete your own account');
            users = users.filter(u => u.id !== target.id);
            Object.values(assignments).forEach(map => Object.keys(map).forEach(issue => {
                map[issue] = map[issue].filter(id => id !== target.id);
                if (!map[issue].length) delete map[issue];
            }));
            saveUsers();
            saveAssignments();
            res.writeHead(204);
            return res.end();
        }
    }
    if (p === '/admin/workspaces' && req.method === 'POST') {
        const b = await readJsonBody(req);
        const slug = String(b.slug || '').trim();
        const apiKey = String(b.apiKey || '').trim();
        if (!/^[A-Za-z0-9_-]{1,60}$/.test(slug) || !apiKey) throw fail(400, 'Workspace slug and API key are required');
        if (wsByLink(slug)) throw fail(409, 'This workspace is already added');
        const probe = await callPlane({ slug, apiKey }, 'GET', '/projects/', '');
        if (probe.status !== 200) throw fail(400, `Plane rejected that slug/key (${probe.status})`);
        config.workspaces.push({ slug, apiKey });
        saveConfig();
        return sendJson(res, 201, { slug });
    }
    if ((m = p.match(/^\/admin\/workspaces\/([A-Za-z0-9_-]+)$/)) && req.method === 'DELETE') {
        if (config.workspaces.length <= 1) throw fail(400, 'At least one workspace must remain');
        config.workspaces = config.workspaces.filter(w => w.slug !== m[1]);
        saveConfig();
        res.writeHead(204);
        return res.end();
    }
    if ((m = p.match(/^\/admin\/plane-me\/([A-Za-z0-9_-]+)$/)) && req.method === 'GET') {
        const ws = wsByLink(m[1]);
        if (!ws) throw fail(404, 'Unknown workspace');
        const r = await fetch(`${config.planeBase}/api/v1/users/me/`, { headers: { 'X-API-Key': ws.apiKey } });
        res.writeHead(r.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(await r.text());
    }
    throw fail(404, 'Not found');
}

async function apiRoutes(req, res, user, url) {
    const p = url.pathname;
    const slug = url.searchParams.get('slug') || '';
    let m;
    if ((m = p.match(new RegExp(`^/api/attach/([A-Za-z0-9_-]+)/(${UUID})/(${UUID})$`, 'i'))) && req.method === 'POST') {
        return sendJson(res, 200, await uploadAttachment(req, user, m[1], m[2], m[3], url));
    }
    if ((m = p.match(new RegExp(`^/api/attach-file/([A-Za-z0-9_-]+)/(${UUID})/(${UUID})/(${UUID})$`, 'i'))) && req.method === 'GET') {
        const loc = await attachmentLink(user, m[1], m[2], m[3], m[4]);
        res.writeHead(302, { Location: loc, 'Cache-Control': 'no-store' });
        return res.end();
    }
    if (p === '/api/files' && req.method === 'GET') return sendJson(res, 200, listFiles(user, slug));
    if ((m = p.match(new RegExp(`^/api/files/([A-Za-z0-9_-]+)/(${UUID})$`, 'i'))) && req.method === 'POST') {
        return sendJson(res, 201, await saveUpload(req, user, m[1], m[2], url));
    }
    if ((m = p.match(new RegExp(`^/api/files/([A-Za-z0-9_-]+)/(${UUID})/download$`, 'i'))) && req.method === 'GET') {
        return sendStoredFile(req, res, user, m[1], m[2].toLowerCase(), url.searchParams.get('inline') === '1');
    }
    if ((m = p.match(new RegExp(`^/api/links/([A-Za-z0-9_-]+)/(${UUID})$`, 'i'))) && req.method === 'POST') {
        return sendJson(res, 201, saveLink(user, m[1], m[2], await readJsonBody(req)));
    }
    if ((m = p.match(new RegExp(`^/api/files/([A-Za-z0-9_-]+)/(${UUID})$`, 'i'))) && req.method === 'PATCH') {
        return sendJson(res, 200, updateFileItem(user, m[1], m[2].toLowerCase(), await readJsonBody(req)));
    }
    if ((m = p.match(new RegExp(`^/api/files/([A-Za-z0-9_-]+)/(${UUID})$`, 'i'))) && req.method === 'DELETE') {
        deleteStoredFile(user, m[1], m[2].toLowerCase());
        return sendJson(res, 200, { ok: true });
    }
    if (p === '/api/notes' && req.method === 'GET') return sendJson(res, 200, notes[user.id] || []);
    if (p === '/api/notes' && req.method === 'PUT') {
        const b = await readJsonBody(req);
        return sendJson(res, 200, setNotes(user, b.notes));
    }
    if (p === '/api/team' && req.method === 'GET') {
        if (!userSlugs(user).includes(slug)) throw fail(403, 'Not allowed for your account');
        return sendJson(res, 200, teamOf(slug));
    }
    if (p === '/api/assignments' && req.method === 'GET') {
        if (!userSlugs(user).includes(slug)) throw fail(403, 'Not allowed for your account');
        return sendJson(res, 200, assignments[slug] || {});
    }
    if (p === '/api/module-leads' && req.method === 'GET') {
        if (!userSlugs(user).includes(slug)) throw fail(403, 'Not allowed for your account');
        return sendJson(res, 200, moduleLeads[slug] || {});
    }
    if ((m = p.match(/^\/api\/module-leads\/([A-Za-z0-9_-]+)\/([0-9a-f-]{36})$/i)) && req.method === 'PUT') {
        if (!userSlugs(user).includes(m[1])) throw fail(403, 'Not allowed for your account');
        const b = await readJsonBody(req);
        return sendJson(res, 200, { userId: setModuleLead(user, m[1], m[2], b.projectId, b.userId) });
    }
    if ((m = p.match(/^\/api\/assignments\/([A-Za-z0-9_-]+)\/([0-9a-f-]{36})$/i)) && req.method === 'PUT') {
        const b = await readJsonBody(req);
        const iid = m[2].toLowerCase(), pid = String(b.projectId || '').toLowerCase();
        if (!UUID_RE.test(pid)) throw fail(400, 'Bad request');
        const chk = await planeAs(user, m[1], 'GET', `/projects/${pid}/issues/${iid}/`, ''); // 403/404 unless the task is in a project you can see
        if (chk.status !== 200) throw fail(404, 'That task is not in that project');
        return sendJson(res, 200, { userIds: setAssignment(user, m[1], iid, pid, b.userIds) });
    }
    throw fail(404, 'Not found');
}

// ---------- MCP: Claude tools, gated by the token owner's role ----------
const MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const str = { type: 'string' };
const wsArg = { workspace: { type: 'string', description: 'Workspace slug; defaults to your first workspace (see list_projects).' } };
const pidArg = { project_id: { type: 'string', description: 'Project id from list_projects.' } };
const dateArg = (d) => ({ type: 'string', description: `${d} as YYYY-MM-DD, or "" to clear.` });
const schema = (props, required) => ({ type: 'object', properties: Object.assign({}, wsArg, props), required: required || [], additionalProperties: false });

function pickWs(user, args) {
    const slugs = userSlugs(user);
    const slug = args.workspace || slugs[0];
    if (!slug || !slugs.includes(slug)) throw new Error(`Unknown workspace. Yours: ${slugs.join(', ') || 'none'}`);
    return slug;
}
function needId(args, key, hint) {
    const v = String(args[key] || '').toLowerCase();
    if (!UUID_RE.test(v)) throw new Error(`${key} must be an id${hint ? ' from ' + hint : ''}.`);
    return v;
}
function needDate(v, key) {
    if (v === undefined) return undefined;
    if (v === '' || v === null) return null;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(v))) throw new Error(`${key} must be YYYY-MM-DD.`);
    return v;
}
const escHtml = (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function planeError(out) {
    try {
        const d = JSON.parse(out.body);
        const first = Object.entries(d)[0];
        const msg = d.error || d.detail || d.message || (first && `${first[0]}: ${[].concat(first[1]).join(' ')}`);
        if (msg) return `${msg} (${out.status})`;
    } catch (e) { /* not json */ }
    return `Plane returned ${out.status}`;
}
async function pj(user, slug, method, rest, search, obj) {
    let out;
    try {
        out = await planeAs(user, slug, method, rest, search || '', obj === undefined ? null : Buffer.from(JSON.stringify(obj)));
    } catch (e) {
        if (e.status === 403) throw new Error(user.role === 'admin' ? 'Not allowed.' : 'Not allowed for your account — employees can only work on tasks in their own projects.');
        throw e;
    }
    if (out.status >= 400) throw new Error(planeError(out));
    return out.status === 204 || !out.body ? null : JSON.parse(out.body);
}
const listOf = (d) => (Array.isArray(d) ? d : (d && Array.isArray(d.results) ? d.results : []));
async function allPages(user, slug, rest) {
    const all = [];
    let cursor = '';
    for (let page = 0; page < 10; page++) {
        const qs = new URLSearchParams({ per_page: '100' });
        if (cursor) qs.set('cursor', cursor);
        const d = await pj(user, slug, 'GET', rest, '?' + qs.toString());
        const list = listOf(d);
        all.push(...list);
        if (list.length < 100 || !d.next_cursor || d.next_cursor === cursor) break;
        cursor = d.next_cursor;
    }
    return all;
}
async function statesOf(user, slug, pid) {
    return listOf(await pj(user, slug, 'GET', `/projects/${pid}/states/`)).map(s => ({ id: s.id, name: s.name, group: s.group }));
}
async function resolveState(user, slug, pid, value) {
    if (value === undefined || value === '') return undefined;
    const states = await statesOf(user, slug, pid);
    const v = String(value).toLowerCase();
    const hit = states.find(s => s.id === v) || states.find(s => s.name.toLowerCase() === v) || states.find(s => s.group === v);
    if (!hit) throw new Error(`Unknown state "${value}". Use one of: ${states.map(s => s.name).join(', ')}`);
    return hit.id;
}
async function nameBook(user, slug) {
    const book = new Map(listOf(await pj(user, slug, 'GET', '/members/')).map(m => [m.id, m.display_name || [m.first_name, m.last_name].filter(Boolean).join(' ') || 'Member']));
    users.forEach(u => book.set('dash:' + u.id, u.name));
    return book;
}
function taskView(t, slug, states, book) {
    const st = states.find(s => s.id === t.state);
    const plane = (t.assignees || []).map(a => book.get(typeof a === 'string' ? a : a.id) || 'Unknown');
    const dash = ((assignments[slug] || {})[t.id] || []).map(id => book.get('dash:' + id)).filter(Boolean);
    return {
        id: t.id, name: t.name, state: st ? st.name : null, state_group: st ? st.group : null, priority: t.priority,
        start_date: t.start_date || null, due_date: t.target_date || null, assignees: plane.concat(dash),
        completed_at: t.completed_at || null, updated_at: t.updated_at
    };
}
function moduleMeta(m) {
    if (m.external_source !== MODULE_TAG_SRC) return {};
    try { return JSON.parse(m.external_id || '{}') || {}; } catch (e) { return {}; }
}
function versionStatus(c) {
    if (!c.start_date || !c.end_date) return 'draft';
    const today = new Date().toISOString().slice(0, 10);
    const s = String(c.start_date).slice(0, 10);
    const e = String(c.end_date).slice(0, 10);
    return today < s ? 'upcoming' : today > e ? 'released' : 'active';
}
const mustManage = (user, slug, pid) => { if (!managesProject(user, slug, pid)) throw new Error('Only an admin or this project\'s admin can change its modules and versions.'); };

const TOOLS = [
    {
        name: 'list_projects', description: 'List the projects you can work on, with their ids and workspace. you_manage = true means you may also create and change its versions and modules.',
        inputSchema: schema({}),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            return { workspace: slug, workspaces: userSlugs(user), you: { name: user.name, role: user.role }, projects: listOf(await pj(user, slug, 'GET', '/projects/')).map(p => ({ id: p.id, name: p.name, identifier: p.identifier, you_manage: managesProject(user, slug, p.id) })) };
        }
    },
    {
        name: 'list_states', description: 'List the task states (statuses) of a project.',
        inputSchema: schema(Object.assign({}, pidArg), ['project_id']),
        run: async (user, a) => statesOf(user, pickWs(user, a), needId(a, 'project_id', 'list_projects'))
    },
    {
        name: 'list_tasks', description: 'List tasks in a project. Finished and cancelled tasks are hidden unless include_done is true.',
        inputSchema: schema(Object.assign({}, pidArg, {
            search: { type: 'string', description: 'Only tasks whose name contains this text.' },
            state: { type: 'string', description: 'Only tasks in this state (name, id, or group such as started).' },
            assigned_to_me: { type: 'boolean', description: 'Only tasks assigned to you in this dashboard.' },
            include_done: { type: 'boolean', description: 'Also include completed and cancelled tasks.' },
            limit: { type: 'number', description: 'Maximum tasks to return (default 50, max 200).' }
        }), ['project_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            const [tasks, states, book] = await Promise.all([allPages(user, slug, `/projects/${pid}/issues/`), statesOf(user, slug, pid), nameBook(user, slug)]);
            const stateId = await resolveState(user, slug, pid, a.state);
            const want = String(a.state || '').toLowerCase();
            const exact = states.some(st => st.id === want || st.name.toLowerCase() === want); // a state name/id → that state; a group name → every state in it
            const stateIds = !stateId ? null : new Set(exact ? [stateId] : states.filter(st => st.group === want).map(st => st.id));
            const mine = new Set(Object.entries(assignments[slug] || {}).filter(([, ids]) => ids.includes(user.id)).map(([id]) => id));
            const q = String(a.search || '').toLowerCase();
            const out = tasks
                .filter(t => !stateIds || stateIds.has(t.state))
                .filter(t => !a.assigned_to_me || mine.has(t.id))
                .map(t => taskView(t, slug, states, book))
                .filter(t => a.include_done || stateId || !['completed', 'cancelled'].includes(t.state_group))
                .filter(t => !q || String(t.name).toLowerCase().includes(q));
            const limit = Math.min(200, Math.max(1, Number(a.limit) || 50));
            return { total: out.length, tasks: out.slice(0, limit) };
        }
    },
    {
        name: 'get_task', description: 'Get one task with its description.',
        inputSchema: schema(Object.assign({}, pidArg, { task_id: str }), ['project_id', 'task_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            const tid = needId(a, 'task_id', 'list_tasks');
            const [t, states, book] = await Promise.all([pj(user, slug, 'GET', `/projects/${pid}/issues/${tid}/`), statesOf(user, slug, pid), nameBook(user, slug)]);
            return Object.assign(taskView(t, slug, states, book), { description: t.description_stripped || '' });
        }
    },
    {
        name: 'create_task', description: 'Create a task in a project.',
        inputSchema: schema(Object.assign({}, pidArg, {
            name: str,
            description: { type: 'string', description: 'Plain-text description.' },
            priority: { type: 'string', enum: ['none', 'low', 'medium', 'high', 'urgent'] },
            state: { type: 'string', description: 'State name or id (see list_states).' },
            start_date: dateArg('Start date'), due_date: dateArg('Due date'),
            assign_to_me: { type: 'boolean', description: 'Assign the new task to yourself (employees).' }
        }), ['project_id', 'name']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            if (!String(a.name || '').trim()) throw new Error('name is required.');
            const body = { name: String(a.name).trim().slice(0, 255) };
            if (a.description) body.description_html = `<p>${escHtml(a.description)}</p>`;
            if (a.priority) body.priority = a.priority;
            const state = await resolveState(user, slug, pid, a.state);
            if (state) body.state = state;
            const sd = needDate(a.start_date, 'start_date');
            const dd = needDate(a.due_date, 'due_date');
            if (sd) body.start_date = sd;
            if (dd) body.target_date = dd;
            const t = await pj(user, slug, 'POST', `/projects/${pid}/issues/`, '', body);
            if (a.assign_to_me && user.role === 'employee') setAssignment(user, slug, t.id, pid, [user.id]);
            return { created: taskView(t, slug, await statesOf(user, slug, pid), await nameBook(user, slug)) };
        }
    },
    {
        name: 'update_task', description: 'Change a task: name, description, state, priority or dates. Only the fields you pass change.',
        inputSchema: schema(Object.assign({}, pidArg, {
            task_id: str, name: str,
            description: { type: 'string', description: 'Replaces the description (plain text).' },
            priority: { type: 'string', enum: ['none', 'low', 'medium', 'high', 'urgent'] },
            state: { type: 'string', description: 'State name or id, e.g. "In Progress" or "Done".' },
            start_date: dateArg('Start date'), due_date: dateArg('Due date')
        }), ['project_id', 'task_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            const tid = needId(a, 'task_id', 'list_tasks');
            const body = {};
            if (a.name !== undefined) body.name = String(a.name).trim().slice(0, 255);
            if (a.description !== undefined) body.description_html = `<p>${escHtml(a.description)}</p>`;
            if (a.priority !== undefined) body.priority = a.priority;
            const state = await resolveState(user, slug, pid, a.state);
            if (state) body.state = state;
            const sd = needDate(a.start_date, 'start_date');
            const dd = needDate(a.due_date, 'due_date');
            if (sd !== undefined) body.start_date = sd;
            if (dd !== undefined) body.target_date = dd;
            if (!Object.keys(body).length) throw new Error('Pass at least one field to change.');
            const t = await pj(user, slug, 'PATCH', `/projects/${pid}/issues/${tid}/`, '', body);
            return { updated: taskView(t, slug, await statesOf(user, slug, pid), await nameBook(user, slug)) };
        }
    },
    {
        name: 'add_comment', description: 'Add a comment to a task, e.g. a progress note. Your name is added in front.',
        inputSchema: schema(Object.assign({}, pidArg, { task_id: str, text: str }), ['project_id', 'task_id', 'text']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            const tid = needId(a, 'task_id', 'list_tasks');
            if (!String(a.text || '').trim()) throw new Error('text is required.');
            const c = await pj(user, slug, 'POST', `/projects/${pid}/issues/${tid}/comments/`, '', { comment_html: `<p>${escHtml(`[${user.name}] ${a.text}`)}</p>` });
            return { commented: true, id: c && c.id };
        }
    },
    {
        name: 'list_team', description: 'List the dashboard people (employees) who can be assigned tasks in a workspace.',
        inputSchema: schema({}),
        run: async (user, a) => teamOf(pickWs(user, a))
    },
    {
        name: 'assign_task', description: 'Set who works on a task (dashboard people, by name, username or id). Replaces the current dashboard assignees; pass [] to clear.',
        inputSchema: schema(Object.assign({}, pidArg, { task_id: str, people: { type: 'array', items: str } }), ['project_id', 'task_id', 'people']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            const tid = needId(a, 'task_id', 'list_tasks');
            await pj(user, slug, 'GET', `/projects/${pid}/issues/${tid}/`); // proves the task is in a project you can see
            const team = users.filter(u => u.role === 'employee' && u.active);
            if (!Array.isArray(a.people)) throw new Error('people must be a list, e.g. ["Sara"] — use [] to clear.');
            const ids = a.people.map(x => {
                const v = String(x).toLowerCase();
                const u = team.find(t => t.id === v || t.username === v || t.name.toLowerCase() === v);
                if (!u) throw new Error(`No dashboard person called "${x}" (see list_team).`);
                return u.id;
            });
            return { assigned: setAssignment(user, slug, tid, pid, ids).map(id => users.find(u => u.id === id).name) };
        }
    },
    {
        name: 'list_modules', description: 'List the modules (main work packages) of a project and the version each belongs to. Read-only for employees.',
        inputSchema: schema(Object.assign({}, pidArg), ['project_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            return (await allPages(user, slug, `/projects/${pid}/modules/`)).map(m => ({
                id: m.id, name: m.name, status: m.status, version_id: moduleMeta(m).v || null,
                start_date: m.start_date || null, target_date: m.target_date || null,
                total_tasks: m.total_issues, completed_tasks: m.completed_issues
            }));
        }
    },
    {
        name: 'list_versions', description: 'List the versions (release phases) of a project. Read-only for employees.',
        inputSchema: schema(Object.assign({}, pidArg), ['project_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            return (await allPages(user, slug, `/projects/${pid}/cycles/`)).map(c => ({
                id: c.id, name: c.name, status: versionStatus(c),
                start_date: c.start_date ? String(c.start_date).slice(0, 10) : null, end_date: c.end_date ? String(c.end_date).slice(0, 10) : null,
                total_tasks: c.total_issues, completed_tasks: c.completed_issues
            }));
        }
    },
    {
        name: 'create_version', admin: true, description: 'Admin or project admin: create a version (release phase) in a project.',
        inputSchema: schema(Object.assign({}, pidArg, { name: str, description: str, start_date: dateArg('Start date'), end_date: dateArg('Release date') }), ['project_id', 'name']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            mustManage(user, slug, pid);
            const sd = needDate(a.start_date, 'start_date');
            const ed = needDate(a.end_date, 'end_date');
            if (!!sd !== !!ed) throw new Error('Give both start_date and end_date, or neither (draft).');
            const body = { name: String(a.name || '').trim() };
            if (!body.name) throw new Error('name is required.');
            if (a.description) body.description = String(a.description);
            if (sd) { body.start_date = sd; body.end_date = ed; }
            const c = await pj(user, slug, 'POST', `/projects/${pid}/cycles/`, '', body);
            return { created: { id: c.id, name: c.name, status: versionStatus(c) } };
        }
    },
    {
        name: 'create_module', admin: true, description: 'Admin or project admin: create a module in a project, optionally inside a version.',
        inputSchema: schema(Object.assign({}, pidArg, { name: str, version_id: { type: 'string', description: 'Version id from list_versions.' }, start_date: dateArg('Start date'), target_date: dateArg('Target date') }), ['project_id', 'name']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            mustManage(user, slug, pid);
            const body = { name: String(a.name || '').trim() };
            if (!body.name) throw new Error('name is required.');
            if (a.version_id) {
                body.external_source = MODULE_TAG_SRC;
                body.external_id = JSON.stringify({ v: needId(a, 'version_id', 'list_versions'), u: crypto.randomBytes(5).toString('hex') });
            }
            const sd = needDate(a.start_date, 'start_date');
            const td = needDate(a.target_date, 'target_date');
            if (sd) body.start_date = sd;
            if (td) body.target_date = td;
            const m = await pj(user, slug, 'POST', `/projects/${pid}/modules/`, '', body);
            return { created: { id: m.id, name: m.name, version_id: moduleMeta(m).v || null } };
        }
    },
    {
        name: 'set_module_version', admin: true, description: 'Admin or project admin: move a module into a version, or out of any version (version_id "").',
        inputSchema: schema(Object.assign({}, pidArg, { module_id: str, version_id: str }), ['project_id', 'module_id', 'version_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            mustManage(user, slug, pid);
            const mid = needId(a, 'module_id', 'list_modules');
            const vid = a.version_id ? needId(a, 'version_id', 'list_versions') : null;
            const m = await pj(user, slug, 'GET', `/projects/${pid}/modules/${mid}/`);
            if (m.external_source && m.external_source !== MODULE_TAG_SRC) throw new Error('This module is linked to an import and cannot be tied to a version.');
            const o = Object.assign({}, moduleMeta(m), { m: mid }); // keeps its tag, department and order
            delete o.u; delete o.v;
            if (vid) o.v = vid;
            const body = Object.keys(o).length > 1 ? { external_source: MODULE_TAG_SRC, external_id: JSON.stringify(o) } : { external_source: null, external_id: null };
            await pj(user, slug, 'PATCH', `/projects/${pid}/modules/${mid}/`, '', body);
            return { module_id: mid, version_id: vid };
        }
    },
    {
        name: 'add_task_to_module', admin: true, description: 'Admin or project admin: put a task into a module (and into that module\'s version, if it has one).',
        inputSchema: schema(Object.assign({}, pidArg, { module_id: str, task_id: str }), ['project_id', 'module_id', 'task_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            mustManage(user, slug, pid);
            const mid = needId(a, 'module_id', 'list_modules');
            const tid = needId(a, 'task_id', 'list_tasks');
            await pj(user, slug, 'POST', `/projects/${pid}/modules/${mid}/module-issues/`, '', { issues: [tid] });
            const vid = moduleMeta(await pj(user, slug, 'GET', `/projects/${pid}/modules/${mid}/`)).v;
            let version = null;
            if (vid) {
                try { await pj(user, slug, 'POST', `/projects/${pid}/cycles/${vid}/cycle-issues/`, '', { issues: [tid] }); version = vid; } catch (e) { version = `not added: ${e.message}`; }
            }
            return { module_id: mid, task_id: tid, version };
        }
    },
    {
        name: 'remove_task_from_module', admin: true, description: 'Admin or project admin: take a task out of a module.',
        inputSchema: schema(Object.assign({}, pidArg, { module_id: str, task_id: str }), ['project_id', 'module_id', 'task_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            mustManage(user, slug, pid);
            await pj(user, slug, 'DELETE', `/projects/${pid}/modules/${needId(a, 'module_id', 'list_modules')}/module-issues/${needId(a, 'task_id', 'list_tasks')}/`);
            return { removed: true };
        }
    },
    {
        name: 'add_task_to_version', admin: true, description: 'Admin or project admin: put a task into a version.',
        inputSchema: schema(Object.assign({}, pidArg, { version_id: str, task_id: str }), ['project_id', 'version_id', 'task_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            mustManage(user, slug, pid);
            await pj(user, slug, 'POST', `/projects/${pid}/cycles/${needId(a, 'version_id', 'list_versions')}/cycle-issues/`, '', { issues: [needId(a, 'task_id', 'list_tasks')] });
            return { added: true };
        }
    },
    {
        name: 'remove_task_from_version', admin: true, description: 'Admin or project admin: take a task out of a version.',
        inputSchema: schema(Object.assign({}, pidArg, { version_id: str, task_id: str }), ['project_id', 'version_id', 'task_id']),
        run: async (user, a) => {
            const slug = pickWs(user, a);
            const pid = needId(a, 'project_id', 'list_projects');
            mustManage(user, slug, pid);
            await pj(user, slug, 'DELETE', `/projects/${pid}/cycles/${needId(a, 'version_id', 'list_versions')}/cycle-issues/${needId(a, 'task_id', 'list_tasks')}/`);
            return { removed: true };
        }
    }
];
const toolsFor = (user) => TOOLS.filter(t => !t.admin || managesAny(user)); // each admin tool still checks the project it is given

async function mcpHandle(user, m) {
    const reply = (result) => ({ jsonrpc: '2.0', id: m.id, result });
    const error = (code, message) => ({ jsonrpc: '2.0', id: m && m.id !== undefined ? m.id : null, error: { code, message } });
    if (!m || m.jsonrpc !== '2.0' || typeof m.method !== 'string') return error(-32600, 'Invalid Request');
    const notification = m.id === undefined || m.id === null;
    if (notification) return null; // notifications get no reply and run nothing
    const params = m.params || {};
    if (m.method === 'initialize') {
        return reply({
            protocolVersion: MCP_VERSIONS.includes(params.protocolVersion) ? params.protocolVersion : MCP_VERSIONS[0],
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: 'swb-dashboard', version: '1.0.0' },
            instructions: user.role === 'admin'
                ? `You act as ${user.name} (admin). You can manage tasks, modules and versions. Start with list_projects.`
                : managesAny(user)
                    ? `You act as ${user.name} (project admin). In the projects you manage you can also create versions and modules and move tasks between them; elsewhere you can read projects and create, update, comment on and assign tasks. Start with list_projects.`
                    : `You act as ${user.name} (employee). You can read your projects and create, update, comment on and assign tasks. Modules and versions are read-only. Start with list_projects.`
        });
    }
    if (m.method === 'ping') return reply({});
    if (m.method === 'tools/list') return reply({ tools: toolsFor(user).map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
    if (m.method === 'tools/call') {
        const tool = toolsFor(user).find(t => t.name === params.name);
        if (!tool) return error(-32602, `Unknown tool: ${params.name}`);
        try {
            const out = await tool.run(user, params.arguments || {});
            return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
        } catch (e) {
            return reply({ content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true });
        }
    }
    if (notification) return null;
    return error(-32601, `Method not found: ${m.method}`);
}

async function mcpRoute(req, res) {
    if (req.method !== 'POST') { res.writeHead(405, { Allow: 'POST' }); return res.end(); }
    const user = bearerUser(req);
    if (!user) return sendJson(res, 401, { error: 'A valid access token is required (Authorization: Bearer dash_…)' }, { 'WWW-Authenticate': 'Bearer' });
    let msg;
    try { msg = JSON.parse((await readBody(req)).toString('utf8')); } catch (e) {
        if (e.status === 413) return sendJson(res, 413, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Request too large' } });
        return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    }
    const batch = Array.isArray(msg);
    if (batch && !msg.length) return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request: empty batch' } });
    const replies = [];
    for (const one of batch ? msg : [msg]) {
        const r = await mcpHandle(user, one);
        if (r) replies.push(r);
    }
    if (!replies.length) { res.writeHead(202); return res.end(); }
    sendJson(res, 200, batch ? replies : replies[0]);
}

async function handle(req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    const url = new URL(req.url, 'http://local');
    const p = url.pathname;
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(fs.readFileSync(PAGE_FILE));
    }
    if (p === '/mcp') return mcpRoute(req, res);
    if (p === '/auth/login' && req.method === 'POST') return login(req, res);
    if (p === '/auth/logout' && req.method === 'POST') return sendJson(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    const viaToken = !!req.headers.authorization;
    const user = viaToken ? bearerUser(req) : sessionUser(req);
    if (!user) throw fail(401, viaToken ? 'Invalid or revoked access token' : 'Sign in required');
    if (p === '/auth/me' && req.method === 'GET') return sendJson(res, 200, me(user));
    // Cookies need the custom header (CSRF guard); a bearer token cannot be sent by another site.
    if (!viaToken && req.method !== 'GET' && req.headers['x-requested-with'] !== 'dash') throw fail(403, 'Missing request header');
    let m;
    if ((m = p.match(/^\/plane\/([A-Za-z0-9_-]+)(\/.*)$/))) return planeProxy(req, res, user, m[1], m[2], url.search);
    if (p.startsWith('/admin/')) {
        if (viaToken) throw fail(403, 'Access tokens cannot manage accounts or workspaces');
        return adminRoutes(req, res, user, p);
    }
    if (p.startsWith('/api/')) return apiRoutes(req, res, user, url);
    throw fail(404, 'Not found');
}

// ---------- Command line ----------
async function cli(args) {
    const [cmd, username, password, a, ...rest] = args;
    if (cmd === 'adduser') {
        const role = ['admin', 'employee'].includes(a) ? a : 'employee';
        const name = (['admin', 'employee'].includes(a) ? rest : [a, ...rest]).filter(Boolean).join(' ') || username;
        if (!username || !password || password.length < 8) throw new Error('Usage: node server.js adduser <username> <password ≥ 8 chars> [admin|employee] [Full Name]');
        if (users.some(u => u.username === username.toLowerCase())) throw new Error('Username already exists');
        const u = { id: crypto.randomUUID(), username: username.toLowerCase(), name, role, active: true, access: {}, tokens: [], createdAt: new Date().toISOString() };
        await setPassword(u, password);
        users.push(u);
        saveUsers();
        console.log(`Created ${role} “${u.username}”.`);
    } else if (cmd === 'passwd') {
        const u = users.find(x => x.username === String(username).toLowerCase());
        if (!u || !password || password.length < 8) throw new Error('Usage: node server.js passwd <username> <new password ≥ 8 chars>');
        await setPassword(u, password);
        saveUsers();
        console.log(`Password changed for “${u.username}”.`);
    } else {
        throw new Error('Commands: adduser, passwd');
    }
}

if (['adduser', 'passwd'].includes(process.argv[2])) {
    cli(process.argv.slice(2)).catch(e => { console.error(e.message); process.exit(1); });
} else {
    const server = http.createServer((req, res) => {
        handle(req, res).catch(e => {
            const status = e.status || 500;
            if (status === 500) console.error(new Date().toISOString(), req.method, req.url, e);
            if (!res.headersSent) sendJson(res, status, { error: status === 500 ? 'Server error' : e.message });
            else res.end();
        });
    });
    process.on('uncaughtException', (e) => console.error(new Date().toISOString(), 'uncaught:', e));
    process.on('unhandledRejection', (e) => console.error(new Date().toISOString(), 'unhandled:', e));
    server.listen(config.port, config.host, () => {
        console.log(`Dashboard on http://${config.host}:${config.port}  (${users.length} user(s), ${config.workspaces.length} workspace(s))  ·  MCP: /mcp`);
        if (!users.length) console.log('No users yet — create the first admin: node server.js adduser <username> <password> admin');
    });
}
