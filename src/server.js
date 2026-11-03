import express from 'express';
import { db, audit } from './db.js';
import {
  hashPassword, verifyPassword, dummyVerify, TARGET_ITERATIONS, sha256, newToken,
  requireKey, rateLimit, NICK_RE, normNick
} from './security.js';

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));

const ORIGIN = process.env.SITE_ORIGIN || '';
app.use((req, res, next) => {
  if (ORIGIN && req.get('origin') === ORIGIN) {
    res.set({ 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Vary': 'Origin' });
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const ip = (req) => req.ip;
const loginLimit = rateLimit({ windowMs: 15 * 60000, max: 10, keyFn: (r) => `l:${ip(r)}:${normNick(r.body?.nick)}` });
const ipLimit = rateLimit({ windowMs: 60000, max: 60, keyFn: (r) => `i:${ip(r)}` });

const getAccount = (nick) => db.prepare('SELECT * FROM accounts WHERE nick = ?').get(normNick(nick));
const rec = (a) => ({ iterations: a.pw_iterations, salt: a.pw_salt, hash: a.pw_hash });

app.get('/health', (_req, res) => res.json({ ok: true }));

// ---------- NexoriaLogin (chave LOGIN_KEY) ----------
const loginKey = requireKey('LOGIN_KEY');

app.post('/v1/auth/register', loginKey, async (req, res) => {
  const { nick, password, uuid } = req.body || {};
  if (!NICK_RE.test(nick || '')) return res.status(400).json({ error: 'invalid_nick' });
  if (typeof password !== 'string' || password.length < 6 || password.length > 128)
    return res.status(400).json({ error: 'invalid_password' });
  if (getAccount(nick)) return res.status(409).json({ error: 'nick_taken' });
  const p = await hashPassword(password);
  const r = db.prepare(`INSERT INTO accounts(nick,display_nick,uuid,pw_algorithm,pw_iterations,pw_salt,pw_hash)
    VALUES(?,?,?,?,?,?,?)`).run(normNick(nick), nick, uuid || null, p.algorithm, p.iterations, p.salt, p.hash);
  audit('login-plugin', 'register', nick);
  res.status(201).json({ ok: true, accountId: Number(r.lastInsertRowid) });
});

app.post('/v1/auth/verify', loginKey, loginLimit, async (req, res) => {
  const { nick, password } = req.body || {};
  const a = getAccount(nick);
  if (!a) { await dummyVerify(String(password || '')); return res.status(401).json({ error: 'invalid_credentials' }); }
  if (!(await verifyPassword(String(password || ''), rec(a)))) return res.status(401).json({ error: 'invalid_credentials' });
  await upgradeHash(a, password);
  res.json({ ok: true, accountId: a.id });
});

app.post('/v1/auth/exists', loginKey, (req, res) => res.json({ exists: !!getAccount(req.body?.nick) }));

app.post('/v1/auth/change-password', loginKey, loginLimit, async (req, res) => {
  const { nick, oldPassword, newPassword } = req.body || {};
  const a = getAccount(nick);
  if (!a || typeof newPassword !== 'string' || newPassword.length < 6 || newPassword.length > 128)
    return res.status(400).json({ error: 'invalid_request' });
  if (!(await verifyPassword(String(oldPassword || ''), rec(a)))) return res.status(401).json({ error: 'invalid_credentials' });
  const p = await hashPassword(newPassword);
  db.prepare('UPDATE accounts SET pw_iterations=?,pw_salt=?,pw_hash=? WHERE id=?').run(p.iterations, p.salt, p.hash, a.id);
  db.prepare('DELETE FROM sessions WHERE account_id=?').run(a.id); // derruba sessoes do site
  audit('login-plugin', 'change_password', a.display_nick);
  res.json({ ok: true });
});

async function upgradeHash(a, password) {
  if (a.pw_iterations >= TARGET_ITERATIONS) return;
  const p = await hashPassword(password);
  db.prepare('UPDATE accounts SET pw_iterations=?,pw_salt=?,pw_hash=? WHERE id=?').run(p.iterations, p.salt, p.hash, a.id);
}

// ---------- Site (sessao por cookie httpOnly) ----------
const HOURS = Number(process.env.SESSION_HOURS || 24);
const cookieOpts = `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${HOURS * 3600}`;
const readCookie = (req) => (req.get('cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith('sid='))?.slice(4);

app.post('/v1/site/login', ipLimit, loginLimit, async (req, res) => {
  const { nick, password } = req.body || {};
  const a = getAccount(nick);
  const ok = a ? await verifyPassword(String(password || ''), rec(a)) : await dummyVerify(String(password || ''));
  if (!a || !ok) return res.status(401).json({ error: 'invalid_credentials' });
  await upgradeHash(a, password);
  const token = newToken();
  db.prepare('INSERT INTO sessions(token_hash,account_id,expires_at) VALUES(?,?,?)')
    .run(sha256(token), a.id, Date.now() + HOURS * 3600000);
  res.set('Set-Cookie', `sid=${token}; ${cookieOpts}`).json({ ok: true, nick: a.display_nick });
});

function siteAuth(req, res, next) {
  const t = readCookie(req);
  const s = t && db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(sha256(t));
  if (!s || s.expires_at < Date.now()) return res.status(401).json({ error: 'unauthenticated' });
  req.accountId = s.account_id; next();
}
app.post('/v1/site/logout', (req, res) => {
  const t = readCookie(req);
  if (t) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha256(t));
  res.set('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0').json({ ok: true });
});
app.get('/v1/site/me', siteAuth, (req, res) => {
  const a = db.prepare('SELECT id,display_nick FROM accounts WHERE id=?').get(req.accountId);
  const p = db.prepare('SELECT data,updated_at FROM profiles WHERE account_id=?').get(req.accountId);
  res.json({ nick: a.display_nick, profile: p ? JSON.parse(p.data) : null, updatedAt: p?.updated_at || null });
});
// pede dado fresco: a API so registra o pedido, o Bridge busca
app.post('/v1/site/refresh', siteAuth, rateLimit({ windowMs: 30000, max: 3, keyFn: (r) => `rf:${r.ip}` }), (req, res) => {
  db.prepare("INSERT INTO refresh_requests(account_id) VALUES(?)").run(req.accountId);
  res.status(202).json({ ok: true });
});

// ---------- NexoriaBridge (chave BRIDGE_KEY) ----------
const bridgeKey = requireKey('BRIDGE_KEY');
app.put('/v1/bridge/profile/:nick', bridgeKey, (req, res) => {
  const a = getAccount(req.params.nick);
  if (!a) return res.status(404).json({ error: 'unknown_account' });
  db.prepare(`INSERT INTO profiles(account_id,data,updated_at) VALUES(?,?,datetime('now'))
    ON CONFLICT(account_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`)
    .run(a.id, JSON.stringify(req.body || {}));
  res.json({ ok: true });
});
app.get('/v1/bridge/refresh-requests', bridgeKey, (_req, res) => {
  const rows = db.prepare(`SELECT r.id, a.display_nick AS nick FROM refresh_requests r
    JOIN accounts a ON a.id=r.account_id WHERE r.status='pending' LIMIT 50`).all();
  res.json({ requests: rows });
});
app.post('/v1/bridge/refresh-requests/:id/done', bridgeKey, (req, res) => {
  db.prepare("UPDATE refresh_requests SET status='done' WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// ---------- Plugin de VIP (chave VIP_KEY): fila de comandos ----------
const vipKey = requireKey('VIP_KEY');
app.get('/v1/vip/commands', vipKey, (_req, res) => {
  const rows = db.prepare(`SELECT c.id,c.event_id,c.type,c.payload,a.display_nick AS nick,a.uuid
    FROM commands c JOIN accounts a ON a.id=c.account_id WHERE c.status='pending' ORDER BY c.id LIMIT 50`).all();
  res.json({ commands: rows.map(r => ({ ...r, payload: JSON.parse(r.payload) })) });
});
app.post('/v1/vip/commands/:id/ack', vipKey, (req, res) => {
  db.prepare("UPDATE commands SET status='done', done_at=datetime('now') WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'internal' }); });
const port = Number(process.env.PORT || 80);
app.listen(port, '0.0.0.0', () => console.log(`API ouvindo em ${port}`));
