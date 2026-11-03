import express from 'express';
import { randomInt } from 'node:crypto';
import { db, audit } from './db.js';
import {
  hashPassword, verifyPassword, dummyVerify, TARGET_ITERATIONS, sha256, safeEqualStr, newToken,
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
const adminTokenLimit = rateLimit({ windowMs: 15 * 60000, max: 5, keyFn: (r) => `at:${ip(r)}:${normNick(r.body?.nick)}` });
const adminAuthLimit = rateLimit({ windowMs: 15 * 60000, max: 10, keyFn: (r) => `aa:${ip(r)}:${normNick(r.body?.nick)}` });

const getAccount = (nick) => db.prepare('SELECT * FROM accounts WHERE nick = ?').get(normNick(nick));
const rec = (a) => ({ iterations: a.pw_iterations, salt: a.pw_salt, hash: a.pw_hash });
const ADMIN_OWNER_NICK = normNick(process.env.ADMIN_OWNER_NICK || '');

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
  db.prepare('DELETE FROM admin_sessions WHERE account_id=?').run(a.id);
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

// ---------- Admin do site (senha independente + token de uso unico) ----------
const adminCookieOpts = `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${HOURS * 3600}`;
const readAdminCookie = (req) => (req.get('cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith('admin_sid='))?.slice(10);
const getAdminCredential = (accountId) => db.prepare('SELECT * FROM admin_credentials WHERE account_id=?').get(accountId);

function adminOwner(nick) {
  if (!ADMIN_OWNER_NICK || !NICK_RE.test(nick || '') || normNick(nick) !== ADMIN_OWNER_NICK) return null;
  return getAccount(nick);
}

async function verifyAdminServerPassword(nick, password) {
  const account = adminOwner(nick);
  const value = typeof password === 'string' ? password : '';
  if (!account) { await dummyVerify(value); return null; }
  if (value.length > 128) { await dummyVerify(value); return null; }
  if (!(await verifyPassword(value, rec(account)))) return null;
  await upgradeHash(account, value);
  return account;
}

function consumeAdminToken(accountId, token) {
  const challenge = db.prepare('SELECT * FROM admin_challenges WHERE account_id=?').get(accountId);
  if (!challenge || challenge.expires_at < Date.now() || challenge.attempts >= 5) {
    db.prepare('DELETE FROM admin_challenges WHERE account_id=?').run(accountId);
    return false;
  }
  if (typeof token !== 'string' || !safeEqualStr(sha256(token), challenge.token_hash)) {
    db.prepare('UPDATE admin_challenges SET attempts=attempts+1 WHERE account_id=? AND token_hash=?')
      .run(accountId, challenge.token_hash);
    return false;
  }
  return db.prepare('DELETE FROM admin_challenges WHERE account_id=? AND token_hash=? AND expires_at>=? AND attempts<5')
    .run(accountId, challenge.token_hash, Date.now()).changes === 1;
}

function startAdminSession(res, account) {
  const token = newToken();
  db.prepare('INSERT INTO admin_sessions(token_hash,account_id,expires_at) VALUES(?,?,?)')
    .run(sha256(token), account.id, Date.now() + HOURS * 3600000);
  res.set('Set-Cookie', `admin_sid=${token}; ${adminCookieOpts}`);
  audit(account.display_nick, 'admin_login', 'site');
}

function adminAuth(req, res, next) {
  const token = readAdminCookie(req);
  const session = token && db.prepare('SELECT * FROM admin_sessions WHERE token_hash=?').get(sha256(token));
  if (!session || session.expires_at < Date.now()) {
    if (token) db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(sha256(token));
    return res.status(401).json({ error: 'unauthenticated' });
  }
  req.adminAccountId = session.account_id;
  next();
}

app.get('/v1/site/admin/status', (_req, res) => {
  const account = ADMIN_OWNER_NICK ? getAccount(ADMIN_OWNER_NICK) : null;
  res.json({ configured: !!(account && getAdminCredential(account.id)) });
});

app.post('/v1/site/admin/token', adminTokenLimit, async (req, res) => {
  if (!ADMIN_OWNER_NICK) return res.status(503).json({ error: 'admin_not_configured' });
  const { nick, password } = req.body || {};
  const account = await verifyAdminServerPassword(nick, password);
  if (!account) return res.status(401).json({ error: 'invalid_credentials' });

  const token = String(randomInt(100000, 1000000));
  db.prepare(`INSERT INTO admin_challenges(account_id,token_hash,expires_at,attempts)
    VALUES(?,?,?,0) ON CONFLICT(account_id) DO UPDATE SET token_hash=excluded.token_hash,
    expires_at=excluded.expires_at, attempts=0, created_at=datetime('now')`)
    .run(account.id, sha256(token), Date.now() + 5 * 60000);
  console.info(`[admin] token for ${account.display_nick}: ${token} (expires in 5 minutes)`);
  res.json({ ok: true, setupRequired: !getAdminCredential(account.id) });
});

app.post('/v1/site/admin/setup', adminAuthLimit, async (req, res) => {
  const { nick, password, token, adminPassword } = req.body || {};
  const account = await verifyAdminServerPassword(nick, password);
  if (!account) return res.status(401).json({ error: 'invalid_credentials' });
  if (getAdminCredential(account.id)) return res.status(409).json({ error: 'admin_already_registered' });
  if (typeof adminPassword !== 'string' || adminPassword.length < 12 || adminPassword.length > 128 || adminPassword === password)
    return res.status(400).json({ error: 'invalid_admin_password' });
  if (!consumeAdminToken(account.id, token)) return res.status(401).json({ error: 'invalid_or_expired_token' });

  const credential = await hashPassword(adminPassword);
  const result = db.prepare(`INSERT INTO admin_credentials(account_id,pw_iterations,pw_salt,pw_hash)
    VALUES(?,?,?,?) ON CONFLICT(account_id) DO NOTHING`)
    .run(account.id, credential.iterations, credential.salt, credential.hash);
  if (result.changes !== 1) return res.status(409).json({ error: 'admin_already_registered' });
  startAdminSession(res, account);
  res.status(201).json({ ok: true, nick: account.display_nick });
});

app.post('/v1/site/admin/login', adminAuthLimit, async (req, res) => {
  const { nick, password, token, adminPassword } = req.body || {};
  const account = await verifyAdminServerPassword(nick, password);
  if (!account) return res.status(401).json({ error: 'invalid_credentials' });
  const credential = getAdminCredential(account.id);
  if (!credential) return res.status(409).json({ error: 'admin_not_registered' });
  if (typeof adminPassword !== 'string' || adminPassword.length > 128 || !(await verifyPassword(adminPassword, rec(credential))))
    return res.status(401).json({ error: 'invalid_credentials' });
  if (!consumeAdminToken(account.id, token)) return res.status(401).json({ error: 'invalid_or_expired_token' });
  startAdminSession(res, account);
  res.json({ ok: true, nick: account.display_nick });
});

app.get('/v1/site/admin/me', adminAuth, (req, res) => {
  const account = db.prepare('SELECT display_nick FROM accounts WHERE id=?').get(req.adminAccountId);
  res.json({ nick: account.display_nick });
});

app.post('/v1/site/admin/logout', (req, res) => {
  const token = readAdminCookie(req);
  if (token) db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(sha256(token));
  res.set('Set-Cookie', 'admin_sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0').json({ ok: true });
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
