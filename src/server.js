import express from 'express';
import { randomBytes, randomInt } from 'node:crypto';
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

app.get('/v1/site/admin/accounts', adminAuth, (req, res) => {
  const search = String(req.query.search || '').trim().slice(0, 32);
  const pattern = `%${search.replace(/[\\%_]/g, '\\$&')}%`;
  const rows = db.prepare(`SELECT a.id, a.display_nick AS nick, a.uuid, a.created_at AS createdAt,
      p.data AS profile, p.updated_at AS updatedAt
    FROM accounts a LEFT JOIN profiles p ON p.account_id=a.id
    WHERE ?='' OR a.nick LIKE ? ESCAPE '\\' OR a.display_nick LIKE ? ESCAPE '\\'
    ORDER BY lower(a.display_nick) LIMIT 100`).all(search, pattern, pattern);
  res.json({ accounts: rows.map(row => ({ ...row, profile: row.profile ? JSON.parse(row.profile) : null })) });
});

app.get('/v1/site/admin/roles', adminAuth, (_req, res) => {
  res.json({ roles: db.prepare('SELECT id,name,lp_group AS groupName FROM admin_roles ORDER BY name').all()
    .map(role => ({ id: role.id, name: role.name, group: role.groupName })) });
});

app.post('/v1/site/admin/roles', adminAuth, (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const group = typeof req.body?.group === 'string' ? req.body.group.trim() : '';
  if (!/^[A-Za-z0-9 _-]{2,32}$/.test(name) || !/^[A-Za-z0-9._-]{1,64}$/.test(group) || group.toLowerCase() === 'default')
    return res.status(400).json({ error: 'invalid_role' });
  try {
    const result = db.prepare('INSERT INTO admin_roles(name,lp_group) VALUES(?,?)').run(name, group);
    audit(ADMIN_OWNER_NICK, 'admin_role_create', `${name}:${group}`);
    res.status(201).json({ role: { id: Number(result.lastInsertRowid), name, group } });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'role_exists' });
    throw error;
  }
});

app.delete('/v1/site/admin/roles/:id', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'invalid_role' });
  const result = db.prepare('DELETE FROM admin_roles WHERE id=?').run(id);
  if (!result.changes) return res.status(404).json({ error: 'role_not_found' });
  audit(ADMIN_OWNER_NICK, 'admin_role_delete', String(id));
  res.json({ ok: true });
});

app.get('/v1/site/admin/actions', adminAuth, (_req, res) => {
  const actions = db.prepare(`SELECT x.id, a.display_nick AS nick, x.actor_nick AS actor, x.action,
      x.status, x.result, x.created_at AS createdAt, x.completed_at AS completedAt
    FROM admin_actions x JOIN accounts a ON a.id=x.target_account_id ORDER BY x.id DESC LIMIT 100`).all();
  res.json({ actions });
});

app.post('/v1/site/admin/accounts/:nick/actions', adminAuth, (req, res) => {
  const account = getAccount(req.params.nick);
  if (!account) return res.status(404).json({ error: 'account_not_found' });
  const { action } = req.body || {};
  const allowed = new Set(['ban', 'unban', 'kick', 'mute', 'unmute', 'warn', 'set_role', 'reset_password']);
  if (!allowed.has(action)) return res.status(400).json({ error: 'invalid_action' });

  if (action === 'reset_password') {
    const password = randomBytes(18).toString('base64url');
    return hashPassword(password).then(credential => {
      db.prepare('UPDATE accounts SET pw_iterations=?,pw_salt=?,pw_hash=? WHERE id=?')
        .run(credential.iterations, credential.salt, credential.hash, account.id);
      db.prepare('DELETE FROM sessions WHERE account_id=?').run(account.id);
      db.prepare('DELETE FROM admin_sessions WHERE account_id=?').run(account.id);
      audit(ADMIN_OWNER_NICK, 'admin_password_reset', account.display_nick);
      res.json({ ok: true, temporaryPassword: password });
    }).catch(error => res.status(500).json({ error: 'password_reset_failed' }));
  }

  const payload = {};
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
  if (['ban', 'kick', 'mute', 'warn'].includes(action) && (!reason || reason.length > 200))
    return res.status(400).json({ error: 'invalid_reason' });
  if (['ban', 'kick', 'mute', 'warn'].includes(action)) payload.reason = reason;

  if (action === 'ban' && req.body?.days !== '' && req.body?.days != null) {
    const days = Number(req.body.days);
    if (!Number.isInteger(days) || days < 1 || days > 3650) return res.status(400).json({ error: 'invalid_duration' });
    payload.expiresAt = Date.now() + days * 86400000;
  }
  if (action === 'mute') {
    const minutes = Number(req.body?.minutes);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 525600) return res.status(400).json({ error: 'invalid_duration' });
    payload.expiresAt = Date.now() + minutes * 60000;
    db.prepare(`INSERT INTO admin_mutes(account_id,actor_nick,reason,expires_at) VALUES(?,?,?,?)
      ON CONFLICT(account_id) DO UPDATE SET actor_nick=excluded.actor_nick, reason=excluded.reason,
      expires_at=excluded.expires_at, updated_at=datetime('now')`)
      .run(account.id, ADMIN_OWNER_NICK, reason, payload.expiresAt);
  }
  if (action === 'unmute') db.prepare('DELETE FROM admin_mutes WHERE account_id=?').run(account.id);
  if (action === 'set_role') {
    const role = db.prepare('SELECT id,name,lp_group AS groupName FROM admin_roles WHERE id=?').get(Number(req.body?.roleId));
    if (!role) return res.status(400).json({ error: 'invalid_role' });
    payload.roleName = role.name;
    payload.roleGroup = role.groupName;
    payload.mappedGroups = db.prepare('SELECT lp_group FROM admin_roles').all().map(row => row.lp_group);
  }

  const result = db.prepare('INSERT INTO admin_actions(target_account_id,actor_nick,action,payload) VALUES(?,?,?,?)')
    .run(account.id, ADMIN_OWNER_NICK, action, JSON.stringify(payload));
  audit(ADMIN_OWNER_NICK, `admin_${action}`, account.display_nick);
  res.status(202).json({ ok: true, id: Number(result.lastInsertRowid), status: 'pending' });
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
app.get('/v1/bridge/admin/actions', bridgeKey, (_req, res) => {
  const actions = db.prepare(`SELECT x.id, a.display_nick AS nick, a.uuid, x.action,
      x.payload, x.status FROM admin_actions x JOIN accounts a ON a.id=x.target_account_id
    WHERE x.status='pending' ORDER BY x.id LIMIT 50`).all();
  res.json({ actions: actions.map(row => ({ ...row, payload: JSON.parse(row.payload) })) });
});
app.post('/v1/bridge/admin/actions/:id/result', bridgeKey, (req, res) => {
  const { status, result } = req.body || {};
  if (!['done', 'error'].includes(status) || typeof result !== 'string' || result.length > 200)
    return res.status(400).json({ error: 'invalid_result' });
  const update = db.prepare(`UPDATE admin_actions SET status=?, result=?, completed_at=datetime('now')
    WHERE id=? AND status='pending'`).run(status, result, req.params.id);
  res.json({ ok: true, updated: update.changes === 1 });
});
app.get('/v1/bridge/admin/mutes', bridgeKey, (_req, res) => {
  db.prepare('DELETE FROM admin_mutes WHERE expires_at<=?').run(Date.now());
  const mutes = db.prepare(`SELECT a.display_nick AS nick, a.uuid, m.reason, m.expires_at AS expiresAt
    FROM admin_mutes m JOIN accounts a ON a.id=m.account_id WHERE m.expires_at>?`).all(Date.now());
  res.json({ mutes });
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
