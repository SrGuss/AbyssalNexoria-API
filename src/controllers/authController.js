import { createHmac, randomInt, timingSafeEqual } from 'node:crypto';

const CODE_TTL_MS = 5 * 60 * 1000;
const RESEND_INTERVAL_MS = 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;
const GENERIC_LOGIN_MESSAGE = 'Se houver uma conta vinculada a este e-mail, enviaremos um código de acesso.';
const normalizeEmail = value => typeof value === 'string' ? value.trim().toLowerCase() : '';
const validEmail = value => value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

export function createAuthController({ db, audit, sendEmail, accessCodeEmail, createSiteSession }) {
  function codeHash(accountId, purpose, email, code) {
    const pepper = process.env.EMAIL_CODE_PEPPER || process.env.LOGIN_KEY;
    if (!pepper) throw new Error('email_code_secret_not_configured');
    return createHmac('sha256', pepper).update(`${accountId}:${purpose}:${email}:${code}`).digest('hex');
  }

  function canSend(accountId, purpose) {
    const last = db.prepare(`SELECT created_at AS createdAt FROM email_access_codes
      WHERE account_id=? AND purpose=? ORDER BY id DESC LIMIT 1`).get(accountId, purpose);
    return !last || Date.now() - last.createdAt >= RESEND_INTERVAL_MS;
  }

  async function issueCode(account, email, purpose) {
    if (!canSend(account.id, purpose)) return false;
    const code = String(randomInt(0, 1000000)).padStart(6, '0');
    const now = Date.now();
    const hash = codeHash(account.id, purpose, email, code);
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare(`UPDATE email_access_codes SET consumed_at=?
        WHERE account_id=? AND purpose=? AND consumed_at IS NULL`).run(now, account.id, purpose);
      db.prepare(`INSERT INTO email_access_codes(account_id,email,purpose,code_hash,expires_at,created_at)
        VALUES(?,?,?,?,?,?)`).run(account.id, email, purpose, hash, now + CODE_TTL_MS, now);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }

    try {
      await sendEmail({ to: email, ...accessCodeEmail({ code, purpose }) });
      return true;
    } catch (error) {
      db.prepare('UPDATE email_access_codes SET consumed_at=? WHERE account_id=? AND purpose=? AND code_hash=? AND consumed_at IS NULL')
        .run(Date.now(), account.id, purpose, hash);
      throw error;
    }
  }

  function consumeCode(accountId, purpose, email, code) {
    const now = Date.now();
    db.exec('BEGIN IMMEDIATE');
    try {
      const record = db.prepare(`SELECT * FROM email_access_codes
        WHERE account_id=? AND purpose=? AND email=? AND consumed_at IS NULL
        ORDER BY id DESC LIMIT 1`).get(accountId, purpose, email);
      if (!record || record.expires_at <= now || record.attempts >= MAX_CODE_ATTEMPTS) {
        if (record) db.prepare('UPDATE email_access_codes SET consumed_at=? WHERE id=? AND consumed_at IS NULL').run(now, record.id);
        db.exec('COMMIT');
        return false;
      }

      const expected = Buffer.from(record.code_hash, 'hex');
      const supplied = Buffer.from(codeHash(accountId, purpose, email, code), 'hex');
      const matches = expected.length === supplied.length && timingSafeEqual(expected, supplied);
      if (!matches) {
        db.prepare(`UPDATE email_access_codes SET attempts=attempts+1,
          consumed_at=CASE WHEN attempts+1>=? THEN ? ELSE consumed_at END WHERE id=? AND consumed_at IS NULL`)
          .run(MAX_CODE_ATTEMPTS, now, record.id);
        db.exec('COMMIT');
        return false;
      }

      const consumed = db.prepare(`UPDATE email_access_codes SET consumed_at=?
        WHERE id=? AND consumed_at IS NULL AND expires_at>? AND attempts<?`)
        .run(now, record.id, now, MAX_CODE_ATTEMPTS);
      db.exec('COMMIT');
      return consumed.changes === 1;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  async function requestLoginCode(req, res) {
    const email = normalizeEmail(req.body?.email);
    if (validEmail(email)) {
      const account = db.prepare('SELECT id,display_nick FROM accounts WHERE lower(email)=? AND email_verified=1').get(email);
      if (account && canSend(account.id, 'site_login')) {
        try { await issueCode(account, email, 'site_login'); }
        catch { /* Do not reveal account existence or SMTP state on this public route. */ }
      }
    }
    res.status(202).json({ ok: true, message: GENERIC_LOGIN_MESSAGE });
  }

  function verifyLoginCode(req, res) {
    const email = normalizeEmail(req.body?.email);
    const rawCode = typeof req.body?.code === 'string' ? req.body.code : '';
    const code = /^\d{6}$/.test(rawCode) ? rawCode : '';
    const account = validEmail(email)
      ? db.prepare('SELECT id,display_nick FROM accounts WHERE lower(email)=? AND email_verified=1').get(email)
      : null;
    if (!account || !consumeCode(account.id, 'site_login', email, code))
      return res.status(401).json({ error: 'invalid_or_expired_code' });
    createSiteSession(res, account);
    audit(account.display_nick, 'site_email_login', 'verified_code');
    res.json({ ok: true, nick: account.display_nick });
  }

  async function requestEmailLinkCode(req, res) {
    const email = normalizeEmail(req.body?.email);
    if (!validEmail(email)) return res.status(400).json({ error: 'invalid_email' });
    const account = db.prepare('SELECT id,display_nick,email,email_verified AS emailVerified FROM accounts WHERE id=?').get(req.accountId);
    if (account.emailVerified && account.email?.toLowerCase() === email)
      return res.status(409).json({ error: 'email_already_verified' });
    const other = db.prepare('SELECT id FROM accounts WHERE lower(email)=? AND email_verified=1 AND id<>?').get(email, req.accountId);
    if (other) return res.status(409).json({ error: 'email_in_use' });
    if (!canSend(account.id, 'email_link')) return res.status(429).json({ error: 'email_code_cooldown' });
    try {
      await issueCode(account, email, 'email_link');
      res.status(202).json({ ok: true, message: 'Se o endereço puder ser usado, enviaremos um código de confirmação.' });
    } catch {
      res.status(503).json({ error: 'email_unavailable' });
    }
  }

  function verifyEmailLinkCode(req, res) {
    const email = normalizeEmail(req.body?.email);
    const rawCode = typeof req.body?.code === 'string' ? req.body.code : '';
    const code = /^\d{6}$/.test(rawCode) ? rawCode : '';
    if (!validEmail(email) || !consumeCode(req.accountId, 'email_link', email, code))
      return res.status(401).json({ error: 'invalid_or_expired_code' });
    try {
      const result = db.prepare('UPDATE accounts SET email=?,email_verified=1 WHERE id=?').run(email, req.accountId);
      if (!result.changes) return res.status(404).json({ error: 'account_not_found' });
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'email_in_use' });
      throw error;
    }
    db.prepare(`UPDATE email_access_codes SET consumed_at=? WHERE account_id=? AND purpose='email_link' AND consumed_at IS NULL`)
      .run(Date.now(), req.accountId);
    audit(String(req.accountId), 'site_email_verified', 'account_email');
    res.json({ ok: true, email, emailVerified: true });
  }

  return { requestLoginCode, verifyLoginCode, requestEmailLinkCode, verifyEmailLinkCode };
}
