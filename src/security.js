import { pbkdf2, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
const pbkdf2p = promisify(pbkdf2);

export const TARGET_ITERATIONS = 310000; // mantem compat. com contas antigas; sobe no login
const hex = (b) => b.toString('hex');

export async function hashPassword(password, iterations = TARGET_ITERATIONS) {
  const salt = randomBytes(16);
  const hash = await pbkdf2p(password, salt, iterations, 32, 'sha256');
  return { algorithm: 'pbkdf2-sha256', iterations, salt: hex(salt), hash: hex(hash) };
}
export async function verifyPassword(password, rec) {
  const h = await pbkdf2p(password, Buffer.from(rec.salt, 'hex'), rec.iterations, 32, 'sha256');
  const a = Buffer.from(rec.hash, 'hex');
  return a.length === h.length && timingSafeEqual(a, h);
}
// hash falso para igualar o tempo quando o nick nao existe
const DUMMY = { salt: '00'.repeat(16), iterations: TARGET_ITERATIONS, hash: '00'.repeat(32) };
export const dummyVerify = (pw) => verifyPassword(pw, DUMMY).catch(() => false);

export const sha256 = (s) => createHash('sha256').update(s).digest('hex');
export const newToken = () => randomBytes(32).toString('base64url');

export function safeEqualStr(a = '', b = '') {
  const x = Buffer.from(sha256(a)), y = Buffer.from(sha256(b));
  return timingSafeEqual(x, y);
}
export function requireKey(envName) {
  return (req, res, next) => {
    const key = process.env[envName];
    const got = req.get('x-api-key') || '';
    if (!key || !safeEqualStr(got, key)) return res.status(401).json({ error: 'unauthorized' });
    next();
  };
}

// rate limit simples em memoria (janela fixa)
export function rateLimit({ windowMs, max, keyFn }) {
  const hits = new Map();
  setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 60000).unref();
  return (req, res, next) => {
    const k = keyFn(req), n = Date.now();
    let e = hits.get(k);
    if (!e || e.reset < n) e = { count: 0, reset: n + windowMs };
    e.count++; hits.set(k, e);
    if (e.count > max) {
      res.set('Retry-After', Math.ceil((e.reset - n) / 1000));
      return res.status(429).json({ error: 'too_many_requests' });
    }
    next();
  };
}
// nick: Java 3-16 [A-Za-z0-9_], Bedrock pode ter prefixo "." (Floodgate)
export const NICK_RE = /^\.?[A-Za-z0-9_]{3,16}$/;
export const normNick = (n) => String(n || '').trim().toLowerCase();
