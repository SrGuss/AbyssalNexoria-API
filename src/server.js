import 'dotenv/config';
import express from 'express';
import { createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { db, audit } from './db.js';
import { sendEmail, verifyEmailTransport } from './services/emailService.js';
import { accessCodeEmail } from './templates/accessCodeEmail.js';
import { createAuthRoutes } from './routes/authRoutes.js';
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

function createSiteSession(res, account) {
  const token = newToken();
  db.prepare('INSERT INTO sessions(token_hash,account_id,expires_at) VALUES(?,?,?)')
    .run(sha256(token), account.id, Date.now() + HOURS * 3600000);
  res.set('Set-Cookie', `sid=${token}; ${cookieOpts}`);
}

app.post('/v1/site/login', ipLimit, loginLimit, async (req, res) => {
  const { nick, password } = req.body || {};
  const a = getAccount(nick);
  const ok = a ? await verifyPassword(String(password || ''), rec(a)) : await dummyVerify(String(password || ''));
  if (!a || !ok) return res.status(401).json({ error: 'invalid_credentials' });
  await upgradeHash(a, password);
  createSiteSession(res, a);
  res.json({ ok: true, nick: a.display_nick });
});

function siteAuth(req, res, next) {
  const t = readCookie(req);
  const s = t && db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(sha256(t));
  if (!s || s.expires_at < Date.now()) return res.status(401).json({ error: 'unauthenticated' });
  const account = db.prepare('SELECT id,display_nick,created_at,email_verified FROM accounts WHERE id=?').get(s.account_id);
  if (!account) return res.status(401).json({ error: 'unauthenticated' });
  const deadline = emailRegistrationDeadline(account);
  const path = req.originalUrl.split('?')[0];
  const canRegisterEmail = path === '/v1/site/me' || /^\/v1\/site\/auth\/email-code\/link\/(request|verify)$/.test(path);
  if (!account.email_verified && deadline !== null && deadline <= Date.now() && !canRegisterEmail)
    return res.status(403).json({ error: 'email_registration_required' });
  req.accountId = s.account_id;
  next();
}
app.use('/v1/site/auth', createAuthRoutes({ db, audit, sendEmail, accessCodeEmail, createSiteSession, siteAuth, rateLimit }));
app.post('/v1/site/logout', (req, res) => {
  const t = readCookie(req);
  if (t) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha256(t));
  res.set('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0').json({ ok: true });
});
app.get('/v1/site/me', siteAuth, (req, res) => {
  const a = db.prepare('SELECT id,display_nick,created_at AS createdAt,email,email_verified AS emailVerified FROM accounts WHERE id=?').get(req.accountId);
  const p = db.prepare('SELECT data,updated_at FROM profiles WHERE account_id=?').get(req.accountId);
  const emailDeadline = emailRegistrationDeadline({ ...a, id: req.accountId, created_at: a.createdAt });
  res.json({ nick: a.display_nick, email: a.email || null, emailVerified: Boolean(a.emailVerified), emailRequired: emailDeadline !== null, emailDeadline, profile: p ? JSON.parse(p.data) : null, updatedAt: p?.updated_at || null });
});

// ---------- Loja ----------
const storeProductsQuery = `SELECT p.id,p.category_id AS categoryId,c.name AS category,p.name,p.description,
    p.price_cents AS priceCents,p.kind,p.vip_group AS vipGroup,p.duration_days AS durationDays,
    p.product_code AS productCode,p.active
  FROM store_products p JOIN store_categories c ON c.id=p.category_id`;

app.get('/v1/site/store/catalog', (_req, res) => {
  const products = db.prepare(`${storeProductsQuery} WHERE p.active=1 ORDER BY c.name,p.name`).all();
  const categories = [...new Map(products.map(product => [product.categoryId, { id: product.categoryId, name: product.category }])).values()];
  res.json({ categories, products });
});

const paymentLimit = rateLimit({ windowMs: 60000, max: 5, keyFn: (r) => `pay:${r.ip}:${r.accountId || ''}` });
const paymentVerifyLimit = rateLimit({ windowMs: 60000, max: 8, keyFn: (r) => `pv:${r.ip}:${r.accountId || ''}:${r.params.id}` });
const PIX_EXPIRATION_MS = 30 * 60 * 1000;
let pixCleanupRunning = false;
async function cleanupExpiredPixOrders() {
  if (pixCleanupRunning) return;
  pixCleanupRunning = true;
  const now = Date.now();
  const expiredOrders = db.prepare("SELECT * FROM store_orders WHERE status='pending' AND expires_at IS NOT NULL AND expires_at<=?").all(now);
  const accessToken = process.env.MP_ACCESS_TOKEN;
  const mpBase = (process.env.MP_API_URL || 'https://api.mercadopago.com').replace(/\/$/, '');
  try {
    for (const order of expiredOrders) {
      if (!order.payment_id) {
        db.prepare("DELETE FROM store_orders WHERE id=? AND status='pending' AND expires_at<=?").run(order.id, now);
        audit('system', 'store_pix_expired', order.id);
        continue;
      }
      if (!accessToken) continue;
      try {
        const headers = { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' };
        const response = await fetch(`${mpBase}/v1/payments/${encodeURIComponent(order.payment_id)}`, {
          headers, signal: AbortSignal.timeout(10000),
        });
        if (response.status === 404) {
          db.prepare("DELETE FROM store_orders WHERE id=? AND status='pending' AND expires_at<=?").run(order.id, now);
          audit('system', 'store_pix_expired', order.id);
          continue;
        }
        if (!response.ok) continue;
        const payment = await response.json();
        if (payment.external_reference !== order.id || payment.currency_id !== 'BRL'
          || Math.round(Number(payment.transaction_amount) * 100) !== order.amount_cents) {
          console.error('[mercadopago] expired order verification mismatch', order.id, String(payment.id || ''));
          continue;
        }
        if (payment.status === 'approved') {
          finalizeApprovedPayment(order, payment);
          continue;
        }
        const methodId = String(payment.payment_method_id || order.payment_method_id || '').toLowerCase();
        if (!methodId) continue;
        if (methodId !== 'pix') {
          db.prepare("UPDATE store_orders SET expires_at=NULL,payment_method_id=?,payment_type=COALESCE(?,payment_type) WHERE id=? AND status='pending'")
            .run(methodId, payment.payment_type_id || null, order.id);
          continue;
        }
        db.prepare("UPDATE store_orders SET payment_method_id='pix',payment_type=COALESCE(?,payment_type) WHERE id=? AND status='pending'")
          .run(payment.payment_type_id || null, order.id);
        if (['cancelled', 'expired', 'rejected'].includes(payment.status)) {
          db.prepare("DELETE FROM store_orders WHERE id=? AND status='pending' AND expires_at<=?").run(order.id, now);
          audit('system', 'store_pix_expired', order.id);
          continue;
        }
        if (!['pending', 'in_process', 'authorized'].includes(payment.status)) continue;

        const cancellation = await fetch(`${mpBase}/v1/payments/${encodeURIComponent(order.payment_id)}`, {
          method: 'PUT', headers, body: JSON.stringify({ status: 'cancelled' }), signal: AbortSignal.timeout(10000),
        });
        const cancelledPayment = await cancellation.json().catch(() => ({}));
        if (cancellation.ok && cancelledPayment.status === 'cancelled') {
          db.prepare("DELETE FROM store_orders WHERE id=? AND status='pending' AND expires_at<=?").run(order.id, now);
          audit('system', 'store_pix_expired', order.id);
        }
      } catch (error) {
        console.error('[mercadopago] expired Pix cleanup failed', order.id, String(error?.message || error).slice(0, 120));
      }
    }
  } finally {
    pixCleanupRunning = false;
  }
}
const pixCleanupTimer = setInterval(() => { cleanupExpiredPixOrders().catch(error => console.error('[store] Pix cleanup failed', error)); }, 30000);
pixCleanupTimer.unref();
cleanupExpiredPixOrders().catch(error => console.error('[store] Pix cleanup failed', error));

function isValidCpf(value) {
  if (typeof value !== 'string' || !/^\d{11}$/.test(value) || /^([0-9])\1{10}$/.test(value)) return false;
  const checkDigit = length => {
    let sum = 0;
    for (let index = 0; index < length; index++) sum += Number(value[index]) * (length + 1 - index);
    const remainder = (sum * 10) % 11;
    return remainder === 10 ? 0 : remainder;
  };
  return checkDigit(9) === Number(value[9]) && checkDigit(10) === Number(value[10]);
}

function finalizeApprovedPayment(order, payment) {
  const items = db.prepare('SELECT * FROM store_order_items WHERE order_id=?').all(order.id);
  db.exec('BEGIN IMMEDIATE');
  try {
    const updated = db.prepare(`UPDATE store_orders SET status='paid',payment_id=?,payment_method_id=COALESCE(?,payment_method_id),
      payment_type=COALESCE(?,payment_type),paid_at=COALESCE(paid_at,?),updated_at=datetime('now') WHERE id=? AND status='pending'`)
      .run(String(payment.id), payment.payment_method_id || null, payment.payment_type_id || null, Date.now(), order.id);
    if (updated.changes) {
      const command = db.prepare('INSERT OR IGNORE INTO commands(event_id,account_id,type,payload) VALUES(?,?,?,?)');
      for (const item of items) {
        const type = item.kind === 'vip' ? 'GRANT_VIP' : 'STORE_PRODUCT';
        const payload = JSON.stringify({
          orderId: order.id, productId: item.product_id, productName: item.name, quantity: item.quantity,
          group: item.vip_group, durationDays: item.duration_days, productCode: item.product_code,
        });
        command.run(`mp:${payment.id}:${item.id}`, order.account_id, type, payload);
      }
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  if (order.status !== 'paid') audit('mercadopago', 'store_payment_approved', order.id);
}

app.post('/v1/site/store/payments', siteAuth, paymentLimit, async (req, res) => {
  const accessToken = process.env.MP_ACCESS_TOKEN;
  const webhookSecret = process.env.MP_WEBHOOK_SECRET;
  const webhookUrl = process.env.MP_WEBHOOK_URL;
  if (!accessToken || !webhookSecret || !webhookUrl)
    return res.status(503).json({ error: 'payments_not_configured' });

  const requested = req.body?.items;
  if (!Array.isArray(requested) || requested.length < 1 || requested.length > 20)
    return res.status(400).json({ error: 'invalid_cart' });
  const form = req.body?.payment;
  const methodId = typeof form?.payment_method_id === 'string' ? form.payment_method_id : '';
  const payer = form?.payer || {};
  const email = typeof payer.email === 'string' ? payer.email.trim().toLowerCase() : '';
  const identificationType = typeof payer.identification?.type === 'string' ? payer.identification.type.trim() : '';
  const identificationNumber = typeof payer.identification?.number === 'string'
    ? payer.identification.number.replace(/\D/g, '') : '';
  const validIdentification = /^[a-z0-9_-]{1,16}$/i.test(identificationType)
    && /^\d{5,20}$/.test(identificationNumber);
  if (!/^[a-z0-9_-]{2,64}$/i.test(methodId) || email.length > 254
    || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'invalid_payment_data' });
  if (methodId === 'pix' && (identificationType.toUpperCase() !== 'CPF' || !isValidCpf(identificationNumber)))
    return res.status(400).json({ error: 'pix_cpf_invalid' });
  const paymentToken = typeof form.token === 'string' ? form.token : '';
  const isCard = !!paymentToken;
  if ((isCard && (paymentToken.length > 2048 || !Number.isSafeInteger(Number(form.installments))
      || Number(form.installments) < 1 || Number(form.installments) > 24))
    || (!isCard && methodId !== 'pix' && methodId !== 'bolbradesco'))
    return res.status(400).json({ error: 'invalid_payment_data' });

  const quantities = new Map();
  for (const item of requested) {
    const id = Number(item?.id), quantity = Number(item?.quantity);
    if (!Number.isSafeInteger(id) || id < 1 || !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 99)
      return res.status(400).json({ error: 'invalid_cart' });
    quantities.set(id, (quantities.get(id) || 0) + quantity);
  }
  if ([...quantities.values()].some(quantity => quantity > 99)) return res.status(400).json({ error: 'invalid_cart' });

  const ids = [...quantities.keys()];
  const products = db.prepare(`${storeProductsQuery} WHERE p.active=1 AND p.id IN (${ids.map(() => '?').join(',')})`).all(...ids);
  if (products.length !== ids.length) return res.status(400).json({ error: 'products_unavailable' });
  const amountCents = products.reduce((sum, product) => sum + product.priceCents * quantities.get(product.id), 0);
  if (!Number.isSafeInteger(amountCents) || amountCents < 100) return res.status(400).json({ error: 'invalid_total' });

  const expiresAt = methodId === 'pix' ? Date.now() + PIX_EXPIRATION_MS : null;
  const orderId = randomUUID();
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('INSERT INTO store_orders(id,account_id,amount_cents,expires_at) VALUES(?,?,?,?)')
      .run(orderId, req.accountId, amountCents, expiresAt);
    const insertItem = db.prepare(`INSERT INTO store_order_items(order_id,product_id,name,kind,vip_group,duration_days,product_code,price_cents,quantity)
      VALUES(?,?,?,?,?,?,?,?,?)`);
    for (const product of products) insertItem.run(orderId, product.id, product.name, product.kind, product.vipGroup,
      product.durationDays, product.productCode, product.priceCents, quantities.get(product.id));
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  const mpBase = (process.env.MP_API_URL || 'https://api.mercadopago.com').replace(/\/$/, '');
  try {
    const paymentRequest = {
      transaction_amount: amountCents / 100,
      description: products.map(product => product.name).join(', ').slice(0, 250),
      payment_method_id: methodId,
      payer: {
        email,
      },
      external_reference: orderId,
      notification_url: webhookUrl,
    };
    if (expiresAt) paymentRequest.date_of_expiration = new Date(expiresAt).toISOString();
    if (/^[a-z0-9_-]{1,16}$/i.test(identificationType) && /^\d{5,20}$/.test(identificationNumber))
      paymentRequest.payer.identification = { type: identificationType, number: identificationNumber };
    for (const key of ['first_name', 'last_name']) {
      const value = typeof payer[key] === 'string' ? payer[key].trim().slice(0, 80) : '';
      if (value) paymentRequest.payer[key] = value;
    }
    if (isCard) {
      paymentRequest.token = paymentToken;
      paymentRequest.installments = Number(form.installments);
      if (/^\d+$/.test(String(form.issuer_id || ''))) paymentRequest.issuer_id = String(form.issuer_id);
      if (typeof form.payment_method_option_id === 'string') paymentRequest.payment_method_option_id = form.payment_method_option_id;
    }
    const response = await fetch(`${mpBase}/v1/payments`, {
      method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', 'X-Idempotency-Key': randomUUID() },
      body: JSON.stringify(paymentRequest), signal: AbortSignal.timeout(15000),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.id || !data.status) {
      const causes = Array.isArray(data.cause) ? data.cause.map(cause => ({
        code: String(cause?.code || '').slice(0, 80),
        description: String(cause?.description || '').slice(0, 160),
      })) : [];
      console.error('[mercadopago] payment request rejected', response.status, JSON.stringify({ message: data.message, causes }));
        db.prepare("UPDATE store_orders SET status='failed',payment_method_id=?,payment_type=?,updated_at=datetime('now') WHERE id=? AND status='pending'")
          .run(methodId, typeof form.checkout_payment_type === 'string' ? form.checkout_payment_type.slice(0, 40) : null, orderId);
      return res.status(402).json({
        error: 'payment_rejected',
        statusDetail: typeof data.status_detail === 'string' ? data.status_detail.slice(0, 80) : null,
        causeCodes: causes.map(cause => cause.code).filter(Boolean).slice(0, 3),
      });
    }
    const order = db.prepare('SELECT * FROM store_orders WHERE id=?').get(orderId);
    if (data.status === 'approved') {
      if (data.currency_id !== 'BRL' || Math.round(Number(data.transaction_amount) * 100) !== amountCents)
        return res.status(502).json({ error: 'payment_verification_failed' });
      finalizeApprovedPayment(order, data);
    } else {
      const status = ['rejected', 'cancelled'].includes(data.status) ? 'failed' : 'pending';
      db.prepare("UPDATE store_orders SET status=?,payment_id=?,payment_method_id=?,payment_type=?,updated_at=datetime('now') WHERE id=? AND status='pending'")
        .run(status, String(data.id), data.payment_method_id || methodId,
          typeof form.checkout_payment_type === 'string' ? form.checkout_payment_type.slice(0, 40) : data.payment_type_id || null, orderId);
      if (status === 'failed') return res.status(402).json({
        error: 'payment_rejected',
        statusDetail: typeof data.status_detail === 'string' ? data.status_detail.slice(0, 80) : null,
      });
    }
    res.status(data.status === 'approved' ? 201 : 202).json({
      orderId, status: data.status, statusDetail: data.status_detail || null,
      expiresAt,
      pixQrCode: data.point_of_interaction?.transaction_data?.qr_code || null,
      pixQrCodeBase64: data.point_of_interaction?.transaction_data?.qr_code_base64 || null,
      ticketUrl: data.transaction_details?.external_resource_url || null,
    });
  } catch (error) {
    console.error('[mercadopago] payment request failed', String(error?.message || error).slice(0, 200));
    db.prepare("UPDATE store_orders SET status='failed',payment_method_id=?,payment_type=?,updated_at=datetime('now') WHERE id=? AND status='pending'")
      .run(methodId, typeof form.checkout_payment_type === 'string' ? form.checkout_payment_type.slice(0, 40) : null, orderId);
    res.status(502).json({ error: 'checkout_unavailable' });
  }
});

app.get('/v1/site/store/orders/:id', siteAuth, async (req, res) => {
  await cleanupExpiredPixOrders();
  const order = db.prepare('SELECT id,status FROM store_orders WHERE id=? AND account_id=?').get(req.params.id, req.accountId);
  if (!order) return res.sendStatus(404);
  res.json(order);
});

app.post('/v1/site/store/orders/:id/verify', siteAuth, paymentVerifyLimit, async (req, res) => {
  await cleanupExpiredPixOrders();
  const order = db.prepare('SELECT * FROM store_orders WHERE id=? AND account_id=?').get(req.params.id, req.accountId);
  if (!order) return res.sendStatus(404);
  if (order.status !== 'pending') return res.json({ id: order.id, status: order.status });
  if (!order.payment_id) return res.status(409).json({ error: 'payment_not_linked' });

  const accessToken = process.env.MP_ACCESS_TOKEN;
  if (!accessToken) return res.status(503).json({ error: 'payments_not_configured' });
  const mpBase = (process.env.MP_API_URL || 'https://api.mercadopago.com').replace(/\/$/, '');
  try {
    const response = await fetch(`${mpBase}/v1/payments/${encodeURIComponent(order.payment_id)}`, {
      headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return res.status(502).json({ error: 'payment_status_unavailable' });
    const payment = await response.json();
    if (payment.external_reference !== order.id || payment.currency_id !== 'BRL'
      || Math.round(Number(payment.transaction_amount) * 100) !== order.amount_cents) {
      console.error('[mercadopago] payment verification mismatch', order.id, String(payment.id || ''));
      return res.status(409).json({ error: 'payment_verification_mismatch' });
    }

    if (payment.status === 'approved') {
      finalizeApprovedPayment(order, payment);
      return res.json({ id: order.id, status: 'paid' });
    }
    if (['rejected', 'cancelled'].includes(payment.status)) {
      db.prepare("UPDATE store_orders SET status='failed',updated_at=datetime('now') WHERE id=? AND status='pending'").run(order.id);
      return res.json({ id: order.id, status: 'failed' });
    }
    res.json({ id: order.id, status: 'pending', providerStatus: String(payment.status || 'pending') });
  } catch (error) {
    console.error('[mercadopago] payment status check failed', order.id, String(error?.message || error).slice(0, 160));
    res.status(502).json({ error: 'payment_status_unavailable' });
  }
});

function validPaymentSignature(req, paymentId) {
  const signature = req.get('x-signature') || '';
  const requestId = req.get('x-request-id') || '';
  const parts = Object.fromEntries(signature.split(',').map(part => part.trim().split('=')));
  if (!parts.ts || !parts.v1 || !paymentId) return false;
  const manifest = `id:${String(paymentId).toLowerCase()};request-id:${requestId};ts:${parts.ts};`;
  const expected = createHmac('sha256', process.env.MP_WEBHOOK_SECRET).update(manifest).digest();
  let received;
  try { received = Buffer.from(parts.v1, 'hex'); } catch { return false; }
  return received.length === expected.length && timingSafeEqual(received, expected);
}

app.post('/v1/site/payments/webhook', async (req, res) => {
  await cleanupExpiredPixOrders();
  const paymentId = req.query['data.id'] || req.body?.data?.id;
  if (!process.env.MP_ACCESS_TOKEN || !process.env.MP_WEBHOOK_SECRET) return res.sendStatus(503);
  if (!validPaymentSignature(req, paymentId)) return res.sendStatus(401);
  if (req.body?.type !== 'payment' && !String(req.body?.action || '').startsWith('payment.')) return res.sendStatus(200);

  const mpBase = (process.env.MP_API_URL || 'https://api.mercadopago.com').replace(/\/$/, '');
  try {
    const response = await fetch(`${mpBase}/v1/payments/${encodeURIComponent(paymentId)}`, {
      headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` }, signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return res.sendStatus(502);
    const payment = await response.json();
    if (payment.status !== 'approved') return res.sendStatus(200);
    const orderId = payment.external_reference;
    const order = db.prepare('SELECT * FROM store_orders WHERE id=?').get(orderId);
    if (!order || payment.currency_id !== 'BRL' || Math.round(Number(payment.transaction_amount) * 100) !== order.amount_cents)
      return res.sendStatus(200);
    if (order.status === 'paid') return res.sendStatus(200);

    finalizeApprovedPayment(order, payment);
    res.sendStatus(200);
  } catch {
    res.sendStatus(502);
  }
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

function adminStaff(accountId) {
  return db.prepare('SELECT role_key,created_at FROM admin_staff WHERE account_id=?').get(accountId);
}

function isAdminOwner(account) {
  return !!(ADMIN_OWNER_NICK && account && normNick(account.display_nick) === ADMIN_OWNER_NICK);
}

function sqliteTimestamp(value) {
  const timestamp = Date.parse(`${String(value || '').replace(' ', 'T')}Z`);
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function emailRegistrationDeadline(account) {
  const deadlines = [];
  const staff = adminStaff(account.id);
  if (staff || isAdminOwner(account))
    deadlines.push(sqliteTimestamp(staff?.created_at || account.created_at) + 72 * 60 * 60 * 1000);
  const policy = db.prepare('SELECT required,deadline_hours AS deadlineHours,enabled_at AS enabledAt FROM email_registration_policy WHERE id=1').get();
  if (policy?.required) {
    const startedAt = Math.max(sqliteTimestamp(account.created_at), policy.enabledAt || 0);
    deadlines.push(startedAt + policy.deadlineHours * 60 * 60 * 1000);
  }
  return deadlines.length ? Math.min(...deadlines) : null;
}

function maskEmail(value) {
  const [local, domain] = String(value || '').split('@');
  return local && domain ? `${local[0]}***@${domain}` : '';
}

async function verifyAdminServerPassword(nick, password) {
  const account = NICK_RE.test(nick || '') ? getAccount(nick) : null;
  const value = typeof password === 'string' ? password : '';
  const isAllowed = account && (isAdminOwner(account) || adminStaff(account.id));
  if (!isAllowed) { await dummyVerify(value); return null; }
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
  const account = db.prepare('SELECT id,display_nick FROM accounts WHERE id=?').get(session.account_id);
  const staff = adminStaff(session.account_id);
  if (!account || !getAdminCredential(session.account_id) || (!isAdminOwner(account) && !staff))
    return res.status(401).json({ error: 'admin_access_revoked' });
  const emailState = db.prepare('SELECT created_at AS createdAt,email_verified AS emailVerified FROM accounts WHERE id=?').get(session.account_id);
  const deadline = emailRegistrationDeadline({ ...account, ...emailState, created_at: emailState.createdAt });
  if (!emailState.emailVerified && deadline !== null && deadline <= Date.now())
    return res.status(403).json({ error: 'email_registration_required' });
  req.adminAccountId = session.account_id;
  req.adminNick = account.display_nick;
  req.adminRole = isAdminOwner(account) ? 'owner' : staff.role_key;
  next();
}

function requireAdminRoles(...roles) {
  return (req, res, next) => roles.includes(req.adminRole)
    ? next()
    : res.status(403).json({ error: 'forbidden' });
}

app.get('/v1/site/admin/status', (_req, res) => {
  const account = ADMIN_OWNER_NICK ? getAccount(ADMIN_OWNER_NICK) : null;
  res.json({ configured: !!(account && getAdminCredential(account.id)) });
});

app.post('/v1/site/admin/token', adminTokenLimit, async (req, res) => {
  const { nick, password } = req.body || {};
  const account = await verifyAdminServerPassword(nick, password);
  if (!account) return res.status(401).json({ error: 'invalid_credentials' });
  if (!account.email || !account.email_verified) return res.status(409).json({ error: 'email_required' });

  const token = String(randomInt(100000, 1000000));
  db.prepare(`INSERT INTO admin_challenges(account_id,token_hash,expires_at,attempts)
    VALUES(?,?,?,0) ON CONFLICT(account_id) DO UPDATE SET token_hash=excluded.token_hash,
    expires_at=excluded.expires_at, attempts=0, created_at=datetime('now')`)
    .run(account.id, sha256(token), Date.now() + 5 * 60000);
  try {
    await sendEmail({ to: account.email, ...accessCodeEmail({ code: token, purpose: 'admin_login' }) });
  } catch {
    db.prepare('DELETE FROM admin_challenges WHERE account_id=?').run(account.id);
    return res.status(503).json({ error: 'email_unavailable' });
  }
  res.json({ ok: true, setupRequired: !getAdminCredential(account.id), emailHint: maskEmail(account.email) });
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
  res.status(201).json({ ok: true, nick: account.display_nick, role: isAdminOwner(account) ? 'owner' : adminStaff(account.id).role_key });
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
  res.json({ ok: true, nick: account.display_nick, role: isAdminOwner(account) ? 'owner' : adminStaff(account.id).role_key });
});

app.get('/v1/site/admin/me', adminAuth, (req, res) => {
  const account = db.prepare('SELECT display_nick FROM accounts WHERE id=?').get(req.adminAccountId);
  res.json({ nick: account.display_nick, role: req.adminRole });
});

app.get('/v1/site/admin/security/email-policy', adminAuth, requireAdminRoles('owner'), (_req, res) => {
  const policy = db.prepare('SELECT required,deadline_hours AS deadlineHours FROM email_registration_policy WHERE id=1').get();
  res.json({ required: Boolean(policy.required), deadlineHours: policy.deadlineHours });
});

app.patch('/v1/site/admin/security/email-policy', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const { required, deadlineHours } = req.body || {};
  if (typeof required !== 'boolean' || !Number.isInteger(deadlineHours) || deadlineHours < 1 || deadlineHours > 720)
    return res.status(400).json({ error: 'invalid_email_policy' });
  const current = db.prepare('SELECT required,enabled_at AS enabledAt FROM email_registration_policy WHERE id=1').get();
  const enabledAt = required ? (current.required ? current.enabledAt : Date.now()) : null;
  db.prepare('UPDATE email_registration_policy SET required=?,deadline_hours=?,enabled_at=? WHERE id=1')
    .run(required ? 1 : 0, deadlineHours, enabledAt);
  audit(req.adminNick, 'admin_email_policy_updated', `${required}:${deadlineHours}`);
  res.json({ ok: true, required, deadlineHours });
});

const manageStore = requireAdminRoles('owner', 'admin');
function storeTransactionAccess(req, res, next) {
  if (req.adminRole === 'owner') return next();
  const access = db.prepare('SELECT can_view FROM store_transaction_access WHERE role_key=?').get(req.adminRole);
  return access?.can_view ? next() : res.status(403).json({ error: 'forbidden' });
}

app.get('/v1/site/admin/store/transactions/access', adminAuth, (req, res) => {
  const roles = db.prepare('SELECT role_key AS role,can_view AS canView FROM store_transaction_access ORDER BY role_key').all()
    .map(row => ({ role: row.role, canView: Boolean(row.canView) }));
  const current = roles.find(row => row.role === req.adminRole);
  res.json({ canView: req.adminRole === 'owner' || Boolean(current?.canView), roles: req.adminRole === 'owner' ? roles : undefined });
});

app.put('/v1/site/admin/store/transactions/access', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const roles = req.body?.roles;
  const allowed = new Set(['admin', 'moderator', 'helper']);
  if (!Array.isArray(roles) || roles.some(role => typeof role !== 'string' || !allowed.has(role)))
    return res.status(400).json({ error: 'invalid_transaction_access' });
  db.exec('BEGIN IMMEDIATE');
  try {
    const update = db.prepare("UPDATE store_transaction_access SET can_view=?,updated_at=datetime('now') WHERE role_key=?");
    for (const role of allowed) update.run(roles.includes(role) ? 1 : 0, role);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  audit(req.adminNick, 'store_transaction_access_updated', [...new Set(roles)].sort().join(','));
  res.json({ ok: true, roles: db.prepare('SELECT role_key AS role,can_view AS canView FROM store_transaction_access ORDER BY role_key').all()
    .map(row => ({ role: row.role, canView: Boolean(row.canView) })) });
});

app.get('/v1/site/admin/store/transactions', adminAuth, storeTransactionAccess, async (req, res) => {
  await cleanupExpiredPixOrders();
  const status = ['all', 'pending', 'paid', 'failed'].includes(req.query.status) ? req.query.status : 'all';
  const orders = db.prepare(`SELECT o.id,o.status,o.amount_cents AS amountCents,o.payment_id AS paymentId,
      o.payment_method_id AS paymentMethodId,o.payment_type AS paymentType,
      o.created_at AS createdAt,o.updated_at AS updatedAt,o.expires_at AS expiresAt,a.display_nick AS player,
      COUNT(DISTINCT i.id) AS itemCount,
      COUNT(DISTINCT CASE WHEN c.status='done' THEN i.id END) AS deliveredCount
    FROM store_orders o JOIN accounts a ON a.id=o.account_id
    LEFT JOIN store_order_items i ON i.order_id=o.id
    LEFT JOIN commands c ON c.event_id=('mp:' || o.payment_id || ':' || i.id)
    WHERE ?='all' OR o.status=?
    GROUP BY o.id ORDER BY o.created_at DESC LIMIT 200`).all(status, status);
  if (orders.length === 0) return res.json({ orders: [] });

  const ids = orders.map(order => order.id);
  const items = db.prepare(`SELECT i.order_id AS orderId,i.product_id AS productId,i.name,i.kind,
      i.price_cents AS priceCents,i.quantity,c.status AS deliveryStatus
    FROM store_order_items i
    JOIN store_orders o ON o.id=i.order_id
    LEFT JOIN commands c ON c.event_id=('mp:' || o.payment_id || ':' || i.id)
    WHERE i.order_id IN (${ids.map(() => '?').join(',')}) ORDER BY i.id`).all(...ids);
  const byOrder = new Map(orders.map(order => [order.id, []]));
  for (const item of items) byOrder.get(item.orderId)?.push({
    ...item, deliveryStatus: item.deliveryStatus === 'done' ? 'delivered' : orderDeliveryStatus(item.deliveryStatus),
  });
  res.json({ orders: orders.map(order => {
    const orderItems = byOrder.get(order.id) || [];
    const deliveredCount = Number(order.deliveredCount);
    const deliveryStatus = order.status !== 'paid' ? 'not_paid'
      : deliveredCount === Number(order.itemCount) ? 'delivered' : deliveredCount ? 'partial' : 'pending';
    return { ...order, deliveryStatus, items: orderItems };
  }) });
});

function currentBrasiliaMonth() {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit' })
    .formatToParts(new Date());
  const year = parts.find(part => part.type === 'year')?.value;
  const month = parts.find(part => part.type === 'month')?.value;
  return `${year}-${month}`;
}

function financeMonthRange(value) {
  const month = /^\d{4}-(0[1-9]|1[0-2])$/.test(value || '') ? value : currentBrasiliaMonth();
  const [year, monthNumber] = month.split('-').map(Number);
  const startUtc = Date.UTC(year, monthNumber - 1, 1) + 3 * 60 * 60 * 1000;
  const endUtc = Date.UTC(year, monthNumber, 1) + 3 * 60 * 60 * 1000;
  const next = new Date(Date.UTC(year, monthNumber, 1));
  const expenseStart = `${month}-01`;
  const expenseEnd = `${next.getUTCFullYear()}-${String(next.getUTCMonth() + 1).padStart(2, '0')}-01`;
  return { month, startUtc, endUtc, expenseStart, expenseEnd };
}

app.get('/v1/site/admin/store/finance', adminAuth, storeTransactionAccess, async (req, res) => {
  await cleanupExpiredPixOrders();
  const range = financeMonthRange(String(req.query.month || ''));
  const income = db.prepare(`SELECT COALESCE(SUM(amount_cents),0) AS totalCents,COUNT(*) AS count
    FROM store_orders WHERE status='paid' AND paid_at>=? AND paid_at<?`).get(range.startUtc, range.endUtc);
  const expenseTotals = db.prepare(`SELECT COALESCE(SUM(amount_cents),0) AS totalCents,COUNT(*) AS count
    FROM store_expenses WHERE expense_date>=? AND expense_date<?`).get(range.expenseStart, range.expenseEnd);
  const expenses = db.prepare(`SELECT id,expense_date AS expenseDate,category,description,amount_cents AS amountCents,
      created_by AS createdBy,created_at AS createdAt FROM store_expenses
    WHERE expense_date>=? AND expense_date<? ORDER BY expense_date DESC,id DESC LIMIT 500`)
    .all(range.expenseStart, range.expenseEnd);
  const sales = db.prepare(`SELECT o.id,a.display_nick AS player,o.amount_cents AS amountCents,o.paid_at AS paidAt,
      o.payment_method_id AS paymentMethodId,o.payment_type AS paymentType
    FROM store_orders o JOIN accounts a ON a.id=o.account_id
    WHERE o.status='paid' AND o.paid_at>=? AND o.paid_at<? ORDER BY o.paid_at DESC LIMIT 500`)
    .all(range.startUtc, range.endUtc);
  const incomeCents = Number(income.totalCents), expenseCents = Number(expenseTotals.totalCents);
  res.json({
    month: range.month,
    summary: {
      incomeCents, expenseCents, balanceCents: incomeCents - expenseCents,
      salesCount: Number(income.count), expenseCount: Number(expenseTotals.count),
    },
    sales, expenses,
  });
});

app.post('/v1/site/admin/store/finance/expenses', adminAuth, storeTransactionAccess, (req, res) => {
  const { expenseDate, category, description } = req.body || {};
  const date = typeof expenseDate === 'string' ? expenseDate : '';
  const expenseCategory = typeof category === 'string' ? category.trim() : '';
  const expenseDescription = typeof description === 'string' ? description.trim() : '';
  const amountCents = Number(req.body?.amountCents);
  const validDate = /^\d{4}-\d{2}-\d{2}$/.test(date)
    && new Date(`${date}T00:00:00.000Z`).toISOString().slice(0, 10) === date;
  if (!validDate || expenseCategory.length < 2 || expenseCategory.length > 40
    || expenseDescription.length < 2 || expenseDescription.length > 180
    || !Number.isSafeInteger(amountCents) || amountCents < 1 || amountCents > 1000000000)
    return res.status(400).json({ error: 'invalid_expense' });
  const result = db.prepare(`INSERT INTO store_expenses(expense_date,category,description,amount_cents,created_by)
    VALUES(?,?,?,?,?)`).run(date, expenseCategory, expenseDescription, amountCents, req.adminNick);
  audit(req.adminNick, 'store_expense_created', `${date}:${expenseCategory}:${amountCents}`);
  res.status(201).json({ id: Number(result.lastInsertRowid) });
});

app.delete('/v1/site/admin/store/finance/expenses/:id', adminAuth, storeTransactionAccess, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'invalid_expense' });
  const expense = db.prepare('SELECT expense_date,category,amount_cents FROM store_expenses WHERE id=?').get(id);
  if (!expense) return res.sendStatus(404);
  db.prepare('DELETE FROM store_expenses WHERE id=?').run(id);
  audit(req.adminNick, 'store_expense_deleted', `${id}:${expense.expense_date}:${expense.category}:${expense.amount_cents}`);
  res.json({ ok: true });
});

app.delete('/v1/site/admin/store/transactions', adminAuth, requireAdminRoles('owner'), async (req, res) => {
  await cleanupExpiredPixOrders();
  db.exec('BEGIN IMMEDIATE');
  try {
    const pending = Number(db.prepare("SELECT COUNT(*) AS count FROM store_orders WHERE status='pending'").get().count);
    const deleted = db.prepare("DELETE FROM store_orders WHERE status IN ('paid','failed')").run().changes;
    db.exec('COMMIT');
    audit(req.adminNick, 'store_transactions_cleared', `deleted=${deleted};pending_preserved=${pending}`);
    res.json({ ok: true, deleted, pendingPreserved: pending });
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
});

function orderDeliveryStatus(status) {
  return status === 'error' ? 'failed' : 'pending';
}

app.get('/v1/site/admin/store', adminAuth, manageStore, (_req, res) => {
  const categories = db.prepare('SELECT id,name FROM store_categories ORDER BY name').all();
  const products = db.prepare(`${storeProductsQuery} ORDER BY c.name,p.name`).all();
  res.json({ categories, products });
});

app.post('/v1/site/admin/store/categories', adminAuth, manageStore, (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  if (name.length < 2 || name.length > 40) return res.status(400).json({ error: 'invalid_category' });
  try {
    const result = db.prepare('INSERT INTO store_categories(name) VALUES(?)').run(name);
    audit(req.adminNick, 'store_category_created', name);
    res.status(201).json({ id: Number(result.lastInsertRowid), name });
  } catch { res.status(409).json({ error: 'category_exists' }); }
});

app.patch('/v1/site/admin/store/categories/:id', adminAuth, manageStore, (req, res) => {
  const id = Number(req.params.id), name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  if (!Number.isSafeInteger(id) || id < 1 || name.length < 2 || name.length > 40)
    return res.status(400).json({ error: 'invalid_category' });
  try {
    const result = db.prepare('UPDATE store_categories SET name=? WHERE id=?').run(name, id);
    if (!result.changes) return res.sendStatus(404);
    audit(req.adminNick, 'store_category_updated', name);
    res.json({ id, name });
  } catch { res.status(409).json({ error: 'category_exists' }); }
});

app.delete('/v1/site/admin/store/categories/:id', adminAuth, manageStore, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'invalid_category' });
  if (db.prepare('SELECT 1 FROM store_products WHERE category_id=? LIMIT 1').get(id))
    return res.status(409).json({ error: 'category_not_empty' });
  const result = db.prepare('DELETE FROM store_categories WHERE id=?').run(id);
  if (!result.changes) return res.sendStatus(404);
  audit(req.adminNick, 'store_category_deleted', String(id));
  res.json({ ok: true });
});

function storeProductInput(body) {
  const name = typeof body?.name === 'string' ? body.name.trim() : '';
  const description = typeof body?.description === 'string' ? body.description.trim() : '';
  const categoryId = Number(body?.categoryId);
  const price = typeof body?.price === 'string' || typeof body?.price === 'number' ? String(body.price).trim() : '';
  const kind = body?.kind;
  const vipGroup = typeof body?.vipGroup === 'string' ? body.vipGroup.trim() : '';
  const productCode = typeof body?.productCode === 'string' ? body.productCode.trim() : '';
  const durationDays = body?.durationDays === '' || body?.durationDays == null ? null : Number(body.durationDays);
  if (name.length < 2 || name.length > 80 || description.length > 1000
    || !Number.isSafeInteger(categoryId) || categoryId < 1 || !/^\d{1,7}(\.\d{1,2})?$/.test(price)
    || !['vip', 'product'].includes(kind)) return null;
  const priceCents = Math.round(Number(price) * 100);
  if (!Number.isSafeInteger(priceCents) || priceCents < 100 || priceCents > 100000000) return null;
  if (kind === 'vip' && !/^[A-Za-z0-9._-]{1,64}$/.test(vipGroup)) return null;
  if (kind === 'product' && !/^[A-Za-z0-9._-]{1,64}$/.test(productCode)) return null;
  if (durationDays != null && (!Number.isSafeInteger(durationDays) || durationDays < 1 || durationDays > 3650)) return null;
  if (!db.prepare('SELECT 1 FROM store_categories WHERE id=?').get(categoryId)) return null;
  return { name, description, categoryId, priceCents, kind, vipGroup: kind === 'vip' ? vipGroup : null,
    durationDays: kind === 'vip' ? durationDays : null, productCode: kind === 'product' ? productCode : null,
    active: body.active === false || body.active === 0 ? 0 : 1 };
}

app.post('/v1/site/admin/store/products', adminAuth, manageStore, (req, res) => {
  const product = storeProductInput(req.body);
  if (!product) return res.status(400).json({ error: 'invalid_product' });
  const result = db.prepare(`INSERT INTO store_products(category_id,name,description,price_cents,kind,vip_group,duration_days,product_code,active)
    VALUES(?,?,?,?,?,?,?,?,?)`).run(product.categoryId, product.name, product.description, product.priceCents,
    product.kind, product.vipGroup, product.durationDays, product.productCode, product.active);
  audit(req.adminNick, 'store_product_created', product.name);
  res.status(201).json({ id: Number(result.lastInsertRowid) });
});

app.patch('/v1/site/admin/store/products/:id', adminAuth, manageStore, (req, res) => {
  const id = Number(req.params.id), product = storeProductInput(req.body);
  if (!Number.isSafeInteger(id) || id < 1 || !product) return res.status(400).json({ error: 'invalid_product' });
  const result = db.prepare(`UPDATE store_products SET category_id=?,name=?,description=?,price_cents=?,kind=?,vip_group=?,duration_days=?,product_code=?,active=?,updated_at=datetime('now')
    WHERE id=?`).run(product.categoryId, product.name, product.description, product.priceCents,
    product.kind, product.vipGroup, product.durationDays, product.productCode, product.active, id);
  if (!result.changes) return res.sendStatus(404);
  audit(req.adminNick, 'store_product_updated', product.name);
  res.json({ ok: true });
});

app.delete('/v1/site/admin/store/products/:id', adminAuth, manageStore, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'invalid_product' });
  const result = db.prepare("UPDATE store_products SET active=0,updated_at=datetime('now') WHERE id=?").run(id);
  if (!result.changes) return res.sendStatus(404);
  audit(req.adminNick, 'store_product_disabled', String(id));
  res.json({ ok: true });
});

app.get('/v1/site/admin/staff', adminAuth, requireAdminRoles('owner'), (_req, res) => {
  const staff = db.prepare(`SELECT a.display_nick AS nick, s.role_key AS role, s.created_at AS createdAt,
      a.email_verified AS emailVerified, EXISTS(SELECT 1 FROM admin_credentials c WHERE c.account_id=a.id) AS configured
    FROM admin_staff s JOIN accounts a ON a.id=s.account_id ORDER BY lower(a.display_nick)`).all();
  res.json({ staff: staff.map(member => ({ ...member, emailVerified: Boolean(member.emailVerified) })) });
});

app.post('/v1/site/admin/staff', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const nick = typeof req.body?.nick === 'string' ? req.body.nick.trim() : '';
  const role = req.body?.role;
  if (!NICK_RE.test(nick) || !['admin', 'moderator', 'helper'].includes(role))
    return res.status(400).json({ error: 'invalid_staff' });
  const account = getAccount(nick);
  if (!account) return res.status(404).json({ error: 'account_not_found' });
  if (isAdminOwner(account)) return res.status(400).json({ error: 'cannot_change_owner' });
  if (adminStaff(account.id)) return res.status(409).json({ error: 'staff_exists' });
  db.prepare('INSERT INTO admin_staff(account_id,role_key,created_by) VALUES(?,?,?)').run(account.id, role, req.adminAccountId);
  audit(req.adminNick, 'admin_staff_add', `${account.display_nick}:${role}`);
  res.status(201).json({ ok: true, nick: account.display_nick, role });
});

app.patch('/v1/site/admin/staff/:nick', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const account = getAccount(req.params.nick);
  const role = req.body?.role;
  if (!account) return res.status(404).json({ error: 'account_not_found' });
  if (isAdminOwner(account)) return res.status(400).json({ error: 'cannot_change_owner' });
  if (!['admin', 'moderator', 'helper'].includes(role)) return res.status(400).json({ error: 'invalid_staff' });
  const changed = db.prepare('UPDATE admin_staff SET role_key=? WHERE account_id=?').run(role, account.id);
  if (!changed.changes) return res.status(404).json({ error: 'staff_not_found' });
  db.prepare('DELETE FROM admin_sessions WHERE account_id=?').run(account.id);
  db.prepare('DELETE FROM admin_challenges WHERE account_id=?').run(account.id);
  audit(req.adminNick, 'admin_staff_role', `${account.display_nick}:${role}`);
  res.json({ ok: true, nick: account.display_nick, role });
});

app.delete('/v1/site/admin/staff/:nick', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const account = getAccount(req.params.nick);
  if (!account) return res.status(404).json({ error: 'account_not_found' });
  if (isAdminOwner(account)) return res.status(400).json({ error: 'cannot_change_owner' });
  const result = db.prepare('DELETE FROM admin_staff WHERE account_id=?').run(account.id);
  if (!result.changes) return res.status(404).json({ error: 'staff_not_found' });
  db.prepare('DELETE FROM admin_credentials WHERE account_id=?').run(account.id);
  db.prepare('DELETE FROM admin_challenges WHERE account_id=?').run(account.id);
  db.prepare('DELETE FROM admin_sessions WHERE account_id=?').run(account.id);
  audit(req.adminNick, 'admin_staff_remove', account.display_nick);
  res.json({ ok: true });
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

app.get('/v1/site/admin/luckperms/groups', adminAuth, (_req, res) => {
  const sync = db.prepare('SELECT available, synced_at AS syncedAt FROM luckperms_sync WHERE id=1').get();
  const groups = db.prepare('SELECT name FROM luckperms_groups ORDER BY lower(name)').all().map(row => row.name);
  res.json({ available: !!sync?.available, syncedAt: sync?.syncedAt || null, groups });
});

app.post('/v1/site/admin/roles', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const group = typeof req.body?.group === 'string' ? req.body.group.trim() : '';
  if (!/^[A-Za-z0-9 _-]{2,32}$/.test(name) || !/^[A-Za-z0-9._-]{1,64}$/.test(group) || group.toLowerCase() === 'default')
    return res.status(400).json({ error: 'invalid_role' });
  const sync = db.prepare('SELECT available FROM luckperms_sync WHERE id=1').get();
  if (!sync?.available) return res.status(503).json({ error: 'luckperms_unavailable' });
  if (!db.prepare('SELECT 1 FROM luckperms_groups WHERE name=?').get(group))
    return res.status(400).json({ error: 'luckperms_group_not_found' });
  try {
    const result = db.prepare('INSERT INTO admin_roles(name,lp_group) VALUES(?,?)').run(name, group);
    audit(req.adminNick, 'admin_role_create', `${name}:${group}`);
    res.status(201).json({ role: { id: Number(result.lastInsertRowid), name, group } });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'role_exists' });
    throw error;
  }
});

app.patch('/v1/site/admin/roles/:id', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const id = Number(req.params.id);
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const group = typeof req.body?.group === 'string' ? req.body.group.trim() : '';
  if (!Number.isSafeInteger(id) || id < 1 || !/^[A-Za-z0-9 _-]{2,32}$/.test(name)
    || !/^[A-Za-z0-9._-]{1,64}$/.test(group) || group.toLowerCase() === 'default')
    return res.status(400).json({ error: 'invalid_role' });
  const sync = db.prepare('SELECT available FROM luckperms_sync WHERE id=1').get();
  if (!sync?.available) return res.status(503).json({ error: 'luckperms_unavailable' });
  if (!db.prepare('SELECT 1 FROM luckperms_groups WHERE name=?').get(group))
    return res.status(400).json({ error: 'luckperms_group_not_found' });
  try {
    const result = db.prepare('UPDATE admin_roles SET name=?,lp_group=? WHERE id=?').run(name, group, id);
    if (!result.changes) return res.status(404).json({ error: 'role_not_found' });
    audit(req.adminNick, 'admin_role_update', `${name}:${group}`);
    res.json({ ok: true, role: { id, name, group } });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'role_exists' });
    throw error;
  }
});

app.delete('/v1/site/admin/roles/:id', adminAuth, requireAdminRoles('owner'), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'invalid_role' });
  const result = db.prepare('DELETE FROM admin_roles WHERE id=?').run(id);
  if (!result.changes) return res.status(404).json({ error: 'role_not_found' });
  audit(req.adminNick, 'admin_role_delete', String(id));
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
  const allowedByRole = {
    owner: allowed,
    admin: allowed,
    moderator: new Set(['ban', 'unban', 'kick', 'mute', 'unmute', 'warn']),
    helper: new Set(['mute', 'unmute', 'warn']),
  };
  if (!allowedByRole[req.adminRole]?.has(action)) return res.status(403).json({ error: 'forbidden' });

  if (action === 'reset_password') {
    const password = randomBytes(18).toString('base64url');
    return hashPassword(password).then(credential => {
      db.prepare('UPDATE accounts SET pw_iterations=?,pw_salt=?,pw_hash=? WHERE id=?')
        .run(credential.iterations, credential.salt, credential.hash, account.id);
      db.prepare('DELETE FROM sessions WHERE account_id=?').run(account.id);
      db.prepare('DELETE FROM admin_sessions WHERE account_id=?').run(account.id);
      audit(req.adminNick, 'admin_password_reset', account.display_nick);
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
      .run(account.id, req.adminNick, reason, payload.expiresAt);
  }
  if (action === 'unmute') db.prepare('DELETE FROM admin_mutes WHERE account_id=?').run(account.id);
  if (action === 'set_role') {
    const role = db.prepare('SELECT id,name,lp_group AS groupName FROM admin_roles WHERE id=?').get(Number(req.body?.roleId));
    if (!role) return res.status(400).json({ error: 'invalid_role' });
    const luckperms = db.prepare('SELECT available FROM luckperms_sync WHERE id=1').get();
    if (!luckperms?.available) return res.status(503).json({ error: 'luckperms_unavailable' });
    if (!db.prepare('SELECT 1 FROM luckperms_groups WHERE name=?').get(role.groupName))
      return res.status(409).json({ error: 'luckperms_group_not_found' });
    payload.roleName = role.name;
    payload.roleGroup = role.groupName;
    payload.mappedGroups = db.prepare('SELECT lp_group FROM admin_roles').all().map(row => row.lp_group);
  }

  const result = db.prepare('INSERT INTO admin_actions(target_account_id,actor_nick,action,payload) VALUES(?,?,?,?)')
    .run(account.id, req.adminNick, action, JSON.stringify(payload));
  audit(req.adminNick, `admin_${action}`, account.display_nick);
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
app.put('/v1/bridge/luckperms/groups', bridgeKey, (req, res) => {
  const { available, groups } = req.body || {};
  if (typeof available !== 'boolean' || !Array.isArray(groups) || groups.length > 1000
    || groups.some(group => typeof group !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(group)))
    return res.status(400).json({ error: 'invalid_luckperms_groups' });
  const unique = [...new Set(groups)];
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('DELETE FROM luckperms_groups').run();
    if (available) {
      const insert = db.prepare('INSERT INTO luckperms_groups(name,synced_at) VALUES(?,datetime(\'now\'))');
      for (const group of unique) insert.run(group);
    }
    db.prepare('UPDATE luckperms_sync SET available=?,synced_at=datetime(\'now\') WHERE id=1')
      .run(available ? 1 : 0);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  res.json({ ok: true, available, count: available ? unique.length : 0 });
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
app.listen(port, '0.0.0.0', () => {
  console.log(`API ouvindo em ${port}`);
  verifyEmailTransport().catch(() => {});
});
