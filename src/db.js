import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const path = process.env.DB_PATH || './data/abyssal.db';
mkdirSync(dirname(path), { recursive: true });
export const db = new DatabaseSync(path);
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nick TEXT NOT NULL UNIQUE,          -- normalizado em minusculas
  display_nick TEXT NOT NULL,
  uuid TEXT,
  pw_algorithm TEXT NOT NULL,
  pw_iterations INTEGER NOT NULL,
  pw_salt TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS profiles (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admin_credentials (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  pw_iterations INTEGER NOT NULL,
  pw_salt TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admin_staff (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  role_key TEXT NOT NULL CHECK(role_key IN ('admin','moderator','helper')),
  created_by INTEGER NOT NULL REFERENCES accounts(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admin_challenges (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admin_roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  lp_group TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS luckperms_sync (
  id INTEGER PRIMARY KEY CHECK(id=1),
  available INTEGER NOT NULL DEFAULT 0,
  synced_at TEXT
);
INSERT OR IGNORE INTO luckperms_sync(id,available,synced_at) VALUES(1,0,NULL);
CREATE TABLE IF NOT EXISTS luckperms_groups (
  name TEXT PRIMARY KEY,
  synced_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admin_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  actor_nick TEXT NOT NULL,
  action TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  result TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS admin_actions_pending ON admin_actions(status, id);
CREATE TABLE IF NOT EXISTS admin_mutes (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  actor_nick TEXT NOT NULL,
  reason TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS refresh_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,      -- idempotencia (ex: id do pagamento)
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  type TEXT NOT NULL,                 -- GRANT_VIP | REVOKE_VIP
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  done_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS store_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS store_products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category_id INTEGER NOT NULL REFERENCES store_categories(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  price_cents INTEGER NOT NULL CHECK(price_cents > 0),
  kind TEXT NOT NULL CHECK(kind IN ('vip','product')),
  vip_group TEXT,
  duration_days INTEGER,
  product_code TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS store_products_active ON store_products(active, category_id);
CREATE TABLE IF NOT EXISTS store_orders (
  id TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed')),
  amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
  preference_id TEXT,
  payment_id TEXT UNIQUE,
  payment_method_id TEXT,
  payment_type TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS store_orders_recent ON store_orders(created_at DESC, status);
CREATE TABLE IF NOT EXISTS store_order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL REFERENCES store_orders(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  vip_group TEXT,
  duration_days INTEGER,
  product_code TEXT,
  price_cents INTEGER NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity > 0)
);
CREATE TABLE IF NOT EXISTS store_transaction_access (
  role_key TEXT PRIMARY KEY CHECK(role_key IN ('admin','moderator','helper')),
  can_view INTEGER NOT NULL DEFAULT 0 CHECK(can_view IN (0,1)),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO store_transaction_access(role_key,can_view) VALUES('admin',1),('moderator',0),('helper',0);
`);

const orderColumns = new Set(db.prepare('PRAGMA table_info(store_orders)').all().map(column => column.name));
if (!orderColumns.has('payment_method_id')) db.exec('ALTER TABLE store_orders ADD COLUMN payment_method_id TEXT');
if (!orderColumns.has('payment_type')) db.exec('ALTER TABLE store_orders ADD COLUMN payment_type TEXT');
export const audit = (actor, action, detail = '') =>
  db.prepare('INSERT INTO audit(actor,action,detail) VALUES(?,?,?)').run(actor, action, String(detail));
