// Uso: node scripts/import-users.js caminho/users.json Macalay
import { readFileSync } from 'node:fs';
import { db, audit } from '../src/db.js';
const [file, only] = process.argv.slice(2);
if (!file || !only) { console.log('uso: node scripts/import-users.js users.json Macalay'); process.exit(1); }
const u = JSON.parse(readFileSync(file, 'utf8')).find(x => x.nick.toLowerCase() === only.toLowerCase());
if (!u) { console.log('conta nao encontrada'); process.exit(1); }
const r = db.prepare(`INSERT OR IGNORE INTO accounts(nick,display_nick,uuid,pw_algorithm,pw_iterations,pw_salt,pw_hash)
  VALUES(?,?,?,?,?,?,?)`).run(u.nick.toLowerCase(), u.nick, u.uuid || null, u.password.algorithm,
  u.password.iterations, u.password.salt, u.password.hash);
if (u.profile) {
  const id = db.prepare('SELECT id FROM accounts WHERE nick=?').get(u.nick.toLowerCase()).id;
  db.prepare('INSERT OR REPLACE INTO profiles(account_id,data) VALUES(?,?)').run(id, JSON.stringify(u.profile));
}
audit('import', 'import_user', u.nick);
console.log(r.changes ? 'importada' : 'ja existia');
