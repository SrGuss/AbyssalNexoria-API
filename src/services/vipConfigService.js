const EMPTY_CONFIG = Object.freeze({
  vips: [], kits: [], crates: [],
  settings: { syncGroupsOnStart: true, boundItems: { soulbound: true, destroyForeign: true, blockAnvil: true } },
});
const VIP_ID = /^[a-z0-9_]{2,24}$/;
const CRATE_ID = /^[a-z0-9_-]{2,32}$/;
const MATERIAL_ID = /^[a-z0-9_]{1,64}$/;
const PERMISSION = /^[A-Za-z0-9._-]{1,128}$/;
const OPERATIONS = new Set(['ADD_NUMBER', 'ADD_SCALAR', 'ADD_MULTIPLIED_BASE', 'ADD_MULTIPLIED_TOTAL']);
const EQUIPMENT_SLOTS = new Set(['ANY', 'HAND', 'OFF_HAND', 'FEET', 'LEGS', 'CHEST', 'HEAD', 'BODY']);

function boundedString(value, maxLength, fallback = '') {
  if (typeof value !== 'string') return fallback;
  const text = value.trim();
  return text.length <= maxLength ? text : null;
}

function stringList(value, maxItems, maxLength, pattern = null) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const result = [];
  for (const entry of value) {
    const text = boundedString(entry, maxLength);
    if (!text || (pattern && !pattern.test(text)) || /[\r\n]/.test(text)) return null;
    if (!result.includes(text)) result.push(text);
  }
  return result;
}

function normalizeItem(item, defaultSlot) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
  const rawMaterial = boundedString(item.material, 64);
  const material = rawMaterial?.replace(/^minecraft:/i, '').toLowerCase();
  const slot = item.slot == null ? defaultSlot : Number(item.slot);
  const amount = Number(item.amount ?? 1);
  const name = boundedString(item.name ?? '', 128);
  const lore = stringList(item.lore, 30, 200);
  const itemFlags = stringList(item.itemFlags, 24, 48);
  const rawEnchantments = item.enchantments ?? [];
  const enchantments = [];
  if (Array.isArray(rawEnchantments)) {
    if (rawEnchantments.length > 32) return null;
    for (const enchantment of rawEnchantments) {
      const rawId = boundedString(enchantment?.id, 64);
      const id = rawId?.toLowerCase().replace(/^minecraft:/, '');
      const level = Number(enchantment?.level);
      if (!MATERIAL_ID.test(id) || !Number.isInteger(level) || level < 1 || level > 255) return null;
      enchantments.push({ id, level });
    }
  } else if (rawEnchantments && typeof rawEnchantments === 'object') {
    const entries = Object.entries(rawEnchantments);
    if (entries.length > 32) return null;
    for (const [rawId, rawLevel] of entries) {
      const id = typeof rawId === 'string' ? rawId.toLowerCase().replace(/^minecraft:/, '') : '';
      const level = Number(rawLevel);
      if (!MATERIAL_ID.test(id) || !Number.isInteger(level) || level < 1 || level > 255) return null;
      enchantments.push({ id, level });
    }
  } else return null;

  const rawBoundVip = item.boundVip == null || item.boundVip === '' ? null : boundedString(item.boundVip, 24);
  const boundVip = rawBoundVip == null ? null : rawBoundVip.toLowerCase();
  const customModelData = item.customModelData == null || item.customModelData === '' ? null : Number(item.customModelData);
  if (!MATERIAL_ID.test(material) || !Number.isInteger(slot) || slot < 0 || slot > 53
    || !Number.isInteger(amount) || amount < 1 || amount > 64 || name == null || lore == null || itemFlags == null
    || (boundVip != null && !VIP_ID.test(boundVip))
    || (customModelData != null && (!Number.isSafeInteger(customModelData) || customModelData < 0))) return null;
  if (itemFlags.some(flag => !/^HIDE_[A-Z_]{1,42}$/.test(flag))) return null;

  const rawAttributes = item.attributes ?? [];
  if (!Array.isArray(rawAttributes) || rawAttributes.length > 16) return null;
  const attributes = [];
  for (const attribute of rawAttributes) {
    const id = boundedString(attribute?.id, 64).toLowerCase().replace(/^minecraft:/, '');
    const amountValue = Number(attribute?.amount);
    const operation = boundedString(attribute?.operation, 32).toUpperCase();
    const equipmentSlot = boundedString(attribute?.slot ?? 'ANY', 16).toUpperCase();
    if (!MATERIAL_ID.test(id) || !Number.isFinite(amountValue) || Math.abs(amountValue) > 10000
      || !OPERATIONS.has(operation) || !EQUIPMENT_SLOTS.has(equipmentSlot)) return null;
    attributes.push({ id, amount: amountValue, operation, slot: equipmentSlot });
  }

  return {
    slot, material: material.toUpperCase(), amount, name, lore, enchantments,
    boundVip, customModelData, unbreakable: item.unbreakable === true, itemFlags, attributes,
  };
}

function normalizeVip(raw) {
  const id = boundedString(raw?.id, 24)?.toLowerCase();
  const name = boundedString(raw?.name, 80);
  const group = boundedString(raw?.group, 64).toLowerCase();
  const prefix = boundedString(raw?.prefix ?? '', 64);
  const weight = Number(raw?.weight ?? 0);
  if (!VIP_ID.test(id) || !name || !group || !/^[a-z0-9._-]{1,64}$/.test(group)
    || prefix == null || !Number.isInteger(weight) || weight < -100000 || weight > 100000) return null;
  const permissions = stringList(raw?.permissions, 128, 128, PERMISSION);
  const kits = stringList(raw?.kits, 64, 24, VIP_ID);
  const kitsOnGrant = stringList(raw?.kitsOnGrant, 64, 24, VIP_ID);
  const commandsOnGrant = stringList(raw?.commandsOnGrant, 32, 256);
  const commandsOnExpire = stringList(raw?.commandsOnExpire, 32, 256);
  const replaces = stringList(raw?.replaces, 24, 24, VIP_ID);
  if (!permissions || !kits || !kitsOnGrant || !commandsOnGrant || !commandsOnExpire || !replaces) return null;
  return { id, name, group, weight, prefix, permissions, kits, kitsOnGrant, commandsOnGrant, commandsOnExpire, replaces };
}

function normalizeKit(raw) {
  const id = boundedString(raw?.id, 24)?.toLowerCase();
  const name = boundedString(raw?.name, 80);
  const permission = boundedString(raw?.permission ?? '', 128);
  const icon = boundedString(raw?.icon ?? 'CHEST', 64)?.replace(/^minecraft:/i, '').toUpperCase();
  const cooldown = Number(raw?.cooldown ?? 0);
  const slot = Number(raw?.slot ?? -1);
  const once = raw?.once === true;
  const commands = stringList(raw?.commands, 32, 256);
  const rawItems = raw?.items ?? [];
  if (!VIP_ID.test(id) || !name || !permission || !PERMISSION.test(permission)
    || !MATERIAL_ID.test(icon.toLowerCase()) || !Number.isSafeInteger(cooldown) || cooldown < 0 || cooldown > 31536000
    || !Number.isInteger(slot) || slot < -1 || slot > 53 || !commands || !Array.isArray(rawItems) || rawItems.length > 54) return null;
  const items = [];
  const slots = new Set();
  for (let index = 0; index < rawItems.length; index++) {
    const item = normalizeItem(rawItems[index], index);
    if (!item || slots.has(item.slot)) return null;
    slots.add(item.slot);
    items.push(item);
  }
  return { id, name, permission, icon, cooldown, slot, once, commands, items };
}

function normalizeCrate(raw, vipIds) {
  const id = boundedString(raw?.id, 32)?.toLowerCase();
  const name = boundedString(raw?.name, 48);
  if (!CRATE_ID.test(id) || !name) return null;
  let block = null;
  if (raw.block != null) {
    const world = boundedString(raw.block?.world, 80);
    const x = Number(raw.block?.x), y = Number(raw.block?.y), z = Number(raw.block?.z);
    if (!world || !Number.isSafeInteger(x) || !Number.isSafeInteger(y) || !Number.isSafeInteger(z)) return null;
    block = { world, x, y, z };
  }
  if (!Array.isArray(raw.rewards ?? []) || (raw.rewards ?? []).length > 54) return null;
  const rewards = [];
  for (let index = 0; index < (raw.rewards ?? []).length; index++) {
    const reward = raw.rewards[index];
    const weight = Number(reward?.weight);
    const command = reward?.command == null || reward.command === '' ? null : boundedString(reward.command, 256);
    const item = reward?.item == null ? null : normalizeItem(reward.item, index);
    if (!Number.isInteger(weight) || weight < 1 || weight > 1000000 || (command == null) === (item == null)) return null;
    if (command != null && /[\r\n]/.test(command)) return null;
    if (item?.boundVip && !vipIds.has(item.boundVip)) return null;
    rewards.push({ weight, command, item });
  }
  return { id, name, block, rewards };
}

export function normalizeVipConfig(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
    || !Array.isArray(raw.vips) || raw.vips.length > 100
    || !Array.isArray(raw.kits) || raw.kits.length > 200
    || !Array.isArray(raw.crates ?? []) || (raw.crates ?? []).length > 100) return null;
  const vips = raw.vips.map(normalizeVip);
  const kits = raw.kits.map(normalizeKit);
  if (vips.some(value => value == null) || kits.some(value => value == null)) return null;
  if (new Set(vips.map(value => value.id)).size !== vips.length || new Set(kits.map(value => value.id)).size !== kits.length) return null;
  const vipIds = new Set(vips.map(value => value.id));
  const kitIds = new Set(kits.map(value => value.id));
  if (vips.some(vip => [...vip.kits, ...vip.kitsOnGrant].some(id => !kitIds.has(id))
    || vip.replaces.some(id => !vipIds.has(id)))
    || kits.some(kit => kit.items.some(item => item.boundVip && !vipIds.has(item.boundVip)))) return null;
  const crates = (raw.crates ?? []).map(crate => normalizeCrate(crate, vipIds));
  if (crates.some(value => value == null) || new Set(crates.map(value => value.id)).size !== crates.length) return null;
  const rawSettings = raw.settings && typeof raw.settings === 'object' && !Array.isArray(raw.settings) ? raw.settings : {};
  const rawBoundItems = rawSettings.boundItems && typeof rawSettings.boundItems === 'object' && !Array.isArray(rawSettings.boundItems)
    ? rawSettings.boundItems : {};
  const syncGroupsOnStart = rawSettings.syncGroupsOnStart ?? true;
  const soulbound = rawBoundItems.soulbound ?? true;
  const destroyForeign = rawBoundItems.destroyForeign ?? true;
  const blockAnvil = rawBoundItems.blockAnvil ?? true;
  if ([syncGroupsOnStart, soulbound, destroyForeign, blockAnvil].some(value => typeof value !== 'boolean')) return null;
  return { vips, kits, crates, settings: { syncGroupsOnStart, boundItems: { soulbound, destroyForeign, blockAnvil } } };
}

export function createVipConfigService(db, audit) {
  function read() {
    const row = db.prepare(`SELECT revision,applied_revision AS appliedRevision,applied_at AS appliedAt,config
      FROM vip_plugin_config WHERE id=1`).get();
    return row ? { initialized: true, revision: row.revision, appliedRevision: row.appliedRevision, appliedAt: row.appliedAt, config: JSON.parse(row.config) }
      : { initialized: false, revision: 0, appliedRevision: 0, appliedAt: null, config: EMPTY_CONFIG };
  }

  function markApplied(revision) {
    const result = db.prepare(`UPDATE vip_plugin_config SET applied_revision=MAX(applied_revision,?),applied_at=datetime('now')
      WHERE id=1 AND revision>=?`).run(revision, revision);
    return result.changes === 1;
  }

  function write(expectedRevision, rawConfig, actor = 'nexoria-vip') {
    const config = normalizeVipConfig(rawConfig);
    if (!config) return { ok: false, error: 'invalid_vip_config' };
    db.exec('BEGIN IMMEDIATE');
    try {
      const current = db.prepare('SELECT revision FROM vip_plugin_config WHERE id=1').get();
      const revision = current?.revision ?? 0;
      if (revision !== expectedRevision) {
        db.exec('ROLLBACK');
        return { ok: false, error: 'vip_config_conflict', revision };
      }
      const nextRevision = revision + 1;
      db.prepare(`INSERT INTO vip_plugin_config(id,revision,config,updated_at) VALUES(1,?,?,datetime('now'))
        ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,config=excluded.config,updated_at=excluded.updated_at`)
        .run(nextRevision, JSON.stringify(config));
      audit(actor, 'vip_config_updated', String(nextRevision));
      db.exec('COMMIT');
      return { ok: true, revision: nextRevision, config };
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  return { read, write, markApplied };
}
