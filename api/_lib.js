// Shared helpers for the key generator API.
//
// Redis layout (shared with the remote-browser site):
//   k:<key>     hash: kind, tag, created, expires ("" = never), active ("1"/"0"), owner, usedAt,
//               dev ("1" on genuine Dev keys only)
//   keys        set of every key
//   tag:<TAG>   -> key
//   admin:<sha256(code)> -> device that claimed this admin code
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const redis = require("./_redis");

const DEVICE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const KEY_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const TAG_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MAX_DATE_MS = 8.64e15;   // the largest timestamp JavaScript dates can represent

const sha = s => crypto.createHash("sha256").update(String(s)).digest("hex");
const rand = (chars, n) => Array.from({ length: n }, () => chars[crypto.randomInt(chars.length)]).join("");
const clientIp = req => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "?";

function readBody(req) {
  let b = req.body;
  if (typeof b === "string") { try { b = JSON.parse(b); } catch { b = {}; } }
  return b && typeof b === "object" ? b : {};
}

function loadCodes() {
  for (const p of [path.join(process.cwd(), "codes.txt"), path.join(__dirname, "..", "codes.txt")]) {
    try {
      return fs.readFileSync(p, "utf8").split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith("#"));
    } catch { /* try next */ }
  }
  return null;
}

// Checks x-code / x-device headers. Sends the error response itself and returns false on failure.
async function authenticate(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try {
    const rl = "rl:admin:" + clientIp(req);
    if (Number((await redis(["GET", rl])) || 0) >= 10) { res.status(429).json({ error: "rate" }); return false; }

    const code = String(req.headers["x-code"] || "").trim();
    const device = String(req.headers["x-device"] || "");
    let ok = false;
    if (code && code.length <= 200 && DEVICE_RE.test(device)) {
      const codes = loadCodes();
      if (codes === null) { res.status(500).json({ error: "codes.txt was not found in this deployment" }); return false; }
      const h = sha(code);
      if (codes.some(c => crypto.timingSafeEqual(Buffer.from(sha(c)), Buffer.from(h)))) {
        // first device to use a code keeps it
        const k = "admin:" + h;
        ok = (await redis(["SET", k, device, "NX"])) === "OK" || (await redis(["GET", k])) === device;
      }
    }
    if (!ok) {
      const n = await redis(["INCR", rl]);
      if (n === 1) await redis(["EXPIRE", rl, 600]);
      res.status(401).json({ error: "denied" });
      return false;
    }
    return true;
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
    return false;
  }
}

function toObj(arr) {
  const o = {};
  if (Array.isArray(arr)) for (let i = 0; i + 1 < arr.length; i += 2) o[arr[i]] = arr[i + 1];
  return o;
}

// Strict parsing of one duration field. Blank / missing = 0. Returns a BigInt, or throws a readable Error.
function parseUnit(value, label, maxValue, maxDigits) {
  if (value === undefined || value === null) return 0n;
  let str;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a whole number, 0 or more.`);
    str = String(value);
  } else if (typeof value === "string") {
    str = value.trim();
  } else {
    throw new Error(`${label} must be a whole number, 0 or more.`);
  }
  if (str === "") return 0n;
  if (!/^[0-9]+$/.test(str)) throw new Error(`${label} must be a whole number, 0 or more (no signs, decimals or letters).`);
  if (str.length > 20) throw new Error(`${label} is too large.`);
  if (maxDigits && str.length > maxDigits) {
    throw new Error(`${label} can have at most ${maxDigits} digits.`);
  }
  const n = BigInt(str);
  if (maxValue !== undefined && n > BigInt(maxValue)) throw new Error(`${label} must be between 0 and ${maxValue}.`);
  return n;
}

// -> total milliseconds as a BigInt (> 0). Throws if invalid, all zero, or too long to represent safely.
function parseDuration(body, now) {
  const days = parseUnit(body.days, "Days");
  const hours = parseUnit(body.hours, "Hours", 23, 2);
  const minutes = parseUnit(body.minutes, "Minutes", 59, 2);
  const total = days * 86400000n + hours * 3600000n + minutes * 60000n;
  if (total <= 0n) throw new Error("A temporary key needs a duration: set at least 1 minute, or turn on Permanent.");
  const room = BigInt(MAX_DATE_MS) - BigInt(now);
  if (total > room) {
    throw new Error(`That duration is too long. The maximum is ${room / 86400000n} days.`);
  }
  return total;
}

const truthy = v => v === true || v === "true" || v === 1 || v === "1";

// Generates a key. The rules are enforced here, whatever the page sent:
//   Dev Key on  -> a Dev key ("d-"), ALWAYS permanent. permanent / days / hours / minutes are ignored entirely.
//   Permanent   -> a permanent Standard key ("p-", expires "" - the same representation as before).
//   otherwise   -> a temporary Standard key ("s-") that expires after days + hours + minutes.
async function generateKey(body) {
  if (body.type !== undefined && body.dev === undefined && body.permanent === undefined) {
    throw new Error("This page is out of date. Refresh it (Ctrl+Shift+R) and try again.");
  }
  const dev = truthy(body.dev);
  const permanent = dev || truthy(body.permanent);
  const kind = dev ? "d" : permanent ? "p" : "s";
  const created0 = Date.now();
  const ms = permanent ? null : parseDuration(body, created0);   // validated before anything is written

  for (let attempt = 0; attempt < 30; attempt++) {
    const key = kind + "-" + rand(KEY_CHARS, 6);
    const created = Date.now();
    // HSETNX claims the key atomically; 0 means it already exists, so roll again
    if ((await redis(["HSETNX", "k:" + key, "created", String(created)])) !== 1) continue;

    let tag = null;
    for (let j = 0; j < 60 && !tag; j++) {
      const t = rand(TAG_CHARS, 4);
      if ((await redis(["SET", "tag:" + t, key, "NX"])) === "OK") tag = t;
    }
    if (!tag) { await redis(["DEL", "k:" + key]); throw new Error("could not allocate a unique ID"); }

    let expires = null;
    if (ms !== null) {
      const at = BigInt(created) + ms;
      if (at > BigInt(MAX_DATE_MS)) { await redis.pipeline([["DEL", "k:" + key], ["DEL", "tag:" + tag]]); throw new Error("That duration is too long."); }
      expires = Number(at);
    }
    const fields = ["kind", kind, "tag", tag, "expires", expires ? String(expires) : "", "active", "1"];
    if (dev) fields.push("dev", "1");
    await redis.pipeline([["HSET", "k:" + key, ...fields], ["SADD", "keys", key]]);
    return { key, kind, tag, created, expires, dev, permanent };
  }
  throw new Error("could not generate a unique key");
}

async function listKeys() {
  const keys = (await redis(["SMEMBERS", "keys"])) || [];
  const rows = [];
  for (let i = 0; i < keys.length; i += 200) {
    const chunk = keys.slice(i, i + 200);
    const res = await redis.pipeline(chunk.map(k => ["HGETALL", "k:" + k]));
    chunk.forEach((key, n) => {
      const r = toObj(res[n]);
      if (!r.kind) return;
      rows.push({
        key, kind: r.kind, tag: r.tag, created: Number(r.created) || 0,
        expires: r.expires ? Number(r.expires) : null,
        active: r.active !== "0",
        archived: r.archived === "1",
        dev: r.kind === "d" && r.dev === "1",
        legacy: r.kind === "d" && r.dev !== "1",   // an old Demo key: no longer valid
        used: !!r.owner,                           // the device id itself is never sent to the browser
        usedAt: r.usedAt ? Number(r.usedAt) : null,
      });
    });
  }
  rows.sort((a, b) => b.created - a.created);
  return rows;
}

const KEY_RE = /^[spd]-[A-Za-z0-9]{6}$/;
module.exports = { authenticate, readBody, generateKey, listKeys, parseDuration, KEY_RE, redis, toObj };
