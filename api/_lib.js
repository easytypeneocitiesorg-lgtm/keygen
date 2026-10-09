// Shared helpers for the key generator API.
//
// Redis layout (shared with the remote-browser site):
//   k:<key>     hash: kind, tag, created, expires ("" = never), active ("1"/"0"), owner, usedAt
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
const DURATIONS = { s: 20 * 86400e3, d: 8 * 3600e3, p: null };   // standard 20 days, demo 8 hours, permanent never

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

async function generateKey(kind) {
  if (!(kind in DURATIONS)) throw new Error("bad type");
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

    const expires = DURATIONS[kind] ? created + DURATIONS[kind] : null;
    await redis.pipeline([
      ["HSET", "k:" + key, "kind", kind, "tag", tag, "expires", expires ? String(expires) : "", "active", "1"],
      ["SADD", "keys", key],
    ]);
    return { key, kind, tag, created, expires };
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
        used: !!r.owner,                           // the device id itself is never sent to the browser
        usedAt: r.usedAt ? Number(r.usedAt) : null,
      });
    });
  }
  rows.sort((a, b) => b.created - a.created);
  return rows;
}

const KEY_RE = /^[spd]-[A-Za-z0-9]{6}$/;
module.exports = { authenticate, readBody, generateKey, listKeys, KEY_RE, redis };
