// Removes legacy Demo keys ("d-" keys that are NOT genuine Dev keys). Opt-in, from the key console.
// Safe by design:
//   - never touches Standard keys (s-/p-) or Dev keys (dev="1")
//   - writes a full backup of every record it removes to Redis (backup:demo:<timestamp>) first
//   - idempotent: running it again finds nothing left to remove
const { authenticate, readBody, redis, toObj } = require("./_lib");
const cors = require("./_cors");

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  if (!(await authenticate(req, res))) return;
  try {
    const keys = (await redis(["SMEMBERS", "keys"])) || [];
    const legacy = [];
    for (let i = 0; i < keys.length; i += 200) {
      const chunk = keys.slice(i, i + 200);
      const recs = await redis.pipeline(chunk.map(k => ["HGETALL", "k:" + k]));
      chunk.forEach((key, n) => {
        const r = toObj(recs[n]);
        if (r.kind === "d" && r.dev !== "1") legacy.push({ key, record: r });
      });
    }
    const dryRun = readBody(req).dryRun === true;
    if (!legacy.length || dryRun) return res.status(200).json({ ok: true, removed: 0, found: legacy.length });

    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    await redis(["SET", "backup:demo:" + stamp, JSON.stringify(legacy)]);      // backup first
    const cmds = [];
    for (const { key, record } of legacy) {
      cmds.push(["DEL", "k:" + key], ["SREM", "keys", key]);
      if (record.tag) cmds.push(["DEL", "tag:" + record.tag]);
    }
    for (let i = 0; i < cmds.length; i += 300) await redis.pipeline(cmds.slice(i, i + 300));
    res.status(200).json({ ok: true, removed: legacy.length, backup: "backup:demo:" + stamp });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
};
