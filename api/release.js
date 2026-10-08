// Un-binds a key from the device that used it, so a different device can use it
// (for when someone cleared their browser data or got a new phone).
const { authenticate, readBody, KEY_RE, redis } = require("./_lib");
module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  if (!(await authenticate(req, res))) return;
  const key = String(readBody(req).key || "");
  if (!KEY_RE.test(key)) return res.status(400).json({ error: "bad key" });
  try {
    if (!(await redis(["HGET", "k:" + key, "kind"]))) return res.status(404).json({ error: "no such key" });
    await redis(["HDEL", "k:" + key, "owner", "usedAt"]);
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
};
