// Deactivates a key. server.py re-checks keys every few seconds and disconnects (or removes
// from the queue) anyone using it.
const { authenticate, readBody, KEY_RE, redis } = require("./_lib");
const cors = require("./_cors");

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  if (!(await authenticate(req, res))) return;
  const key = String(readBody(req).key || "");
  if (!KEY_RE.test(key)) return res.status(400).json({ error: "bad key" });
  try {
    if (!(await redis(["HGET", "k:" + key, "kind"]))) return res.status(404).json({ error: "no such key" });
    await redis(["HSET", "k:" + key, "active", "0"]);
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
};
