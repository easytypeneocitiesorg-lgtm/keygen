// Archives a key (hides it from the manager's default list) - only allowed once the key is
// deactivated or expired. Un-archiving is always allowed.
const { authenticate, readBody, KEY_RE, redis } = require("./_lib");
const cors = require("./_cors");

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  if (!(await authenticate(req, res))) return;

  const body = readBody(req);
  const key = String(body.key || "");
  const archive = body.archived !== false;          // { key, archived: true | false }
  if (!KEY_RE.test(key)) return res.status(400).json({ error: "bad key" });

  try {
    const [kind, active, expires] = await redis.pipeline([
      ["HGET", "k:" + key, "kind"], ["HGET", "k:" + key, "active"], ["HGET", "k:" + key, "expires"],
    ]);
    if (!kind) return res.status(404).json({ error: "no such key" });

    if (archive) {
      const deactivated = active === "0";
      const expired = !!expires && Date.now() > Number(expires);
      if (!deactivated && !expired) {
        return res.status(400).json({ error: "Only deactivated or expired keys can be archived." });
      }
      await redis(["HSET", "k:" + key, "archived", "1"]);
    } else {
      await redis(["HDEL", "k:" + key, "archived"]);
    }
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
};
