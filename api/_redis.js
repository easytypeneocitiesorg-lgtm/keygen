// Tiny Redis-over-HTTP helper (Upstash REST API).
// Files starting with "_" are not exposed as routes.
function conf() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) {
    throw new Error("No Redis database is connected to this Vercel project (set UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN)");
  }
  return { url: url.replace(/\/+$/, ""), token };
}

async function redis(cmd) {
  const { url, token } = conf();
  const r = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

// Several commands in one round trip. Returns the array of results.
redis.pipeline = async function (cmds) {
  if (!cmds.length) return [];
  const { url, token } = conf();
  const r = await fetch(url + "/pipeline", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify(cmds),
  });
  const j = await r.json();
  if (!Array.isArray(j)) throw new Error((j && j.error) || "bad pipeline response");
  return j.map(x => { if (x.error) throw new Error(x.error); return x.result; });
};

module.exports = redis;
