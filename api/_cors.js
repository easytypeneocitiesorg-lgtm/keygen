// CORS: lets the static frontend (a different domain, e.g. on Wasmer) call this API from the browser.
// Optional env var ALLOWED_ORIGINS = comma-separated frontend origins, e.g. https://my-site.wasmer.app
// If it is not set, any origin is allowed (fine to start with: nothing here uses cookies).
// Returns true when the request was a preflight that has already been answered.
module.exports = function cors(req, res) {
  const allowed = (process.env.ALLOWED_ORIGINS || "")
    .split(",").map(s => s.trim().replace(/\/+$/, "")).filter(Boolean);
  const origin = req.headers.origin;
  if (!allowed.length) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (origin && allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-code, x-device, x-server-key");
  res.setHeader("Access-Control-Max-Age", "86400");
  if (req.method === "OPTIONS") { res.status(204).end(); return true; }
  return false;
};
