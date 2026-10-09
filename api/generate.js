const { authenticate, readBody, generateKey } = require("./_lib");
const cors = require("./_cors");

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
  if (!(await authenticate(req, res))) return;
  try {
    res.status(200).json(await generateKey(String(readBody(req).type || "")));
  } catch (e) {
    res.status(400).json({ error: String(e.message || e) });
  }
};
