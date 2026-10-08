const { authenticate, listKeys } = require("./_lib");
module.exports = async (req, res) => {
  if (!(await authenticate(req, res))) return;
  try {
    res.status(200).json({ now: Date.now(), keys: await listKeys() });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
};
