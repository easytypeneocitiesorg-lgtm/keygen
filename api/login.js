// Used by the page to check an admin code (and to remember this device for it).
const { authenticate } = require("./_lib");
const cors = require("./_cors");

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (await authenticate(req, res)) res.status(200).json({ ok: true });
};
