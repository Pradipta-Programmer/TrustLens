// Creates an admin from ADMIN_EMAIL / ADMIN_PASSWORD env vars. No default credentials exist.
const bcrypt = require('bcryptjs'), User = require('../models/User');
const { connectDb } = require('../config/db');
(async () => {
  const { ADMIN_EMAIL: e, ADMIN_PASSWORD: p } = process.env;
  if (!e || !p || p.length < 12) { console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD (>=12 chars) in the environment.'); process.exit(1); }
  if (!(await connectDb())) process.exit(1);
  await User.updateOne({ email: e.toLowerCase() }, { $set: { name: 'Administrator', role: 'admin', passwordHash: await bcrypt.hash(p, 12) } }, { upsert: true });
  console.log('Admin ready:', e); process.exit(0);
})();
