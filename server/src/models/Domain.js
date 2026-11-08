// One record per normalised domain: the anchor for scans, certs, reports, reputation.
const { Schema, model } = require('mongoose');
module.exports = model('Domain', new Schema({
  name: { type: String, required: true, unique: true, lowercase: true },
  reputation: { classification: { type: String, enum: ['unknown', 'low', 'moderate', 'high', 'critical'], default: 'unknown' }, reportCount: { type: Number, default: 0 }, verifiedReportCount: { type: Number, default: 0 } },
  firstSeenAt: { type: Date, default: Date.now }, lastScannedAt: Date,
}, { timestamps: true }));
