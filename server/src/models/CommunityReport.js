const { Schema, model } = require('mongoose');
const CATEGORIES = ['phishing', 'fake_recruitment', 'fake_banking', 'fake_payment', 'brand_impersonation', 'suspicious_redirect', 'other'];
const s = new Schema({
  url: { type: String, required: true, maxlength: 2048 }, domainName: { type: String, required: true, index: true },
  category: { type: String, enum: CATEGORIES, required: true }, description: { type: String, maxlength: 1000 },
  reporter: { type: Schema.Types.ObjectId, ref: 'User', required: true, select: false }, // never exposed publicly
  status: { type: String, enum: ['pending_review', 'under_verification', 'verified', 'rejected'], default: 'pending_review' },
  reviewedBy: { type: Schema.Types.ObjectId, ref: 'User', select: false }, reviewedAt: Date,
}, { timestamps: true });
s.index({ domainName: 1, category: 1, reporter: 1 }, { unique: true }); // one report per user per domain+category
const M = model('CommunityReport', s); M.CATEGORIES = CATEGORIES; module.exports = M;
