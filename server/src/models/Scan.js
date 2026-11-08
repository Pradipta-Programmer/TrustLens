// Module results carry explicit status so "not assessed" is never shown as a pass.
const { Schema, model } = require('mongoose');
const moduleResult = { status: { type: String, enum: ['live', 'demo', 'pending', 'not_assessed', 'unavailable', 'failed'], default: 'pending' }, score: Number, findings: [Schema.Types.Mixed] };
const scanSchema = new Schema({
  submittedUrl: { type: String, required: true, maxlength: 2048 },
  domain: { type: Schema.Types.ObjectId, ref: 'Domain', index: true }, domainName: { type: String, index: true },
  requestedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  mode: { type: String, enum: ['live', 'demo'], required: true },
  status: { type: String, enum: ['queued', 'running', 'completed', 'failed'], default: 'queued' },
  riskScore: Number, confidence: Number, classification: String,
  modules: { threat: moduleResult, security: moduleResult, certificate: moduleResult, community: moduleResult, impersonation: moduleResult },
  evidence: [Schema.Types.Mixed], recommendations: [String],
}, { timestamps: true });

scanSchema.index({ domainName: 1, createdAt: -1 });
scanSchema.index({ requestedBy: 1, createdAt: -1 });

module.exports = model('Scan', scanSchema);
