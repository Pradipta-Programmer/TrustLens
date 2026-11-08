const { Schema, model } = require('mongoose');
module.exports = model('ThreatIntel', new Schema({
  domainName: { type: String, required: true, index: true }, url: String,
  source: { type: String, required: true }, category: String, observedAt: Date, raw: Schema.Types.Mixed,
}, { timestamps: true }).index({ domainName: 1, source: 1, url: 1 }, { unique: true }));
