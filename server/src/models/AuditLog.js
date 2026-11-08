const { Schema, model } = require('mongoose');
module.exports = model('AuditLog', new Schema({
  actor: { type: Schema.Types.ObjectId, ref: 'User', required: true }, action: { type: String, required: true },
  targetType: String, targetId: String, detail: Schema.Types.Mixed,
}, { timestamps: { createdAt: true, updatedAt: false } }).index({ createdAt: -1 }));
