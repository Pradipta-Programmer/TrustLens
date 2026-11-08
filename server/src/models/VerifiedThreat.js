const { Schema, model } = require('mongoose');
module.exports = model('VerifiedThreat', new Schema({
  domainName: { type: String, required: true, unique: true }, category: String,
  sourceReports: [{ type: Schema.Types.ObjectId, ref: 'CommunityReport' }], verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' }, verifiedAt: Date,
}, { timestamps: true }));
