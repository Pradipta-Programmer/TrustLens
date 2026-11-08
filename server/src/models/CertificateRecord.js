const { Schema, model } = require('mongoose');
module.exports = model('CertificateRecord', new Schema({
  domainName: { type: String, required: true, index: true }, issuer: String, subject: String, san: [String],
  validFrom: Date, validTo: Date, hostnameMatch: Boolean, chainValid: Boolean, ctObservations: [Schema.Types.Mixed],
  ctFetchedAt: Date,
  mode: { type: String, enum: ['live', 'demo'], required: true }, observedAt: { type: Date, default: Date.now },
}, { timestamps: true }));
