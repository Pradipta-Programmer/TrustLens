const { Schema, model } = require('mongoose');

const certificateRecordSchema = new Schema({
  domainName: { type: String, required: true, index: true }, issuer: String, subject: String, san: [String],
  validFrom: Date, validTo: Date, hostnameMatch: Boolean, chainValid: Boolean, ctObservations: [Schema.Types.Mixed],
  ctFetchedAt: Date,
  mode: { type: String, enum: ['live', 'demo'], required: true }, observedAt: { type: Date, default: Date.now, index: true },
}, { timestamps: true });

certificateRecordSchema.index({ domainName: 1, observedAt: -1 });

module.exports = model('CertificateRecord', certificateRecordSchema);
