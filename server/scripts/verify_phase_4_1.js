'use strict';
require('dotenv').config();
const mongoose = require('mongoose');
const config = require('../src/config/index');
const Scan = require('../src/models/Scan');
const CertificateRecord = require('../src/models/CertificateRecord');

async function run() {
  console.log('Connecting to Atlas...');
  await mongoose.connect(config.mongoUri, { serverSelectionTimeoutMS: 8000 });
  console.log('Connected to Atlas successfully.');

  console.log('\n--- Syncing Indexes on Scan ---');
  await Scan.syncIndexes();
  const scanIndexes = await Scan.collection.indexes();
  console.log('Scan collection indexes:');
  scanIndexes.forEach(ix => console.log(' -', JSON.stringify(ix.key), ix.name));

  console.log('\n--- Syncing Indexes on CertificateRecord ---');
  await CertificateRecord.syncIndexes();
  const certIndexes = await CertificateRecord.collection.indexes();
  console.log('CertificateRecord collection indexes:');
  certIndexes.forEach(ix => console.log(' -', JSON.stringify(ix.key), ix.name));

  const testUserId = new mongoose.Types.ObjectId();

  console.log('\n--- Evaluating Query Plan for Scan History Query ---');
  console.log('Query: Scan.find({ requestedBy: ' + testUserId + ' }).sort({ createdAt: -1 })');
  const scanExplain = await Scan.find({ requestedBy: testUserId })
    .sort({ createdAt: -1 })
    .explain('executionStats');

  const scanWinningStage = scanExplain.queryPlanner.winningPlan;
  console.log('Scan Query Planner Winning Plan Stage:', scanWinningStage.stage);
  console.log('Scan Winning Plan Details:', JSON.stringify(scanWinningStage, null, 2));

  console.log('\n--- Evaluating Query Plan for Certificate Listing Query ---');
  console.log('Query: CertificateRecord.find().sort({ observedAt: -1 })');
  const certListExplain = await CertificateRecord.find()
    .sort({ observedAt: -1 })
    .explain('executionStats');
  console.log('Cert List Winning Plan Stage:', certListExplain.queryPlanner.winningPlan.stage);
  console.log('Cert List Winning Plan Details:', JSON.stringify(certListExplain.queryPlanner.winningPlan, null, 2));

  console.log('\n--- Evaluating Query Plan for Certificate Substring Search vs Prefix Search ---');
  console.log('Regex Substring Query: CertificateRecord.find({ domainName: /test/i }).sort({ observedAt: -1 })');
  const regexExplain = await CertificateRecord.find({ domainName: /test/i })
    .sort({ observedAt: -1 })
    .explain('executionStats');
  console.log('Regex Substring Winning Plan Stage:', regexExplain.queryPlanner.winningPlan.stage);

  console.log('Prefix Query: CertificateRecord.find({ domainName: /^test/i }).sort({ observedAt: -1 })');
  const prefixExplain = await CertificateRecord.find({ domainName: /^test/i })
    .sort({ observedAt: -1 })
    .explain('executionStats');
  console.log('Prefix Winning Plan Stage:', prefixExplain.queryPlanner.winningPlan.stage);

  console.log('Exact Equality Query: CertificateRecord.find({ domainName: "test.com" }).sort({ observedAt: -1 })');
  const exactExplain = await CertificateRecord.find({ domainName: "test.com" })
    .sort({ observedAt: -1 })
    .explain('executionStats');
  console.log('Exact Equality Winning Plan Stage:', exactExplain.queryPlanner.winningPlan.stage);

  const client = mongoose.connection.getClient();
  await client.close(true);
  await mongoose.connection.close();
  console.log('\nConnection closed cleanly.');
}

run().catch(e => {
  console.error('Error during index verification:', e);
  process.exit(1);
});
