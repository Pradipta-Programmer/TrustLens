// server/src/scripts/prepareTestIndexes.js
// Priority 6.3 Stage 1 — Safe Test Database Index Preparation
// Strictly operates on trustlens_test with fail-closed safety assertions.
'use strict';
process.env.NODE_ENV = 'test';
process.env.USE_TEST_DB = 'true';

require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { connectDb, closeDb, assertTestDatabase } = require('../config/db');
const User = require('../models/User');
const CommunityReport = require('../models/CommunityReport');
const Scan = require('../models/Scan');

async function prepareTestIndexes() {
  console.log('[STAGE 1] Connecting to isolated test database...');
  const ok = await connectDb();
  assert.ok(ok, 'connectDb() must succeed');

  try {
    // 1. Verify connected database is exactly trustlens_test
    const dbName = mongoose.connection.name;
    console.log(`[STAGE 1] Connected database: "${dbName}"`);
    assert.equal(dbName, 'trustlens_test', 'FATAL: Expected "trustlens_test", got "' + dbName + '"');
    assertTestDatabase();

    // 2. Check for duplicate emails before creating unique email index
    console.log('[STAGE 1] Checking for duplicate email records in trustlens_test.users...');
    const duplicateEmails = await User.aggregate([
      { $group: { _id: '$email', count: { $sum: 1 } } },
      { $match: { count: { $gt: 1 }, _id: { $ne: null } } },
    ]);
    if (duplicateEmails.length > 0) {
      throw new Error(`Duplicate emails found in test database: ${JSON.stringify(duplicateEmails)}`);
    }
    console.log('  ✓ No duplicate emails found.');

    // 3. User indexes: Create unique { email: 1 } if missing
    assertTestDatabase();
    const existingUserIndexes = await User.collection.indexes().catch(() => []);
    const hasEmailIdx = existingUserIndexes.some(idx => idx.key && idx.key.email === 1);
    if (!hasEmailIdx) {
      console.log('[STAGE 1] Creating unique { email: 1 } index on trustlens_test.users...');
      await User.collection.createIndex({ email: 1 }, { unique: true, background: true });
      console.log('  ✓ Unique email index created.');
    } else {
      console.log('  ✓ User email index already present.');
    }

    // 4. CommunityReport indexes: Check and create missing required indexes
    assertTestDatabase();
    const existingReportIndexes = await CommunityReport.collection.indexes().catch(() => []);
    const hasCompoundReportIdx = existingReportIndexes.some(
      idx => idx.key && idx.key.domainName === 1 && idx.key.category === 1 && idx.key.reporter === 1
    );
    if (!hasCompoundReportIdx) {
      console.log('[STAGE 1] Creating compound unique { domainName: 1, category: 1, reporter: 1 } index...');
      await CommunityReport.collection.createIndex(
        { domainName: 1, category: 1, reporter: 1 },
        { unique: true, background: true }
      );
      console.log('  ✓ Compound unique report index created.');
    } else {
      console.log('  ✓ Compound unique report index already present.');
    }

    const hasReportDomainIdx = existingReportIndexes.some(idx => idx.key && idx.key.domainName === 1 && Object.keys(idx.key).length === 1);
    if (!hasReportDomainIdx) {
      await CommunityReport.collection.createIndex({ domainName: 1 }, { background: true });
      console.log('  ✓ CommunityReport domainName index created.');
    }

    // 5. Scan indexes: Check and create missing query indexes
    assertTestDatabase();
    const existingScanIndexes = await Scan.collection.indexes().catch(() => []);
    const hasScanDomainIdx = existingScanIndexes.some(idx => idx.key && idx.key.domainName === 1 && idx.key.createdAt === -1);
    if (!hasScanDomainIdx) {
      console.log('[STAGE 1] Creating Scan { domainName: 1, createdAt: -1 } index...');
      await Scan.collection.createIndex({ domainName: 1, createdAt: -1 }, { background: true });
      console.log('  ✓ Scan domainName+createdAt index created.');
    } else {
      console.log('  ✓ Scan domainName+createdAt index already present.');
    }

    const hasScanUserIdx = existingScanIndexes.some(idx => idx.key && idx.key.requestedBy === 1 && idx.key.createdAt === -1);
    if (!hasScanUserIdx) {
      console.log('[STAGE 1] Creating Scan { requestedBy: 1, createdAt: -1 } index...');
      await Scan.collection.createIndex({ requestedBy: 1, createdAt: -1 }, { background: true });
      console.log('  ✓ Scan requestedBy+createdAt index created.');
    } else {
      console.log('  ✓ Scan requestedBy+createdAt index already present.');
    }

    // 6. Verify and output all created indexes
    assertTestDatabase();
    const finalUserIndexes = await User.collection.indexes();
    const finalReportIndexes = await CommunityReport.collection.indexes();
    const finalScanIndexes = await Scan.collection.indexes();

    console.log('\n[STAGE 1 VERIFICATION] Current indexes on trustlens_test:');
    console.log('  - users:', finalUserIndexes.map(i => i.name).join(', '));
    console.log('  - communityreports:', finalReportIndexes.map(i => i.name).join(', '));
    console.log('  - scans:', finalScanIndexes.map(i => i.name).join(', '));
    console.log('\n✓ Stage 1 index preparation completed successfully on trustlens_test.');

  } finally {
    await closeDb();
    console.log('[STAGE 1] Database connection closed cleanly.');
  }
}

if (require.main === module) {
  prepareTestIndexes().catch((err) => {
    console.error('[STAGE 1 ERROR]', err);
    process.exit(1);
  });
}

module.exports = prepareTestIndexes;
