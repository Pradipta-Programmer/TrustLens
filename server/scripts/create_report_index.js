'use strict';
const mongoose = require('mongoose');
const config = require('../src/config/index');
const Report = require('../src/models/CommunityReport');

async function run() {
  console.log('Connecting to Atlas...');
  await mongoose.connect(config.mongoUri, { serverSelectionTimeoutMS: 8000 });
  console.log('Connected.');

  console.log('Creating unique index on CommunityReport: { domainName: 1, category: 1, reporter: 1 }...');
  const indexName = await Report.collection.createIndex(
    { domainName: 1, category: 1, reporter: 1 },
    { unique: true }
  );
  console.log('Created index successfully:', indexName);

  console.log('\nVerifying current indexes on collection:');
  const indexes = await Report.collection.indexes();
  indexes.forEach(ix => console.log(' -', JSON.stringify(ix)));

  const client = mongoose.connection.getClient();
  await client.close(true);
  await mongoose.connection.close();
  console.log('\nConnection closed cleanly.');
}

run().catch(e => {
  console.error('Error creating index:', e.message);
  process.exit(1);
});
