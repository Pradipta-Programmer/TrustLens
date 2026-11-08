// server/src/services/feedScheduler.js
// Background synchronization runner for external threat intelligence feeds.
// Controlled via ENABLE_BACKGROUND_FEED_SYNC=true. Disabled by default.

'use strict';

const config = require('../config');
const { syncFeeds } = require('./threatFeedService');
const { dbReady } = require('../config/db');
const logger = require('../utils/logger');

let timer = null;
let isSyncing = false;

/**
 * Executes a single synchronization cycle with concurrency guard and failure isolation.
 */
async function executeSync(source = 'scheduled_runner') {
  if (isSyncing) {
    logger.warn('Scheduled threat feed sync skipped: previous synchronization cycle still active');
    return null;
  }

  if (!dbReady()) {
    logger.warn('Scheduled threat feed sync skipped: database is unavailable');
    return null;
  }

  isSyncing = true;
  const startedAt = Date.now();
  try {
    logger.info('Starting scheduled threat feed synchronization', { source });
    const result = await syncFeeds({ source: 'all' });
    const durationMs = Date.now() - startedAt;
    logger.info('Scheduled threat feed synchronization completed', {
      totalProcessed: result.totalProcessed,
      totalIngested: result.totalIngested,
      duplicatesSkipped: result.duplicatesSkipped,
      durationMs,
    });
    return result;
  } catch (err) {
    logger.error('Scheduled threat feed synchronization failed', {
      error: err.message,
      durationMs: Date.now() - startedAt,
    });
    return null;
  } finally {
    isSyncing = false;
  }
}

/**
 * Initializes the recurring timer if background feed sync is enabled.
 */
function startScheduledSync(intervalMs = config.feedSyncIntervalMs) {
  if (timer) return;
  logger.info(`Initializing background threat feed scheduler (interval: ${Math.round(intervalMs / 1000 / 60)} minutes)`);
  timer = setInterval(() => {
    executeSync('interval_timer').catch(() => {});
  }, intervalMs);
  if (timer.unref) {
    timer.unref(); // Allows process to terminate naturally if no other event loop tasks are queued
  }
}

/**
 * Clears the recurring timer for graceful server shutdown.
 */
function stopScheduledSync() {
  if (timer) {
    clearInterval(timer);
    timer = null;
    logger.info('Background threat feed scheduler stopped cleanly');
  }
}

function isScheduledSyncRunning() {
  return timer !== null;
}

module.exports = {
  startScheduledSync,
  stopScheduledSync,
  isScheduledSyncRunning,
  executeSync,
};
