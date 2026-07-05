/**
 * Audit Logger - Structured NDJSON logging for security events
 *
 * Records blocked attacks, tool invocations, and authentication events
 * in newline-delimited JSON format with log rotation and PII redaction.
 *
 * Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8
 */

import { writeFileSync, statSync, renameSync, mkdirSync, appendFileSync } from 'node:fs';
import { dirname } from 'node:path';

/** Log level hierarchy */
const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

/** Max log file size in bytes (50 MB) */
const MAX_FILE_SIZE = 50 * 1024 * 1024;

/** Max rotated files to retain */
const MAX_ROTATED_FILES = 5;

/** PII patterns to redact from log data */
const PII_PATTERNS = [
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: '[REDACTED:SSN]' },
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: '[REDACTED:EMAIL]' },
  { pattern: /\bVB-\d{6}\b/g, label: '[REDACTED:ACCOUNT]' },
];

/** Secret-like patterns to redact */
const SECRET_PATTERNS = [
  { pattern: /\b(sk-[A-Za-z0-9_\-]{20,})\b/g, label: '[REDACTED:API_KEY]' },
  { pattern: /\b(sk-ant-[A-Za-z0-9_\-]{20,})\b/g, label: '[REDACTED:API_KEY]' },
  { pattern: /\b(AKIA[A-Z0-9]{16})\b/g, label: '[REDACTED:API_KEY]' },
  { pattern: /\b(gsk_[A-Za-z0-9_\-]{20,})\b/g, label: '[REDACTED:API_KEY]' },
  { pattern: /password\s*[=:]\s*\S+/gi, label: '[REDACTED:SECRET]' },
  { pattern: /passwd\s*[=:]\s*\S+/gi, label: '[REDACTED:SECRET]' },
];

/** System prompt indicator patterns */
const SYSTEM_PROMPT_PATTERNS = [
  /You are a [\s\S]{30,}/gi,
  /\[SYSTEM\][\s\S]{30,}/gi,
  /<<SYS>>[\s\S]*?<<\/SYS>>/gi,
];

/**
 * Redact sensitive data from a value (string or object).
 * Ensures secrets, PII, and system prompts are never logged.
 * @param {*} value - Value to sanitize
 * @returns {*} Sanitized value
 */
function redactSensitive(value) {
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') {
    let result = value;

    // Redact PII
    for (const { pattern, label } of PII_PATTERNS) {
      result = result.replace(new RegExp(pattern.source, pattern.flags), label);
    }

    // Redact secrets
    for (const { pattern, label } of SECRET_PATTERNS) {
      result = result.replace(new RegExp(pattern.source, pattern.flags), label);
    }

    // Redact system prompts
    for (const pat of SYSTEM_PROMPT_PATTERNS) {
      result = result.replace(new RegExp(pat.source, pat.flags), '[REDACTED:SYSTEM_PROMPT]');
    }

    return result;
  }

  if (Array.isArray(value)) {
    return value.map(item => redactSensitive(item));
  }

  if (typeof value === 'object') {
    const redacted = {};
    for (const [key, val] of Object.entries(value)) {
      // Redact keys that look like they hold secrets
      const lowerKey = key.toLowerCase();
      if (
        lowerKey.includes('password') ||
        lowerKey.includes('secret') ||
        lowerKey.includes('token') ||
        lowerKey.includes('apikey') ||
        lowerKey.includes('api_key') ||
        lowerKey === 'authorization'
      ) {
        redacted[key] = '[REDACTED:SECRET]';
      } else if (lowerKey === 'systemprompt' || lowerKey === 'system_prompt') {
        redacted[key] = '[REDACTED:SYSTEM_PROMPT]';
      } else {
        redacted[key] = redactSensitive(val);
      }
    }
    return redacted;
  }

  return value;
}

/**
 * Rotate log file if it exceeds the max size.
 * Renames current -> .1, .1 -> .2, etc. Removes files beyond MAX_ROTATED_FILES.
 * @param {string} logFilePath
 */
function rotateIfNeeded(logFilePath) {
  try {
    const stats = statSync(logFilePath);
    if (stats.size < MAX_FILE_SIZE) return;
  } catch {
    // File doesn't exist yet, no rotation needed
    return;
  }

  // Shift rotated files: .5 is deleted, .4 -> .5, .3 -> .4, etc.
  for (let i = MAX_ROTATED_FILES; i >= 1; i--) {
    const src = i === 1 ? logFilePath : `${logFilePath}.${i - 1}`;
    const dest = `${logFilePath}.${i}`;
    try {
      if (i === MAX_ROTATED_FILES) {
        // Delete the oldest rotated file (if exists) by overwriting
        try {
          statSync(dest);
          // File exists, will be overwritten by rename
        } catch {
          // doesn't exist, fine
        }
      }
      renameSync(src, dest);
    } catch {
      // Source doesn't exist, skip
    }
  }
}

/**
 * Write queue for atomic writes.
 * Ensures no interleaved JSON lines from concurrent calls.
 */
class WriteQueue {
  constructor() {
    this._queue = [];
    this._flushing = false;
  }

  enqueue(line, logFilePath, onFileError) {
    this._queue.push({ line, logFilePath, onFileError });
    this._drain();
  }

  _drain() {
    if (this._flushing) return;
    this._flushing = true;

    while (this._queue.length > 0) {
      const { line, logFilePath, onFileError } = this._queue.shift();

      // Always write to stdout atomically (single write call)
      process.stdout.write(line + '\n');

      // Write to file if configured
      if (logFilePath) {
        try {
          rotateIfNeeded(logFilePath);
          appendFileSync(logFilePath, line + '\n', { flag: 'a' });
        } catch (err) {
          onFileError(err);
        }
      }
    }

    this._flushing = false;
  }

  async flush() {
    // All writes are synchronous, so nothing pending
    return;
  }
}

/**
 * Creates an AuditLogger instance.
 *
 * @param {Object} config
 * @param {string} [config.logFilePath] - Path to the log file (optional; if omitted, logs to stdout only)
 * @param {string} [config.minLevel='INFO'] - Minimum log level: DEBUG, INFO, WARN, ERROR
 * @param {number} [config.recentEventsLimit=1000] - Max recent events to retain in memory
 * @returns {AuditLogger}
 */
export function createAuditLogger(config = {}) {
  const {
    logFilePath = null,
    minLevel = 'INFO',
    recentEventsLimit = 1000,
  } = config;

  const minLevelValue = LOG_LEVELS[minLevel] ?? LOG_LEVELS.INFO;
  const recentEvents = [];
  const writeQueue = new WriteQueue();
  let fileAvailable = !!logFilePath;
  let fileErrorLogged = false;

  // Ensure log directory exists if a file path is configured
  if (logFilePath) {
    try {
      mkdirSync(dirname(logFilePath), { recursive: true });
    } catch {
      // Directory may already exist or be inaccessible; handled at write time
    }
  }

  function handleFileError(err) {
    if (!fileErrorLogged) {
      fileErrorLogged = true;
      fileAvailable = false;

      // Emit diagnostic event to stdout (Req 13.7)
      const diagnosticEvent = {
        timestamp: new Date().toISOString(),
        level: 'WARN',
        eventType: 'log_file_failure',
        data: {
          reason: err.message || 'Unknown file write error',
          logFilePath,
          fallback: 'stdout',
        },
      };
      process.stdout.write(JSON.stringify(diagnosticEvent) + '\n');
    }
  }

  /**
   * Core log method. Writes a structured NDJSON event.
   * @param {string} level - DEBUG, INFO, WARN, ERROR
   * @param {string} eventType - Event type identifier
   * @param {Object} data - Event-specific payload
   */
  function log(level, eventType, data = {}) {
    const levelValue = LOG_LEVELS[level];
    if (levelValue === undefined || levelValue < minLevelValue) return;

    const sanitizedData = redactSensitive(data);

    const event = {
      timestamp: new Date().toISOString(),
      level,
      eventType,
      ...sanitizedData,
    };

    // Store in recent events ring buffer
    recentEvents.push(event);
    if (recentEvents.length > recentEventsLimit) {
      recentEvents.shift();
    }

    // Serialize atomically (single JSON.stringify call)
    const line = JSON.stringify(event);

    // Write via queue for atomicity (Req 13.8)
    writeQueue.enqueue(
      line,
      fileAvailable ? logFilePath : null,
      handleFileError
    );
  }

  /**
   * Log a blocked attack event. (Req 13.1)
   * Logged at WARN level.
   * @param {Object} data - { sourceIP, agentTarget, attackCategory, matchedPattern, action, inputPreview? }
   */
  function logBlockedAttack(data = {}) {
    log('WARN', 'blocked_attack', data);
  }

  /**
   * Log a tool invocation event. (Req 13.2)
   * Logged at INFO level.
   * @param {Object} data - { agentId, toolName, parameters, resultStatus }
   */
  function logToolInvocation(data = {}) {
    log('INFO', 'tool_invocation', data);
  }

  /**
   * Log an authentication event. (Req 13.3)
   * Logged at ERROR for failures, INFO for successes.
   * @param {Object} data - { claimedIdentity, verificationMethod, outcome }
   */
  function logAuthEvent(data = {}) {
    const level = data.outcome && data.outcome !== 'verified' ? 'ERROR' : 'INFO';
    log(level, 'auth_event', data);
  }

  /**
   * Flush any pending writes. Returns a resolved promise since writes are synchronous.
   * @returns {Promise<void>}
   */
  async function flush() {
    await writeQueue.flush();
  }

  /**
   * Get recent events from the in-memory buffer.
   * @param {number} [limit=100] - Max number of events to return
   * @returns {Object[]}
   */
  function getRecentEvents(limit = 100) {
    const start = Math.max(0, recentEvents.length - limit);
    return recentEvents.slice(start);
  }

  return {
    log,
    logBlockedAttack,
    logToolInvocation,
    logAuthEvent,
    flush,
    getRecentEvents,
  };
}
