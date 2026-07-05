/**
 * Memory Sanitizer - Memory Injection Defense with Per-User Isolation
 *
 * Validates, sanitizes, and enforces access control on entries written to
 * or read from persistent agent memory. Prevents instruction injection,
 * credential storage, and cross-user data leakage.
 *
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8
 */

import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

/** Maximum content length per entry (characters) */
const MAX_CONTENT_LENGTH = 500;

/** Maximum entries per user before FIFO eviction */
const MAX_ENTRIES_PER_USER = 50;

/**
 * Creates a MemorySanitizer instance that loads patterns from a JSON file.
 *
 * @param {string} patternsPath - Path to the memory-patterns JSON configuration file
 * @returns {MemorySanitizer}
 */
export function createMemorySanitizer(patternsPath) {
  let instructionPatterns = [];
  let credentialPatterns = [];
  let compiledInstructionPatterns = [];
  let compiledCredentialPatterns = [];

  /** In-memory store: Map<userId, MemoryEntry[]> */
  const store = new Map();

  /**
   * Load and compile patterns from the JSON file.
   */
  function loadPatterns() {
    const raw = readFileSync(patternsPath, 'utf-8');
    const config = JSON.parse(raw);

    instructionPatterns = config.instructionPatterns || [];
    credentialPatterns = config.credentialPatterns || [];

    compiledInstructionPatterns = instructionPatterns.map(entry => ({
      regex: new RegExp(entry.pattern, entry.flags || ''),
      category: entry.category,
    }));

    compiledCredentialPatterns = credentialPatterns.map(entry => ({
      regex: new RegExp(entry.pattern, entry.flags || ''),
      category: entry.category,
    }));
  }

  // Initial load
  loadPatterns();

  /**
   * Validates that a user identifier is present and non-empty.
   *
   * @param {*} userId
   * @returns {{ valid: boolean, error?: string }}
   */
  function validateUserId(userId) {
    if (
      userId === null ||
      userId === undefined ||
      (typeof userId === 'string' && userId.trim() === '') ||
      (typeof userId !== 'string' && typeof userId !== 'number')
    ) {
      return { valid: false, error: 'Authentication required: valid user identifier missing' };
    }
    return { valid: true };
  }

  /**
   * Write a memory entry for the given user.
   * Rejects instruction-like patterns, credential patterns, oversized content,
   * and unauthenticated requests.
   *
   * @param {string} userId - Authenticated user identifier
   * @param {string} content - Content to store
   * @returns {MemoryWriteResult}
   */
  function write(userId, content) {
    // Req 4.7: Reject requests lacking valid authenticated user identifier
    const userValidation = validateUserId(userId);
    if (!userValidation.valid) {
      return { accepted: false, error: userValidation.error };
    }

    // Validate content is a string
    if (typeof content !== 'string') {
      return { accepted: false, error: 'Content must be a string' };
    }

    // Req 4.4: Reject writes exceeding 500 characters
    if (content.length > MAX_CONTENT_LENGTH) {
      return {
        accepted: false,
        error: `Maximum entry size exceeded: ${content.length} characters (limit: ${MAX_CONTENT_LENGTH})`,
      };
    }

    // Req 4.1: Reject instruction-like patterns within 50ms
    for (const { regex, category } of compiledInstructionPatterns) {
      regex.lastIndex = 0;
      if (regex.test(content)) {
        return {
          accepted: false,
          error: `Policy violation: content contains disallowed instruction pattern (${category})`,
        };
      }
    }

    // Req 4.6: Reject credential patterns
    for (const { regex, category } of compiledCredentialPatterns) {
      regex.lastIndex = 0;
      if (regex.test(content)) {
        return {
          accepted: false,
          error: `Policy violation: content contains credential material (${category})`,
        };
      }
    }

    // Req 4.2: Tag entry with user ID and UTC ISO 8601 timestamp (ms precision)
    const entry = {
      id: randomUUID(),
      userId: String(userId),
      content,
      createdAt: new Date().toISOString(),
    };

    // Get or create user's entry list
    if (!store.has(String(userId))) {
      store.set(String(userId), []);
    }
    const userEntries = store.get(String(userId));

    // Req 4.5: FIFO eviction at 50 entries per user
    if (userEntries.length >= MAX_ENTRIES_PER_USER) {
      userEntries.shift(); // Remove the oldest entry
    }

    userEntries.push(entry);

    return { accepted: true, entry };
  }

  /**
   * Read memory entries for the given user.
   * Returns only entries tagged with the requesting user's ID.
   *
   * @param {string} userId - Authenticated user identifier
   * @returns {MemoryEntry[]}
   */
  function read(userId) {
    // Req 4.7: Reject requests lacking valid authenticated user identifier
    const userValidation = validateUserId(userId);
    if (!userValidation.valid) {
      return [];
    }

    // Req 4.3: Return only entries matching requesting user's ID
    const userEntries = store.get(String(userId));
    if (!userEntries || userEntries.length === 0) {
      return [];
    }

    return [...userEntries];
  }

  /**
   * Get statistics for a user's memory store.
   *
   * @param {string} userId - Authenticated user identifier
   * @returns {{ entryCount: number, oldestTimestamp: string }}
   */
  function getStats(userId) {
    const userValidation = validateUserId(userId);
    if (!userValidation.valid) {
      return { entryCount: 0, oldestTimestamp: '' };
    }

    const userEntries = store.get(String(userId));
    if (!userEntries || userEntries.length === 0) {
      return { entryCount: 0, oldestTimestamp: '' };
    }

    return {
      entryCount: userEntries.length,
      oldestTimestamp: userEntries[0].createdAt,
    };
  }

  /**
   * Hot-reload patterns from the JSON file.
   * Allows updating patterns without restarting the application.
   */
  function reload() {
    loadPatterns();
  }

  return {
    write,
    read,
    getStats,
    reload,
  };
}
