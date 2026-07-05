/**
 * Context Protector - Context Window Overflow Defense
 *
 * Manages token budget allocation to ensure safety instructions are never
 * displaced from the context window. Implements sandwich defense placement,
 * oldest-first truncation, message length limits, echo/reproduce detection,
 * and capacity warnings.
 *
 * Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7
 */

import { createAuditLogger } from './audit-logger.js';

/** Default configuration values */
const DEFAULTS = {
  minSafetyBudget: 500,
  maxMessageLength: 2000,
};

/** Valid configuration ranges */
const RANGES = {
  minSafetyBudget: { min: 100, max: 2000 },
  maxMessageLength: { min: 100, max: 10000 },
};

/** Token threshold for echo/reproduce detection */
const ECHO_TOKEN_THRESHOLD = 500;

/** Capacity warning threshold (80%) */
const CAPACITY_WARNING_THRESHOLD = 0.8;

/**
 * Patterns that indicate a request to reproduce/echo content.
 * These detect attempts to trick the model into outputting large
 * amounts of prior content, which can displace safety instructions.
 */
const ECHO_PATTERNS = [
  /\b(?:repeat|reproduce|echo|reprint|copy|output|print|show)\b.*\b(?:above|previous|prior|entire|all|everything|full|complete|whole)\b/i,
  /\b(?:above|previous|prior|entire|all|everything|full|complete|whole)\b.*\b(?:repeat|reproduce|echo|reprint|copy|output|print|show)\b/i,
  /\b(?:write out|type out|give me|send me|paste)\b.*\b(?:everything|all|entire|whole|full)\b/i,
  /\b(?:recite|reiterate|restate)\b.*\b(?:conversation|history|messages|chat|context)\b/i,
];

/**
 * Estimate the number of tokens in a text string.
 * Uses a simple heuristic: approximately 4 characters per token,
 * with a minimum of 1 token for non-empty strings.
 *
 * @param {string} text - The text to estimate tokens for
 * @returns {number} Estimated token count
 */
function estimateTokens(text) {
  if (!text || typeof text !== 'string') {
    return 0;
  }
  // Simple heuristic: ~4 characters per token
  return Math.max(1, Math.ceil(text.length / 4));
}

/**
 * Validate a config value against its valid range.
 * Returns the value if valid, or the default if out of range.
 *
 * @param {*} value - The configuration value to validate
 * @param {string} key - The config key name
 * @returns {number} Validated value or default
 */
function validateConfigValue(value, key) {
  const range = RANGES[key];
  const defaultVal = DEFAULTS[key];

  if (value === undefined || value === null) {
    return defaultVal;
  }

  const numVal = Number(value);
  if (isNaN(numVal) || numVal < range.min || numVal > range.max) {
    return defaultVal;
  }

  return numVal;
}

/**
 * Detect if a message is requesting to reproduce/echo content
 * that would exceed the token threshold.
 *
 * @param {string} message - The user message to check
 * @param {number} conversationTokens - Total tokens in conversation history
 * @returns {boolean} True if echo attempt detected
 */
function detectEchoRequest(message, conversationTokens) {
  if (!message || typeof message !== 'string') {
    return false;
  }

  // Check if the message matches echo patterns
  const matchesPattern = ECHO_PATTERNS.some(pattern => pattern.test(message));
  if (!matchesPattern) {
    return false;
  }

  // If the conversation history is estimated at 500+ tokens, this is suspicious
  return conversationTokens >= ECHO_TOKEN_THRESHOLD;
}

/**
 * Creates a ContextProtector instance with configurable token budgets.
 *
 * @param {Object} config - Configuration options
 * @param {number} [config.minSafetyBudget=500] - Minimum tokens reserved for safety (100-2000)
 * @param {number} [config.maxMessageLength=2000] - Maximum tokens per message (100-10000)
 * @returns {ContextProtector}
 */
export function createContextProtector(config = {}) {
  const logger = createAuditLogger({ minLevel: 'DEBUG' });

  // Req 9.7: Validate config ranges, fall back to defaults if invalid
  const minSafetyBudget = validateConfigValue(config.minSafetyBudget, 'minSafetyBudget');
  const maxMessageLength = validateConfigValue(config.maxMessageLength, 'maxMessageLength');

  /**
   * Assemble the prompt with safety sandwich defense and token budget management.
   *
   * @param {string} safetyInstructions - System safety instructions text
   * @param {string[]} conversationHistory - Array of previous messages
   * @param {string} newMessage - The new user message to process
   * @param {number} modelContextSize - Total model context window in tokens (default 4096)
   * @returns {ContextProtectionResult}
   */
  function assemblePrompt(safetyInstructions, conversationHistory, newMessage, modelContextSize = 4096) {
    // Validate inputs
    if (!safetyInstructions || typeof safetyInstructions !== 'string') {
      safetyInstructions = '';
    }
    if (!Array.isArray(conversationHistory)) {
      conversationHistory = [];
    }
    if (!newMessage || typeof newMessage !== 'string') {
      newMessage = '';
    }

    const safetyTokens = estimateTokens(safetyInstructions);
    const newMessageTokens = estimateTokens(newMessage);

    // Req 9.4: Reject messages exceeding max length
    if (newMessageTokens > maxMessageLength) {
      return {
        allowed: false,
        error: `Message exceeds maximum length of ${maxMessageLength} tokens (estimated: ${newMessageTokens} tokens). Please shorten your message.`,
      };
    }

    // Req 9.5: Detect and refuse echo/reproduce requests
    const conversationTokens = conversationHistory.reduce(
      (sum, msg) => sum + estimateTokens(msg),
      0
    );

    if (detectEchoRequest(newMessage, conversationTokens)) {
      logger.log('WARN', 'context-overflow-attempt', {
        attackCategory: 'context_overflow',
        action: 'blocked',
        reason: 'echo_reproduce_request',
        estimatedTokens: conversationTokens,
      });

      return {
        allowed: false,
        error: 'Request to reproduce large amounts of prior content has been denied to protect context integrity.',
      };
    }

    // Req 9.1: Reserve budget for safety instructions (sandwich = 2x safety)
    const sandwichSafetyTokens = safetyTokens * 2;
    const reservedBudget = Math.max(sandwichSafetyTokens, minSafetyBudget);

    // Calculate available budget for user content
    const availableBudget = modelContextSize - reservedBudget;

    if (availableBudget <= 0) {
      return {
        allowed: false,
        error: 'Context window is too small to accommodate safety instructions and user content.',
      };
    }

    // Req 9.3: Truncate oldest messages first, preserving most recent + safety
    let includedHistory = [...conversationHistory];
    let historyTokens = includedHistory.reduce((sum, msg) => sum + estimateTokens(msg), 0);
    const totalUserTokens = historyTokens + newMessageTokens;

    // If total user content exceeds available budget, truncate oldest messages
    if (totalUserTokens > availableBudget) {
      // Always preserve the new message
      let remainingBudget = availableBudget - newMessageTokens;

      if (remainingBudget < 0) {
        // Even the new message alone exceeds budget — still allow it but truncate history entirely
        includedHistory = [];
      } else {
        // Remove oldest messages until we fit within budget
        const keptMessages = [];
        // Iterate from newest to oldest (reverse), keeping as many as fit
        for (let i = includedHistory.length - 1; i >= 0; i--) {
          const msgTokens = estimateTokens(includedHistory[i]);
          if (msgTokens <= remainingBudget) {
            keptMessages.unshift(includedHistory[i]);
            remainingBudget -= msgTokens;
          } else {
            // Once we can't fit a message, stop (oldest messages dropped)
            break;
          }
        }
        includedHistory = keptMessages;
      }
    }

    // Req 9.2: Sandwich defense - safety at beginning AND end
    const messages = [
      safetyInstructions,
      ...includedHistory,
      newMessage,
      safetyInstructions,
    ];

    // Req 9.6: Calculate cumulative usage and check 80% threshold
    const actualHistoryTokens = includedHistory.reduce((sum, msg) => sum + estimateTokens(msg), 0);
    const totalUsed = sandwichSafetyTokens + actualHistoryTokens + newMessageTokens;
    const usageRatio = totalUsed / modelContextSize;
    const capacityWarning = usageRatio >= CAPACITY_WARNING_THRESHOLD;

    const result = {
      allowed: true,
      messages,
    };

    if (capacityWarning) {
      result.capacityWarning = true;
    }

    return result;
  }

  return {
    assemblePrompt,
    estimateTokens,
  };
}
