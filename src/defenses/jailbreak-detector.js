/**
 * Jailbreak Detector - Multi-pattern jailbreak detection with session tracking
 *
 * Detects DAN mode, roleplay bypass, hypothetical framing, and multi-turn
 * erosion attacks. Tracks per-session attempt counters, escalates to heightened
 * alert state, and responds with standardized refusals.
 *
 * Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8
 */

import { readFileSync } from 'node:fs';
import { createAuditLogger } from './audit-logger.js';

/** Default confidence threshold for triggering a jailbreak detection */
const DEFAULT_CONFIDENCE_THRESHOLD = 0.8;

/** Stricter threshold applied in heightened alert state */
const HEIGHTENED_CONFIDENCE_THRESHOLD = 0.5;

/** Number of attempts in sliding window to trigger heightened state */
const ESCALATION_ATTEMPT_COUNT = 3;

/** Sliding window size (messages) for escalation tracking */
const ESCALATION_WINDOW_SIZE = 10;

/** Multi-turn erosion: boundary-testing inputs needed in window */
const EROSION_COUNT_THRESHOLD = 5;

/** Multi-turn erosion: sliding window of messages to track */
const EROSION_WINDOW_SIZE = 15;

/** Confidence range for boundary-testing (multi-turn erosion) */
const EROSION_CONFIDENCE_LOW = 0.4;
const EROSION_CONFIDENCE_HIGH = 0.7;

/** Clean messages needed to downgrade from heightened state */
const DOWNGRADE_CLEAN_COUNT = 20;

/** Standardized refusal message (Req 20.4: no detection logic, no echo) */
const STANDARD_REFUSAL = {
  status: 'blocked',
  category: 'jailbreak_attempt',
  message: 'I\'m unable to process this request. Please rephrase your message within acceptable use guidelines.',
};

/**
 * @typedef {Object} JailbreakCheckResult
 * @property {boolean} pass - Whether the input is allowed through
 * @property {boolean} [detected] - Whether a jailbreak was detected
 * @property {number} [confidence] - Highest confidence score of matched patterns
 * @property {string[]} [categories] - Matched pattern categories
 * @property {Object} [refusal] - Standardized refusal response (if blocked)
 * @property {boolean} [heightened] - Whether session is in heightened alert state
 * @property {boolean} [erosionAlert] - Whether a multi-turn erosion alert was raised
 * @property {number} [attemptCounter] - Current session attempt counter
 */

/**
 * Creates a JailbreakDetector instance.
 *
 * @param {Object} options
 * @param {string} [options.patternsPath] - Path to jailbreak-patterns.json config file
 * @param {Object} [options.auditLogger] - AuditLogger instance for event logging
 * @returns {JailbreakDetector}
 */
export function createJailbreakDetector(options = {}) {
  const {
    patternsPath = null,
    auditLogger = null,
  } = options;

  const logger = auditLogger || createAuditLogger({ minLevel: 'DEBUG' });

  let patterns = [];
  let compiledPatterns = [];

  /**
   * Load and compile patterns from the JSON config file.
   */
  function loadPatterns() {
    if (!patternsPath) return;
    try {
      const raw = readFileSync(patternsPath, 'utf-8');
      const config = JSON.parse(raw);
      patterns = config.patterns || [];
      compiledPatterns = patterns.map(entry => ({
        regex: new RegExp(entry.pattern, entry.flags || 'i'),
        weight: typeof entry.weight === 'number' ? entry.weight : 0.5,
        category: entry.category || 'unknown',
      }));
    } catch {
      // Fall back to empty patterns on load failure
      patterns = [];
      compiledPatterns = [];
    }
  }

  // Initial pattern load
  loadPatterns();

  /**
   * Per-session state tracking.
   * Map<sessionId, SessionState>
   */
  const sessions = new Map();

  /**
   * @typedef {Object} SessionState
   * @property {number} attemptCounter - Total jailbreak attempts
   * @property {boolean} heightened - Whether in heightened alert state
   * @property {number} cleanCount - Consecutive clean messages since last detection
   * @property {Array<{index: number, detected: boolean}>} recentMessages - Sliding window for escalation
   * @property {Array<{index: number, confidence: number}>} erosionWindow - Sliding window for erosion detection
   * @property {number} messageIndex - Total messages processed
   */

  /**
   * Get or create session state.
   * @param {string} sessionId
   * @returns {SessionState}
   */
  function getSession(sessionId) {
    if (!sessions.has(sessionId)) {
      sessions.set(sessionId, {
        attemptCounter: 0,
        heightened: false,
        cleanCount: 0,
        recentMessages: [],
        erosionWindow: [],
        messageIndex: 0,
      });
    }
    return sessions.get(sessionId);
  }

  /**
   * Analyze input against all jailbreak patterns.
   * Returns matched patterns sorted by confidence.
   *
   * @param {string} input - User input text
   * @param {boolean} heightened - Whether session is in heightened state
   * @returns {{ confidence: number, categories: string[], matches: Array }}
   */
  function analyzePatterns(input, heightened) {
    const threshold = heightened ? HEIGHTENED_CONFIDENCE_THRESHOLD : DEFAULT_CONFIDENCE_THRESHOLD;
    const matches = [];
    let maxConfidence = 0;
    const categories = new Set();

    for (const { regex, weight, category } of compiledPatterns) {
      regex.lastIndex = 0;
      if (regex.test(input)) {
        matches.push({ weight, category });
        categories.add(category);
        if (weight > maxConfidence) {
          maxConfidence = weight;
        }
      }
    }

    // Aggregate confidence: use max weight plus a small boost for multiple matches
    let confidence = maxConfidence;
    if (matches.length > 1) {
      const boost = Math.min(0.1, (matches.length - 1) * 0.03);
      confidence = Math.min(1.0, confidence + boost);
    }

    return {
      confidence,
      categories: [...categories],
      matches,
      isAboveThreshold: confidence >= threshold,
      isBoundaryTesting: confidence >= EROSION_CONFIDENCE_LOW && confidence <= EROSION_CONFIDENCE_HIGH,
    };
  }

  /**
   * Check user input for jailbreak patterns.
   *
   * @param {string} input - User input text
   * @param {Object} context - Request context
   * @param {string} context.sessionId - Session identifier (required)
   * @param {string} [context.sourceIP] - Source IP address
   * @param {string} [context.agentId] - Target agent identifier
   * @returns {JailbreakCheckResult}
   */
  function check(input, context = {}) {
    const { sessionId = 'default', sourceIP, agentId } = context;

    if (typeof input !== 'string' || input.length === 0) {
      return { pass: true, detected: false };
    }

    const session = getSession(sessionId);
    session.messageIndex++;

    const analysis = analyzePatterns(input, session.heightened);

    // Track in escalation window (last ESCALATION_WINDOW_SIZE messages)
    session.recentMessages.push({
      index: session.messageIndex,
      detected: analysis.isAboveThreshold,
    });
    if (session.recentMessages.length > ESCALATION_WINDOW_SIZE) {
      session.recentMessages.shift();
    }

    // Track in erosion window (last EROSION_WINDOW_SIZE messages)
    session.erosionWindow.push({
      index: session.messageIndex,
      confidence: analysis.confidence,
      isBoundaryTesting: analysis.isBoundaryTesting,
    });
    if (session.erosionWindow.length > EROSION_WINDOW_SIZE) {
      session.erosionWindow.shift();
    }

    // Check if jailbreak detected (above threshold)
    if (analysis.isAboveThreshold) {
      // Req 20.1: Increment per-session jailbreak attempt counter
      session.attemptCounter++;
      session.cleanCount = 0;

      // Req 20.2: Check escalation (3 attempts in 10-message window)
      const attemptsInWindow = session.recentMessages.filter(m => m.detected).length;
      if (attemptsInWindow >= ESCALATION_ATTEMPT_COUNT && !session.heightened) {
        session.heightened = true;
      }

      // Req 20.6: Log events above 0.8 confidence
      if (analysis.confidence >= 0.8) {
        logger.log('WARN', 'jailbreak_detected', {
          sessionId,
          sourceIP: sourceIP || 'unknown',
          agentTarget: agentId || 'unknown',
          categories: analysis.categories,
          confidence: analysis.confidence,
          attemptCounter: session.attemptCounter,
          heightened: session.heightened,
        });
      }

      // Req 20.4: Return standardized refusal
      return {
        pass: false,
        detected: true,
        confidence: analysis.confidence,
        categories: analysis.categories,
        refusal: { ...STANDARD_REFUSAL },
        heightened: session.heightened,
        erosionAlert: false,
        attemptCounter: session.attemptCounter,
      };
    }

    // Req 20.3: Detect multi-turn erosion
    const boundaryTestingCount = session.erosionWindow.filter(m => m.isBoundaryTesting).length;
    let erosionAlert = false;

    if (boundaryTestingCount >= EROSION_COUNT_THRESHOLD) {
      erosionAlert = true;
      session.attemptCounter++;
      session.cleanCount = 0;

      // Escalate on erosion as well
      if (!session.heightened) {
        const attemptsInWindow = session.recentMessages.filter(m => m.detected).length;
        if (attemptsInWindow + 1 >= ESCALATION_ATTEMPT_COUNT) {
          session.heightened = true;
        }
      }

      // Log the erosion event
      logger.log('WARN', 'multi_turn_erosion_detected', {
        sessionId,
        sourceIP: sourceIP || 'unknown',
        agentTarget: agentId || 'unknown',
        boundaryTestingCount,
        windowSize: session.erosionWindow.length,
        attemptCounter: session.attemptCounter,
        heightened: session.heightened,
      });

      // Return refusal for erosion attack
      return {
        pass: false,
        detected: true,
        confidence: analysis.confidence,
        categories: ['multi_turn_erosion'],
        refusal: { ...STANDARD_REFUSAL },
        heightened: session.heightened,
        erosionAlert: true,
        attemptCounter: session.attemptCounter,
      };
    }

    // Input is clean — track for heightened state downgrade
    if (analysis.confidence < EROSION_CONFIDENCE_LOW) {
      session.cleanCount++;
    } else {
      // Partial match but not above threshold; don't reset clean count for boundary-testing
      // but also don't increment it
    }

    // Req 20.7: Downgrade from heightened state after 20 clean consecutive messages
    if (session.heightened && session.cleanCount >= DOWNGRADE_CLEAN_COUNT) {
      session.heightened = false;
      session.attemptCounter = 0;
      session.cleanCount = 0;
      // Clear erosion window on downgrade
      session.erosionWindow = [];
    }

    return {
      pass: true,
      detected: false,
      confidence: analysis.confidence,
      categories: analysis.categories.length > 0 ? analysis.categories : undefined,
      heightened: session.heightened,
      erosionAlert: false,
      attemptCounter: session.attemptCounter,
    };
  }

  /**
   * Get the current state of a session.
   *
   * @param {string} sessionId
   * @returns {Object} Session state summary
   */
  function getSessionState(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) {
      return { exists: false };
    }
    return {
      exists: true,
      attemptCounter: session.attemptCounter,
      heightened: session.heightened,
      cleanCount: session.cleanCount,
      messageIndex: session.messageIndex,
    };
  }

  /**
   * Reset a session's state (e.g., on session termination).
   *
   * @param {string} sessionId
   */
  function resetSession(sessionId) {
    sessions.delete(sessionId);
  }

  /**
   * Hot-reload patterns from the JSON configuration file.
   */
  function reload() {
    loadPatterns();
  }

  return {
    check,
    getSessionState,
    resetSession,
    reload,
  };
}
