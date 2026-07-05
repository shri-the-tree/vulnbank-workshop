/**
 * Session Isolator - Cryptographic Session Management and Cross-Session Isolation
 *
 * Enforces strict per-session data boundaries, preventing memory, context, and
 * state from leaking between user sessions or agent instances. Assigns UUID v4
 * session IDs with 128-bit entropy, isolates conversation history and memory
 * entries, and enforces configurable inactivity timeouts with full state purge.
 *
 * Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6, 22.7, 22.8
 */

import { randomUUID } from 'node:crypto';

/** Default inactivity timeout in milliseconds (30 minutes) */
const DEFAULT_INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000;

/**
 * Creates a SessionIsolator instance.
 *
 * @param {Object} [options] - Configuration options
 * @param {number} [options.inactivityTimeoutMs=1800000] - Inactivity timeout in ms (default: 30 min)
 * @param {Object} [options.logger] - AuditLogger instance for logging session events
 * @returns {SessionIsolator}
 */
export function createSessionIsolator(options = {}) {
  const {
    inactivityTimeoutMs = DEFAULT_INACTIVITY_TIMEOUT_MS,
    logger = null,
  } = options;

  /**
   * Session store: Map<sessionId, SessionState>
   *
   * SessionState: {
   *   sessionId: string,
   *   userId: string,
   *   createdAt: number (timestamp ms),
   *   lastActivity: number (timestamp ms),
   *   messages: Array<{ sessionId, userId, role, content, timestamp }>,
   *   memory: Array<{ sessionId, userId, key, value, timestamp }>,
   *   securityEvents: Array<{ type, timestamp, details }>,
   *   messageCount: number,
   *   config: Object (isolated copy),
   *   toolRegistry: Object (isolated copy),
   * }
   */
  const sessions = new Map();

  /**
   * Log a session event via the audit logger.
   * @param {string} eventType
   * @param {Object} data
   */
  function logEvent(eventType, data) {
    if (logger && typeof logger.log === 'function') {
      logger.log('INFO', eventType, data);
    }
  }

  /**
   * Log a security violation event.
   * @param {string} eventType
   * @param {Object} data
   */
  function logSecurityEvent(eventType, data) {
    if (logger && typeof logger.log === 'function') {
      logger.log('WARN', eventType, data);
    }
  }

  /**
   * Check if a session has expired due to inactivity.
   * @param {Object} session - SessionState
   * @returns {boolean}
   */
  function isExpired(session) {
    const now = Date.now();
    return (now - session.lastActivity) > inactivityTimeoutMs;
  }

  /**
   * Purge all in-memory state for a session and log termination.
   * Req 22.5: Full state purge on expiration.
   * Req 22.7: Log termination with duration, message count, security events.
   *
   * @param {string} sessionId
   * @param {string} reason - 'expired' | 'logout' | 'forced'
   */
  function purgeSession(sessionId, reason = 'expired') {
    const session = sessions.get(sessionId);
    if (!session) return;

    const duration = Date.now() - session.createdAt;
    const messageCount = session.messageCount;
    const securityEventCount = session.securityEvents.length;

    // Log session termination (Req 22.7)
    logEvent('session_terminated', {
      sessionId,
      userId: session.userId,
      reason,
      durationMs: duration,
      messageCount,
      securityEventCount,
      securityEvents: session.securityEvents,
    });

    // Full state purge (Req 22.5)
    sessions.delete(sessionId);
  }

  /**
   * Run expiration checks against all sessions.
   * Called lazily on operations to avoid timer dependencies.
   */
  function cleanupExpiredSessions() {
    for (const [sessionId, session] of sessions) {
      if (isExpired(session)) {
        purgeSession(sessionId, 'expired');
      }
    }
  }

  /**
   * Create a new session for a user. Assigns a UUID v4 session ID (128-bit entropy).
   * Req 22.1: Cryptographically random session ID, minimum 128-bit entropy, UUID v4.
   *
   * @param {string} userId - Authenticated user identifier
   * @param {Object} [baseConfig={}] - Base config to create an isolated copy from
   * @param {Object} [baseToolRegistry={}] - Base tool registry to create an isolated copy from
   * @returns {{ sessionId: string, createdAt: string }}
   */
  function createSession(userId, baseConfig = {}, baseToolRegistry = {}) {
    if (!userId || typeof userId !== 'string' || userId.trim() === '') {
      return { error: 'Authentication required: valid user identifier missing' };
    }

    // Cleanup expired sessions lazily
    cleanupExpiredSessions();

    // Req 22.1: UUID v4 (128-bit entropy) session ID
    const sessionId = randomUUID();
    const now = Date.now();

    // Req 22.6: Isolated config and tool registry copies (deep clone, no shared mutable state)
    const isolatedConfig = JSON.parse(JSON.stringify(baseConfig));
    const isolatedToolRegistry = JSON.parse(JSON.stringify(baseToolRegistry));

    const sessionState = {
      sessionId,
      userId: userId.trim(),
      createdAt: now,
      lastActivity: now,
      messages: [],
      memory: [],
      securityEvents: [],
      messageCount: 0,
      config: Object.freeze(isolatedConfig),
      toolRegistry: Object.freeze(isolatedToolRegistry),
    };

    sessions.set(sessionId, sessionState);

    logEvent('session_created', {
      sessionId,
      userId: userId.trim(),
      createdAt: new Date(now).toISOString(),
    });

    return {
      sessionId,
      createdAt: new Date(now).toISOString(),
    };
  }

  /**
   * Validate a session ID: exists, not expired, and belongs to the given user.
   * Req 22.4: Reject invalid/expired session IDs (require re-auth).
   *
   * @param {string} sessionId
   * @param {string} userId
   * @returns {{ valid: boolean, error?: string, session?: Object }}
   */
  function validateSession(sessionId, userId) {
    if (!sessionId || typeof sessionId !== 'string') {
      return { valid: false, error: 'Invalid session: session identifier required' };
    }

    if (!userId || typeof userId !== 'string' || userId.trim() === '') {
      return { valid: false, error: 'Authentication required: valid user identifier missing' };
    }

    const session = sessions.get(sessionId);

    if (!session) {
      return { valid: false, error: 'Invalid session: session not found, re-authentication required' };
    }

    // Req 22.5: Check inactivity timeout
    if (isExpired(session)) {
      purgeSession(sessionId, 'expired');
      return { valid: false, error: 'Session expired: re-authentication required' };
    }

    // Verify user ownership
    if (session.userId !== userId.trim()) {
      // Req 22.8: Cross-session access violation
      const violation = {
        type: 'cross_session_user_mismatch',
        timestamp: new Date().toISOString(),
        details: { sessionId, requestingUserId: userId.trim(), sessionOwner: session.userId },
      };
      session.securityEvents.push(violation);

      logSecurityEvent('cross_session_access_violation', {
        sessionId,
        requestingUserId: userId.trim(),
        sessionOwner: session.userId,
        reason: 'user_mismatch',
      });

      return { valid: false, error: 'Access denied: session does not belong to requesting user' };
    }

    // Update last activity timestamp
    session.lastActivity = Date.now();

    return { valid: true, session };
  }

  /**
   * Add a message to conversation history for a session.
   * Req 22.2: Tag messages with session ID; only same-session messages returned.
   *
   * @param {string} sessionId
   * @param {string} userId
   * @param {string} role - 'user' | 'assistant' | 'system'
   * @param {string} content - Message content
   * @returns {{ success: boolean, error?: string }}
   */
  function addMessage(sessionId, userId, role, content) {
    const validation = validateSession(sessionId, userId);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    const { session } = validation;

    const message = {
      sessionId,
      userId: userId.trim(),
      role,
      content,
      timestamp: new Date().toISOString(),
    };

    session.messages.push(message);
    session.messageCount++;

    return { success: true };
  }

  /**
   * Get conversation history filtered by session ID.
   * Req 22.2: Return only messages matching the requesting session ID.
   *
   * @param {string} sessionId
   * @param {string} userId
   * @returns {{ messages: Array, error?: string }}
   */
  function getConversationHistory(sessionId, userId) {
    const validation = validateSession(sessionId, userId);
    if (!validation.valid) {
      return { messages: [], error: validation.error };
    }

    const { session } = validation;

    // Return only messages matching this session ID (Req 22.2)
    const filtered = session.messages.filter(m => m.sessionId === sessionId);
    return { messages: filtered };
  }

  /**
   * Write a memory entry tagged with session ID and user ID.
   * Req 22.3: Tag memory entries with session ID + user ID.
   *
   * @param {string} sessionId
   * @param {string} userId
   * @param {string} key - Memory entry key
   * @param {*} value - Memory entry value
   * @returns {{ success: boolean, error?: string }}
   */
  function writeMemory(sessionId, userId, key, value) {
    const validation = validateSession(sessionId, userId);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    const { session } = validation;

    const entry = {
      sessionId,
      userId: userId.trim(),
      key,
      value,
      timestamp: new Date().toISOString(),
    };

    session.memory.push(entry);

    return { success: true };
  }

  /**
   * Read memory entries matching both session ID and user ID.
   * Req 22.3: Enforce both session ID and user ID on read.
   * Req 22.8: Reject cross-session access attempts.
   *
   * @param {string} sessionId
   * @param {string} userId
   * @param {string} [targetSessionId] - If provided and differs from sessionId, reject as cross-session
   * @returns {{ entries: Array, error?: string }}
   */
  function readMemory(sessionId, userId, targetSessionId = null) {
    // Req 22.8: Reject cross-session access attempts
    if (targetSessionId && targetSessionId !== sessionId) {
      const session = sessions.get(sessionId);
      if (session) {
        const violation = {
          type: 'cross_session_memory_access',
          timestamp: new Date().toISOString(),
          details: { requestingSessionId: sessionId, targetSessionId },
        };
        session.securityEvents.push(violation);
      }

      logSecurityEvent('cross_session_access_violation', {
        requestingSessionId: sessionId,
        targetSessionId,
        userId,
        reason: 'cross_session_memory_read',
      });

      return { entries: [], error: 'Access denied: cross-session data access is not permitted' };
    }

    const validation = validateSession(sessionId, userId);
    if (!validation.valid) {
      return { entries: [], error: validation.error };
    }

    const { session } = validation;

    // Req 22.3: Return only entries matching both session ID and user ID
    const filtered = session.memory.filter(
      e => e.sessionId === sessionId && e.userId === userId.trim()
    );

    return { entries: filtered };
  }

  /**
   * Get isolated config copy for a session's agent invocation.
   * Req 22.6: Provide isolated config copies per agent invocation (no shared mutable state).
   *
   * @param {string} sessionId
   * @param {string} userId
   * @returns {{ config: Object | null, error?: string }}
   */
  function getIsolatedConfig(sessionId, userId) {
    const validation = validateSession(sessionId, userId);
    if (!validation.valid) {
      return { config: null, error: validation.error };
    }

    const { session } = validation;

    // Return a deep copy so mutations don't affect stored state
    return { config: JSON.parse(JSON.stringify(session.config)) };
  }

  /**
   * Get isolated tool registry copy for a session's agent invocation.
   * Req 22.6: Provide isolated tool registry copies per agent invocation (no shared mutable state).
   *
   * @param {string} sessionId
   * @param {string} userId
   * @returns {{ toolRegistry: Object | null, error?: string }}
   */
  function getIsolatedToolRegistry(sessionId, userId) {
    const validation = validateSession(sessionId, userId);
    if (!validation.valid) {
      return { toolRegistry: null, error: validation.error };
    }

    const { session } = validation;

    // Return a deep copy so mutations don't affect stored state
    return { toolRegistry: JSON.parse(JSON.stringify(session.toolRegistry)) };
  }

  /**
   * Terminate a session explicitly (logout).
   * Req 22.7: Log termination with duration, message count, security events.
   *
   * @param {string} sessionId
   * @param {string} userId
   * @returns {{ success: boolean, error?: string }}
   */
  function terminateSession(sessionId, userId) {
    const session = sessions.get(sessionId);

    if (!session) {
      return { success: false, error: 'Invalid session: session not found' };
    }

    if (session.userId !== userId) {
      logSecurityEvent('cross_session_access_violation', {
        sessionId,
        requestingUserId: userId,
        sessionOwner: session.userId,
        reason: 'unauthorized_termination_attempt',
      });
      return { success: false, error: 'Access denied: cannot terminate another user\'s session' };
    }

    purgeSession(sessionId, 'logout');
    return { success: true };
  }

  /**
   * Record a security event for a session.
   *
   * @param {string} sessionId
   * @param {string} eventType
   * @param {Object} details
   */
  function recordSecurityEvent(sessionId, eventType, details = {}) {
    const session = sessions.get(sessionId);
    if (!session) return;

    session.securityEvents.push({
      type: eventType,
      timestamp: new Date().toISOString(),
      details,
    });
  }

  /**
   * Get session info (for diagnostics/testing).
   *
   * @param {string} sessionId
   * @param {string} userId
   * @returns {{ info: Object | null, error?: string }}
   */
  function getSessionInfo(sessionId, userId) {
    const validation = validateSession(sessionId, userId);
    if (!validation.valid) {
      return { info: null, error: validation.error };
    }

    const { session } = validation;

    return {
      info: {
        sessionId: session.sessionId,
        userId: session.userId,
        createdAt: new Date(session.createdAt).toISOString(),
        lastActivity: new Date(session.lastActivity).toISOString(),
        messageCount: session.messageCount,
        memoryEntryCount: session.memory.length,
        securityEventCount: session.securityEvents.length,
      },
    };
  }

  /**
   * Get active session count (for diagnostics).
   * @returns {number}
   */
  function getActiveSessionCount() {
    cleanupExpiredSessions();
    return sessions.size;
  }

  return {
    createSession,
    validateSession,
    addMessage,
    getConversationHistory,
    writeMemory,
    readMemory,
    getIsolatedConfig,
    getIsolatedToolRegistry,
    terminateSession,
    recordSecurityEvent,
    getSessionInfo,
    getActiveSessionCount,
  };
}
