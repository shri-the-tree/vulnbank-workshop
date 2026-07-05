/**
 * WebSocket Security Manager - Connection Security for Real-Time Agent Communication
 *
 * Enforces authentication, message validation, rate limiting, origin verification,
 * and idle timeout on WebSocket connections used for real-time agent communication.
 *
 * Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.7, 18.8
 */

import nacl from 'tweetnacl';
import { createAuditLogger } from './audit-logger.js';

/** Default message rate limit: 60 messages per 60 seconds */
const DEFAULT_RATE_LIMIT = 60;
const DEFAULT_RATE_WINDOW_SECONDS = 60;

/** Maximum message payload size: 64 KB */
const MAX_PAYLOAD_SIZE = 64 * 1024;

/** Idle timeout: 5 minutes (300 seconds) */
const DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000;

/** Pong timeout: 10 seconds */
const PONG_TIMEOUT_MS = 10 * 1000;

/** WebSocket close codes */
const CLOSE_CODES = {
  ORIGIN_NOT_PERMITTED: 4003,
  RATE_LIMIT_EXCEEDED: 4008,
  MESSAGE_TOO_LARGE: 4009,
};

/**
 * Base64URL decode to a Buffer.
 * @param {string} str
 * @returns {Buffer}
 */
function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Validate a JWT token using Ed25519 signature verification.
 *
 * @param {string} token - JWT token string (header.payload.signature)
 * @param {Object} keyRegistry - Maps agentId/userId → base64-encoded Ed25519 public key
 * @param {Object} options
 * @param {number} [options.ttlSeconds=60] - Token TTL in seconds
 * @returns {{ valid: boolean, error?: string, claims?: Object }}
 */
function validateJwt(token, keyRegistry, options = {}) {
  const { ttlSeconds = 60 } = options;

  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Missing authentication token' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'Malformed token: invalid structure' };
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Parse header
  let header;
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
  } catch {
    return { valid: false, error: 'Malformed token: invalid header' };
  }

  if (header.alg !== 'EdDSA' || header.typ !== 'JWT') {
    return { valid: false, error: 'Malformed token: unsupported algorithm or type' };
  }

  // Parse payload
  let payload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    return { valid: false, error: 'Malformed token: invalid payload' };
  }

  if (!payload.sub || typeof payload.sub !== 'string') {
    return { valid: false, error: 'Malformed token: missing required claim "sub"' };
  }

  if (payload.iat === undefined || payload.iat === null || typeof payload.iat !== 'number') {
    return { valid: false, error: 'Malformed token: missing required claim "iat"' };
  }

  // Verify signature
  const publicKeyB64 = keyRegistry[payload.sub];
  if (!publicKeyB64) {
    return { valid: false, error: 'Invalid signature: no key found for identity' };
  }

  let publicKeyBytes;
  try {
    publicKeyBytes = new Uint8Array(Buffer.from(publicKeyB64, 'base64'));
  } catch {
    return { valid: false, error: 'Invalid signature: malformed public key' };
  }

  const signedMessage = `${headerB64}.${payloadB64}`;
  const signedMessageBytes = new Uint8Array(Buffer.from(signedMessage, 'utf8'));

  let signatureBytes;
  try {
    signatureBytes = new Uint8Array(base64UrlDecode(signatureB64));
  } catch {
    return { valid: false, error: 'Invalid signature: malformed signature encoding' };
  }

  const isValidSignature = nacl.sign.detached.verify(
    signedMessageBytes,
    signatureBytes,
    publicKeyBytes
  );

  if (!isValidSignature) {
    return { valid: false, error: 'Invalid signature: verification failed' };
  }

  // Check expiration
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expiresAt = payload.iat + ttlSeconds;

  if (nowSeconds > expiresAt) {
    return { valid: false, error: 'Token expired' };
  }

  return { valid: true, claims: payload };
}

/**
 * Validate a message payload against the agent message schema.
 * Required fields: type, content, timestamp
 *
 * @param {string} rawMessage - Raw message string
 * @returns {{ valid: boolean, error?: string, parsed?: Object }}
 */
function validateMessageSchema(rawMessage) {
  if (typeof rawMessage !== 'string') {
    return { valid: false, error: 'Message must be a string' };
  }

  let parsed;
  try {
    parsed = JSON.parse(rawMessage);
  } catch {
    return { valid: false, error: 'Message is not valid JSON' };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { valid: false, error: 'Message must be a JSON object' };
  }

  if (!parsed.type || typeof parsed.type !== 'string') {
    return { valid: false, error: 'Missing or invalid required field: type' };
  }

  if (parsed.content === undefined || parsed.content === null) {
    return { valid: false, error: 'Missing required field: content' };
  }

  if (!parsed.timestamp || typeof parsed.timestamp !== 'string') {
    return { valid: false, error: 'Missing or invalid required field: timestamp' };
  }

  return { valid: true, parsed };
}

/**
 * Creates a WebSocketSecurityManager instance.
 *
 * @param {Object} options
 * @param {Object} options.keyRegistry - Maps identity → base64-encoded Ed25519 public key for JWT verification
 * @param {string[]} [options.allowedOrigins=[]] - Allowed Origin header values
 * @param {number} [options.rateLimit=60] - Max messages per window per connection
 * @param {number} [options.rateWindowSeconds=60] - Rate limit window in seconds
 * @param {number} [options.maxPayloadSize=65536] - Max message payload size in bytes
 * @param {number} [options.idleTimeoutMs=300000] - Idle timeout in milliseconds (default: 5 min)
 * @param {number} [options.pongTimeoutMs=10000] - Pong response timeout in milliseconds
 * @param {number} [options.tokenTtlSeconds=60] - JWT token TTL in seconds
 * @param {Object} [options.logger] - Audit logger instance
 * @param {Object} [options.perAgentRateLimits={}] - Per-agent rate limit overrides { agentId: { rateLimit, rateWindowSeconds } }
 * @returns {WebSocketSecurityManager}
 */
export function createWebSocketSecurityManager(options = {}) {
  const {
    keyRegistry = {},
    allowedOrigins = [],
    rateLimit = DEFAULT_RATE_LIMIT,
    rateWindowSeconds = DEFAULT_RATE_WINDOW_SECONDS,
    maxPayloadSize = MAX_PAYLOAD_SIZE,
    idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
    pongTimeoutMs = PONG_TIMEOUT_MS,
    tokenTtlSeconds = 60,
    logger = createAuditLogger({ minLevel: 'DEBUG' }),
    perAgentRateLimits = {},
  } = options;

  // Track active connections for lifecycle management
  const activeConnections = new Map();
  let connectionIdCounter = 0;

  /**
   * Generate a unique connection identifier.
   * @returns {string}
   */
  function generateConnectionId() {
    connectionIdCounter++;
    return `ws-${Date.now()}-${connectionIdCounter}`;
  }

  /**
   * Get rate limit config for a specific agent.
   * @param {string} agentId
   * @returns {{ rateLimit: number, rateWindowSeconds: number }}
   */
  function getRateLimitForAgent(agentId) {
    if (agentId && perAgentRateLimits[agentId]) {
      return {
        rateLimit: perAgentRateLimits[agentId].rateLimit || rateLimit,
        rateWindowSeconds: perAgentRateLimits[agentId].rateWindowSeconds || rateWindowSeconds,
      };
    }
    return { rateLimit, rateWindowSeconds };
  }

  /**
   * Authenticate a WebSocket upgrade request (Req 18.1, 18.2).
   * Validates the JWT token from the request headers or query parameters.
   *
   * @param {Object} req - HTTP upgrade request
   * @returns {{ authenticated: boolean, error?: string, claims?: Object, statusCode?: number }}
   */
  function authenticateUpgrade(req) {
    // Extract token from Authorization header or query param
    let token = null;

    const authHeader = req.headers?.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    }

    // Fallback: check for token in URL query params
    if (!token) {
      try {
        const url = new URL(req.url, 'http://localhost');
        token = url.searchParams.get('token');
      } catch {
        // Invalid URL, no token from query
      }
    }

    if (!token) {
      return {
        authenticated: false,
        error: 'Missing authentication token',
        statusCode: 401,
      };
    }

    const result = validateJwt(token, keyRegistry, { ttlSeconds: tokenTtlSeconds });

    if (!result.valid) {
      return {
        authenticated: false,
        error: result.error,
        statusCode: 401,
      };
    }

    return {
      authenticated: true,
      claims: result.claims,
    };
  }

  /**
   * Verify the Origin header against the configured allowlist (Req 18.3).
   *
   * @param {Object} req - HTTP upgrade request
   * @returns {{ allowed: boolean, origin?: string }}
   */
  function verifyOrigin(req) {
    const origin = req.headers?.origin;

    // If no allowlist configured, allow all origins
    if (allowedOrigins.length === 0) {
      return { allowed: true, origin: origin || 'none' };
    }

    // If no origin header present, reject
    if (!origin) {
      return { allowed: false, origin: 'none' };
    }

    // Check against allowlist (case-insensitive)
    const normalizedOrigin = origin.toLowerCase();
    const isAllowed = allowedOrigins.some(
      allowed => allowed.toLowerCase() === normalizedOrigin
    );

    return { allowed: isAllowed, origin };
  }

  /**
   * Handle a WebSocket upgrade request.
   * Performs authentication and origin verification before allowing the upgrade.
   *
   * @param {Object} req - HTTP IncomingMessage for the upgrade request
   * @param {Object} socket - Network socket
   * @param {Buffer} head - First packet of the upgrade stream
   * @returns {{ allowed: boolean, connectionId?: string, claims?: Object, error?: string, statusCode?: number, closeCode?: number }}
   */
  function handleUpgrade(req, socket, head) {
    const remoteIP = req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown';

    // Req 18.1, 18.2: Authenticate the upgrade request
    const authResult = authenticateUpgrade(req);
    if (!authResult.authenticated) {
      // Log auth failure
      logger.logAuthEvent({
        claimedIdentity: 'unknown',
        verificationMethod: 'websocket_jwt',
        outcome: 'rejected_invalid_signature',
        sourceIP: remoteIP,
        reason: authResult.error,
      });

      return {
        allowed: false,
        error: authResult.error,
        statusCode: authResult.statusCode || 401,
      };
    }

    // Req 18.3: Verify Origin header
    const originResult = verifyOrigin(req);
    if (!originResult.allowed) {
      logger.log('WARN', 'websocket_origin_rejected', {
        sourceIP: remoteIP,
        origin: originResult.origin,
        userId: authResult.claims?.sub,
        action: 'closed',
        closeCode: CLOSE_CODES.ORIGIN_NOT_PERMITTED,
      });

      return {
        allowed: false,
        error: 'Origin not permitted',
        closeCode: CLOSE_CODES.ORIGIN_NOT_PERMITTED,
      };
    }

    // Create connection state
    const connectionId = generateConnectionId();
    const connectionState = {
      connectionId,
      userId: authResult.claims.sub,
      remoteIP,
      origin: originResult.origin,
      createdAt: Date.now(),
      messageTimestamps: [],
      lastActivity: Date.now(),
      idleTimer: null,
      pongTimer: null,
      closed: false,
    };

    activeConnections.set(connectionId, connectionState);

    // Log connection open event (Req 18.8)
    logger.log('INFO', 'websocket_connection_open', {
      connectionId,
      userId: authResult.claims.sub,
      sourceIP: remoteIP,
      origin: originResult.origin,
    });

    return {
      allowed: true,
      connectionId,
      claims: authResult.claims,
    };
  }

  /**
   * Check message rate limit for a connection (Req 18.4).
   *
   * @param {string} connectionId - Connection identifier
   * @param {string} [agentId] - Target agent identifier for per-agent limits
   * @returns {{ allowed: boolean, error?: string, closeCode?: number }}
   */
  function checkRateLimit(connectionId, agentId) {
    const state = activeConnections.get(connectionId);
    if (!state) {
      return { allowed: false, error: 'Unknown connection' };
    }

    const now = Date.now();
    const limits = getRateLimitForAgent(agentId);
    const windowMs = limits.rateWindowSeconds * 1000;

    // Clean up old timestamps outside the window
    const cutoff = now - windowMs;
    state.messageTimestamps = state.messageTimestamps.filter(ts => ts > cutoff);

    // Check if rate limit exceeded
    if (state.messageTimestamps.length >= limits.rateLimit) {
      // Log rate limit event (Req 18.8)
      logger.log('WARN', 'websocket_rate_limited', {
        connectionId,
        userId: state.userId,
        sourceIP: state.remoteIP,
        messageCount: state.messageTimestamps.length,
        limit: limits.rateLimit,
        windowSeconds: limits.rateWindowSeconds,
      });

      return {
        allowed: false,
        error: 'Rate limit exceeded',
        closeCode: CLOSE_CODES.RATE_LIMIT_EXCEEDED,
      };
    }

    // Record this message timestamp
    state.messageTimestamps.push(now);

    return { allowed: true };
  }

  /**
   * Validate an incoming WebSocket message (Req 18.5, 18.6).
   *
   * @param {string|Buffer} rawMessage - Raw message data
   * @param {string} connectionId - Connection identifier
   * @param {string} [agentId] - Target agent for per-agent rate limits
   * @returns {{ valid: boolean, error?: string, closeCode?: number, parsed?: Object }}
   */
  function validateMessage(rawMessage, connectionId, agentId) {
    const state = activeConnections.get(connectionId);

    // Req 18.6: Check maximum payload size
    const payloadSize = typeof rawMessage === 'string'
      ? Buffer.byteLength(rawMessage, 'utf8')
      : rawMessage.length;

    if (payloadSize > maxPayloadSize) {
      if (state) {
        logger.log('WARN', 'websocket_message_too_large', {
          connectionId,
          userId: state.userId,
          sourceIP: state.remoteIP,
          payloadSize,
          maxSize: maxPayloadSize,
        });
      }

      return {
        valid: false,
        error: 'Message too large',
        closeCode: CLOSE_CODES.MESSAGE_TOO_LARGE,
      };
    }

    // Req 18.4: Check rate limit
    const rateLimitResult = checkRateLimit(connectionId, agentId);
    if (!rateLimitResult.allowed) {
      return {
        valid: false,
        error: rateLimitResult.error,
        closeCode: rateLimitResult.closeCode,
      };
    }

    // Req 18.5: Validate message schema (JSON with type, content, timestamp)
    const messageStr = typeof rawMessage === 'string'
      ? rawMessage
      : rawMessage.toString('utf8');

    const schemaResult = validateMessageSchema(messageStr);
    if (!schemaResult.valid) {
      return {
        valid: false,
        error: schemaResult.error,
      };
    }

    // Update last activity timestamp for idle tracking
    if (state) {
      state.lastActivity = Date.now();
    }

    return {
      valid: true,
      parsed: schemaResult.parsed,
    };
  }

  /**
   * Start idle timeout tracking for a connection (Req 18.7).
   * Sends a ping after idleTimeoutMs of inactivity. Closes connection if
   * pong not received within pongTimeoutMs.
   *
   * @param {string} connectionId - Connection identifier
   * @param {Object} ws - WebSocket instance with ping() and close() methods
   * @returns {void}
   */
  function startIdleTracking(connectionId, ws) {
    const state = activeConnections.get(connectionId);
    if (!state) return;

    function resetIdleTimer() {
      // Clear existing timers
      if (state.idleTimer) {
        clearTimeout(state.idleTimer);
        state.idleTimer = null;
      }
      if (state.pongTimer) {
        clearTimeout(state.pongTimer);
        state.pongTimer = null;
      }

      if (state.closed) return;

      // Set idle timer
      state.idleTimer = setTimeout(() => {
        if (state.closed) return;

        // Send ping
        try {
          if (ws.ping) {
            ws.ping();
          }
        } catch {
          // Connection may already be closed
          return;
        }

        // Set pong timeout
        state.pongTimer = setTimeout(() => {
          if (state.closed) return;

          // No pong received, terminate connection
          logger.log('WARN', 'websocket_idle_timeout', {
            connectionId,
            userId: state.userId,
            sourceIP: state.remoteIP,
            idleMs: idleTimeoutMs,
            pongTimeoutMs,
          });

          try {
            if (ws.close) {
              ws.close(1000, 'Idle timeout');
            } else if (ws.terminate) {
              ws.terminate();
            }
          } catch {
            // Already closed
          }

          state.closed = true;
        }, pongTimeoutMs);
      }, idleTimeoutMs);
    }

    // Store the reset function so we can call it on activity
    state.resetIdleTimer = resetIdleTimer;

    // Start the idle timer
    resetIdleTimer();
  }

  /**
   * Record activity on a connection (resets idle timer).
   *
   * @param {string} connectionId - Connection identifier
   */
  function recordActivity(connectionId) {
    const state = activeConnections.get(connectionId);
    if (!state || state.closed) return;

    state.lastActivity = Date.now();

    // Reset idle timer if tracking is active
    if (state.resetIdleTimer) {
      state.resetIdleTimer();
    }
  }

  /**
   * Handle pong received from client (Req 18.7).
   * Clears the pong timeout timer.
   *
   * @param {string} connectionId - Connection identifier
   */
  function handlePong(connectionId) {
    const state = activeConnections.get(connectionId);
    if (!state) return;

    if (state.pongTimer) {
      clearTimeout(state.pongTimer);
      state.pongTimer = null;
    }

    // Reset the idle timer since we got a response
    if (state.resetIdleTimer) {
      state.resetIdleTimer();
    }
  }

  /**
   * Handle connection close (Req 18.8).
   * Cleans up connection state and logs the close event.
   *
   * @param {string} connectionId - Connection identifier
   * @param {number} [code] - WebSocket close code
   * @param {string} [reason] - Close reason
   */
  function handleClose(connectionId, code, reason) {
    const state = activeConnections.get(connectionId);
    if (!state) return;

    state.closed = true;

    // Clear timers
    if (state.idleTimer) {
      clearTimeout(state.idleTimer);
      state.idleTimer = null;
    }
    if (state.pongTimer) {
      clearTimeout(state.pongTimer);
      state.pongTimer = null;
    }

    const duration = Date.now() - state.createdAt;

    // Log connection close event (Req 18.8)
    logger.log('INFO', 'websocket_connection_close', {
      connectionId,
      userId: state.userId,
      sourceIP: state.remoteIP,
      code: code || 1000,
      reason: reason || 'normal',
      durationMs: duration,
      messageCount: state.messageTimestamps.length,
    });

    activeConnections.delete(connectionId);
  }

  /**
   * Handle connection error (Req 18.8).
   *
   * @param {string} connectionId - Connection identifier
   * @param {Error} error - Error that occurred
   */
  function handleError(connectionId, error) {
    const state = activeConnections.get(connectionId);

    // Log error event (Req 18.8)
    logger.log('ERROR', 'websocket_connection_error', {
      connectionId,
      userId: state?.userId || 'unknown',
      sourceIP: state?.remoteIP || 'unknown',
      error: error?.message || 'Unknown error',
    });
  }

  /**
   * Get active connection count and stats.
   *
   * @returns {{ activeConnections: number, connectionIds: string[] }}
   */
  function getStats() {
    return {
      activeConnections: activeConnections.size,
      connectionIds: Array.from(activeConnections.keys()),
    };
  }

  /**
   * Get connection state for a specific connection.
   *
   * @param {string} connectionId
   * @returns {Object|null}
   */
  function getConnectionState(connectionId) {
    const state = activeConnections.get(connectionId);
    if (!state) return null;

    return {
      connectionId: state.connectionId,
      userId: state.userId,
      remoteIP: state.remoteIP,
      origin: state.origin,
      createdAt: state.createdAt,
      lastActivity: state.lastActivity,
      messageCount: state.messageTimestamps.length,
      closed: state.closed,
    };
  }

  return {
    handleUpgrade,
    authenticateUpgrade,
    verifyOrigin,
    validateMessage,
    checkRateLimit,
    startIdleTracking,
    recordActivity,
    handlePong,
    handleClose,
    handleError,
    getStats,
    getConnectionState,
  };
}
