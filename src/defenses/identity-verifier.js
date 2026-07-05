/**
 * Identity Verifier - Ed25519 JWT verification for agent-to-agent communication
 *
 * Validates signed JWT tokens on task delegation requests using Ed25519 key pairs
 * via tweetnacl. Implements custom JWT format (header.payload.signature) with
 * configurable TTL and sender allowlists.
 *
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7
 */

import nacl from 'tweetnacl';

/** Default token time-to-live in seconds */
const DEFAULT_TTL_SECONDS = 60;

/**
 * Base64URL encode a buffer or string.
 * @param {Buffer|Uint8Array|string} input
 * @returns {string}
 */
function base64UrlEncode(input) {
  let base64;
  if (typeof input === 'string') {
    base64 = Buffer.from(input, 'utf8').toString('base64');
  } else {
    base64 = Buffer.from(input).toString('base64');
  }
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64URL decode to a Buffer.
 * @param {string} str
 * @returns {Buffer}
 */
function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Pad to multiple of 4
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

/**
 * Creates an IdentityVerifier instance.
 *
 * @param {Object} keyRegistry - Maps agentId → base64-encoded Ed25519 public key
 * @param {Object} acceptsFrom - Maps receivingAgentId → array of allowed sender agentIds
 * @param {Object} [options] - Optional configuration
 * @param {number} [options.ttlSeconds=60] - Token time-to-live in seconds
 * @param {Object} [options.logger] - AuditLogger instance for logging failed attempts
 * @returns {IdentityVerifier}
 */
export function createIdentityVerifier(keyRegistry, acceptsFrom, options = {}) {
  const { ttlSeconds = DEFAULT_TTL_SECONDS, logger = null } = options;

  /**
   * Log a failed verification attempt (Req 5.6).
   * @param {string} claimedIdentity - The sub claim or 'unknown'
   * @param {string} reason - Failure reason
   * @param {string} [sourceIP] - Source IP if available
   */
  function logFailure(claimedIdentity, reason, sourceIP) {
    const event = {
      claimedIdentity,
      sourceIP: sourceIP || 'unknown',
      failureReason: reason,
      verificationMethod: 'ed25519_jwt',
      outcome: 'rejected',
    };

    if (logger && typeof logger.logAuthEvent === 'function') {
      logger.logAuthEvent(event);
    }

    // Also log to console for environments without a logger
    if (!logger) {
      console.error(
        `[identity-verifier] Verification failed: identity=${claimedIdentity} reason=${reason} ip=${sourceIP || 'unknown'}`
      );
    }
  }

  /**
   * Verify a JWT token for a receiving agent.
   *
   * @param {string} token - The JWT token (header.payload.signature in base64url)
   * @param {string} receivingAgentId - The agent receiving the delegation request
   * @param {Object} [context] - Optional context with source IP
   * @param {string} [context.sourceIP] - Source IP of the request
   * @returns {VerificationResult} { verified: boolean, error?: string, identity?: string }
   */
  function verify(token, receivingAgentId, context = {}) {
    const sourceIP = context.sourceIP || undefined;

    // Req 5.2: Check token presence
    if (!token || typeof token !== 'string') {
      logFailure('unknown', 'missing_token', sourceIP);
      return { verified: false, error: 'Missing authentication token' };
    }

    // Req 5.2: Check token structure (header.payload.signature)
    const parts = token.split('.');
    if (parts.length !== 3) {
      logFailure('unknown', 'malformed_token_structure', sourceIP);
      return { verified: false, error: 'Malformed token: invalid structure' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Parse header
    let header;
    try {
      header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    } catch {
      logFailure('unknown', 'malformed_header', sourceIP);
      return { verified: false, error: 'Malformed token: invalid header' };
    }

    // Verify header algorithm
    if (header.alg !== 'EdDSA' || header.typ !== 'JWT') {
      logFailure('unknown', 'invalid_header_claims', sourceIP);
      return { verified: false, error: 'Malformed token: unsupported algorithm or type' };
    }

    // Parse payload
    let payload;
    try {
      payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
    } catch {
      logFailure('unknown', 'malformed_payload', sourceIP);
      return { verified: false, error: 'Malformed token: invalid payload' };
    }

    // Req 5.2: Validate required claims
    if (!payload.sub || typeof payload.sub !== 'string') {
      logFailure('unknown', 'missing_sub_claim', sourceIP);
      return { verified: false, error: 'Malformed token: missing required claim "sub"' };
    }

    if (payload.iat === undefined || payload.iat === null || typeof payload.iat !== 'number') {
      logFailure(payload.sub, 'missing_iat_claim', sourceIP);
      return { verified: false, error: 'Malformed token: missing required claim "iat"' };
    }

    const claimedIdentity = payload.sub;

    // Req 5.3: Verify signature against trusted key registry
    const publicKeyB64 = keyRegistry[claimedIdentity];
    if (!publicKeyB64) {
      logFailure(claimedIdentity, 'unknown_identity_no_key', sourceIP);
      return { verified: false, error: 'Invalid signature: no key found for identity' };
    }

    let publicKeyBytes;
    try {
      publicKeyBytes = new Uint8Array(Buffer.from(publicKeyB64, 'base64'));
    } catch {
      logFailure(claimedIdentity, 'invalid_public_key_format', sourceIP);
      return { verified: false, error: 'Invalid signature: malformed public key in registry' };
    }

    // Verify Ed25519 signature (Req 5.7)
    const signedMessage = `${headerB64}.${payloadB64}`;
    const signedMessageBytes = new Uint8Array(Buffer.from(signedMessage, 'utf8'));

    let signatureBytes;
    try {
      signatureBytes = new Uint8Array(base64UrlDecode(signatureB64));
    } catch {
      logFailure(claimedIdentity, 'invalid_signature_encoding', sourceIP);
      return { verified: false, error: 'Invalid signature: malformed signature encoding' };
    }

    const isValidSignature = nacl.sign.detached.verify(
      signedMessageBytes,
      signatureBytes,
      publicKeyBytes
    );

    if (!isValidSignature) {
      logFailure(claimedIdentity, 'signature_verification_failed', sourceIP);
      return { verified: false, error: 'Invalid signature: signature verification failed' };
    }

    // Req 5.4: Check token expiration (iat + TTL)
    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiresAt = payload.iat + ttlSeconds;

    if (nowSeconds > expiresAt) {
      logFailure(claimedIdentity, 'token_expired', sourceIP);
      return { verified: false, error: 'Token expired' };
    }

    // Req 5.5: Validate sub against receiver's acceptsFrom allowlist
    const allowedSenders = acceptsFrom[receivingAgentId];
    if (!allowedSenders || !Array.isArray(allowedSenders)) {
      logFailure(claimedIdentity, 'no_acceptsFrom_config_for_receiver', sourceIP);
      return { verified: false, error: 'Unauthorized sender: receiver has no delegation policy' };
    }

    if (!allowedSenders.includes(claimedIdentity)) {
      logFailure(claimedIdentity, 'sender_not_in_allowlist', sourceIP);
      return { verified: false, error: 'Unauthorized sender: not in acceptsFrom allowlist' };
    }

    // All checks passed
    return { verified: true, identity: claimedIdentity };
  }

  return { verify };
}

/**
 * Sign a JWT token for agent-to-agent delegation (test helper).
 *
 * @param {string} agentId - The agent identity (becomes the "sub" claim)
 * @param {Uint8Array|Buffer} privateKey - Ed25519 64-byte secret key (tweetnacl format)
 * @param {Object} [options] - Optional overrides
 * @param {number} [options.iat] - Custom issued-at timestamp (seconds since epoch)
 * @returns {string} The signed JWT token
 */
export function signToken(agentId, privateKey, options = {}) {
  const iat = options.iat !== undefined ? options.iat : Math.floor(Date.now() / 1000);

  const header = { alg: 'EdDSA', typ: 'JWT' };
  const payload = { sub: agentId, iat };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));

  const message = `${headerB64}.${payloadB64}`;
  const messageBytes = new Uint8Array(Buffer.from(message, 'utf8'));

  const privateKeyBytes = privateKey instanceof Uint8Array
    ? privateKey
    : new Uint8Array(privateKey);

  const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
  const signatureB64 = base64UrlEncode(signature);

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}
