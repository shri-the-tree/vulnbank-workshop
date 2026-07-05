/**
 * Tool Registry Verifier - Cryptographic integrity verification for tool registrations
 *
 * Validates tool manifests via SHA-256 content hashes signed by the registry authority
 * using Ed25519 signatures. Maintains a frozen snapshot of registered tools and verifies
 * implementation hashes before execution.
 *
 * Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
 */

import { createHash, verify as cryptoVerify } from 'node:crypto';

/** Default verification timeout in milliseconds (Req 10.7) */
const VERIFICATION_TIMEOUT_MS = 5000;

/**
 * Compute SHA-256 hash of content.
 * @param {string} content - Content to hash
 * @returns {string} Hex-encoded SHA-256 hash
 */
function sha256(content) {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Compute SHA-256 hash of a manifest object (canonical JSON serialization).
 * @param {Object} manifest - Tool manifest object
 * @returns {string} Hex-encoded SHA-256 hash
 */
function computeManifestHash(manifest) {
  const canonical = JSON.stringify(manifest, Object.keys(manifest).sort());
  return sha256(canonical);
}

/**
 * Verify an Ed25519 signature against a public key.
 * @param {string} data - Data that was signed
 * @param {string} signature - Base64-encoded signature
 * @param {string} publicKeyBase64 - Base64-encoded Ed25519 public key
 * @returns {boolean} Whether the signature is valid
 */
function verifySignature(data, signature, publicKeyBase64) {
  try {
    const publicKeyDer = Buffer.from(publicKeyBase64, 'base64');

    // Build a proper Ed25519 public key object from raw bytes
    // Node.js crypto expects the key in a specific format
    let keyObject;
    if (publicKeyDer.length === 32) {
      // Raw 32-byte Ed25519 public key - wrap in PKCS8/SPKI DER
      // Ed25519 SPKI prefix for 32-byte raw key
      const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
      const spkiDer = Buffer.concat([spkiPrefix, publicKeyDer]);
      keyObject = { key: spkiDer, format: 'der', type: 'spki' };
    } else {
      // Assume it's already in DER/SPKI format
      keyObject = { key: publicKeyDer, format: 'der', type: 'spki' };
    }

    const signatureBuffer = Buffer.from(signature, 'base64');
    const dataBuffer = Buffer.from(data, 'utf8');

    return cryptoVerify(null, dataBuffer, keyObject, signatureBuffer);
  } catch {
    return false;
  }
}

/**
 * Run an operation with a timeout (Req 10.7).
 * @param {Function} fn - Synchronous function to execute
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {Function} [onTimeout] - Callback when timeout occurs
 * @returns {{ result: *, timedOut: boolean }}
 */
function withTimeout(fn, timeoutMs, onTimeout) {
  const start = Date.now();

  // For synchronous operations, we check elapsed time after execution.
  // True async timeout would require worker threads; for the sync crypto ops
  // here, we check duration after the fact.
  const result = fn();
  const elapsed = Date.now() - start;

  if (elapsed > timeoutMs) {
    if (onTimeout) onTimeout(elapsed);
    return { result: null, timedOut: true };
  }

  return { result, timedOut: false };
}

/**
 * Creates a ToolRegistryVerifier instance.
 *
 * @param {string} registryAuthorityPublicKey - Base64-encoded Ed25519 public key of the registry authority
 * @param {Object} [options] - Optional configuration
 * @param {number} [options.timeoutMs=5000] - Timeout for verification operations in milliseconds
 * @param {Object} [options.logger] - AuditLogger instance for logging events
 * @returns {ToolRegistryVerifier}
 */
export function createToolRegistryVerifier(registryAuthorityPublicKey, options = {}) {
  const { timeoutMs = VERIFICATION_TIMEOUT_MS, logger = null } = options;

  // Frozen registry of registered tools (Req 10.4)
  // Map: toolId → frozen manifest + metadata
  const registry = new Map();

  // Set of pinned tool version keys: "toolId@version" (Req 10.6)
  const pinnedVersions = new Set();

  /**
   * Log a tool integrity violation event.
   * @param {string} eventType - Specific event sub-type
   * @param {Object} data - Event data
   */
  function logEvent(eventType, data) {
    if (logger && typeof logger.log === 'function') {
      logger.log('WARN', eventType, data);
    }
  }

  /**
   * Log a verification timeout event (Req 10.7).
   * @param {string} operation - Operation that timed out
   * @param {number} elapsed - Elapsed time in ms
   */
  function logTimeout(operation, elapsed) {
    logEvent('verification-timeout', {
      operation,
      elapsedMs: elapsed,
      timeoutMs,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Register a tool manifest after cryptographic verification.
   *
   * @param {Object} manifest - Tool manifest containing at minimum:
   *   { id, name, version, sourceUrl, implementationHash, [pinned] }
   * @param {string} signature - Base64-encoded Ed25519 signature of the manifest's SHA-256 hash
   * @returns {RegistrationResult} { accepted: boolean, error?: string }
   */
  function register(manifest, signature) {
    // Wrap in timeout check (Req 10.7)
    const { result, timedOut } = withTimeout(() => {
      return _doRegister(manifest, signature);
    }, timeoutMs, (elapsed) => logTimeout('register', elapsed));

    if (timedOut) {
      return { accepted: false, error: 'Verification timeout: operation exceeded 5 seconds' };
    }

    return result;
  }

  /**
   * Internal registration logic.
   * @param {Object} manifest
   * @param {string} signature
   * @returns {RegistrationResult}
   */
  function _doRegister(manifest, signature) {
    // Validate manifest has required fields
    if (!manifest || typeof manifest !== 'object') {
      return { accepted: false, error: 'Invalid manifest: must be a non-null object' };
    }

    if (!manifest.id || typeof manifest.id !== 'string') {
      return { accepted: false, error: 'Invalid manifest: missing or invalid "id" field' };
    }

    if (!manifest.implementationHash || typeof manifest.implementationHash !== 'string') {
      return { accepted: false, error: 'Invalid manifest: missing or invalid "implementationHash" field' };
    }

    // Req 10.3: Reject non-HTTPS source URLs
    if (manifest.sourceUrl) {
      try {
        const url = new URL(manifest.sourceUrl);
        if (url.protocol !== 'https:') {
          logEvent('tool-integrity-violation', {
            toolId: manifest.id,
            reason: 'non_tls_source',
            sourceUrl: manifest.sourceUrl,
            timestamp: new Date().toISOString(),
          });
          return { accepted: false, error: 'Non-TLS source not permitted: sourceUrl must use HTTPS' };
        }
      } catch {
        return { accepted: false, error: 'Invalid manifest: sourceUrl is not a valid URL' };
      }
    }

    // Req 10.6: Check if this tool+version is pinned (cannot be overwritten)
    const versionKey = `${manifest.id}@${manifest.version || 'latest'}`;
    if (pinnedVersions.has(versionKey)) {
      return { accepted: false, error: 'Version is pinned and cannot be modified' };
    }

    // Req 10.4: Check if tool already registered (frozen snapshot - reject modifications)
    if (registry.has(manifest.id)) {
      // Only allow modifications if signed by registry authority
      // The signature on the new manifest serves as authority approval
      if (!signature || typeof signature !== 'string') {
        return { accepted: false, error: 'Cannot modify registered tool: modification requires authority signature' };
      }
      // Signature will be verified below; if valid, the modification is allowed
    }

    // Req 10.2: Reject missing signature
    if (!signature || typeof signature !== 'string') {
      logEvent('tool-integrity-violation', {
        toolId: manifest.id,
        reason: 'missing_signature',
        timestamp: new Date().toISOString(),
      });
      return { accepted: false, error: 'Missing signature: tool manifest must be signed by registry authority' };
    }

    // Req 10.1: Validate SHA-256 content hash signed by registry authority
    const manifestHash = computeManifestHash(manifest);
    const isValid = verifySignature(manifestHash, signature, registryAuthorityPublicKey);

    if (!isValid) {
      logEvent('tool-integrity-violation', {
        toolId: manifest.id,
        reason: 'invalid_signature',
        computedHash: manifestHash,
        timestamp: new Date().toISOString(),
      });
      return { accepted: false, error: 'Invalid signature: manifest signature verification failed' };
    }

    // Registration accepted - store frozen snapshot (Req 10.4)
    const frozenManifest = Object.freeze({ ...manifest, _registeredAt: new Date().toISOString() });
    registry.set(manifest.id, frozenManifest);

    // Req 10.6: If tool is marked as pinned, add to pinned set
    if (manifest.pinned === true) {
      pinnedVersions.add(versionKey);
    }

    return { accepted: true };
  }

  /**
   * Verify a tool's implementation hash matches its registered hash before execution.
   * (Req 10.5)
   *
   * @param {string} toolId - The tool identifier to verify
   * @param {string} [currentImplementationHash] - Current hash of the tool implementation
   * @returns {{ allowed: boolean, error?: string }}
   */
  function verifyBeforeExecution(toolId, currentImplementationHash) {
    // Wrap in timeout check (Req 10.7)
    const { result, timedOut } = withTimeout(() => {
      return _doVerify(toolId, currentImplementationHash);
    }, timeoutMs, (elapsed) => logTimeout('verifyBeforeExecution', elapsed));

    if (timedOut) {
      return { allowed: false, error: 'Verification timeout: operation exceeded 5 seconds' };
    }

    return result;
  }

  /**
   * Internal verification logic.
   * @param {string} toolId
   * @param {string} [currentImplementationHash]
   * @returns {{ allowed: boolean, error?: string }}
   */
  function _doVerify(toolId, currentImplementationHash) {
    if (!toolId || typeof toolId !== 'string') {
      return { allowed: false, error: 'Invalid toolId: must be a non-empty string' };
    }

    const registeredTool = registry.get(toolId);
    if (!registeredTool) {
      return { allowed: false, error: `Tool not registered: ${toolId}` };
    }

    // Req 10.5: Verify implementation hash matches registered hash
    if (!currentImplementationHash) {
      return { allowed: false, error: 'Missing implementation hash for verification' };
    }

    if (currentImplementationHash !== registeredTool.implementationHash) {
      logEvent('tool-integrity-violation', {
        toolId,
        reason: 'hash_mismatch',
        registeredHash: registeredTool.implementationHash,
        currentHash: currentImplementationHash,
        timestamp: new Date().toISOString(),
      });
      return { allowed: false, error: 'Hash mismatch: tool implementation has been modified since registration' };
    }

    return { allowed: true };
  }

  /**
   * Get all registered tools (frozen snapshots).
   * @returns {Object[]} Array of registered tool manifests
   */
  function getRegisteredTools() {
    return Array.from(registry.values());
  }

  return {
    register,
    verifyBeforeExecution,
    getRegisteredTools,
  };
}
