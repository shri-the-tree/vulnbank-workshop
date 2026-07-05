/**
 * Token Smuggling Detector - Encoding Normalization and Bypass Prevention
 *
 * Decodes and normalizes encoded inputs (Base64, Unicode escapes, ROT13,
 * HTML entities, URL encoding) before applying security pattern matching.
 * Detects mixed-encoding attacks and suspicious encoding abuse.
 *
 * Requirements: 21.1, 21.2, 21.3, 21.4, 21.5, 21.6, 21.7, 21.8
 */

import { readFileSync } from 'node:fs';
import { createAuditLogger } from './audit-logger.js';

/**
 * @typedef {Object} SmuggleCheckResult
 * @property {boolean} pass - Whether input is allowed through
 * @property {boolean} [encodingDetected] - Whether any encoding was found
 * @property {string[]} [encodingTypes] - Types of encoding detected
 * @property {boolean} [obfuscated] - Flagged as potentially obfuscated (>3 decode layers)
 * @property {boolean} [suspiciousAbuse] - Flagged for encoding abuse
 * @property {string} [decodedContent] - The decoded plaintext
 * @property {Object} [patternMatch] - Matched security pattern details
 * @property {string} [annotation] - Audit annotation string
 */

/**
 * Decode a Base64-encoded string.
 * Returns null if decoding fails or result is not valid text.
 * @param {string} str
 * @returns {string|null}
 */
function decodeBase64(str) {
  try {
    const decoded = Buffer.from(str, 'base64').toString('utf-8');
    // Verify it produced valid readable text (not binary garbage)
    if (/[\x00-\x08\x0E-\x1F]/.test(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Decode Unicode escape sequences (\uXXXX or \xXX) in a string.
 * @param {string} str
 * @returns {string}
 */
function decodeUnicode(str) {
  return str
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/**
 * Decode ROT13-encoded text.
 * @param {string} str
 * @returns {string}
 */
function decodeRot13(str) {
  return str.replace(/[A-Za-z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/**
 * Decode HTML numeric entities (&#xHEX; or &#DEC;).
 * @param {string} str
 * @returns {string}
 */
function decodeHtmlEntities(str) {
  return str.replace(/&#x([0-9A-Fa-f]{2,4});/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  ).replace(/&#(\d{2,5});/g, (_, dec) =>
    String.fromCharCode(parseInt(dec, 10))
  );
}

/**
 * Decode URL percent-encoded sequences.
 * @param {string} str
 * @returns {string}
 */
function decodeUrl(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    // Fallback: decode individual %XX sequences
    return str.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
  }
}

/** Map of decoder identifiers to decoder functions */
const DECODERS = {
  base64: decodeBase64,
  unicode: decodeUnicode,
  rot13: decodeRot13,
  html: decodeHtmlEntities,
  url: decodeUrl,
};

/**
 * Creates a Token Smuggling Detector instance.
 *
 * @param {Object} options
 * @param {string} [options.configPath] - Path to encoding-patterns.json
 * @param {Object} [options.auditLogger] - AuditLogger instance
 * @returns {TokenSmugglingDetector}
 */
export function createTokenSmugglingDetector(options = {}) {
  const { configPath = null, auditLogger = null } = options;

  const logger = auditLogger || createAuditLogger({ minLevel: 'WARN' });

  let encodingDefs = [];
  let securityPatterns = [];
  let compiledSecurityPatterns = [];
  let settings = {
    maxRecursionDepth: 3,
    maxEncodedSegments: 5,
    maxDecodedLengthRatio: 3,
    maxInputLength: 10000,
    timeoutMs: 50,
  };

  /**
   * Load configuration from JSON file.
   */
  function loadConfig() {
    if (!configPath) return;
    try {
      const raw = readFileSync(configPath, 'utf-8');
      const config = JSON.parse(raw);

      if (Array.isArray(config.encodings)) {
        encodingDefs = config.encodings.map(entry => ({
          type: entry.type,
          regex: new RegExp(entry.detectionPattern, entry.detectionFlags || 'g'),
          decoder: entry.decoder,
        }));
      }

      if (Array.isArray(config.securityPatterns)) {
        securityPatterns = config.securityPatterns;
        compiledSecurityPatterns = securityPatterns.map(entry => ({
          regex: new RegExp(entry.pattern, entry.flags || ''),
          category: entry.category,
        }));
      }

      if (config.settings) {
        settings = { ...settings, ...config.settings };
      }
    } catch {
      // Fall back to defaults if config is unavailable
    }
  }

  // Initial load
  loadConfig();

  /**
   * Detect encoded segments in text and return decoded results.
   * @param {string} text
   * @returns {{ segments: Array<{type: string, original: string, decoded: string}>, types: Set<string> }}
   */
  function detectAndDecode(text) {
    const segments = [];
    const types = new Set();

    for (const def of encodingDefs) {
      // Reset regex lastIndex for global patterns
      def.regex.lastIndex = 0;
      let match;
      while ((match = def.regex.exec(text)) !== null) {
        const original = match[0];
        const decoderFn = DECODERS[def.decoder];
        if (!decoderFn) continue;

        let decoded;
        if (def.decoder === 'rot13') {
          // ROT13 entries have a prefix marker - strip it before decoding
          const content = original.replace(/^(?:rot13:|ROT13:)\s*/i, '');
          decoded = decoderFn(content);
        } else {
          decoded = decoderFn(original);
        }

        if (decoded !== null && decoded !== original) {
          segments.push({ type: def.type, original, decoded });
          types.add(def.type);
        }
      }
    }

    return { segments, types };
  }

  /**
   * Apply recursive decoding up to maxRecursionDepth layers.
   * Returns the fully decoded text and metadata.
   * @param {string} text
   * @returns {{ decoded: string, depth: number, types: Set<string>, segments: number, obfuscated: boolean }}
   */
  function recursiveDecode(text) {
    let current = text;
    let allTypes = new Set();
    let totalSegments = 0;
    let depth = 0;

    for (let i = 0; i < settings.maxRecursionDepth; i++) {
      const { segments, types } = detectAndDecode(current);

      if (segments.length === 0) break;

      depth = i + 1;
      totalSegments += segments.length;
      for (const t of types) allTypes.add(t);

      // Replace encoded segments with their decoded content
      let decoded = current;
      // Process segments from end to start to maintain correct offsets
      const sortedSegments = [...segments].sort((a, b) => {
        const idxA = decoded.lastIndexOf(a.original);
        const idxB = decoded.lastIndexOf(b.original);
        return idxB - idxA;
      });

      for (const seg of sortedSegments) {
        decoded = decoded.replace(seg.original, seg.decoded);
      }

      current = decoded;
    }

    // Check if still encoded after max passes (Req 21.2)
    const { segments: remaining } = detectAndDecode(current);
    const obfuscated = remaining.length > 0;

    return {
      decoded: current,
      depth,
      types: allTypes,
      segments: totalSegments,
      obfuscated,
    };
  }

  /**
   * Check decoded text against all security patterns.
   * @param {string} text
   * @returns {{ matched: boolean, category: string|null, pattern: string|null }}
   */
  function checkSecurityPatterns(text) {
    for (const { regex, category } of compiledSecurityPatterns) {
      regex.lastIndex = 0;
      if (regex.test(text)) {
        return { matched: true, category, pattern: regex.source };
      }
    }
    return { matched: false, category: null, pattern: null };
  }

  /**
   * Main check method - scan input for encoded content, decode, and match patterns.
   *
   * @param {string} input - The user-supplied input text
   * @param {Object} [context] - Request context (sourceIP, agentId, etc.)
   * @returns {SmuggleCheckResult}
   */
  function check(input, context = {}) {
    if (typeof input !== 'string' || input.length === 0) {
      return { pass: true, encodingDetected: false };
    }

    // Enforce max input length (Req 21.7)
    const workingInput = input.length > settings.maxInputLength
      ? input.slice(0, settings.maxInputLength)
      : input;

    // Perform recursive decoding (Req 21.1, 21.2, 21.5)
    const decodeResult = recursiveDecode(workingInput);

    // No encoding detected — input is clean
    if (decodeResult.depth === 0 && !decodeResult.obfuscated) {
      return { pass: true, encodingDetected: false };
    }

    const encodingTypes = [...decodeResult.types];
    const isMixedEncoding = encodingTypes.length > 1;

    // Req 21.2: Flag still-encoded content after 3 passes
    if (decodeResult.obfuscated) {
      logger.log('WARN', 'deep-encoding-detected', {
        sourceIP: context.sourceIP || 'unknown',
        agentTarget: context.agentId || 'unknown',
        encodingTypes,
        decodingDepth: decodeResult.depth,
        segmentsDecoded: decodeResult.segments,
      });
    }

    // Req 21.6: Detect suspicious encoding abuse
    const decodedLengthRatio = decodeResult.decoded.length / workingInput.length;
    const suspiciousAbuse = decodeResult.segments > settings.maxEncodedSegments ||
      decodedLengthRatio > settings.maxDecodedLengthRatio;

    if (suspiciousAbuse) {
      logger.logBlockedAttack({
        sourceIP: context.sourceIP || 'unknown',
        agentTarget: context.agentId || 'unknown',
        attackCategory: 'encoding_abuse',
        matchedPattern: `segments=${decodeResult.segments}, ratio=${decodedLengthRatio.toFixed(2)}`,
        action: 'flagged',
        inputPreview: workingInput.slice(0, 100),
      });
    }

    // Req 21.3, 21.4: Apply security pattern checks against decoded plaintext
    const patternResult = checkSecurityPatterns(decodeResult.decoded);

    if (patternResult.matched) {
      // Req 21.4: Annotate audit log with encoding type
      const annotation = `[detected via encoding: ${encodingTypes.join(', ')}]`;

      logger.logBlockedAttack({
        sourceIP: context.sourceIP || 'unknown',
        agentTarget: context.agentId || 'unknown',
        attackCategory: patternResult.category,
        matchedPattern: patternResult.pattern,
        action: 'blocked',
        inputPreview: workingInput.slice(0, 100),
        annotation,
        encodingTypes,
        mixedEncoding: isMixedEncoding,
      });

      return {
        pass: false,
        encodingDetected: true,
        encodingTypes,
        obfuscated: decodeResult.obfuscated,
        suspiciousAbuse,
        decodedContent: decodeResult.decoded,
        patternMatch: {
          category: patternResult.category,
          pattern: patternResult.pattern,
        },
        annotation,
        mixedEncoding: isMixedEncoding,
      };
    }

    // Encoding was detected but no security pattern matched
    return {
      pass: true,
      encodingDetected: true,
      encodingTypes,
      obfuscated: decodeResult.obfuscated,
      suspiciousAbuse,
      decodedContent: decodeResult.decoded,
      mixedEncoding: isMixedEncoding,
    };
  }

  /**
   * Hot-reload configuration from the JSON file.
   */
  function reload() {
    loadConfig();
  }

  /**
   * Get current settings (for inspection/testing).
   * @returns {Object}
   */
  function getSettings() {
    return { ...settings };
  }

  return {
    check,
    reload,
    getSettings,
  };
}
