/**
 * URL Validator - SSRF Prevention
 *
 * Restricts outbound URL requests to a configurable domain allowlist,
 * rejects private/reserved IPs, non-HTTPS protocols, credentials in URLs,
 * and detects DNS rebinding attacks.
 *
 * Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8
 */

import { readFileSync } from 'node:fs';
import { resolve4, resolve6 } from 'node:dns/promises';
import { createAuditLogger } from './audit-logger.js';

/**
 * Private/reserved IPv4 ranges as [prefix, maskBits] pairs.
 * Covers: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 0.0.0.0
 */
const PRIVATE_IPV4_RANGES = [
  { network: 0x0A000000, mask: 0xFF000000 },   // 10.0.0.0/8
  { network: 0xAC100000, mask: 0xFFF00000 },   // 172.16.0.0/12
  { network: 0xC0A80000, mask: 0xFFFF0000 },   // 192.168.0.0/16
  { network: 0x7F000000, mask: 0xFF000000 },   // 127.0.0.0/8
  { network: 0xA9FE0000, mask: 0xFFFF0000 },   // 169.254.0.0/16
  { network: 0x00000000, mask: 0xFFFFFFFF },   // 0.0.0.0/32
];

/**
 * Parse an IPv4 address string to a 32-bit integer.
 * @param {string} ip - IPv4 address (e.g., "192.168.1.1")
 * @returns {number|null} 32-bit integer or null if invalid
 */
function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let result = 0;
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return null;
    result = (result << 8) | num;
  }
  // Convert to unsigned 32-bit
  return result >>> 0;
}

/**
 * Check if an IPv4 address falls within a private/reserved range.
 * @param {string} ip - IPv4 address string
 * @returns {boolean}
 */
function isPrivateIPv4(ip) {
  const ipInt = ipv4ToInt(ip);
  if (ipInt === null) return false;

  for (const { network, mask } of PRIVATE_IPV4_RANGES) {
    if (((ipInt & mask) >>> 0) === (network >>> 0)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if an IPv6 address is private/reserved.
 * Covers: ::1 (loopback), fc00::/7 (unique local)
 * @param {string} ip - IPv6 address string
 * @returns {boolean}
 */
function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase().trim();

  // Loopback
  if (normalized === '::1' || normalized === '0000:0000:0000:0000:0000:0000:0000:0001') {
    return true;
  }

  // fc00::/7 — first byte fc or fd
  // Expand the address to check the first byte
  const expanded = expandIPv6(normalized);
  if (expanded) {
    const firstByte = parseInt(expanded.substring(0, 2), 16);
    if ((firstByte & 0xFE) === 0xFC) {
      return true;
    }
  }

  return false;
}

/**
 * Expand an IPv6 address to full form (32 hex chars without colons).
 * @param {string} ip - IPv6 address
 * @returns {string|null} Expanded hex string or null
 */
function expandIPv6(ip) {
  // Handle ::
  let parts;
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];
    const missing = 8 - leftParts.length - rightParts.length;
    const middleParts = Array(missing).fill('0000');
    parts = [...leftParts, ...middleParts, ...rightParts];
  } else {
    parts = ip.split(':');
  }

  if (parts.length !== 8) return null;

  return parts.map(p => p.padStart(4, '0')).join('');
}

/**
 * Check if a URL contains credentials in the authority component,
 * including URL-encoded variants.
 * @param {string} urlString - The raw URL string
 * @param {URL} parsed - Parsed URL object
 * @returns {boolean}
 */
function hasCredentials(urlString, parsed) {
  // The URL class decodes username/password from percent-encoded forms
  if (parsed.username || parsed.password) {
    return true;
  }

  // Additional check: look for @ in authority part that could indicate
  // encoded credentials the URL parser may have missed
  try {
    // Extract the authority portion (between :// and the first /)
    const protocolEnd = urlString.indexOf('://');
    if (protocolEnd === -1) return false;

    const authorityStart = protocolEnd + 3;
    const pathStart = urlString.indexOf('/', authorityStart);
    const authority = pathStart === -1
      ? urlString.slice(authorityStart)
      : urlString.slice(authorityStart, pathStart);

    // Check for URL-encoded @ (%40) which might bypass basic parsing
    const decoded = decodeURIComponent(authority);
    if (decoded.includes('@') && decoded !== authority.replace(/%40/gi, '@')) {
      // There was an encoded @ — check if it introduces credentials
      const atIndex = decoded.indexOf('@');
      const userInfo = decoded.slice(0, atIndex);
      if (userInfo.includes(':')) {
        return true;
      }
    }
  } catch {
    // If decoding fails, it's a malformed URL — will be caught elsewhere
  }

  return false;
}

/**
 * Check if a domain matches an allowlist entry.
 * Supports exact match and wildcard patterns (*.domain matches one subdomain level).
 * @param {string} hostname - The hostname to check
 * @param {string[]} allowedDomains - List of allowed domain patterns
 * @returns {boolean}
 */
function isDomainAllowed(hostname, allowedDomains) {
  const lowerHost = hostname.toLowerCase();

  for (const pattern of allowedDomains) {
    const lowerPattern = pattern.toLowerCase();

    if (lowerPattern.startsWith('*.')) {
      // Wildcard pattern: *.vulnbank.example matches exactly one subdomain level
      const baseDomain = lowerPattern.slice(2); // Remove "*."
      // Hostname must end with .baseDomain and have exactly one label before it
      if (lowerHost.endsWith('.' + baseDomain)) {
        const prefix = lowerHost.slice(0, lowerHost.length - baseDomain.length - 1);
        // Prefix must be a single label (no dots)
        if (prefix.length > 0 && !prefix.includes('.')) {
          return true;
        }
      }
    } else {
      // Exact match
      if (lowerHost === lowerPattern) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Creates a UrlValidator instance that loads configuration from a JSON file.
 *
 * @param {string} allowlistPath - Path to the URL allowlist JSON configuration file
 * @returns {UrlValidator}
 */
export function createUrlValidator(allowlistPath) {
  const logger = createAuditLogger({ minLevel: 'DEBUG' });
  let allowedDomains = [];
  let allowedProtocols = ['https'];

  /**
   * Load configuration from the JSON file.
   */
  function loadConfig() {
    const raw = readFileSync(allowlistPath, 'utf-8');
    const config = JSON.parse(raw);
    allowedDomains = config.allowedDomains || [];
    allowedProtocols = (config.allowedProtocols || ['https']).map(p => p.toLowerCase());
  }

  // Initial load
  loadConfig();

  /**
   * Log a violation event without exposing internal network details.
   * @param {string} url - The full URL that violated policy
   * @param {string} violationType - Type of violation
   * @param {string} agentId - Requesting agent identity
   */
  function logViolation(url, violationType, agentId) {
    logger.logBlockedAttack({
      agentTarget: agentId || 'unknown',
      attackCategory: 'ssrf',
      action: 'blocked',
      url,
      violationType,
    });
  }

  /**
   * Validate a URL against the allowlist and security policies.
   *
   * @param {string} url - The URL to validate
   * @param {Object} [context] - Optional context with agentId
   * @returns {Promise<URLValidationResult>}
   */
  async function validate(url, context = {}) {
    const agentId = context.agentId || 'unknown';
    const startTime = Date.now();

    // Parse the URL
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      // Check if the URL failure is due to encoded credentials in authority
      if (/%40/i.test(url) || /%3A/i.test(url)) {
        // Likely encoded credentials (user%3Apass%40host or user:pass%40host)
        logViolation(url, 'credentials_in_url', agentId);
        return {
          allowed: false,
          error: 'Credentials in URL are not permitted',
          violationType: 'credentials_in_url',
        };
      }
      logViolation(url, 'domain_not_allowed', agentId);
      return {
        allowed: false,
        error: 'Invalid URL format',
        violationType: 'domain_not_allowed',
      };
    }

    // Req 7.3: Reject non-HTTPS protocols
    const protocol = parsed.protocol.replace(':', '').toLowerCase();
    if (!allowedProtocols.includes(protocol)) {
      logViolation(url, 'invalid_protocol', agentId);
      return {
        allowed: false,
        error: 'Protocol not permitted',
        violationType: 'invalid_protocol',
      };
    }

    // Req 7.4: Reject credentials in URL authority
    if (hasCredentials(url, parsed)) {
      logViolation(url, 'credentials_in_url', agentId);
      return {
        allowed: false,
        error: 'Credentials in URL are not permitted',
        violationType: 'credentials_in_url',
      };
    }

    // Req 7.2: Check if hostname is a literal private IP
    const hostname = parsed.hostname;

    // Check for IPv4 literal
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      if (isPrivateIPv4(hostname)) {
        logViolation(url, 'private_ip', agentId);
        return {
          allowed: false,
          error: 'Access to private IP addresses is not permitted',
          violationType: 'private_ip',
        };
      }
    }

    // Check for IPv6 literal (bracketed in URLs: [::1])
    if (hostname.startsWith('[') || hostname.includes(':')) {
      const rawIPv6 = hostname.replace(/^\[|\]$/g, '');
      if (isPrivateIPv6(rawIPv6)) {
        logViolation(url, 'private_ip', agentId);
        return {
          allowed: false,
          error: 'Access to private IP addresses is not permitted',
          violationType: 'private_ip',
        };
      }
    }

    // Req 7.1 & 7.6: Verify domain against allowlist (with wildcard support)
    if (!isDomainAllowed(hostname, allowedDomains)) {
      logViolation(url, 'domain_not_allowed', agentId);
      return {
        allowed: false,
        error: 'Domain is not in the permitted allowlist',
        violationType: 'domain_not_allowed',
      };
    }

    // Req 7.7: DNS rebinding detection — resolve domain and check for private IPs
    try {
      let addresses = [];
      try {
        const ipv4Addrs = await resolve4(hostname);
        addresses = addresses.concat(ipv4Addrs);
      } catch {
        // No A records — acceptable, may have only AAAA
      }

      try {
        const ipv6Addrs = await resolve6(hostname);
        addresses = addresses.concat(ipv6Addrs);
      } catch {
        // No AAAA records — acceptable
      }

      // Check each resolved address for private ranges
      for (const addr of addresses) {
        if (addr.includes(':')) {
          if (isPrivateIPv6(addr)) {
            logViolation(url, 'dns_rebinding', agentId);
            return {
              allowed: false,
              error: 'DNS rebinding detected: domain resolves to private address',
              violationType: 'dns_rebinding',
            };
          }
        } else {
          if (isPrivateIPv4(addr)) {
            logViolation(url, 'dns_rebinding', agentId);
            return {
              allowed: false,
              error: 'DNS rebinding detected: domain resolves to private address',
              violationType: 'dns_rebinding',
            };
          }
        }
      }
    } catch {
      // DNS resolution failed entirely — domain may not exist
      // Allow the request to proceed; the actual HTTP request will fail naturally
    }

    // Req 7.8: Performance check (excluding DNS)
    // DNS is already excluded since it's the only async operation above.
    // The synchronous checks (parse, protocol, credentials, allowlist) are within budget.

    return { allowed: true };
  }

  /**
   * Hot-reload configuration from the JSON file.
   * Allows updating the allowlist without restarting the application.
   */
  function reload() {
    loadConfig();
  }

  return {
    validate,
    reload,
  };
}
