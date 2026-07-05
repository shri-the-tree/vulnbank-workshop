/**
 * Egress Filter - Outbound Request Restriction
 *
 * Restricts all outbound HTTP/HTTPS requests from agent processes to an
 * allowlisted set of destinations. Blocks unauthorized data exfiltration
 * channels including DNS tunneling attempts.
 *
 * Requirements: 23.1, 23.2, 23.3, 23.4, 23.5, 23.6, 23.7, 23.8
 */

import { readFileSync } from 'node:fs';
import { resolve4, resolve6 } from 'node:dns/promises';
import { createAuditLogger } from './audit-logger.js';

/**
 * Private/reserved IPv4 ranges as [network, mask] pairs (unsigned 32-bit).
 * Covers: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 0.0.0.0/32
 */
const PRIVATE_IPV4_RANGES = [
  { network: 0x0A000000, mask: 0xFF000000 },   // 10.0.0.0/8
  { network: 0xAC100000, mask: 0xFFF00000 },   // 172.16.0.0/12
  { network: 0xC0A80000, mask: 0xFFFF0000 },   // 192.168.0.0/16
  { network: 0x7F000000, mask: 0xFF000000 },   // 127.0.0.0/8
  { network: 0xA9FE0000, mask: 0xFFFF0000 },   // 169.254.0.0/16
  { network: 0x00000000, mask: 0xFFFFFFFF },   // 0.0.0.0/32
];

/** Standard HTTP/HTTPS ports */
const STANDARD_PORTS = [80, 443];

/**
 * Parse an IPv4 address string to an unsigned 32-bit integer.
 * @param {string} ip - IPv4 address (e.g., "192.168.1.1")
 * @returns {number|null} Unsigned 32-bit integer or null if invalid
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
 * Expand an IPv6 address to full 32-char hex form (no colons).
 * @param {string} ip - IPv6 address
 * @returns {string|null} Expanded hex string or null
 */
function expandIPv6(ip) {
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
 * Check if an IP address (v4 or v6) is private/reserved.
 * @param {string} ip - IP address string
 * @returns {boolean}
 */
function isPrivateIP(ip) {
  if (ip.includes(':')) {
    return isPrivateIPv6(ip);
  }
  return isPrivateIPv4(ip);
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
      // Wildcard: *.vulnbank.example matches exactly one subdomain level
      const baseDomain = lowerPattern.slice(2);
      if (lowerHost.endsWith('.' + baseDomain)) {
        const prefix = lowerHost.slice(0, lowerHost.length - baseDomain.length - 1);
        if (prefix.length > 0 && !prefix.includes('.')) {
          return true;
        }
      }
    } else {
      if (lowerHost === lowerPattern) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check if a port is allowed for the given policy.
 * @param {number} port - The port number
 * @param {number[]} allowedPorts - List of explicitly allowed ports
 * @returns {boolean}
 */
function isPortAllowed(port, allowedPorts) {
  return allowedPorts.includes(port);
}

/**
 * @typedef {Object} EgressPolicy
 * @property {string[]} allowedDomains - Allowed destination domains
 * @property {number[]} allowedPorts - Allowed destination ports
 * @property {boolean} allowPrivateRanges - Whether private IP ranges are permitted
 */

/**
 * @typedef {Object} EgressCheckResult
 * @property {boolean} allowed - Whether the outbound request is permitted
 * @property {string} [error] - Error description if blocked
 * @property {string} [blockedBy] - Policy that triggered the block
 * @property {string} [resolvedIP] - Resolved IP address (if resolution was performed)
 */

/**
 * @typedef {Object} DNSCheckResult
 * @property {boolean} allowed - Whether the DNS query is permitted
 * @property {string} [error] - Error description if blocked
 * @property {string} [nxdomain] - NXDOMAIN indicator for blocked queries
 */

/**
 * Creates an EgressFilter instance that restricts outbound requests.
 *
 * @param {string} configPath - Path to the egress allowlist JSON configuration file
 * @returns {EgressFilter}
 */
export function createEgressFilter(configPath) {
  const logger = createAuditLogger({ minLevel: 'DEBUG' });
  let globalPolicy = { allowedDomains: [], allowedPorts: STANDARD_PORTS, allowPrivateRanges: false };
  let agentPolicies = {};

  /**
   * Load configuration from the JSON file.
   */
  function loadConfig() {
    try {
      const raw = readFileSync(configPath, 'utf-8');
      const config = JSON.parse(raw);

      globalPolicy = {
        allowedDomains: config.global?.allowedDomains || [],
        allowedPorts: config.global?.allowedPorts || STANDARD_PORTS,
        allowPrivateRanges: config.global?.allowPrivateRanges || false,
      };

      agentPolicies = {};
      if (config.agents) {
        for (const [agentId, policy] of Object.entries(config.agents)) {
          agentPolicies[agentId] = {
            allowedDomains: policy.allowedDomains || [],
            allowedPorts: policy.allowedPorts || STANDARD_PORTS,
            allowPrivateRanges: policy.allowPrivateRanges || false,
          };
        }
      }
    } catch (err) {
      // Fall back to restrictive defaults on config load failure
      logger.log('WARN', 'egress_config_error', {
        reason: err.message,
        configPath,
        fallback: 'restrictive defaults',
      });
      globalPolicy = { allowedDomains: [], allowedPorts: STANDARD_PORTS, allowPrivateRanges: false };
      agentPolicies = {};
    }
  }

  // Initial load
  loadConfig();

  /**
   * Get the effective policy for an agent.
   * Uses per-agent policy if defined, otherwise falls back to global default.
   * @param {string} agentId - Agent identifier
   * @returns {EgressPolicy}
   */
  function getPolicy(agentId) {
    if (agentId && agentPolicies[agentId]) {
      return agentPolicies[agentId];
    }
    return globalPolicy;
  }

  /**
   * Log a blocked egress event.
   * @param {string} agentId - Requesting agent identity
   * @param {string} destinationUrl - The blocked destination URL
   * @param {string} resolvedIP - Resolved IP address (if available)
   * @param {string} reason - Policy that triggered the block
   */
  function logBlocked(agentId, destinationUrl, resolvedIP, reason) {
    logger.logBlockedAttack({
      agentTarget: agentId || 'unknown',
      attackCategory: 'data_exfiltration',
      action: 'blocked',
      destinationUrl,
      resolvedIP: resolvedIP || 'unresolved',
      triggeringPolicy: reason,
    });
  }

  /**
   * Check if an outbound HTTP/HTTPS request is permitted.
   *
   * Validates the destination against the egress allowlist:
   * - Domain must be in the allowlist (Req 23.1, 23.3)
   * - Resolved IP must not be private/reserved unless explicitly allowed (Req 23.2)
   * - Port must be standard (80/443) unless explicitly allowlisted (Req 23.6)
   * - Per-agent policies take precedence over global default (Req 23.4)
   *
   * @param {string} url - The destination URL
   * @param {Object} [context] - Context with agentId
   * @param {string} [context.agentId] - Identity of the requesting agent
   * @returns {Promise<EgressCheckResult>}
   */
  async function check(url, context = {}) {
    const agentId = context.agentId || 'unknown';
    const policy = getPolicy(agentId);

    // Parse the URL
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      logBlocked(agentId, url, null, 'invalid_url');
      return {
        allowed: false,
        error: 'Invalid URL format',
        blockedBy: 'invalid_url',
      };
    }

    const hostname = parsed.hostname;
    const protocol = parsed.protocol.replace(':', '').toLowerCase();

    // Only allow http and https protocols
    if (protocol !== 'http' && protocol !== 'https') {
      logBlocked(agentId, url, null, 'invalid_protocol');
      return {
        allowed: false,
        error: 'Only HTTP and HTTPS protocols are permitted for outbound requests',
        blockedBy: 'invalid_protocol',
      };
    }

    // Determine the effective port
    let port;
    if (parsed.port) {
      port = parseInt(parsed.port, 10);
    } else {
      port = protocol === 'https' ? 443 : 80;
    }

    // Req 23.6: Block non-standard ports unless explicitly allowlisted
    if (!isPortAllowed(port, policy.allowedPorts)) {
      logBlocked(agentId, url, null, 'non_standard_port');
      return {
        allowed: false,
        error: `Port ${port} is not permitted. Allowed ports: ${policy.allowedPorts.join(', ')}`,
        blockedBy: 'non_standard_port',
      };
    }

    // Req 23.1, 23.3: Verify domain against allowlist
    if (!isDomainAllowed(hostname, policy.allowedDomains)) {
      logBlocked(agentId, url, null, 'domain_not_allowed');
      return {
        allowed: false,
        error: 'Destination is not in the permitted egress allowlist',
        blockedBy: 'domain_not_allowed',
      };
    }

    // Check if hostname is a literal IP address first
    const isIPv4Literal = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
    const isIPv6Literal = hostname.startsWith('[') || hostname.includes(':');

    if (isIPv4Literal) {
      if (!policy.allowPrivateRanges && isPrivateIPv4(hostname)) {
        logBlocked(agentId, url, hostname, 'private_ip_range');
        return {
          allowed: false,
          error: 'Destination resolves to a private/reserved IP range',
          blockedBy: 'private_ip_range',
          resolvedIP: hostname,
        };
      }
      return { allowed: true, resolvedIP: hostname };
    }

    if (isIPv6Literal) {
      const rawIPv6 = hostname.replace(/^\[|\]$/g, '');
      if (!policy.allowPrivateRanges && isPrivateIPv6(rawIPv6)) {
        logBlocked(agentId, url, rawIPv6, 'private_ip_range');
        return {
          allowed: false,
          error: 'Destination resolves to a private/reserved IP range',
          blockedBy: 'private_ip_range',
          resolvedIP: rawIPv6,
        };
      }
      return { allowed: true, resolvedIP: rawIPv6 };
    }

    // Req 23.2: Resolve hostname and check for private/reserved IP ranges
    let resolvedIP = null;
    try {
      let addresses = [];
      try {
        const ipv4Addrs = await resolve4(hostname);
        addresses = addresses.concat(ipv4Addrs);
      } catch {
        // No A records
      }

      try {
        const ipv6Addrs = await resolve6(hostname);
        addresses = addresses.concat(ipv6Addrs);
      } catch {
        // No AAAA records
      }

      if (addresses.length > 0) {
        resolvedIP = addresses[0];
      }

      // Check each resolved address for private ranges
      if (!policy.allowPrivateRanges) {
        for (const addr of addresses) {
          if (isPrivateIP(addr)) {
            logBlocked(agentId, url, addr, 'private_ip_range');
            return {
              allowed: false,
              error: 'Destination resolves to a private/reserved IP range',
              blockedBy: 'private_ip_range',
              resolvedIP: addr,
            };
          }
        }
      }
    } catch {
      // DNS resolution failed — the actual request will fail naturally
      // Allow the check to pass; the HTTP client will handle the error
    }

    return { allowed: true, resolvedIP };
  }

  /**
   * Check if a DNS query is permitted (DNS tunneling prevention).
   *
   * Blocks DNS resolution for domains not in any allowlist.
   * Returns NXDOMAIN indicator and logs dns-exfiltration-attempt for blocked queries.
   *
   * @param {string} domain - The domain being queried
   * @param {Object} [context] - Context with agentId
   * @param {string} [context.agentId] - Identity of the requesting agent
   * @returns {DNSCheckResult}
   */
  function checkDNS(domain, context = {}) {
    const agentId = context.agentId || 'unknown';
    const policy = getPolicy(agentId);

    // Check the domain against the allowlist
    if (!isDomainAllowed(domain, policy.allowedDomains)) {
      // Log dns-exfiltration-attempt event
      logger.log('WARN', 'dns-exfiltration-attempt', {
        agentTarget: agentId,
        domain,
        action: 'blocked',
        reason: 'Domain not in egress allowlist',
      });

      return {
        allowed: false,
        error: 'NXDOMAIN',
        nxdomain: true,
      };
    }

    return { allowed: true };
  }

  /**
   * Hot-reload configuration from the JSON file.
   */
  function reload() {
    loadConfig();
  }

  /**
   * Get the effective policy for an agent (for inspection/testing).
   * @param {string} agentId - Agent identifier
   * @returns {EgressPolicy}
   */
  function getEffectivePolicy(agentId) {
    return getPolicy(agentId);
  }

  return {
    check,
    checkDNS,
    reload,
    getEffectivePolicy,
  };
}
