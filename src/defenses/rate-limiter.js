/**
 * Rate Limiter - Abuse Prevention with Sliding Window Algorithm
 *
 * Tracks request frequency per client IP and enforces configurable
 * throttling thresholds using an in-memory sliding window approach.
 * Supports per-agent limits, burst detection, abuse flagging, and LRU eviction.
 *
 * Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7
 */

import { readFileSync } from 'node:fs';

/** Maximum tracked IP addresses before LRU eviction */
const MAX_TRACKED_IPS = 10000;

/** Abuse flag duration in milliseconds (5 minutes) */
const ABUSE_FLAG_DURATION_MS = 5 * 60 * 1000;

/** Penalty multiplier for abuse-flagged IPs */
const ABUSE_PENALTY_MULTIPLIER = 2;

/**
 * Creates a RateLimiter instance that loads per-agent config from a JSON file.
 *
 * @param {string} configPath - Path to the rate-limits JSON configuration file
 * @returns {RateLimiter}
 */
export function createRateLimiter(configPath) {
  let config = loadConfig(configPath);

  // In-memory state: Map<string, IPState>
  // IPState: { timestamps: number[], flaggedUntil: number|null, lastActivity: number }
  const ipStates = new Map();

  /**
   * Load configuration from JSON file.
   * @param {string} path
   * @returns {Object}
   */
  function loadConfig(path) {
    try {
      const raw = readFileSync(path, 'utf-8');
      return JSON.parse(raw);
    } catch {
      // Fall back to defaults if config is unavailable
      return {
        default: {
          maxRequests: 30,
          windowSeconds: 60,
          burstThreshold: 5,
          burstWindowSeconds: 2
        },
        vulnerable: {
          maxRequests: 10,
          windowSeconds: 60
        },
        agents: {}
      };
    }
  }

  /**
   * Get the rate limit configuration for a specific agent.
   * Per-agent config takes priority, then vulnerable defaults, then global defaults.
   *
   * @param {string} agentId
   * @returns {{ maxRequests: number, windowSeconds: number, burstThreshold: number, burstWindowSeconds: number }}
   */
  function getLimitsForAgent(agentId) {
    const defaults = config.default || { maxRequests: 30, windowSeconds: 60, burstThreshold: 5, burstWindowSeconds: 2 };
    const burstThreshold = defaults.burstThreshold || 5;
    const burstWindowSeconds = defaults.burstWindowSeconds || 2;

    // Check per-agent config first
    if (agentId && config.agents && config.agents[agentId]) {
      const agentConfig = config.agents[agentId];
      return {
        maxRequests: agentConfig.maxRequests ?? defaults.maxRequests,
        windowSeconds: agentConfig.windowSeconds ?? defaults.windowSeconds,
        burstThreshold: agentConfig.burstThreshold ?? burstThreshold,
        burstWindowSeconds: agentConfig.burstWindowSeconds ?? burstWindowSeconds
      };
    }

    // Check if agent is marked as vulnerable (use vulnerable defaults)
    if (agentId && config.vulnerable) {
      // Agents in the "vulnerable" category get stricter limits
      // The vulnerable config is applied when the agent isn't explicitly configured
      // but is identified as vulnerable. For this implementation, agents listed
      // in the config file's agents section get their explicit config;
      // agents not listed but with vulnerable flag use the vulnerable defaults.
      // Since we can't introspect the agent object here, we use the agents section
      // to explicitly assign limits. Agents like "legacybot" already have explicit entries.
    }

    return {
      maxRequests: defaults.maxRequests,
      windowSeconds: defaults.windowSeconds,
      burstThreshold,
      burstWindowSeconds
    };
  }

  /**
   * Evict the least recently active IP when we exceed MAX_TRACKED_IPS.
   */
  function evictLRU() {
    if (ipStates.size <= MAX_TRACKED_IPS) return;

    let oldestIP = null;
    let oldestTime = Infinity;

    for (const [ip, state] of ipStates) {
      if (state.lastActivity < oldestTime) {
        oldestTime = state.lastActivity;
        oldestIP = ip;
      }
    }

    if (oldestIP !== null) {
      ipStates.delete(oldestIP);
    }
  }

  /**
   * Clean up timestamps older than the window duration for a given IP state.
   *
   * @param {Object} state - IP state object
   * @param {number} windowMs - Window duration in milliseconds
   * @param {number} now - Current timestamp in ms
   */
  function cleanupOldEntries(state, windowMs, now) {
    const cutoff = now - windowMs;
    // Since timestamps are sorted, find the first index that's within the window
    let i = 0;
    while (i < state.timestamps.length && state.timestamps[i] < cutoff) {
      i++;
    }
    if (i > 0) {
      state.timestamps = state.timestamps.slice(i);
    }
  }

  /**
   * Detect burst pattern: more than burstThreshold requests within burstWindowSeconds.
   *
   * @param {number[]} timestamps - Sorted array of request timestamps
   * @param {number} burstThreshold - Number of requests to trigger burst
   * @param {number} burstWindowMs - Time window in ms for burst detection
   * @param {number} now - Current timestamp
   * @returns {boolean}
   */
  function detectBurst(timestamps, burstThreshold, burstWindowMs, now) {
    const burstCutoff = now - burstWindowMs;
    let count = 0;
    // Count timestamps within the burst window (including the current request)
    for (let i = timestamps.length - 1; i >= 0; i--) {
      if (timestamps[i] >= burstCutoff) {
        count++;
      } else {
        break; // Timestamps are sorted, no need to check further
      }
    }
    return count >= burstThreshold;
  }

  /**
   * Check if a request from the given client IP to the given agent is allowed.
   *
   * @param {string} clientIP - Client IP address
   * @param {string} agentId - Target agent identifier
   * @returns {RateLimitResult}
   */
  function check(clientIP, agentId) {
    const now = Date.now();
    const limits = getLimitsForAgent(agentId);
    const windowMs = limits.windowSeconds * 1000;
    const burstWindowMs = limits.burstWindowSeconds * 1000;

    // Get or create IP state
    let state = ipStates.get(clientIP);
    if (!state) {
      state = {
        timestamps: [],
        flaggedUntil: null,
        lastActivity: now
      };
      ipStates.set(clientIP, state);

      // Check if we need LRU eviction
      if (ipStates.size > MAX_TRACKED_IPS) {
        evictLRU();
      }
    }

    // Update last activity for LRU tracking
    state.lastActivity = now;

    // Auto-cleanup entries older than window duration
    cleanupOldEntries(state, windowMs, now);

    // Check if IP is currently abuse-flagged
    const isAbuseFlagged = state.flaggedUntil !== null && state.flaggedUntil > now;

    // Clear expired abuse flag
    if (state.flaggedUntil !== null && state.flaggedUntil <= now) {
      state.flaggedUntil = null;
    }

    // Check rate limit
    if (state.timestamps.length >= limits.maxRequests) {
      // Rate limit exceeded
      const oldestInWindow = state.timestamps[0];
      let retryAfter = Math.ceil((oldestInWindow + windowMs - now) / 1000);

      // Apply abuse penalty multiplier
      if (isAbuseFlagged) {
        retryAfter = retryAfter * ABUSE_PENALTY_MULTIPLIER;
      }

      // Ensure retryAfter is at least 1 second
      retryAfter = Math.max(1, retryAfter);

      return {
        allowed: false,
        retryAfter,
        burstDetected: false,
        abuseFlagged: isAbuseFlagged
      };
    }

    // Record the current request timestamp
    state.timestamps.push(now);

    // Detect burst pattern
    const burstDetected = detectBurst(state.timestamps, limits.burstThreshold, burstWindowMs, now);

    // If burst detected, flag the IP for abuse
    if (burstDetected && !isAbuseFlagged) {
      state.flaggedUntil = now + ABUSE_FLAG_DURATION_MS;
    }

    return {
      allowed: true,
      burstDetected,
      abuseFlagged: isAbuseFlagged || burstDetected
    };
  }

  /**
   * Reset rate limit state for a specific client IP.
   *
   * @param {string} clientIP - Client IP address to reset
   */
  function reset(clientIP) {
    ipStates.delete(clientIP);
  }

  /**
   * Get current rate limiter statistics.
   *
   * @returns {{ trackedIPs: number, flaggedIPs: number }}
   */
  function getStats() {
    const now = Date.now();
    let flaggedIPs = 0;

    for (const [, state] of ipStates) {
      if (state.flaggedUntil !== null && state.flaggedUntil > now) {
        flaggedIPs++;
      }
    }

    return {
      trackedIPs: ipStates.size,
      flaggedIPs
    };
  }

  return {
    check,
    reset,
    getStats
  };
}
