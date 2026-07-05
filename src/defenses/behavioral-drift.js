/**
 * Behavioral Drift Detector - Persona Drift Detection via Sliding Window Analysis
 *
 * Monitors agent response patterns over a configurable sliding window and raises
 * alerts when output deviates from established behavioral baselines. Detects:
 * - Response length deviation (>2 std dev from window average)
 * - Refusal rate drops (below 50% of baseline within 5 interactions)
 * - Topic adherence drift (cosine similarity below threshold for 3+ consecutive responses)
 *
 * Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7, 14.8, 14.9
 */

import { readFileSync } from 'node:fs';

/** Default configuration values */
const DEFAULT_CONFIG = {
  windowSize: 10,
  responseLengthDeviationThreshold: 2.0,
  refusalRateBaseline: 0.1,
  topicAdherenceThreshold: 0.6,
  contextResetEnabled: false,
  systemPrompt: ''
};

/**
 * Compute cosine similarity between two text strings using bag-of-words term frequency vectors.
 * Splits on whitespace, builds term frequency maps, computes cosine similarity.
 *
 * @param {string} textA - First text
 * @param {string} textB - Second text
 * @returns {number} Cosine similarity score between 0.0 and 1.0
 */
function cosineSimilarity(textA, textB) {
  if (!textA || !textB) return 0.0;

  const tokenize = (text) => text.toLowerCase().split(/\s+/).filter(t => t.length > 0);

  const tokensA = tokenize(textA);
  const tokensB = tokenize(textB);

  if (tokensA.length === 0 || tokensB.length === 0) return 0.0;

  // Build term frequency maps
  const tfA = new Map();
  for (const token of tokensA) {
    tfA.set(token, (tfA.get(token) || 0) + 1);
  }

  const tfB = new Map();
  for (const token of tokensB) {
    tfB.set(token, (tfB.get(token) || 0) + 1);
  }

  // Compute dot product and magnitudes
  let dotProduct = 0;
  let magnitudeA = 0;
  let magnitudeB = 0;

  for (const [term, freqA] of tfA) {
    magnitudeA += freqA * freqA;
    const freqB = tfB.get(term) || 0;
    dotProduct += freqA * freqB;
  }

  for (const [, freqB] of tfB) {
    magnitudeB += freqB * freqB;
  }

  magnitudeA = Math.sqrt(magnitudeA);
  magnitudeB = Math.sqrt(magnitudeB);

  if (magnitudeA === 0 || magnitudeB === 0) return 0.0;

  return dotProduct / (magnitudeA * magnitudeB);
}

/**
 * Compute standard deviation of an array of numbers.
 *
 * @param {number[]} values - Array of numeric values
 * @param {number} mean - Pre-computed mean
 * @returns {number} Standard deviation
 */
function standardDeviation(values, mean) {
  if (values.length === 0) return 0;
  const squaredDiffs = values.map(v => (v - mean) ** 2);
  const avgSquaredDiff = squaredDiffs.reduce((sum, d) => sum + d, 0) / values.length;
  return Math.sqrt(avgSquaredDiff);
}

/**
 * Creates a BehavioralDriftDetector instance that loads per-agent config from a JSON file.
 *
 * @param {string} configPath - Path to the drift-baselines JSON configuration file
 * @returns {BehavioralDriftDetector}
 */
export function createBehavioralDriftDetector(configPath) {
  let config = loadConfig(configPath);

  // Per-agent sliding window state
  // Map<agentId, AgentState>
  // AgentState: {
  //   responses: Array<{ length: number, wasRefusal: boolean, topicAdherence: number }>,
  //   consecutiveLowAdherence: number,
  //   alerts: Array<Object>
  // }
  const agentStates = new Map();

  /**
   * Load configuration from JSON file with fallback to defaults.
   * Req 14.9: Fall back to default config on missing/invalid JSON file.
   *
   * @param {string} path - Path to JSON configuration file
   * @returns {Object} Parsed configuration
   */
  function loadConfig(path) {
    try {
      const raw = readFileSync(path, 'utf-8');
      const parsed = JSON.parse(raw);
      return parsed;
    } catch (err) {
      // Log configuration error and fall back to defaults
      console.warn(`[behavioral-drift] Configuration error: ${path} - ${err.message}. Using defaults.`);
      return {
        defaults: { ...DEFAULT_CONFIG },
        agents: {}
      };
    }
  }

  /**
   * Get the configuration for a specific agent, merging with defaults.
   *
   * @param {string} agentId - Agent identifier
   * @returns {Object} Merged agent configuration
   */
  function getAgentConfig(agentId) {
    const defaults = config.defaults || DEFAULT_CONFIG;
    const agentSpecific = (config.agents && config.agents[agentId]) || {};

    return {
      windowSize: agentSpecific.windowSize ?? defaults.windowSize ?? DEFAULT_CONFIG.windowSize,
      responseLengthDeviationThreshold: agentSpecific.responseLengthDeviationThreshold ?? defaults.responseLengthDeviationThreshold ?? DEFAULT_CONFIG.responseLengthDeviationThreshold,
      refusalRateBaseline: agentSpecific.refusalRateBaseline ?? defaults.refusalRateBaseline ?? DEFAULT_CONFIG.refusalRateBaseline,
      topicAdherenceThreshold: agentSpecific.topicAdherenceThreshold ?? defaults.topicAdherenceThreshold ?? DEFAULT_CONFIG.topicAdherenceThreshold,
      contextResetEnabled: agentSpecific.contextResetEnabled ?? defaults.contextResetEnabled ?? DEFAULT_CONFIG.contextResetEnabled,
      systemPrompt: agentSpecific.systemPrompt ?? defaults.systemPrompt ?? DEFAULT_CONFIG.systemPrompt
    };
  }

  /**
   * Get or create the sliding window state for an agent.
   *
   * @param {string} agentId - Agent identifier
   * @returns {Object} Agent state
   */
  function getAgentState(agentId) {
    if (!agentStates.has(agentId)) {
      agentStates.set(agentId, {
        responses: [],
        consecutiveLowAdherence: 0,
        alerts: []
      });
    }
    return agentStates.get(agentId);
  }

  /**
   * Log a drift alert with structured information.
   * Req 14.7: Log alerts with drift type, triggering values, baseline values, timestamp.
   *
   * @param {string} agentId - Agent identifier
   * @param {string} driftType - Type of drift detected
   * @param {Object} triggeringValues - Current metric values that triggered the alert
   * @param {Object} baselineValues - Baseline metric values for comparison
   */
  function logDriftAlert(agentId, driftType, triggeringValues, baselineValues) {
    const alert = {
      timestamp: new Date().toISOString(),
      agentId,
      driftType,
      triggeringValues,
      baselineValues
    };

    const state = getAgentState(agentId);
    state.alerts.push(alert);

    // Log to console (in production this would go to the Audit Logger)
    console.warn(`[behavioral-drift] ALERT agent=${agentId} type=${driftType}`, JSON.stringify(alert));
  }

  /**
   * Record a response and check for behavioral drift.
   * Req 14.1: Maintain sliding window of agent output characteristics.
   * Req 14.2: Skip evaluation during baseline building phase.
   *
   * @param {string} agentId - Agent identifier
   * @param {string} response - The agent's response text
   * @param {boolean} wasRefusal - Whether this response was a refusal
   * @returns {DriftCheckResult}
   */
  function recordResponse(agentId, response, wasRefusal) {
    const agentConfig = getAgentConfig(agentId);
    const state = getAgentState(agentId);
    const windowSize = agentConfig.windowSize;

    // Compute topic adherence score via cosine similarity
    const topicAdherence = agentConfig.systemPrompt
      ? cosineSimilarity(response, agentConfig.systemPrompt)
      : 1.0; // If no system prompt configured, assume full adherence

    // Record the response in the sliding window
    const entry = {
      length: response.length,
      wasRefusal,
      topicAdherence
    };

    state.responses.push(entry);

    // Maintain sliding window size - keep one extra for baseline comparison
    // We compute baseline from the window BEFORE adding current, then evaluate current
    if (state.responses.length > windowSize + 1) {
      state.responses = state.responses.slice(state.responses.length - (windowSize + 1));
    }

    // Req 14.2: Skip drift evaluation until window is full (baseline building phase)
    // Need windowSize responses to establish baseline, then evaluate the next one
    if (state.responses.length <= windowSize) {
      // Reset consecutive counter during baseline building since we're not evaluating yet
      state.consecutiveLowAdherence = 0;
      return { driftDetected: false };
    }

    // --- Evaluate drift metrics ---
    // Use the previous windowSize entries (excluding current) as baseline
    const baselineWindow = state.responses.slice(0, -1);
    // After evaluation, trim to keep only the most recent windowSize entries
    state.responses = state.responses.slice(-windowSize);

    // Req 14.3: Response length deviation (>2 std dev from window average)
    const lengths = baselineWindow.map(r => r.length);
    const avgLength = lengths.reduce((sum, l) => sum + l, 0) / lengths.length;
    const rawStdDev = standardDeviation(lengths, avgLength);
    const currentLength = response.length;

    // When std dev is 0 (all identical lengths), use a minimum stdDev floor
    // to avoid flagging trivial differences. Floor is 10% of average or 10 chars minimum.
    const stdDevFloor = Math.max(avgLength * 0.1, 10);
    const stdDev = rawStdDev > 0 ? rawStdDev : stdDevFloor;
    const lengthDeviation = Math.abs(currentLength - avgLength) / stdDev;
    const lengthDrifted = lengthDeviation > agentConfig.responseLengthDeviationThreshold;

    if (lengthDrifted) {
      const metrics = {
        currentLength,
        avgLength: Math.round(avgLength * 100) / 100,
        stdDev: Math.round(stdDev * 100) / 100,
        deviation: Math.round(lengthDeviation * 100) / 100
      };

      const baselineMetrics = {
        avgLength: Math.round(avgLength * 100) / 100,
        stdDev: Math.round(stdDev * 100) / 100,
        threshold: agentConfig.responseLengthDeviationThreshold
      };

      logDriftAlert(agentId, 'response_length', metrics, baselineMetrics);

      const result = {
        driftDetected: true,
        driftType: 'response_length',
        metrics
      };

      // Req 14.8: Support context-reset on drift when enabled
      if (agentConfig.contextResetEnabled) {
        result.contextReset = true;
      }

      return result;
    }

    // Req 14.4: Refusal rate drop below 50% of baseline within 5 interactions
    // Baseline is computed from the full sliding window; the configured refusalRateBaseline
    // serves as the minimum expected baseline (floor) when the window has insufficient data.
    const recentCount = Math.min(5, state.responses.length);
    const recentResponses = state.responses.slice(-recentCount);
    const recentRefusals = recentResponses.filter(r => r.wasRefusal).length;
    const recentRefusalRate = recentRefusals / recentCount;

    // Compute baseline refusal rate from the baseline window
    const baselineRefusals = baselineWindow.filter(r => r.wasRefusal).length;
    const baselineObservedRate = baselineRefusals / baselineWindow.length;

    // The baseline is the rate from the window;
    // use configured baseline as floor when observed rate is lower
    const baselineRefusalRate = Math.max(baselineObservedRate, agentConfig.refusalRateBaseline);

    if (baselineRefusalRate > 0 && recentRefusalRate < baselineRefusalRate * 0.5) {
      const metrics = {
        recentRefusalRate: Math.round(recentRefusalRate * 1000) / 1000,
        baselineRefusalRate: Math.round(baselineRefusalRate * 1000) / 1000,
        recentInteractions: recentCount
      };

      const baselineMetrics = {
        baselineRefusalRate: Math.round(baselineRefusalRate * 1000) / 1000,
        threshold: '50% of baseline',
        windowSize: recentCount
      };

      logDriftAlert(agentId, 'refusal_rate', metrics, baselineMetrics);

      const result = {
        driftDetected: true,
        driftType: 'refusal_rate',
        metrics
      };

      if (agentConfig.contextResetEnabled) {
        result.contextReset = true;
      }

      return result;
    }

    // Req 14.5 & 14.6: Topic adherence below threshold for 3+ consecutive responses
    if (topicAdherence < agentConfig.topicAdherenceThreshold) {
      state.consecutiveLowAdherence++;
    } else {
      state.consecutiveLowAdherence = 0;
    }

    if (state.consecutiveLowAdherence >= 3) {
      const metrics = {
        currentAdherence: Math.round(topicAdherence * 1000) / 1000,
        consecutiveViolations: state.consecutiveLowAdherence,
        threshold: agentConfig.topicAdherenceThreshold
      };

      const baselineMetrics = {
        threshold: agentConfig.topicAdherenceThreshold,
        consecutiveRequired: 3
      };

      logDriftAlert(agentId, 'topic_adherence', metrics, baselineMetrics);

      const result = {
        driftDetected: true,
        driftType: 'topic_adherence',
        metrics
      };

      if (agentConfig.contextResetEnabled) {
        result.contextReset = true;
      }

      return result;
    }

    return { driftDetected: false };
  }

  /**
   * Get baseline metrics for an agent from its sliding window.
   *
   * @param {string} agentId - Agent identifier
   * @returns {{ avgLength: number, refusalRate: number, topicAdherence: number }}
   */
  function getBaseline(agentId) {
    const state = getAgentState(agentId);

    if (state.responses.length === 0) {
      return { avgLength: 0, refusalRate: 0, topicAdherence: 0 };
    }

    const lengths = state.responses.map(r => r.length);
    const avgLength = lengths.reduce((sum, l) => sum + l, 0) / lengths.length;

    const refusals = state.responses.filter(r => r.wasRefusal).length;
    const refusalRate = refusals / state.responses.length;

    const adherences = state.responses.map(r => r.topicAdherence);
    const topicAdherence = adherences.reduce((sum, a) => sum + a, 0) / adherences.length;

    return {
      avgLength: Math.round(avgLength * 100) / 100,
      refusalRate: Math.round(refusalRate * 1000) / 1000,
      topicAdherence: Math.round(topicAdherence * 1000) / 1000
    };
  }

  /**
   * Reset all state for a specific agent.
   *
   * @param {string} agentId - Agent identifier
   */
  function reset(agentId) {
    agentStates.delete(agentId);
  }

  return {
    recordResponse,
    getBaseline,
    reset
  };
}
