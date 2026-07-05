/**
 * Defense Orchestrator - Central coordinator for all defense modules
 *
 * Wires individual defense modules into the agent request/response pipeline
 * based on the active BANK_PROFILE and per-level HARDEN_Ln toggles.
 * Re-evaluates environment variables on each request so toggle changes
 * apply within 1 second without requiring a server restart.
 *
 * Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9, 15.10
 */

import { fileURLToPath } from 'url';
import path from 'path';
import { getBankProfile, isHardenEnabled, isL5AimEnforced } from '../bank/profile.js';
import { createInputValidator } from './input-validator.js';
import { createOutputFilter } from './output-filter.js';
import { createRateLimiter } from './rate-limiter.js';
import { createMemorySanitizer } from './memory-sanitizer.js';
import { createQueryParameterizer } from './query-parameterizer.js';
import { createPathValidator } from './path-validator.js';
import { createUrlValidator } from './url-validator.js';
import { createIdentityVerifier } from './identity-verifier.js';
import { createToolRegistryVerifier } from './tool-registry-verifier.js';
import { createBehavioralDriftDetector } from './behavioral-drift.js';
import { createSecurityHeadersMiddleware } from './security-headers.js';
import { createAuditLogger } from './audit-logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_DIR = path.join(__dirname, 'config');

/**
 * Creates shared module instances (singletons).
 * These are instantiated once and reused across requests.
 */
function createModuleInstances() {
  const inputValidator = createInputValidator(path.join(CONFIG_DIR, 'patterns.json'));
  const outputFilter = createOutputFilter(path.join(CONFIG_DIR, 'output-allowlist.json'));
  const rateLimiter = createRateLimiter(path.join(CONFIG_DIR, 'rate-limits.json'));
  const memorySanitizer = createMemorySanitizer(path.join(CONFIG_DIR, 'memory-patterns.json'));
  const queryParameterizer = createQueryParameterizer(path.join(CONFIG_DIR, 'query-templates.json'));
  const pathValidator = createPathValidator('./workspace/sandbox');
  const urlValidator = createUrlValidator(path.join(CONFIG_DIR, 'url-allowlist.json'));
  const identityVerifier = createIdentityVerifier({}, []);
  const toolRegistryVerifier = createToolRegistryVerifier(null);
  const behavioralDriftDetector = createBehavioralDriftDetector(path.join(CONFIG_DIR, 'drift-baselines.json'));
  const securityHeadersMiddleware = createSecurityHeadersMiddleware({ isAgentRoute: true });
  const auditLogger = createAuditLogger({ minLevel: 'INFO' });

  return {
    inputValidator,
    outputFilter,
    rateLimiter,
    memorySanitizer,
    queryParameterizer,
    pathValidator,
    urlValidator,
    identityVerifier,
    toolRegistryVerifier,
    behavioralDriftDetector,
    securityHeadersMiddleware,
    auditLogger,
  };
}

/**
 * Determines which defense modules are active for a given agent
 * based on the current profile and HARDEN_Ln toggles.
 *
 * @param {string} agentId - The agent's ID
 * @returns {{ preRequest: string[], postResponse: string[], global: string[] }}
 */
function getActiveModulesForAgent(agentId) {
  const profile = getBankProfile();

  // Req 15.1, 15.9: participant mode or unrecognized profile → passthrough
  if (profile !== 'demo') {
    return { preRequest: [], postResponse: [], global: [] };
  }

  const preRequest = [];
  const postResponse = [];
  const global = [];

  // Req 15.3: L1 → Input_Validator + Output_Filter for HelperBot
  if (isHardenEnabled(1) && agentId === 'helperbot') {
    preRequest.push('inputValidator');
    postResponse.push('outputFilter');
  }

  // Req 15.4: L2 → Output_Filter + Memory_Sanitizer for RAGBot
  if (isHardenEnabled(2) && agentId === 'ragbot') {
    postResponse.push('outputFilter');
    preRequest.push('memorySanitizer');
  }

  // Req 15.5: L3 → Query_Parameterizer + Path_Validator + URL_Validator for DataBot/ToolBot
  if (isHardenEnabled(3) && (agentId === 'databot' || agentId === 'toolbot')) {
    preRequest.push('queryParameterizer');
    preRequest.push('pathValidator');
    preRequest.push('urlValidator');
  }

  // Req 15.6: L4 → Memory_Sanitizer + Behavioral_Drift_Detector for MemoryBot
  if (isHardenEnabled(4) && agentId === 'memorybot') {
    preRequest.push('memorySanitizer');
    postResponse.push('behavioralDriftDetector');
  }

  // Req 15.7: L5 (+ AIM) → Identity_Verifier + Tool_Registry_Verifier for A2A Worker
  if (isL5AimEnforced() && agentId === 'worker-1') {
    preRequest.push('identityVerifier');
    preRequest.push('toolRegistryVerifier');
  }

  // Req 15.8: Any HARDEN_Ln=on → Rate_Limiter, Security_Headers, Audit_Logger for ALL agents
  const anyLevelEnabled = isHardenEnabled(1) || isHardenEnabled(2) ||
    isHardenEnabled(3) || isHardenEnabled(4) || isHardenEnabled(5);

  if (anyLevelEnabled) {
    global.push('rateLimiter');
    global.push('securityHeadersMiddleware');
    global.push('auditLogger');
  }

  return { preRequest, postResponse, global };
}

/**
 * Creates a Defense Orchestrator instance.
 *
 * @param {Object[]} agentDefs - Array of agent definition objects (from agents.js)
 * @returns {DefenseOrchestrator}
 */
export function createOrchestrator(agentDefs) {
  const modules = createModuleInstances();
  const agentMap = new Map();

  // Index agents by ID for fast lookup
  for (const agent of agentDefs) {
    agentMap.set(agent.id, agent);
  }

  /**
   * Re-evaluates HARDEN_Ln env vars and rebuilds active defense config.
   * Called on every request to support runtime toggle changes (Req 15.10).
   * Since getBankProfile() and isHardenEnabled() read process.env directly,
   * calling getActiveModulesForAgent on each request ensures changes apply
   * within the same request cycle (well within 1 second).
   */
  function refreshConfig() {
    // No-op: config is evaluated lazily per-request via getActiveModulesForAgent.
    // This function exists for API compatibility and to signal intent.
    // The actual env-var reads happen in getBankProfile/isHardenEnabled on each call.
  }

  /**
   * Runs the pre-request defense pipeline for an agent.
   *
   * @param {Object} req - HTTP request object
   * @param {Object} res - HTTP response object
   * @param {Object} agent - Agent definition
   * @param {Object} activeModules - Active modules config
   * @param {string} userMessage - The user's input message
   * @returns {{ blocked: boolean, sanitizedMessage?: string, blockResponse?: Object }}
   */
  function runPreRequestPipeline(req, res, agent, activeModules, userMessage) {
    const { preRequest, global } = activeModules;

    // Apply global rate limiting first
    if (global.includes('rateLimiter') && modules.rateLimiter) {
      const clientIP = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1';
      const rateLimitResult = modules.rateLimiter.check(clientIP, agent.id);
      if (rateLimitResult && !rateLimitResult.allowed) {
        return {
          blocked: true,
          blockResponse: {
            status: 429,
            body: {
              error: 'rate_limited',
              retryAfter: rateLimitResult.retryAfter || 60,
              message: 'Too many requests. Please try again later.',
            },
          },
        };
      }
    }

    // Apply security headers
    if (global.includes('securityHeadersMiddleware') && modules.securityHeadersMiddleware) {
      modules.securityHeadersMiddleware(req, res, () => {});
    }

    let sanitizedMessage = userMessage;

    // Run per-agent pre-request modules
    for (const moduleName of preRequest) {
      const mod = modules[moduleName];
      if (!mod) continue;

      switch (moduleName) {
        case 'inputValidator': {
          const result = mod.check(sanitizedMessage, { agentId: agent.id });
          if (result && !result.pass) {
            // Log to audit logger if available
            if (global.includes('auditLogger') && modules.auditLogger) {
              modules.auditLogger.log('WARN', 'input_blocked', {
                agentId: agent.id,
                category: result.category,
                action: result.action,
              });
            }
            return {
              blocked: true,
              blockResponse: {
                status: 200,
                body: result.refusal || {
                  blocked: true,
                  category: result.category,
                  message: 'Input rejected by security policy.',
                },
              },
            };
          }
          if (result && result.sanitized) {
            sanitizedMessage = result.sanitized;
          }
          break;
        }
        case 'memorySanitizer': {
          // Memory sanitizer validates memory write operations
          // For pre-request, we check if the message looks like a memory injection
          if (mod.validateWrite) {
            const writeResult = mod.validateWrite(sanitizedMessage, { userId: req.headers['x-user-id'] || 'anonymous' });
            if (writeResult && !writeResult.allowed) {
              if (global.includes('auditLogger') && modules.auditLogger) {
                modules.auditLogger.log('WARN', 'memory_injection_blocked', {
                  agentId: agent.id,
                  reason: writeResult.reason,
                });
              }
              return {
                blocked: true,
                blockResponse: {
                  status: 200,
                  body: {
                    blocked: true,
                    category: 'memory_injection',
                    message: writeResult.reason || 'Memory write rejected by security policy.',
                  },
                },
              };
            }
          }
          break;
        }
        case 'queryParameterizer': {
          // Validate and parameterize SQL queries in the message
          if (mod.parameterize) {
            const paramResult = mod.parameterize(sanitizedMessage);
            if (paramResult && paramResult.rejected) {
              if (global.includes('auditLogger') && modules.auditLogger) {
                modules.auditLogger.log('WARN', 'sql_injection_blocked', {
                  agentId: agent.id,
                  reason: paramResult.reason,
                });
              }
              return {
                blocked: true,
                blockResponse: {
                  status: 200,
                  body: {
                    blocked: true,
                    category: 'sql_injection',
                    message: 'Query rejected by security policy.',
                  },
                },
              };
            }
          }
          break;
        }
        case 'pathValidator': {
          // Validate file paths referenced in the message
          if (mod.validate) {
            const pathResult = mod.validate(sanitizedMessage);
            if (pathResult && !pathResult.allowed) {
              if (global.includes('auditLogger') && modules.auditLogger) {
                modules.auditLogger.log('WARN', 'path_traversal_blocked', {
                  agentId: agent.id,
                  violationType: pathResult.violationType,
                });
              }
              return {
                blocked: true,
                blockResponse: {
                  status: 200,
                  body: {
                    blocked: true,
                    category: 'path_traversal',
                    message: pathResult.error || 'Path access denied by security policy.',
                  },
                },
              };
            }
          }
          break;
        }
        case 'urlValidator': {
          // Validate URLs referenced in the message
          if (mod.validate) {
            const urlResult = mod.validate(sanitizedMessage);
            if (urlResult && !urlResult.allowed) {
              if (global.includes('auditLogger') && modules.auditLogger) {
                modules.auditLogger.log('WARN', 'ssrf_blocked', {
                  agentId: agent.id,
                  reason: urlResult.reason,
                });
              }
              return {
                blocked: true,
                blockResponse: {
                  status: 200,
                  body: {
                    blocked: true,
                    category: 'ssrf',
                    message: urlResult.reason || 'URL access denied by security policy.',
                  },
                },
              };
            }
          }
          break;
        }
        case 'identityVerifier': {
          // Verify cryptographic identity for A2A communication
          if (mod.verify) {
            const token = req.headers['authorization']?.replace('Bearer ', '') || '';
            const verifyResult = mod.verify(token);
            if (verifyResult && !verifyResult.valid) {
              if (global.includes('auditLogger') && modules.auditLogger) {
                modules.auditLogger.log('WARN', 'identity_verification_failed', {
                  agentId: agent.id,
                  reason: verifyResult.reason,
                });
              }
              return {
                blocked: true,
                blockResponse: {
                  status: 401,
                  body: {
                    blocked: true,
                    category: 'identity_verification',
                    message: verifyResult.reason || 'Identity verification failed.',
                  },
                },
              };
            }
          }
          break;
        }
        case 'toolRegistryVerifier': {
          // Verify tool integrity before execution
          // This is typically checked when tool calls are made, not on initial request
          break;
        }
      }
    }

    return { blocked: false, sanitizedMessage };
  }

  /**
   * Runs the post-response defense pipeline for an agent.
   *
   * @param {Object} agent - Agent definition
   * @param {Object} activeModules - Active modules config
   * @param {string} responseText - The agent's raw response
   * @returns {string} The filtered response text
   */
  function runPostResponsePipeline(agent, activeModules, responseText) {
    const { postResponse, global } = activeModules;
    let filtered = responseText;

    for (const moduleName of postResponse) {
      const mod = modules[moduleName];
      if (!mod) continue;

      switch (moduleName) {
        case 'outputFilter': {
          if (mod.apply) {
            const result = mod.apply(filtered, { agentId: agent.id, agentName: agent.name });
            if (result && result.filtered) {
              filtered = result.filtered;
              // Log redactions
              if (result.redactions && result.redactions.length > 0 && global.includes('auditLogger') && modules.auditLogger) {
                modules.auditLogger.log('INFO', 'output_redacted', {
                  agentId: agent.id,
                  redactionCount: result.redactions.length,
                  types: result.redactions.map(r => r.type),
                });
              }
            }
          }
          break;
        }
        case 'behavioralDriftDetector': {
          if (mod.analyze) {
            const driftResult = mod.analyze(filtered, { agentId: agent.id });
            if (driftResult && driftResult.driftDetected) {
              if (global.includes('auditLogger') && modules.auditLogger) {
                modules.auditLogger.log('WARN', 'behavioral_drift_detected', {
                  agentId: agent.id,
                  indicators: driftResult.indicators,
                });
              }
            }
          }
          break;
        }
      }
    }

    // Log the request via audit logger
    if (global.includes('auditLogger') && modules.auditLogger) {
      modules.auditLogger.log('INFO', 'request_completed', {
        agentId: agent.id,
        timestamp: Date.now(),
      });
    }

    return filtered;
  }

  /**
   * Main request handler that wires the pre-request and post-response pipelines.
   * Called as middleware before the agent's generateResponse function.
   *
   * @param {Object} req - HTTP request object
   * @param {Object} res - HTTP response object
   * @param {Object} agent - Agent definition
   * @param {Function} next - The next handler (e.g., generateResponse wrapper)
   */
  async function handleRequest(req, res, agent, next) {
    // Req 15.10: Re-evaluate config on each request for runtime toggle support
    refreshConfig();

    // Req 15.1, 15.9: participant mode or unrecognized profile → passthrough
    const activeModules = getActiveModulesForAgent(agent.id);
    const hasActiveModules = activeModules.preRequest.length > 0 ||
      activeModules.postResponse.length > 0 ||
      activeModules.global.length > 0;

    if (!hasActiveModules) {
      // Full passthrough - no defense processing
      return next(req, res, agent);
    }

    // Extract user message from request body (already parsed upstream)
    const userMessage = req.body?.message || req.body?.content || '';

    // Run pre-request pipeline
    const preResult = runPreRequestPipeline(req, res, agent, activeModules, userMessage);

    if (preResult.blocked) {
      const { status, body } = preResult.blockResponse;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
      return;
    }

    // Replace request message with sanitized version if it was modified
    if (preResult.sanitizedMessage !== userMessage) {
      if (req.body) {
        if (req.body.message !== undefined) req.body.message = preResult.sanitizedMessage;
        if (req.body.content !== undefined) req.body.content = preResult.sanitizedMessage;
      }
    }

    // Call the next handler (generateResponse)
    const result = await next(req, res, agent);

    // Run post-response pipeline on the response text
    if (typeof result === 'string') {
      return runPostResponsePipeline(agent, activeModules, result);
    }

    return result;
  }

  return {
    handleRequest,
    refreshConfig,
    getActiveModulesForAgent,
    /** Exposed for testing */
    _modules: modules,
  };
}

/**
 * Returns the currently active defense configuration for a given agent.
 * Useful for the dashboard to display which defenses are active.
 *
 * @param {string} agentId - The agent's ID
 * @returns {{ preRequest: string[], postResponse: string[], global: string[] }}
 */
export function getActiveDefenses(agentId) {
  return getActiveModulesForAgent(agentId);
}
