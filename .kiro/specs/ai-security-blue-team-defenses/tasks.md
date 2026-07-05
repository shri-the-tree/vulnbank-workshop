# Implementation Plan: AI Security Blue Team Defenses

## Overview

Implement 15 defense modules that integrate into VulnBank's existing HTTP request pipeline via a Defense Orchestrator. Each module is a standalone ES module with a consistent interface (`check()` for validators, `apply()` for transformers). The orchestrator wires modules based on `BANK_PROFILE` and `HARDEN_Ln` toggles. Implementation uses JavaScript (Node.js/Express) matching the existing codebase.

## Tasks

- [x] 1. Set up defense module directory structure and configuration files
  - [x] 1.1 Create `src/defenses/` directory structure and all JSON configuration files
    - Create `src/defenses/config/patterns.json` with initial prompt injection patterns
    - Create `src/defenses/config/rate-limits.json` with default and per-agent limits
    - Create `src/defenses/config/output-allowlist.json` with empty default allowlist
    - Create `src/defenses/config/memory-patterns.json` with instruction-like phrase patterns
    - Create `src/defenses/config/query-templates.json` with approved SQL templates
    - Create `src/defenses/config/url-allowlist.json` with permitted domains
    - Create `src/defenses/config/drift-baselines.json` with per-agent drift config
    - _Requirements: 1.5, 3.1, 4.8, 5.7, 7.1, 8.5, 14.9_

  - [x] 1.2 Create `.env.example` updates with all required defense secret variables
    - Add placeholder entries for all secrets needed by defense modules
    - Include comments documenting each variable's purpose
    - _Requirements: 11.5_

- [x] 2. Implement Audit Logger (foundational dependency for all modules)
  - [x] 2.1 Implement `src/defenses/audit-logger.js` with structured NDJSON logging
    - Implement `createAuditLogger(config)` factory function
    - Support log levels (DEBUG, INFO, WARN, ERROR) with configurable minimum level
    - Output newline-delimited JSON to stdout and configurable log file
    - Implement log rotation at 50 MB with max 5 rotated files
    - Implement atomic writes to prevent interleaved JSON lines
    - Implement convenience methods: `logBlockedAttack`, `logToolInvocation`, `logAuthEvent`
    - Ensure secrets, PII, and system prompts are never included in log entries
    - Handle file write failures gracefully (fallback to stdout with diagnostic event)
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7, 13.8_

  - [ ]* 2.2 Write unit tests for Audit Logger
    - Test log level filtering (DEBUG events not logged when minimum is INFO)
    - Test NDJSON output format and atomicity
    - Test log file rotation at 50 MB threshold
    - Test graceful fallback to stdout on file write failure
    - Test that secrets and PII are never present in log output
    - _Requirements: 13.4, 13.5, 13.6, 13.7, 13.8_

- [x] 3. Implement Secrets Manager
  - [x] 3.1 Implement `src/defenses/secrets-manager.js` with environment variable loading
    - Implement `SecretsManager.initialize(requiredVars)` that loads from env vars at startup
    - Throw on missing required variables (log names but not values)
    - Implement `get(variableName)` accessor using closures to hide from stack traces
    - Implement `getMasked(variableName)` returning first 4 chars + asterisks
    - Implement `detectLeaks(text)` scanning for 8+ char substring matches
    - Throw error on startup if leaked secrets found in agent system prompts
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.6, 11.7_

  - [ ]* 3.2 Write unit tests for Secrets Manager
    - Test startup failure when required vars are missing
    - Test that secret values are not exposed in stack traces
    - Test masked representation format
    - Test leak detection with substring matching
    - _Requirements: 11.2, 11.3, 11.4, 11.6_

- [x] 4. Implement Input Validator
  - [x] 4.1 Implement `src/defenses/input-validator.js` with configurable pattern matching
    - Implement `createInputValidator(patternsPath)` factory loading patterns from JSON
    - Implement `check(input, context)` returning ValidationResult with pass/sanitized/category/refusal
    - Handle reject action: return standardized JSON refusal with "blocked" status and category
    - Handle strip action: remove matched sequences, pass sanitized input, log to Audit_Logger
    - Handle flag action: pass input through but log for audit with category
    - Implement delimiter escape detection (triple backticks, triple dashes + SYSTEM/ADMIN/OVERRIDE)
    - Implement instruction marker detection ([INST], [SYSTEM], [ADMIN])
    - Implement role-confusion detection with boundary prepend
    - Implement input length check (truncate at 10,000 chars, log context-overflow-attempt)
    - Support hot-reload of patterns via `reload()` method
    - Ensure all checks complete within 50ms
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

  - [ ]* 4.2 Write unit tests for Input Validator
    - Test regex pattern matching for known injection patterns
    - Test strip action removes delimiter sequences correctly
    - Test role-confusion boundary prepend
    - Test input truncation at 10,000 characters
    - Test configurable pattern registry hot-reload
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

- [x] 5. Implement Output Filter
  - [x] 5.1 Implement `src/defenses/output-filter.js` with redaction patterns
    - Implement `createOutputFilter(allowlistPath, agentPersonas)` factory
    - Implement `apply(responseText, agentContext)` returning FilterResult with redactions array
    - Detect and redact API key patterns (sk-, sk-ant-, AKIA, Bearer tokens) → [REDACTED:API_KEY]
    - Detect and redact system prompt leakage (30+ char match) → [REDACTED:SYSTEM_PROMPT]
    - Detect and redact PII: SSN (NNN-NN-NNNN), email (RFC 5322), accounts (VB-NNNNNN)
    - Detect and redact database credentials (host=, user=, password=, connection strings)
    - Support configurable allowlist of terms that are never redacted
    - Target 20ms processing for inputs up to 4,000 tokens
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [ ]* 5.2 Write unit tests for Output Filter
    - Test each redaction pattern type independently
    - Test allowlist exemption prevents redaction
    - Test system prompt leakage detection with 30+ char threshold
    - Test that redaction labels are type-specific
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [x] 6. Implement Rate Limiter
  - [x] 6.1 Implement `src/defenses/rate-limiter.js` with sliding window algorithm
    - Implement `createRateLimiter(configPath)` factory loading per-agent config from JSON
    - Implement `check(clientIP, agentId)` returning RateLimitResult
    - Use in-memory sorted timestamp array per IP (no external dependencies)
    - Enforce configurable max requests per sliding window (default: 30/60s)
    - Support per-agent limits (vulnerable agents default to 10/60s)
    - Implement burst detection (5 requests within 2 seconds)
    - Flag abuse IPs with 2x penalty multiplier on Retry-After for 5 minutes
    - Cap tracked IPs at 10,000 with LRU eviction
    - Auto-cleanup entries older than window duration on each request
    - Return HTTP 429 with JSON body and Retry-After header on limit exceeded
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

  - [ ]* 6.2 Write unit tests for Rate Limiter
    - Test sliding window enforcement at threshold boundary
    - Test burst detection triggers at 5 requests in 2 seconds
    - Test abuse flag penalty multiplier
    - Test LRU eviction at 10,000 IP cap
    - Test per-agent configuration override
    - _Requirements: 3.1, 3.2, 3.4, 3.5, 3.6, 3.7_

- [x] 7. Implement Memory Sanitizer
  - [x] 7.1 Implement `src/defenses/memory-sanitizer.js` with per-user isolation
    - Implement `createMemorySanitizer(patternsPath)` factory loading patterns from JSON
    - Implement `write(userId, content)` with instruction-pattern rejection within 50ms
    - Implement `read(userId)` returning only entries tagged with requesting user's ID
    - Tag accepted entries with user ID and UTC ISO 8601 timestamp (ms precision)
    - Reject writes exceeding 500 characters
    - Implement FIFO eviction at 50 entries per user
    - Detect and reject credential patterns (sk-/AKIA, password=, connection strings)
    - Reject requests lacking valid authenticated user identifier
    - Support configurable pattern list hot-reload
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_

  - [ ]* 7.2 Write unit tests for Memory Sanitizer
    - Test instruction-pattern rejection for all configured patterns
    - Test per-user isolation (user A cannot read user B's entries)
    - Test 500-character limit enforcement
    - Test eviction at 50 entries
    - Test credential pattern detection and rejection
    - Test authentication requirement
    - _Requirements: 4.1, 4.3, 4.4, 4.5, 4.6, 4.7_

- [x] 8. Checkpoint - Core validators complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Implement Identity Verifier
  - [x] 9.1 Implement `src/defenses/identity-verifier.js` with Ed25519 JWT verification
    - Implement `createIdentityVerifier(keyRegistry, acceptsFrom)` factory
    - Implement `verify(token, receivingAgentId)` returning VerificationResult
    - Validate JWT structure and required claims (sub, iat)
    - Verify Ed25519 signature against trusted key registry (using tweetnacl)
    - Check token expiration (iat + configurable TTL, default 60s)
    - Validate sub claim against receiver's acceptsFrom allowlist
    - Log failed verification attempts with claimed identity, source IP, failure reason
    - Implement `signToken(agentId, privateKey)` static helper for tests
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

  - [ ]* 9.2 Write unit tests for Identity Verifier
    - Test valid token passes verification
    - Test missing/malformed token rejection
    - Test invalid signature rejection
    - Test expired token rejection
    - Test unauthorized sender rejection (not in acceptsFrom)
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 10. Implement Path Validator
  - [x] 10.1 Implement `src/defenses/path-validator.js` with sandbox enforcement
    - Implement `createPathValidator(sandboxRoot)` factory (default: ./workspace/sandbox)
    - Implement `validate(requestedPath, operation)` returning PathValidationResult
    - Resolve paths to absolute canonical form before comparison
    - Reject paths exceeding 4,096 characters
    - Reject paths containing null bytes or non-printable ASCII (outside 32-126 range)
    - Resolve and reject symbolic links targeting outside sandbox
    - Log violations with original path, resolved path, violation type, requesting agent
    - Ensure atomic rejection (no partial writes on rejected file write calls)
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

  - [ ]* 10.2 Write unit tests for Path Validator
    - Test path traversal (../) rejection
    - Test symlink escape rejection
    - Test null byte and non-printable character rejection
    - Test path length limit (4,096 chars)
    - Test valid paths within sandbox are allowed
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 11. Implement URL Validator
  - [x] 11.1 Implement `src/defenses/url-validator.js` with domain allowlist and SSRF prevention
    - Implement `createUrlValidator(allowlistPath)` factory loading config from JSON
    - Implement async `validate(url)` returning URLValidationResult
    - Parse URL and verify domain against configurable allowlist
    - Support wildcard domain patterns (*.vulnbank.example matches one subdomain level)
    - Reject private/reserved IP ranges (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fc00::/7)
    - Reject non-HTTPS protocols
    - Reject URLs with credentials in authority component (including URL-encoded variants)
    - Detect DNS rebinding (domain passes allowlist but resolves to private IP)
    - Complete validation within 200ms (excluding DNS resolution)
    - Log violations with full URL, violation type, requesting agent (no internal network details)
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8_

  - [ ]* 11.2 Write unit tests for URL Validator
    - Test domain allowlist enforcement
    - Test wildcard subdomain matching
    - Test private IP rejection
    - Test non-HTTPS rejection
    - Test credentials-in-URL rejection
    - Test DNS rebinding detection
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.6, 7.7_

- [x] 12. Implement Query Parameterizer
  - [x] 12.1 Implement `src/defenses/query-parameterizer.js` with SQL injection prevention
    - Implement `createQueryParameterizer(templatesPath)` factory loading approved templates
    - Implement `parameterize(sqlString, agentId)` returning ParameterizeResult
    - Parse SQL, extract string and numeric literals into parameter array
    - Replace literals with positional placeholders in template
    - Reject queries with SQL comment sequences (--, /*, */)
    - Reject queries with multiple statements (semicolons)
    - Reject unauthorized UNION clauses (not in approved template)
    - Reject WHERE clause tautologies (1=1, 'a'='a', OR TRUE)
    - Reject non-SELECT queries (only read operations permitted)
    - Match normalized query structure against registered template registry
    - Log sql-injection-attempt events with timestamp, agent, query, pattern
    - Return rejection within 100ms
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8_

  - [ ]* 12.2 Write unit tests for Query Parameterizer
    - Test literal extraction and parameterization
    - Test comment sequence rejection
    - Test multi-statement rejection
    - Test UNION clause validation against template registry
    - Test tautology detection
    - Test non-SELECT rejection
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.6, 8.8_

- [x] 13. Implement Context Protector
  - [x] 13.1 Implement `src/defenses/context-protector.js` with token budget management
    - Implement `createContextProtector(config)` factory with configurable budgets
    - Implement `assemblePrompt(safetyInstructions, conversationHistory, newMessage, modelContextSize)`
    - Reserve configurable min token budget (100-2000 tokens, default 500) for safety instructions
    - Place safety instructions at beginning AND end of system prompt (sandwich defense)
    - Truncate user content by removing oldest messages first when exceeding context window
    - Preserve most recent user message and all safety instructions during truncation
    - Reject messages exceeding configurable max length (100-10000 tokens, default 2000)
    - Detect and refuse requests to reproduce/echo content estimated at 500+ tokens
    - Display inline warning when cumulative usage reaches 80% of context budget
    - Validate config ranges; fall back to defaults if out of range
    - Implement `estimateTokens(text)` helper
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_

  - [ ]* 13.2 Write unit tests for Context Protector
    - Test sandwich defense placement (safety at beginning and end)
    - Test oldest-message-first truncation preserves recent messages
    - Test message length rejection at configurable threshold
    - Test 80% capacity warning trigger
    - Test config validation and default fallback
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.6, 9.7_

- [x] 14. Implement Tool Registry Verifier
  - [x] 14.1 Implement `src/defenses/tool-registry-verifier.js` with cryptographic integrity checks
    - Implement `createToolRegistryVerifier(registryAuthorityPublicKey)` factory
    - Implement `register(manifest, signature)` validating SHA-256 content hash signed by authority
    - Reject missing/invalid signatures with specific failure reason
    - Reject non-TLS (non-HTTPS) source URLs
    - Maintain frozen snapshot of registered tools (immutable after registration)
    - Implement `verifyBeforeExecution(toolId)` checking implementation hash at invoke time
    - Support pinned tool versions that cannot be overwritten or removed
    - Abort verification operations exceeding 5 seconds with timeout event logging
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

  - [ ]* 14.2 Write unit tests for Tool Registry Verifier
    - Test valid registration with correct signature
    - Test invalid/missing signature rejection
    - Test non-HTTPS source rejection
    - Test frozen snapshot immutability
    - Test hash mismatch detection at execution time
    - Test pinned version protection
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_

- [x] 15. Checkpoint - Security modules complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Implement Security Headers Manager
  - [x] 16.1 Implement `src/defenses/security-headers.js` as Express middleware
    - Implement `applySecurityHeaders(res, options)` adding all required headers
    - Set Content-Security-Policy: default-src 'self'
    - Set X-Content-Type-Options: nosniff
    - Set X-Frame-Options: DENY
    - Set Strict-Transport-Security: max-age=31536000; includeSubDomains
    - Set X-XSS-Protection: 1; mode=block
    - Remove X-Powered-By header
    - Set Cache-Control: no-store for agent API routes
    - Implement configurable CORS origin allowlist (default: same-origin only)
    - Implement `validateContentType(req, res)` rejecting non-JSON POSTs with HTTP 415
    - Implement `handlePreflight(req, res, allowedOrigins)` responding with 204 within 100ms
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_

  - [ ]* 16.2 Write unit tests for Security Headers Manager
    - Test all required headers are present in responses
    - Test X-Powered-By removal
    - Test CORS allowlist enforcement
    - Test Content-Type validation on POST requests
    - Test preflight OPTIONS handling
    - _Requirements: 12.1, 12.2, 12.4, 12.5, 12.6_

- [x] 17. Implement Behavioral Drift Detector
  - [x] 17.1 Implement `src/defenses/behavioral-drift.js` with sliding window analysis
    - Implement `createBehavioralDriftDetector(configPath)` factory loading per-agent config
    - Implement `recordResponse(agentId, response, wasRefusal)` returning DriftCheckResult
    - Maintain sliding window (default 10 responses) per agent
    - Skip drift evaluation until window is full (baseline building phase)
    - Detect response length deviation (>2 standard deviations from window average)
    - Track refusal rate; alert when drops below 50% of baseline within 5 interactions
    - Compute topic-adherence via cosine similarity against system prompt embedding (threshold: 0.6)
    - Alert on 3+ consecutive responses below topic-adherence threshold
    - Log drift alerts with drift type, triggering values, baseline values, timestamp
    - Support context-reset on drift alert when enabled in per-agent config
    - Fall back to default config on missing/invalid JSON file
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7, 14.8, 14.9_

  - [ ]* 17.2 Write unit tests for Behavioral Drift Detector
    - Test baseline building phase (no alerts until window is full)
    - Test response length deviation detection at 2 std dev threshold
    - Test refusal rate drop alert
    - Test topic-adherence threshold breach detection
    - Test context-reset trigger when enabled
    - Test fallback to defaults on invalid config
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.6, 14.8, 14.9_

- [x] 18. Implement RAG Content Sanitizer
  - [x] 18.1 Implement `src/defenses/rag-content-sanitizer.js` with injection neutralization
    - Create configurable injection pattern registry JSON (pattern, severity, action)
    - Scan retrieved documents for instruction-like patterns before prompt insertion
    - Wrap detected documents in explicit delimiters ([BEGIN/END RETRIEVED DOCUMENT])
    - Prepend boundary instruction before opening delimiter
    - Escape delimiter breakout sequences using Unicode full-width equivalents
    - Reject high-severity documents entirely with placeholder message
    - Process within 30ms for documents up to 2,000 tokens
    - Log sanitization events to Audit_Logger with document ID, pattern count, actions
    - Apply uniformly to all document sources (file, vector DB, web-fetched)
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8_

  - [ ]* 18.2 Write unit tests for RAG Content Sanitizer
    - Test instruction pattern detection and wrapping
    - Test delimiter escape with full-width Unicode replacement
    - Test high-severity document rejection with placeholder
    - Test uniform application across all document sources
    - _Requirements: 16.1, 16.2, 16.3, 16.5, 16.8_

- [x] 19. Implement Multimodal Injection Detector
  - [x] 19.1 Implement `src/defenses/multimodal-injection-detector.js` with OCR analysis
    - Perform OCR text extraction on images before forwarding to vision model
    - Match extracted text against prompt injection and jailbreak pattern registries
    - Flag images with >60% text area coverage for enhanced pattern matching
    - Analyze and strip image metadata (EXIF, IPTC, XMP) for embedded instructions
    - Reject images exceeding 10 MB or 4096x4096 pixels
    - Support configurable OCR confidence threshold (default: 0.7)
    - Log blocked/flagged events with SHA-256 image hash, text summary, matched patterns
    - Complete OCR + analysis within 500ms for images up to 5 MB
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7, 17.8_

  - [ ]* 19.2 Write unit tests for Multimodal Injection Detector
    - Test OCR text extraction triggers pattern matching
    - Test image size/dimension rejection
    - Test metadata stripping
    - Test confidence threshold filtering
    - Test high text-coverage enhanced matching
    - _Requirements: 17.1, 17.2, 17.4, 17.5, 17.6_

- [x] 20. Implement WebSocket Security Manager
  - [x] 20.1 Implement `src/defenses/websocket-security-manager.js` with connection security
    - Validate JWT authentication token on WebSocket upgrade requests
    - Reject upgrades without valid/expired token with HTTP 401
    - Verify Origin header against configurable allowlist (close 4003 on mismatch)
    - Enforce per-connection message rate limiting (default: 60 msg/60s)
    - Close connections with code 4008 on rate limit exceeded
    - Validate message payload as JSON with required schema (type, content, timestamp)
    - Enforce 64 KB maximum message payload size (close 4009 on exceed)
    - Implement idle timeout with ping/pong (5 min idle, 10s pong timeout)
    - Log all lifecycle events to Audit_Logger (open, close, error, rate-limited)
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.7, 18.8_

  - [ ]* 20.2 Write unit tests for WebSocket Security Manager
    - Test JWT validation on upgrade
    - Test origin allowlist enforcement
    - Test per-connection rate limiting
    - Test message schema validation
    - Test max payload size enforcement
    - Test idle timeout with ping/pong
    - _Requirements: 18.1, 18.3, 18.4, 18.5, 18.6, 18.7_

- [x] 21. Implement Command Injection Preventer
  - [x] 21.1 Implement `src/defenses/command-injection-preventer.js` with command allowlist
    - Load configurable command allowlist from JSON (default: ls, cat, echo, date, whoami, pwd)
    - Parse command string and verify base command against allowlist
    - Reject commands with shell metacharacters (;, |, &, `, $(), &&, ||, newlines)
    - Reject commands with redirection operators (>, >>, <, <<)
    - Reject path traversal in arguments (../ or ..\)
    - Enforce 1,024 character max command length
    - Execute allowed commands with configurable timeout (default 10s)
    - Terminate timed-out processes and return error
    - Log all rejections to Audit_Logger with full command, reason, agent, source IP
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7, 19.8_

  - [ ]* 21.2 Write unit tests for Command Injection Preventer
    - Test allowlist enforcement (permitted vs blocked commands)
    - Test shell metacharacter rejection for each character type
    - Test redirection operator rejection
    - Test path traversal rejection in arguments
    - Test command length limit
    - Test execution timeout
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.8_

- [x] 22. Implement Jailbreak Detector
  - [x] 22.1 Implement `src/defenses/jailbreak-detector.js` with multi-pattern detection
    - Load configurable jailbreak pattern registry from JSON (pattern, weight, category)
    - Detect DAN mode, roleplay bypass, hypothetical framing, multi-turn erosion
    - Track per-session jailbreak attempt counter
    - Escalate to heightened alert after 3 attempts in 10-message window
    - Apply stricter confidence threshold in heightened state
    - Detect multi-turn erosion (5+ boundary-testing inputs in 15 messages at 40-70% confidence)
    - Respond with standardized refusal (no detection logic or echo of attempt)
    - Log events above 0.8 confidence with session ID, categories, score, counter
    - Downgrade from heightened state after 20 clean consecutive messages
    - Complete analysis within 30ms per input
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8_

  - [ ]* 22.2 Write unit tests for Jailbreak Detector
    - Test DAN mode pattern detection
    - Test per-session counter escalation at threshold
    - Test multi-turn erosion detection
    - Test standardized refusal (no echo, no detection details)
    - Test heightened state downgrade after 20 clean messages
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.7_

- [x] 23. Implement Token Smuggling Detector
  - [x] 23.1 Implement `src/defenses/token-smuggling-detector.js` with encoding normalization
    - Scan inputs for encoded content: Base64 (20+ chars), Unicode escapes, ROT13, HTML entities, URL encoding
    - Implement recursive decoding (max 3 layers deep)
    - Flag inputs still encoded after 3 passes as potentially obfuscated
    - Apply full security pattern checks against decoded plaintext
    - Detect mixed-encoding attacks (multiple schemes combined)
    - Flag suspicious encoding abuse (>5 segments or decoded >3x original length)
    - Annotate audit log with "[detected via encoding: {type}]" when decoded matches pattern
    - Load configurable encoding detection registry from JSON
    - Complete within 50ms for inputs up to 10,000 characters
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.5, 21.6, 21.7, 21.8_

  - [ ]* 23.2 Write unit tests for Token Smuggling Detector
    - Test Base64 decoding and pattern matching on decoded content
    - Test Unicode escape normalization
    - Test recursive decoding depth limit (3 layers)
    - Test mixed-encoding detection
    - Test suspicious abuse flagging thresholds
    - _Requirements: 21.1, 21.2, 21.3, 21.5, 21.6_

- [x] 24. Implement Session Isolator
  - [x] 24.1 Implement `src/defenses/session-isolator.js` with cryptographic session management
    - Assign UUID v4 session IDs (128-bit entropy) on connection/auth
    - Filter conversation history to return only messages matching session ID
    - Tag memory entries with session ID + user ID; enforce both on read
    - Reject requests with invalid/expired session IDs (require re-auth)
    - Enforce configurable inactivity timeout (default: 30 min) with full state purge
    - Provide isolated config/tool registry copies per agent invocation (no shared mutable state)
    - Log session termination with duration, message count, security events
    - Reject cross-session access attempts and log violation events
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6, 22.7, 22.8_

  - [ ]* 24.2 Write unit tests for Session Isolator
    - Test session ID generation (UUID v4 format)
    - Test conversation history isolation between sessions
    - Test memory entry tagging and access control
    - Test session expiration and state purge
    - Test cross-session access rejection
    - _Requirements: 22.1, 22.2, 22.3, 22.5, 22.8_

- [x] 25. Implement Egress Filter
  - [x] 25.1 Implement `src/defenses/egress-filter.js` with outbound request restriction
    - Intercept all outbound HTTP/HTTPS requests from agent processes
    - Load configurable egress allowlist from JSON with per-agent policies
    - Resolve hostnames to IP; reject private/reserved ranges unless explicitly allowlisted
    - Block requests to non-standard ports (not 80/443) unless explicitly allowlisted
    - Support global default allowlist when no per-agent policy exists
    - Block DNS queries for non-allowlisted domains (prevent DNS tunneling)
    - Return NXDOMAIN and log dns-exfiltration-attempt for blocked DNS
    - Complete validation within 100ms (excluding DNS resolution)
    - Log blocked events with agent ID, destination URL, resolved IP, triggering policy
    - _Requirements: 23.1, 23.2, 23.3, 23.4, 23.5, 23.6, 23.7, 23.8_

  - [ ]* 25.2 Write unit tests for Egress Filter
    - Test allowlist enforcement for outbound requests
    - Test private IP rejection after resolution
    - Test non-standard port blocking
    - Test per-agent policy isolation
    - Test DNS tunneling prevention
    - _Requirements: 23.1, 23.2, 23.3, 23.4, 23.6, 23.7_

- [x] 26. Checkpoint - All defense modules complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 27. Implement Defense Orchestrator and integration
  - [x] 27.1 Implement `src/defenses/index.js` Defense Orchestrator
    - Implement `createOrchestrator(agentDefs)` factory
    - Implement `handleRequest(req, res, agent, next)` wiring pre-request and post-response pipelines
    - Implement `refreshConfig()` re-evaluating HARDEN_Ln env vars on each request
    - In "participant" mode (BANK_PROFILE=participant): disable all modules, passthrough
    - In "demo" mode: enable modules per HARDEN_Ln toggles
    - HARDEN_L1=on: activate Input_Validator + Output_Filter for HelperBot
    - HARDEN_L2=on: activate Output_Filter + Memory_Sanitizer for RAGBot
    - HARDEN_L3=on: activate Query_Parameterizer + Path_Validator + URL_Validator for DataBot/ToolBot
    - HARDEN_L4=on: activate Memory_Sanitizer + Behavioral_Drift_Detector for MemoryBot
    - HARDEN_L5=on (+ AIM): activate Identity_Verifier + Tool_Registry_Verifier for A2A Worker
    - Any HARDEN_Ln=on: apply Rate_Limiter, Security_Headers, Audit_Logger to all agents
    - Default to "participant" if BANK_PROFILE unset or unrecognized
    - Apply updated config within 1 second of toggle change (no restart needed)
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9, 15.10_

  - [x] 27.2 Wire Defense Orchestrator into existing server request pipeline
    - Import Defense Orchestrator in `src/index.js` (or relevant server entry point)
    - Insert orchestrator middleware before agent `generateResponse` calls
    - Ensure orchestrator wraps existing `maybeEnforce()` AIM hook pattern
    - Verify passthrough behavior when BANK_PROFILE=participant
    - _Requirements: 15.1, 15.2, 15.8_

  - [ ]* 27.3 Write integration tests for Defense Orchestrator
    - Test participant mode passthrough (no filtering)
    - Test demo mode with HARDEN_L1=on activates correct modules for HelperBot
    - Test demo mode with multiple levels enabled
    - Test runtime toggle change applies within 1 second
    - Test unrecognized BANK_PROFILE defaults to participant
    - _Requirements: 15.1, 15.2, 15.3, 15.9, 15.10_

- [x] 28. Final checkpoint - Full integration verified
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation between major implementation phases
- All modules are ES modules exporting pure functions or stateful singletons
- The project uses Node.js with Express and the existing `tweetnacl` dependency for cryptography
- The Defense Orchestrator (task 27) wires all modules together and must be implemented last
- Audit Logger (task 2) is a foundational dependency used by all other modules for event logging
- Configuration files (task 1) should be created first as modules depend on them at load time

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "3.2", "4.1", "5.1", "6.1", "7.1"] },
    { "id": 3, "tasks": ["4.2", "5.2", "6.2", "7.2", "9.1", "10.1", "11.1", "12.1"] },
    { "id": 4, "tasks": ["9.2", "10.2", "11.2", "12.2", "13.1", "14.1", "16.1"] },
    { "id": 5, "tasks": ["13.2", "14.2", "16.2", "17.1", "18.1", "19.1"] },
    { "id": 6, "tasks": ["17.2", "18.2", "19.2", "20.1", "21.1", "22.1"] },
    { "id": 7, "tasks": ["20.2", "21.2", "22.2", "23.1", "24.1", "25.1"] },
    { "id": 8, "tasks": ["23.2", "24.2", "25.2"] },
    { "id": 9, "tasks": ["27.1"] },
    { "id": 10, "tasks": ["27.2"] },
    { "id": 11, "tasks": ["27.3"] }
  ]
}
```
