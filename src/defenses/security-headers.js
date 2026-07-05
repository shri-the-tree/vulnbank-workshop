/**
 * Security Headers Manager - HTTP Hardening
 *
 * Applies standard security headers to all agent API responses,
 * validates Content-Type on POST requests, and handles CORS preflight.
 * Designed as Express middleware compatible with the existing server architecture.
 *
 * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7
 */

/**
 * Applies security headers to an HTTP response.
 *
 * @param {http.ServerResponse} res - The HTTP response object
 * @param {Object} [options] - Configuration options
 * @param {string[]} [options.allowedOrigins] - CORS origin allowlist (default: empty, same-origin only)
 * @param {boolean} [options.isAgentRoute] - Whether this is an agent API route (adds Cache-Control: no-store)
 * @param {string} [options.requestOrigin] - The Origin header from the incoming request
 */
export function applySecurityHeaders(res, options = {}) {
  const {
    allowedOrigins = [],
    isAgentRoute = false,
    requestOrigin = null
  } = options;

  // Req 12.1: Standard security headers
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Req 12.2: Remove X-Powered-By header
  res.removeHeader('X-Powered-By');

  // Req 12.3: Cache-Control: no-store for agent API routes
  if (isAgentRoute) {
    res.setHeader('Cache-Control', 'no-store');
  }

  // Req 12.4: CORS Access-Control-Allow-Origin from allowlist
  // Only set the header if the request origin is in the allowlist
  if (requestOrigin && allowedOrigins.length > 0) {
    if (allowedOrigins.includes(requestOrigin)) {
      res.setHeader('Access-Control-Allow-Origin', requestOrigin);
    }
    // If origin is not in the allowlist, omit the header entirely
  }
}

/**
 * Validates Content-Type on POST requests.
 * Rejects non-JSON POST requests with HTTP 415 Unsupported Media Type.
 *
 * @param {http.IncomingMessage} req - The HTTP request object
 * @param {http.ServerResponse} res - The HTTP response object
 * @returns {boolean} true if valid (or not a POST), false if rejected (response already sent)
 */
export function validateContentType(req, res) {
  // Only validate POST requests (Req 12.5)
  if (req.method !== 'POST') {
    return true;
  }

  const contentType = req.headers['content-type'] || '';

  // Accept application/json with optional charset/boundary parameters
  if (contentType.startsWith('application/json')) {
    return true;
  }

  // Reject with HTTP 415 Unsupported Media Type
  res.writeHead(415, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    error: 'Unsupported Media Type',
    message: 'Content-Type must be application/json',
    received: contentType || 'none'
  }));

  return false;
}

/**
 * Handles CORS preflight OPTIONS requests.
 * Responds with 204 No Content and appropriate CORS headers.
 *
 * @param {http.IncomingMessage} req - The HTTP request object
 * @param {http.ServerResponse} res - The HTTP response object
 * @param {string[]} [allowedOrigins] - CORS origin allowlist (default: empty)
 * @returns {boolean} true if handled (was a preflight), false if not a preflight request
 */
export function handlePreflight(req, res, allowedOrigins = []) {
  // Only handle OPTIONS requests (Req 12.6)
  if (req.method !== 'OPTIONS') {
    return false;
  }

  const requestOrigin = req.headers['origin'] || '';

  // Set CORS preflight response headers
  if (requestOrigin && allowedOrigins.length > 0 && allowedOrigins.includes(requestOrigin)) {
    res.setHeader('Access-Control-Allow-Origin', requestOrigin);
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');

  // Respond with 204 No Content
  res.writeHead(204);
  res.end();

  return true;
}

/**
 * Express middleware factory that integrates all security header functions.
 * Compatible with Express middleware signature (req, res, next).
 *
 * @param {Object} [config] - Middleware configuration
 * @param {string[]} [config.allowedOrigins] - CORS origin allowlist
 * @param {string} [config.agentApiPrefix] - Path prefix for agent API routes (default: '/chat')
 * @returns {Function} Express middleware function (req, res, next)
 */
export function createSecurityHeadersMiddleware(config = {}) {
  const {
    allowedOrigins = [],
    agentApiPrefix = '/chat'
  } = config;

  return function securityHeadersMiddleware(req, res, next) {
    // Handle preflight first
    if (handlePreflight(req, res, allowedOrigins)) {
      return;
    }

    // Validate Content-Type on POST requests
    if (!validateContentType(req, res)) {
      return;
    }

    // Determine if this is an agent API route
    const isAgentRoute = req.url && (
      req.url.startsWith(agentApiPrefix) ||
      req.url === '/' ||
      req.url.startsWith('/mcp') ||
      req.url.startsWith('/a2a') ||
      req.url.startsWith('/jsonrpc')
    );

    // Apply security headers
    applySecurityHeaders(res, {
      allowedOrigins,
      isAgentRoute,
      requestOrigin: req.headers['origin'] || null
    });

    // Continue to next middleware/handler
    if (typeof next === 'function') {
      next();
    }
  };
}
