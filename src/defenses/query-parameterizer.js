/**
 * Query Parameterizer - SQL Injection Defense
 *
 * Rewrites raw SQL strings into parameterized queries, preventing injection.
 * Extracts string and numeric literals into a parameter array and validates
 * queries against a registry of approved templates.
 *
 * Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8
 */

import { readFileSync } from 'node:fs';
import { createAuditLogger } from './audit-logger.js';

/** SQL comment patterns to reject */
const COMMENT_PATTERNS = [
  /--/,
  /\/\*/,
  /\*\//,
];

/** Tautology patterns in WHERE clauses */
const TAUTOLOGY_PATTERNS = [
  /\b1\s*=\s*1\b/i,
  /\b2\s*=\s*2\b/i,
  /'[^']*'\s*=\s*'[^']*'/i,
  /\bOR\s+TRUE\b/i,
  /\bOR\s+1\s*=\s*1\b/i,
  /\bOR\s+'[^']*'\s*=\s*'[^']*'/i,
];

/**
 * Creates a QueryParameterizer instance that loads approved templates from JSON.
 *
 * @param {string} templatesPath - Path to the query templates JSON configuration file
 * @returns {QueryParameterizer}
 */
export function createQueryParameterizer(templatesPath) {
  const logger = createAuditLogger({ minLevel: 'DEBUG' });
  let templates = [];

  /**
   * Load templates from the JSON file.
   */
  function loadTemplates() {
    const raw = readFileSync(templatesPath, 'utf-8');
    const config = JSON.parse(raw);
    templates = config.templates || [];
  }

  // Initial load
  loadTemplates();

  /**
   * Log a sql-injection-attempt event.
   * @param {string} agentId
   * @param {string} query
   * @param {string} pattern
   */
  function logInjectionAttempt(agentId, query, pattern) {
    logger.log('WARN', 'sql-injection-attempt', {
      timestamp: new Date().toISOString(),
      agentId: agentId || 'unknown',
      query: query.slice(0, 200),
      pattern,
    });
  }

  /**
   * Check if query contains SQL comment sequences.
   * @param {string} sql
   * @returns {boolean}
   */
  function hasComments(sql) {
    return COMMENT_PATTERNS.some(p => p.test(sql));
  }

  /**
   * Check if query contains multiple statements (semicolons).
   * @param {string} sql
   * @returns {boolean}
   */
  function hasMultipleStatements(sql) {
    // Remove string literals before checking for semicolons
    const withoutStrings = sql.replace(/'[^']*'/g, '?');
    return withoutStrings.includes(';');
  }

  /**
   * Check if query is a SELECT statement (read-only).
   * @param {string} sql
   * @returns {boolean}
   */
  function isSelectQuery(sql) {
    const trimmed = sql.trim().toUpperCase();
    return trimmed.startsWith('SELECT');
  }

  /**
   * Check if query contains WHERE clause tautologies.
   * @param {string} sql
   * @returns {{ found: boolean, pattern?: string }}
   */
  function hasTautology(sql) {
    for (const pattern of TAUTOLOGY_PATTERNS) {
      if (pattern.test(sql)) {
        return { found: true, pattern: pattern.source };
      }
    }
    return { found: false };
  }

  /**
   * Check if query contains an unauthorized UNION clause.
   * @param {string} sql
   * @param {string} matchedTemplate - The matched template pattern (if any)
   * @returns {boolean}
   */
  function hasUnauthorizedUnion(sql, matchedTemplate) {
    const upperSql = sql.toUpperCase();
    const hasUnion = /\bUNION\b/.test(upperSql);

    if (!hasUnion) return false;

    // Check if the matched template also contains UNION
    if (matchedTemplate) {
      const upperTemplate = matchedTemplate.toUpperCase();
      return !/\bUNION\b/.test(upperTemplate);
    }

    // No matched template means UNION is unauthorized
    return true;
  }

  /**
   * Extract string and numeric literals from SQL, replacing them with positional placeholders.
   * @param {string} sql
   * @returns {{ template: string, params: Array }}
   */
  function extractLiterals(sql) {
    const params = [];
    let paramIndex = 0;

    // Replace string literals (single-quoted)
    let template = sql.replace(/'([^']*)'/g, (match, value) => {
      params.push(value);
      paramIndex++;
      return '?';
    });

    // Replace numeric literals (standalone numbers, not part of identifiers)
    template = template.replace(/\b(\d+(?:\.\d+)?)\b/g, (match, value, offset) => {
      // Don't replace numbers that are part of identifiers or already placeholders
      const before = template.charAt(offset - 1);
      if (before === '_' || before === '.') return match;

      params.push(Number(value));
      return '?';
    });

    return { template, params };
  }

  /**
   * Normalize a SQL template for comparison by collapsing whitespace
   * and converting to uppercase.
   * @param {string} sql
   * @returns {string}
   */
  function normalizeTemplate(sql) {
    return sql.trim().replace(/\s+/g, ' ').toUpperCase();
  }

  /**
   * Match a parameterized query against the registered template registry.
   * @param {string} queryTemplate - The parameterized query template
   * @returns {{ matched: boolean, templateId?: string, templatePattern?: string }}
   */
  function matchTemplate(queryTemplate) {
    const normalized = normalizeTemplate(queryTemplate);

    for (const tmpl of templates) {
      const normalizedPattern = normalizeTemplate(tmpl.pattern);
      if (normalized === normalizedPattern) {
        return { matched: true, templateId: tmpl.id, templatePattern: tmpl.pattern };
      }
    }

    return { matched: false };
  }

  /**
   * Parameterize a SQL string, validating it against security rules and the template registry.
   *
   * @param {string} sqlString - The raw SQL query string
   * @param {string} agentId - The requesting agent's identity
   * @returns {ParameterizeResult}
   */
  function parameterize(sqlString, agentId) {
    if (typeof sqlString !== 'string' || sqlString.trim().length === 0) {
      return {
        allowed: false,
        error: 'Query must be a non-empty string',
        rejectionType: 'non_select',
      };
    }

    const sql = sqlString.trim();

    // Req 8.8: Only SELECT queries permitted
    if (!isSelectQuery(sql)) {
      logInjectionAttempt(agentId, sql, 'non_select');
      return {
        allowed: false,
        error: 'Only read operations (SELECT) are permitted',
        rejectionType: 'non_select',
      };
    }

    // Req 8.2: Reject SQL comments
    if (hasComments(sql)) {
      logInjectionAttempt(agentId, sql, 'comment_sequence');
      return {
        allowed: false,
        error: 'Query blocked due to disallowed comment sequence',
        rejectionType: 'comment',
      };
    }

    // Req 8.3: Reject multiple statements
    if (hasMultipleStatements(sql)) {
      logInjectionAttempt(agentId, sql, 'multiple_statements');
      return {
        allowed: false,
        error: 'Query blocked due to multiple statements',
        rejectionType: 'multiple_statements',
      };
    }

    // Req 8.6: Reject WHERE tautologies
    const tautologyCheck = hasTautology(sql);
    if (tautologyCheck.found) {
      logInjectionAttempt(agentId, sql, `tautology: ${tautologyCheck.pattern}`);
      return {
        allowed: false,
        error: 'Query blocked due to WHERE clause tautology',
        rejectionType: 'tautology',
      };
    }

    // Req 8.1: Extract literals and create parameterized template
    const { template, params } = extractLiterals(sql);

    // Req 8.5: Match against template registry
    const templateMatch = matchTemplate(template);

    // Req 8.4: Reject unauthorized UNION
    const templatePattern = templateMatch.matched ? templateMatch.templatePattern : null;
    if (hasUnauthorizedUnion(sql, templatePattern)) {
      logInjectionAttempt(agentId, sql, 'unauthorized_union');
      return {
        allowed: false,
        error: 'Query blocked due to unauthorized UNION clause',
        rejectionType: 'unauthorized_union',
      };
    }

    // Req 8.5: Reject if template doesn't match registry
    if (!templateMatch.matched) {
      logInjectionAttempt(agentId, sql, 'unregistered_template');
      return {
        allowed: false,
        error: 'Query structure does not match any approved template',
        rejectionType: 'unregistered_template',
      };
    }

    // Query is valid and parameterized
    return {
      allowed: true,
      template,
      params,
    };
  }

  /**
   * Hot-reload templates from the JSON file.
   */
  function reload() {
    loadTemplates();
  }

  return {
    parameterize,
    reload,
  };
}
