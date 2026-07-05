/**
 * Output Filter - Data exfiltration prevention via redaction
 *
 * Scans agent responses for sensitive data (API keys, system prompts, PII,
 * database credentials) and redacts them before delivery to the user.
 * Supports a configurable allowlist of terms that are never redacted.
 *
 * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
 */

import { readFileSync } from 'node:fs';

/**
 * @typedef {Object} Redaction
 * @property {string} type - The redaction label type (e.g., 'API_KEY', 'SSN')
 * @property {number} position - Character position of the redaction in the original text
 */

/**
 * @typedef {Object} FilterResult
 * @property {string} filtered - Response with redactions applied
 * @property {Array<Redaction>} redactions - Applied redactions
 */

// --- Regex Patterns ---

/** API key patterns (Req 2.1) */
const API_KEY_PATTERNS = [
  // sk-ant- must come before sk- to match the longer prefix first
  /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
  /\bsk-[A-Za-z0-9_\-]{20,}\b/g,
  /\bAKIA[A-Z0-9]{16}\b/g,
  /\bBearer\s+[A-Za-z0-9_\-\.]{10,}\b/g,
];

/** PII patterns (Req 2.3) */
const PII_PATTERNS = [
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: '[REDACTED:SSN]', type: 'SSN' },
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: '[REDACTED:EMAIL]', type: 'EMAIL' },
  { pattern: /\bVB-\d{6}\b/g, label: '[REDACTED:ACCOUNT]', type: 'ACCOUNT' },
];

/** Database credential patterns (Req 2.4) */
const DB_CREDENTIAL_PATTERNS = [
  // Connection string URIs: protocol://user:pass@host
  /(?:mysql|postgres|postgresql|mongodb|redis|mssql):\/\/[^\s]+/gi,
  // host=, user=, password= patterns (through end of credential block)
  /(?:host|user|username|password|passwd|dbname|database)\s*=\s*[^\s;,\n]+(?:\s*[;,]\s*(?:host|user|username|password|passwd|dbname|database|port)\s*=\s*[^\s;,\n]+)*/gi,
];

/**
 * Loads the allowlist from a JSON file.
 * @param {string} allowlistPath - Path to the allowlist JSON file
 * @returns {string[]} Array of allowlisted terms
 */
function loadAllowlist(allowlistPath) {
  try {
    const content = readFileSync(allowlistPath, 'utf-8');
    const parsed = JSON.parse(content);
    return Array.isArray(parsed.allowlist) ? parsed.allowlist : [];
  } catch {
    return [];
  }
}

/**
 * Checks if a matched string is covered by the allowlist.
 * @param {string} match - The matched text
 * @param {string[]} allowlist - Array of allowlisted terms
 * @returns {boolean} True if the match should be preserved (not redacted)
 */
function isAllowlisted(match, allowlist) {
  for (const term of allowlist) {
    if (match.includes(term)) {
      return true;
    }
  }
  return false;
}

/**
 * Detects system prompt leakage in the response text.
 * Finds 30+ consecutive character matches against any agent persona.
 *
 * @param {string} text - Response text to scan
 * @param {Map<string, string>|Object} agentPersonas - Map of agentId → persona/system prompt text
 * @param {Object|null} agentContext - Context with agentId to narrow search
 * @returns {Array<{start: number, end: number}>} Array of match ranges
 */
function detectSystemPromptLeakage(text, agentPersonas, agentContext) {
  const matches = [];
  const MIN_MATCH_LENGTH = 30;

  // Determine which personas to check
  let personasToCheck = [];

  if (agentPersonas instanceof Map) {
    if (agentContext && agentContext.agentId && agentPersonas.has(agentContext.agentId)) {
      personasToCheck.push(agentPersonas.get(agentContext.agentId));
    } else {
      personasToCheck = [...agentPersonas.values()];
    }
  } else if (agentPersonas && typeof agentPersonas === 'object') {
    if (agentContext && agentContext.agentId && agentPersonas[agentContext.agentId]) {
      personasToCheck.push(agentPersonas[agentContext.agentId]);
    } else {
      personasToCheck = Object.values(agentPersonas);
    }
  }

  for (const persona of personasToCheck) {
    if (!persona || typeof persona !== 'string' || persona.length < MIN_MATCH_LENGTH) {
      continue;
    }

    // Sliding window: find 30+ char substrings of the persona in the response
    // Use a step size for performance while still catching matches
    for (let len = Math.min(persona.length, text.length); len >= MIN_MATCH_LENGTH; len = Math.floor(len / 2)) {
      for (let i = 0; i <= persona.length - len; i += Math.max(1, Math.floor(len / 4))) {
        const substring = persona.substring(i, i + len);
        const idx = text.indexOf(substring);
        if (idx !== -1) {
          // Found a match; try to expand it
          let start = idx;
          let end = idx + len;

          // Try to expand backwards and forwards to find the longest match
          let personaStart = i;
          while (start > 0 && personaStart > 0 && text[start - 1] === persona[personaStart - 1]) {
            start--;
            personaStart--;
          }
          let personaEnd = i + len;
          while (end < text.length && personaEnd < persona.length && text[end] === persona[personaEnd]) {
            end++;
            personaEnd++;
          }

          // Only record if the match is at least MIN_MATCH_LENGTH
          if (end - start >= MIN_MATCH_LENGTH) {
            // Check if this range overlaps with existing matches
            let overlaps = false;
            for (const existing of matches) {
              if (start < existing.end && end > existing.start) {
                // Merge with existing
                existing.start = Math.min(existing.start, start);
                existing.end = Math.max(existing.end, end);
                overlaps = true;
                break;
              }
            }
            if (!overlaps) {
              matches.push({ start, end });
            }
          }
          // Skip ahead past this match at this length
          break;
        }
      }
    }
  }

  return matches;
}

/**
 * Creates an OutputFilter instance.
 *
 * @param {string} allowlistPath - Path to the allowlist JSON file
 * @param {Map<string, string>|Object} agentPersonas - Map of agentId → persona/system prompt text
 * @returns {OutputFilter}
 */
export function createOutputFilter(allowlistPath, agentPersonas = {}) {
  let allowlist = loadAllowlist(allowlistPath);

  /**
   * Applies all redaction patterns to the response text.
   *
   * @param {string} responseText - The raw response text from the agent
   * @param {Object} [agentContext] - Context about the agent (e.g., { agentId: 'helperbot' })
   * @returns {FilterResult}
   */
  function apply(responseText, agentContext = null) {
    if (!responseText || typeof responseText !== 'string') {
      return { filtered: responseText || '', redactions: [] };
    }

    const redactions = [];
    // Track ranges that have been redacted to avoid double-redaction
    // Each entry: { start, end, label }
    const redactedRanges = [];

    // --- Pass 1: System prompt leakage (Req 2.2) ---
    const promptMatches = detectSystemPromptLeakage(responseText, agentPersonas, agentContext);
    for (const match of promptMatches) {
      const matchText = responseText.substring(match.start, match.end);
      if (!isAllowlisted(matchText, allowlist)) {
        redactedRanges.push({ start: match.start, end: match.end, label: '[REDACTED:SYSTEM_PROMPT]', type: 'SYSTEM_PROMPT' });
      }
    }

    // --- Pass 2: API keys (Req 2.1) ---
    for (const pattern of API_KEY_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let m;
      while ((m = regex.exec(responseText)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (!isAllowlisted(m[0], allowlist) && !isInRedactedRange(start, end, redactedRanges)) {
          redactedRanges.push({ start, end, label: '[REDACTED:API_KEY]', type: 'API_KEY' });
        }
      }
    }

    // --- Pass 3: Database credentials (Req 2.4) ---
    // DB credentials before PII because connection strings contain @ which looks like emails
    for (const pattern of DB_CREDENTIAL_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let m;
      while ((m = regex.exec(responseText)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (!isAllowlisted(m[0], allowlist) && !isInRedactedRange(start, end, redactedRanges)) {
          redactedRanges.push({ start, end, label: '[REDACTED:DB_CREDENTIALS]', type: 'DB_CREDENTIALS' });
        }
      }
    }

    // --- Pass 4: PII (Req 2.3) ---
    for (const { pattern, label, type } of PII_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let m;
      while ((m = regex.exec(responseText)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (!isAllowlisted(m[0], allowlist) && !isInRedactedRange(start, end, redactedRanges)) {
          redactedRanges.push({ start, end, label, type });
        }
      }
    }

    // --- Apply redactions (sorted by position, from end to start for correct indexing) ---
    redactedRanges.sort((a, b) => a.start - b.start);

    // Build filtered text
    let filtered = '';
    let lastEnd = 0;
    for (const range of redactedRanges) {
      // Skip overlapping ranges (keep earliest)
      if (range.start < lastEnd) continue;
      filtered += responseText.substring(lastEnd, range.start);
      filtered += range.label;
      redactions.push({ type: range.type, position: range.start });
      lastEnd = range.end;
    }
    filtered += responseText.substring(lastEnd);

    return { filtered, redactions };
  }

  /**
   * Hot-reload the allowlist from the configured path.
   */
  function reload() {
    allowlist = loadAllowlist(allowlistPath);
  }

  return { apply, reload };
}

/**
 * Checks if a range overlaps with any already-redacted range.
 * @param {number} start
 * @param {number} end
 * @param {Array<{start: number, end: number}>} ranges
 * @returns {boolean}
 */
function isInRedactedRange(start, end, ranges) {
  for (const range of ranges) {
    if (start < range.end && end > range.start) {
      return true;
    }
  }
  return false;
}
