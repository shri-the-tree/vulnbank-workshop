/**
 * Path Validator - Sandbox enforcement for file-access tool calls
 *
 * Restricts file system access to a configurable sandbox directory,
 * blocking path traversal, symlink escapes, and invalid characters.
 *
 * Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7
 */

import { realpathSync, lstatSync, readlinkSync } from 'node:fs';
import { resolve, normalize, sep } from 'node:path';
import { createAuditLogger } from './audit-logger.js';

/** Maximum allowed path length (Req 6.1) */
const MAX_PATH_LENGTH = 4096;

/** Default sandbox root (Req 6.5) */
const DEFAULT_SANDBOX_ROOT = './workspace/sandbox';

/**
 * @typedef {Object} PathValidationResult
 * @property {boolean} allowed - Whether path is within sandbox
 * @property {string} [resolvedPath] - Canonical resolved path
 * @property {string} [error] - Violation description
 * @property {'traversal'|'symlink_escape'|'invalid_characters'|'too_long'} [violationType]
 */

/**
 * Check if a character code is a valid path character.
 * Allows printable ASCII (32-126) plus path separators.
 * Rejects null bytes and non-printable characters.
 * (Req 6.3)
 *
 * @param {number} charCode - Character code to check
 * @returns {boolean} Whether the character is valid
 */
function isValidPathChar(charCode) {
  // Null byte is always rejected
  if (charCode === 0x00) return false;

  // Path separators are always allowed (/ and \ on Windows)
  if (charCode === 0x2F) return true; // forward slash
  if (charCode === 0x5C) return true; // backslash (Windows separator)

  // Printable ASCII range: 32-126
  return charCode >= 32 && charCode <= 126;
}

/**
 * Validate that a path contains only allowed characters.
 * (Req 6.3)
 *
 * @param {string} pathStr - Path to validate
 * @returns {boolean} Whether all characters are valid
 */
function hasValidCharacters(pathStr) {
  for (let i = 0; i < pathStr.length; i++) {
    if (!isValidPathChar(pathStr.charCodeAt(i))) {
      return false;
    }
  }
  return true;
}

/**
 * Check if a path is a symbolic link and resolve its target.
 * Returns the real path if it's a symlink, null otherwise.
 * (Req 6.4)
 *
 * @param {string} absolutePath - Absolute path to check
 * @returns {{ isSymlink: boolean, realPath: string | null }}
 */
function resolveSymlink(absolutePath) {
  try {
    const stats = lstatSync(absolutePath);
    if (stats.isSymbolicLink()) {
      const realPath = realpathSync(absolutePath);
      return { isSymlink: true, realPath };
    }
    return { isSymlink: false, realPath: null };
  } catch {
    // Path doesn't exist yet (e.g., new file write) - not a symlink
    return { isSymlink: false, realPath: null };
  }
}

/**
 * Creates a PathValidator instance bound to a sandbox root directory.
 * (Req 6.5)
 *
 * @param {string} [sandboxRoot] - Sandbox root directory (default: ./workspace/sandbox)
 * @param {Object} [options] - Additional options
 * @param {Object} [options.logger] - Audit logger instance
 * @returns {PathValidator}
 */
export function createPathValidator(sandboxRoot, options = {}) {
  // Resolve sandbox root to absolute canonical form (Req 6.5)
  const resolvedSandboxRoot = resolve(sandboxRoot || DEFAULT_SANDBOX_ROOT);
  // Normalize with trailing separator for prefix comparison
  const sandboxPrefix = resolvedSandboxRoot.endsWith(sep)
    ? resolvedSandboxRoot
    : resolvedSandboxRoot + sep;

  const logger = options.logger || createAuditLogger({ minLevel: 'WARN' });

  /**
   * Log a path violation event.
   * (Req 6.6)
   *
   * @param {string} originalPath - Original requested path
   * @param {string} resolvedPath - Resolved canonical path
   * @param {string} violationType - Type of violation
   * @param {string} [agentId] - Requesting agent identity
   */
  function logViolation(originalPath, resolvedPath, violationType, agentId) {
    logger.logBlockedAttack({
      attackCategory: 'path_traversal',
      action: 'blocked',
      originalPath,
      resolvedPath,
      violationType,
      agentId: agentId || 'unknown',
    });
  }

  /**
   * Validate a requested file path against the sandbox.
   *
   * @param {string} requestedPath - Path requested by the agent
   * @param {string} operation - Operation type (read, write, delete, list)
   * @param {Object} [context] - Additional context
   * @param {string} [context.agentId] - Requesting agent identity
   * @returns {PathValidationResult}
   */
  function validate(requestedPath, operation, context = {}) {
    const agentId = context.agentId || 'unknown';

    // Req 6.1: Reject paths exceeding 4,096 characters
    if (requestedPath.length > MAX_PATH_LENGTH) {
      const result = {
        allowed: false,
        error: `Path exceeds maximum length of ${MAX_PATH_LENGTH} characters`,
        violationType: 'too_long',
      };
      logViolation(requestedPath.substring(0, 100) + '...', '', 'too_long', agentId);
      return result;
    }

    // Req 6.3: Reject paths with null bytes or non-printable ASCII
    if (!hasValidCharacters(requestedPath)) {
      const result = {
        allowed: false,
        error: 'Path contains invalid characters (null bytes or non-printable ASCII)',
        violationType: 'invalid_characters',
      };
      logViolation(requestedPath, '', 'invalid_characters', agentId);
      return result;
    }

    // Req 6.1: Resolve to absolute canonical form
    const resolvedPath = resolve(resolvedSandboxRoot, normalize(requestedPath));

    // Req 6.2: Verify resolved path starts with sandbox root (no I/O)
    if (resolvedPath !== resolvedSandboxRoot && !resolvedPath.startsWith(sandboxPrefix)) {
      const result = {
        allowed: false,
        resolvedPath,
        error: 'Path resolves outside the sandbox directory',
        violationType: 'traversal',
      };
      logViolation(requestedPath, resolvedPath, 'traversal', agentId);
      return result;
    }

    // Req 6.4: Check for symlinks targeting outside sandbox
    const symlinkCheck = resolveSymlink(resolvedPath);
    if (symlinkCheck.isSymlink) {
      const symlinkTarget = symlinkCheck.realPath;
      if (symlinkTarget !== resolvedSandboxRoot && !symlinkTarget.startsWith(sandboxPrefix)) {
        const result = {
          allowed: false,
          resolvedPath: symlinkTarget,
          error: 'Symbolic link target resolves outside the sandbox directory',
          violationType: 'symlink_escape',
        };
        logViolation(requestedPath, symlinkTarget, 'symlink_escape', agentId);
        return result;
      }
    }

    // All checks passed
    return {
      allowed: true,
      resolvedPath,
    };
  }

  return {
    validate,
    /** Expose sandbox root for testing/introspection */
    get sandboxRoot() {
      return resolvedSandboxRoot;
    },
  };
}
