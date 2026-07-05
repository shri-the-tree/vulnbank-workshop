/**
 * Command Injection Preventer - Validates and restricts shell commands
 *
 * Enforces an allowlist of permitted commands, blocks shell metacharacters,
 * redirection operators, and path traversal sequences. Executes allowed
 * commands with a configurable timeout.
 *
 * Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.7, 19.8
 */

import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { createAuditLogger } from './audit-logger.js';

/**
 * Shell metacharacters that indicate command chaining or injection.
 * Covers: ; | & ` $() && || and newline characters.
 */
const SHELL_METACHAR_PATTERN = /[;|&`]|\$\(|\n|\r|&&|\|\|/;

/**
 * Redirection operators: >, >>, <, <<
 */
const REDIRECTION_PATTERN = />>|<<|[><]/;

/**
 * Path traversal patterns: ../ or ..\
 */
const PATH_TRAVERSAL_PATTERN = /\.\.[/\\]/;

/**
 * @typedef {Object} CommandCheckResult
 * @property {boolean} allowed - Whether the command passed validation
 * @property {string} [error] - Error message if rejected
 * @property {string} [reason] - Machine-readable rejection reason
 * @property {string[]} [allowedCommands] - List of allowed commands (on rejection)
 */

/**
 * @typedef {Object} CommandExecutionResult
 * @property {boolean} success - Whether execution completed successfully
 * @property {string} [stdout] - Command stdout output
 * @property {string} [stderr] - Command stderr output
 * @property {string} [error] - Error message if execution failed
 * @property {string} [reason] - Machine-readable error reason
 */

/**
 * Creates a Command Injection Preventer instance.
 *
 * @param {Object} options
 * @param {string} [options.configPath] - Path to command-allowlist.json
 * @param {Object} [options.auditLogger] - AuditLogger instance for logging rejections
 * @returns {CommandInjectionPreventer}
 */
export function createCommandInjectionPreventer(options = {}) {
  const {
    configPath = null,
    auditLogger = null,
  } = options;

  let config = {
    allowedCommands: ['ls', 'cat', 'echo', 'date', 'whoami', 'pwd'],
    maxCommandLength: 1024,
    executionTimeoutMs: 10000,
  };

  // Load configuration from JSON file if provided
  if (configPath) {
    try {
      const raw = readFileSync(configPath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.allowedCommands)) {
        config.allowedCommands = parsed.allowedCommands;
      }
      if (typeof parsed.maxCommandLength === 'number' && parsed.maxCommandLength > 0) {
        config.maxCommandLength = parsed.maxCommandLength;
      }
      if (typeof parsed.executionTimeoutMs === 'number' && parsed.executionTimeoutMs > 0) {
        config.executionTimeoutMs = parsed.executionTimeoutMs;
      }
    } catch {
      // Fall back to defaults if config file is unavailable
    }
  }

  const logger = auditLogger || createAuditLogger({ minLevel: 'WARN' });

  /**
   * Log a command rejection to the audit logger.
   * @param {string} command - Full command string
   * @param {string} reason - Rejection reason
   * @param {Object} context - Additional context (agent, sourceIP)
   */
  function logRejection(command, reason, context = {}) {
    logger.logBlockedAttack({
      sourceIP: context.sourceIP || 'unknown',
      agentTarget: context.agent || 'unknown',
      attackCategory: 'command_injection',
      matchedPattern: reason,
      action: 'blocked',
      inputPreview: command.substring(0, 200),
    });
  }

  /**
   * Parse the base command (first token) from a command string.
   * Handles quoted strings and extracts just the command name without path.
   * @param {string} commandStr - Raw command string
   * @returns {string} The base command name
   */
  function parseBaseCommand(commandStr) {
    const trimmed = commandStr.trim();
    // Extract the first token (space-delimited)
    const firstSpace = trimmed.indexOf(' ');
    const firstToken = firstSpace === -1 ? trimmed : trimmed.substring(0, firstSpace);

    // Strip any path prefix to get just the command name
    // e.g., /usr/bin/ls -> ls, ./script -> script
    const lastSlash = Math.max(firstToken.lastIndexOf('/'), firstToken.lastIndexOf('\\'));
    return lastSlash === -1 ? firstToken : firstToken.substring(lastSlash + 1);
  }

  /**
   * Validate a command string against all security checks.
   *
   * @param {string} command - The command string to validate
   * @param {Object} [context] - Context (agent, sourceIP)
   * @returns {CommandCheckResult}
   */
  function check(command, context = {}) {
    // Check for empty/null command
    if (!command || typeof command !== 'string' || command.trim().length === 0) {
      return {
        allowed: false,
        error: 'Command string is empty or invalid',
        reason: 'empty_command',
      };
    }

    // Requirement 19.6: Enforce max command length (1,024 characters)
    if (command.length > config.maxCommandLength) {
      logRejection(command, 'command_length_exceeded', context);
      return {
        allowed: false,
        error: `Command exceeds maximum length of ${config.maxCommandLength} characters`,
        reason: 'length_exceeded',
      };
    }

    // Requirement 19.3: Reject shell metacharacters
    if (SHELL_METACHAR_PATTERN.test(command)) {
      logRejection(command, 'shell_metacharacters', context);
      return {
        allowed: false,
        error: 'Command contains shell metacharacters that are not permitted (;, |, &, `, $(), &&, ||, newlines)',
        reason: 'shell_metacharacters',
      };
    }

    // Requirement 19.4: Reject redirection operators
    if (REDIRECTION_PATTERN.test(command)) {
      logRejection(command, 'redirection_operators', context);
      return {
        allowed: false,
        error: 'Command contains redirection operators that are not permitted (>, >>, <, <<)',
        reason: 'redirection_operators',
      };
    }

    // Requirement 19.5: Reject path traversal in arguments
    // Check the arguments portion (everything after base command)
    const trimmed = command.trim();
    const firstSpace = trimmed.indexOf(' ');
    if (firstSpace !== -1) {
      const args = trimmed.substring(firstSpace + 1);
      if (PATH_TRAVERSAL_PATTERN.test(args)) {
        logRejection(command, 'path_traversal_in_arguments', context);
        return {
          allowed: false,
          error: 'Command arguments contain path traversal sequences (../ or ..\\ ) that are not permitted',
          reason: 'path_traversal',
        };
      }
    }

    // Requirement 19.1, 19.2: Verify base command against allowlist
    const baseCommand = parseBaseCommand(command);
    if (!config.allowedCommands.includes(baseCommand)) {
      logRejection(command, 'command_not_allowed', context);
      return {
        allowed: false,
        error: `Command '${baseCommand}' is not permitted. Allowed commands: ${config.allowedCommands.join(', ')}`,
        reason: 'command_not_allowed',
        allowedCommands: [...config.allowedCommands],
      };
    }

    return { allowed: true };
  }

  /**
   * Execute a validated command with timeout enforcement.
   *
   * @param {string} command - The command string to execute
   * @param {Object} [context] - Context (agent, sourceIP)
   * @returns {Promise<CommandExecutionResult>}
   */
  async function execute(command, context = {}) {
    // First validate the command
    const validation = check(command, context);
    if (!validation.allowed) {
      return {
        success: false,
        error: validation.error,
        reason: validation.reason,
      };
    }

    // Parse into command and arguments for execFile (safer than exec)
    const trimmed = command.trim();
    const parts = splitCommandArgs(trimmed);
    const cmd = parts[0];
    const args = parts.slice(1);

    return new Promise((resolve) => {
      const child = execFile(cmd, args, {
        timeout: config.executionTimeoutMs,
        maxBuffer: 1024 * 1024, // 1MB output buffer
        shell: false, // No shell interpretation for safety
      }, (error, stdout, stderr) => {
        if (error) {
          // Requirement 19.8: Handle timeout
          if (error.killed || error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' ||
              (error.signal === 'SIGTERM')) {
            logRejection(command, 'execution_timeout', context);
            resolve({
              success: false,
              error: `Command execution timed out after ${config.executionTimeoutMs}ms`,
              reason: 'execution_timeout',
            });
            return;
          }

          resolve({
            success: false,
            stdout: stdout || '',
            stderr: stderr || error.message || '',
            error: `Command execution failed: ${error.message}`,
            reason: 'execution_error',
          });
          return;
        }

        resolve({
          success: true,
          stdout: stdout || '',
          stderr: stderr || '',
        });
      });

      // Ensure timed-out processes are terminated (Req 19.8)
      // The timeout option in execFile sends SIGTERM automatically,
      // but we add a safety net to force kill if still running
      if (config.executionTimeoutMs > 0) {
        setTimeout(() => {
          try {
            if (child.exitCode === null) {
              child.kill('SIGKILL');
            }
          } catch {
            // Process may have already exited
          }
        }, config.executionTimeoutMs + 1000);
      }
    });
  }

  /**
   * Split a command string into an array of arguments.
   * Handles basic quoting (single and double quotes).
   * @param {string} commandStr
   * @returns {string[]}
   */
  function splitCommandArgs(commandStr) {
    const parts = [];
    let current = '';
    let inSingle = false;
    let inDouble = false;

    for (let i = 0; i < commandStr.length; i++) {
      const ch = commandStr[i];

      if (ch === "'" && !inDouble) {
        inSingle = !inSingle;
      } else if (ch === '"' && !inSingle) {
        inDouble = !inDouble;
      } else if (ch === ' ' && !inSingle && !inDouble) {
        if (current.length > 0) {
          parts.push(current);
          current = '';
        }
      } else {
        current += ch;
      }
    }

    if (current.length > 0) {
      parts.push(current);
    }

    return parts;
  }

  /**
   * Get the current configuration (for inspection/testing).
   * @returns {Object}
   */
  function getConfig() {
    return { ...config, allowedCommands: [...config.allowedCommands] };
  }

  return {
    check,
    execute,
    getConfig,
  };
}
