/**
 * Secrets Manager - Credential management via environment variables
 *
 * Loads sensitive values from environment variables at startup and provides
 * controlled access that prevents exposure in logs, stack traces, or prompts.
 *
 * Requirements: 11.1, 11.2, 11.3, 11.4, 11.6, 11.7
 */

/**
 * @typedef {Object} SecretsManager
 * @property {function(string): string} get - Returns secret value via closure
 * @property {function(string): string} getMasked - Returns masked representation
 * @property {function(string): string[]} detectLeaks - Scans text for leaked secrets
 */

/**
 * Creates and initializes a SecretsManager that loads secrets from environment variables.
 *
 * @param {string[]} requiredVars - List of environment variable names that must be present
 * @param {Object} [options] - Optional configuration
 * @param {string[]} [options.systemPrompts] - Agent system prompts to scan for leaked secrets
 * @returns {SecretsManager}
 * @throws {Error} If any required environment variable is missing
 * @throws {Error} If any loaded secret is detected in system prompts
 */
export function createSecretsManager(requiredVars, options = {}) {
  return SecretsManager.initialize(requiredVars, options);
}

export class SecretsManager {
  // Private store using a WeakRef-inaccessible closure pattern
  #secretAccessors;
  #loadedVarNames;

  /**
   * Loads secrets from environment. Throws if required vars missing.
   * Must be called at application startup.
   *
   * @param {string[]} requiredVars - List of required environment variable names
   * @param {Object} [options] - Optional configuration
   * @param {string[]} [options.systemPrompts] - Agent system prompts to scan for leaked secrets
   * @returns {SecretsManager}
   * @throws {Error} If any required variable is missing (logs names but NOT values)
   * @throws {Error} If leaked secrets found in system prompts
   */
  static initialize(requiredVars, options = {}) {
    if (!Array.isArray(requiredVars) || requiredVars.length === 0) {
      throw new Error('SecretsManager: requiredVars must be a non-empty array of variable names');
    }

    // Req 11.1: Load all sensitive values exclusively from environment variables at startup
    const missing = [];
    const loaded = new Map();

    for (const varName of requiredVars) {
      const value = process.env[varName];
      if (value === undefined || value === '') {
        missing.push(varName);
      } else {
        loaded.set(varName, value);
      }
    }

    // Req 11.2: If required env var is missing, prevent app from starting;
    // log names but NOT values
    if (missing.length > 0) {
      const missingNames = missing.join(', ');
      throw new Error(
        `SecretsManager: application cannot start. Missing required environment variables: ${missingNames}`
      );
    }

    const instance = new SecretsManager(loaded);

    // Req 11.6: Detect leaked secrets in agent system prompts at startup
    if (options.systemPrompts && Array.isArray(options.systemPrompts)) {
      for (const prompt of options.systemPrompts) {
        const leaks = instance.detectLeaks(prompt);
        if (leaks.length > 0) {
          throw new Error(
            `SecretsManager: configuration error - secret values detected in agent system prompts. ` +
            `Leaked variables: ${leaks.join(', ')}. Remove secret values from system prompts.`
          );
        }
      }
    }

    return instance;
  }

  /**
   * @param {Map<string, string>} loaded - Map of variable name to value
   */
  constructor(loaded) {
    this.#loadedVarNames = [...loaded.keys()];

    // Req 11.4: Use closures to hide values from stack traces.
    // Each accessor is a closure that captures the value without
    // exposing it as a property on any reachable object.
    this.#secretAccessors = new Map();

    for (const [name, value] of loaded) {
      // The value is captured in this closure's scope only.
      // It won't appear in Error stack traces or object inspection.
      const accessor = () => value;
      this.#secretAccessors.set(name, accessor);
    }
  }

  /**
   * Returns the secret value. Throws if variable was not loaded.
   * Value is not exposed in stack traces (uses a closure).
   *
   * Req 11.4: Controlled accessor that does not expose value in stack traces
   * Req 11.7: If secret not loaded, throw error indicating which variable
   *           is unavailable without revealing other secrets
   *
   * @param {string} variableName - The environment variable name
   * @returns {string} The secret value
   * @throws {Error} If the variable was not loaded at startup
   */
  get(variableName) {
    const accessor = this.#secretAccessors.get(variableName);
    if (!accessor) {
      // Req 11.7: indicate which variable is unavailable without revealing other secrets
      throw new Error(
        `SecretsManager: secret '${variableName}' is not available. ` +
        `It was not loaded at startup.`
      );
    }
    return accessor();
  }

  /**
   * Returns masked representation (first 4 chars + asterisks).
   *
   * Req 11.3: Never include raw secret values in log output, system prompts,
   * or error messages; use masked representation
   *
   * @param {string} variableName - The environment variable name
   * @returns {string} Masked value (first 4 chars + asterisks)
   * @throws {Error} If the variable was not loaded at startup
   */
  getMasked(variableName) {
    const value = this.get(variableName);
    if (value.length <= 4) {
      return value.charAt(0) + '****';
    }
    return value.substring(0, 4) + '****';
  }

  /**
   * Scans text for leaked secret values (≥8 char substring match).
   * Returns list of variable names whose values appear in the text.
   *
   * Req 11.6: Detect 8+ char substring match of any loaded secret in text
   *
   * @param {string} text - Text to scan for leaked secrets
   * @returns {string[]} List of variable names whose values were found in the text
   */
  detectLeaks(text) {
    if (!text || typeof text !== 'string') {
      return [];
    }

    const leaked = [];

    for (const varName of this.#loadedVarNames) {
      const value = this.get(varName);

      // Only check secrets that are at least 8 characters long
      if (value.length < 8) {
        continue;
      }

      // Check if any 8+ character substring of the secret appears in the text
      if (text.includes(value)) {
        leaked.push(varName);
        continue;
      }

      // Also check for partial matches - any 8-char contiguous substring
      // of the secret value appearing in the text
      const minLen = 8;
      for (let i = 0; i <= value.length - minLen; i++) {
        const substring = value.substring(i, i + minLen);
        if (text.includes(substring)) {
          leaked.push(varName);
          break;
        }
      }
    }

    return leaked;
  }

  /**
   * Returns the list of loaded variable names (for diagnostics, not values).
   * @returns {string[]}
   */
  getLoadedVariableNames() {
    return [...this.#loadedVarNames];
  }
}
