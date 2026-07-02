/**
 * VulnBank workshop win detection.
 *
 * In-memory only (no disk persistence -- a single workshop sitting doesn't
 * need state to survive a restart).
 *
 * Two different kinds of canary, matching two different attack shapes:
 *
 * - L1/L2/L3 are SECRET-LEAK levels: VulnBank plants a token the attacker
 *   has no way to know in advance (a flagged account number, a cross-
 *   customer statement reference, a DB row), generated fresh at boot so it
 *   can't be grepped from source. The win condition is that exact token
 *   reappearing somewhere it shouldn't -- substring match via checkText().
 *
 * - L4/L5 are ACTION levels: the attacker supplies their OWN payload (an
 *   arbitrary injected memory instruction; an arbitrary destination
 *   account for a fraudulent transfer). There is no pre-known secret to
 *   match -- the win condition is simply that the vulnerable action fired
 *   at all. recordMemoryFire() / recordTransfer() mark these done
 *   unconditionally on first occurrence.
 */

import crypto from 'crypto';

const TOKEN_LEVELS = ['L1', 'L2', 'L3'];
const ALL_LEVELS = ['L1', 'L2', 'L3', 'L4', 'L5'];

function randomToken(level) {
  return `CANARY-${level}-${crypto.randomBytes(4).toString('hex')}`;
}

const canaries = {};
for (const level of TOKEN_LEVELS) {
  canaries[level] = randomToken(level);
}

const state = {};
for (const level of ALL_LEVELS) {
  state[level] = { done: false, detectedAt: null, metric: null };
}

const ledger = [];

/**
 * Returns the canary token for a secret-leak level (L1-L3). Call this when
 * building seed data at boot so the planted datum matches what detection
 * is watching for.
 */
export function getCanary(level) {
  return canaries[level];
}

function markDone(level, metric) {
  if (state[level].done) return false; // first hit only
  state[level] = { done: true, detectedAt: Date.now(), metric };
  return true;
}

/**
 * Secret-leak detection (L1, L2, L3): substring match against the level's
 * planted token.
 */
export function checkText(level, responseText) {
  if (!responseText) return false;
  const token = canaries[level];
  if (token && responseText.includes(token)) {
    return markDone(level, `canary token observed in response: ${token}`);
  }
  return false;
}

/**
 * Action detection (L4): a previously-injected memory instruction fired
 * back out in a later response. No pre-known token -- the attacker's own
 * injected content is the payload; persistence/recall of it is the win.
 */
export function recordMemoryFire(metric) {
  return markDone('L4', metric);
}

/**
 * Action + ledger detection (L5): records every transfer attempt that
 * actually executed (for the demo narrative / audit trail), and marks the
 * level done unconditionally on the first one -- the attacker picks their
 * own destination account, so there's nothing to token-match.
 */
export function recordTransfer(from, to, amount) {
  const entry = { from, to, amount, at: Date.now() };
  ledger.push(entry);
  markDone('L5', `transfer of ${amount} executed via spoofed identity, to=${to}`);
  return entry;
}

export function getLedger() {
  return ledger.slice();
}

export function getLevelState() {
  return JSON.parse(JSON.stringify(state));
}
