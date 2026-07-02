/**
 * VulnBank workshop run-profile gating.
 *
 * BANK_PROFILE=participant (default) forces every HARDEN_Ln toggle off,
 * regardless of what's actually set in the environment -- this is the
 * safety net that stops a stray env var from handing participants a
 * hardened (boring) agent. BANK_PROFILE=demo is the presenter's profile;
 * only there do HARDEN_L1..HARDEN_L5 and AIM_ENFORCEMENT actually control
 * anything.
 */

export function getBankProfile() {
  return process.env.BANK_PROFILE === 'demo' ? 'demo' : 'participant';
}

export function isHardenEnabled(level) {
  if (getBankProfile() !== 'demo') return false;
  return process.env[`HARDEN_L${level}`] === 'on';
}

/**
 * L5 additionally respects DVAA's existing AIM_ENFORCEMENT variable
 * (documented in README, already used by the shipped RAGBot-AIM demo).
 * Both must agree for L5's AIM gate to be live: HARDEN_L5=on AND
 * AIM_ENFORCEMENT is not explicitly 'off'.
 */
export function isL5AimEnforced() {
  return isHardenEnabled(5) && process.env.AIM_ENFORCEMENT !== 'off';
}
