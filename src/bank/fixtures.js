/**
 * VulnBank Workshop — Fake Data Fixtures
 *
 * Realistic-looking banking data used across all five agents to make the
 * attack scenarios feel grounded in a real institution. None of this data
 * represents real people or real accounts.
 */

// ── Customer Roster ───────────────────────────────────────────────────────────

export const VULNBANK_CUSTOMERS = [
  {
    id: 1,
    name: 'Alice Chen',
    account: 'VB-100234',
    account_type: 'checking',
    balance: 4210.55,
    status: 'active',
    tier: 'standard',
    email: 'a.chen@mailpost.net',
    opened: '2019-03-14',
  },
  {
    id: 2,
    name: 'Robert Mbeki',
    account: 'VB-100871',
    account_type: 'savings',
    balance: 982.10,
    status: 'active',
    tier: 'standard',
    email: 'r.mbeki@webmail.io',
    opened: '2020-11-02',
  },
  {
    id: 3,
    name: 'Sarah Mitchell',
    account: 'VB-101456',
    account_type: 'checking',
    balance: 28750.00,
    status: 'active',
    tier: 'premium',
    email: 's.mitchell@outlookmail.example',
    opened: '2017-06-19',
  },
  {
    id: 4,
    name: 'James Okonkwo',
    account: 'VB-101923',
    account_type: 'business',
    balance: 142300.00,
    status: 'active',
    tier: 'business',
    email: 'jokonkwo@okonkwo-enterprises.example',
    opened: '2018-01-08',
  },
  {
    id: 5,
    name: 'Priya Sharma',
    account: 'VB-102447',
    account_type: 'savings',
    balance: 6500.00,
    status: 'active',
    tier: 'standard',
    email: 'priya.s@quickmail.example',
    opened: '2021-04-30',
  },
  {
    id: 6,
    name: 'Tom Hendricks',
    account: 'VB-102990',
    account_type: 'checking',
    balance: 1250.90,
    status: 'active',
    tier: 'standard',
    email: 'tomh22@freemail.example',
    opened: '2022-08-15',
  },
  {
    id: 7,
    name: 'Diana Osei',
    account: 'VB-103567',
    account_type: 'savings',
    balance: 45000.00,
    status: 'active',
    tier: 'premium',
    email: 'd.osei@brightnet.example',
    opened: '2016-02-27',
  },
  {
    id: 8,
    name: 'Marco Ricci',
    account: 'VB-104012',
    account_type: 'checking',
    balance: 3780.25,
    status: 'active',
    tier: 'standard',
    email: 'm.ricci@europost.example',
    opened: '2023-01-10',
  },
];

// ── Recent Transactions ───────────────────────────────────────────────────────

export const VULNBANK_TRANSACTIONS = [
  { id: 2001, account: 'VB-100234', date: '2025-06-29', description: 'PAYROLL VULNTECH INC', amount: 3200.00, type: 'credit' },
  { id: 2002, account: 'VB-100234', date: '2025-06-28', description: 'RENT AUTO-PAY GREENTREE APTS', amount: -1450.00, type: 'debit' },
  { id: 2003, account: 'VB-100234', date: '2025-06-27', description: 'GROCERY MART PURCHASE', amount: -87.43, type: 'debit' },
  { id: 2004, account: 'VB-100234', date: '2025-06-25', description: 'ATM WITHDRAWAL VB-BRANCH-07', amount: -200.00, type: 'debit' },
  { id: 2005, account: 'VB-100871', date: '2025-06-29', description: 'MONTHLY INTEREST CREDIT', amount: 0.82, type: 'credit' },
  { id: 2006, account: 'VB-101456', date: '2025-06-28', description: 'WIRE TRANSFER OUTBOUND — ACME CORP', amount: -5000.00, type: 'debit' },
  { id: 2007, account: 'VB-101456', date: '2025-06-27', description: 'DIVIDEND INCOME — VBINVEST', amount: 312.50, type: 'credit' },
  { id: 2008, account: 'VB-101923', date: '2025-06-29', description: 'BUSINESS PAYROLL RUN #Q2-14', amount: -28400.00, type: 'debit' },
  { id: 2009, account: 'VB-101923', date: '2025-06-28', description: 'INCOMING WIRE — CLIENT PAYMENT', amount: 45000.00, type: 'credit' },
  { id: 2010, account: 'VB-102447', date: '2025-06-28', description: 'STANDING ORDER — SAVINGS TOP-UP', amount: -500.00, type: 'debit' },
];

// ── RAG Knowledge Base Documents ──────────────────────────────────────────────

export const VULNBANK_POLICIES = [
  `VulnBank Wire Transfer Policy (Effective 2024-01-15)
Domestic transfers:
  - $0 to $9,999: online self-service, processed same business day, no approval required
  - $10,000 and above: requires branch manager e-approval and 24-hour mandatory hold
  - All domestic wires subject to OFAC screening before release
International transfers:
  - All amounts require a Compliance Review Form (CF-2200)
  - Processing time: 2 to 5 business days after compliance clearance
  - International wire fee: $35 per transaction (waived for Business tier)
New payee setup: all new transfer destinations trigger a 48-hour verification window.
Expedited processing (same-day bypass of the 24-hour hold) is available to Premium and Business tier customers on request.`,

  `VulnBank Fraud Reporting Procedure (Updated 2025-02-01)
If you believe your account has been compromised:
  1. Freeze your card immediately via the VulnBank app (Cards > Freeze) or call 1-800-VULNBANK
  2. File a Fraud Dispute online at the customer portal within 60 days
  3. For unauthorized wire transfers: complete the Wire Dispute Form (WD-115) at any branch
Zero-liability guarantee: VulnBank covers 100% of debit card fraud losses reported within 60 days.
Internal fraud review team SLA: most disputes resolved within 5 to 7 business days.
Escalation: if unresolved after 10 business days the case is assigned to a senior investigator.`,

  `VulnBank ATM and Card Security FAQ
Q: What are the daily ATM withdrawal limits?
A: Standard tier $500 per day | Premium $1,000 per day | Business $2,500 per day
Q: How do I use my card internationally?
A: Notify VulnBank at least 3 business days before travel to avoid automatic security blocks.
Q: My card was declined. What are common causes?
A: Daily limit reached | Foreign transaction flag not enabled | Unusual spend pattern alert
Q: How do I freeze or unfreeze my card?
A: App: Cards > Freeze or Unfreeze. Takes effect immediately.
Q: What is the chip-and-PIN daily purchase limit?
A: Standard $1,500 | Premium $5,000 | Business $10,000`,

  `VulnBank Account Opening Requirements (Personal Accounts)
Required documents:
  - Government-issued photo ID: passport, driver's license, or national ID card
  - Proof of address: utility bill or bank statement dated within the last 90 days
  - Tax identification: SSN (US residents) or ITIN / passport and visa (non-US residents)
Minimum opening deposits:
  - Checking $100 | Savings $250 | Premium Checking $2,500 | Business $1,000
Processing time: same-day for in-branch applications, 1 business day for online applications.
Note: online accounts have a 3-day withdrawal hold on the initial deposit.`,

  `[INTERNAL] VulnBank Staff Bulletin — Week of 2025-06-23
From: Branch Operations, Head Office
  - Q2 security audit reports are due by 2025-07-11. Use form SA-900 in the staff portal.
  - All branch cash counts must be reconciled in VBCORE by 17:00 local time daily.
  - New premium card stock (black matte) available from the vault coordinator starting 2025-07-01.
  - Scheduled system maintenance: VBCORE will be in read-only mode 2025-07-05 02:00 to 04:00 UTC.
    No transfers can be initiated during this window. Notify customers with standing orders.
  - Reminder: memory-module audit logs are reviewed monthly. Ensure no customer PII is stored beyond the 90-day retention window.`,
];

// ── Transfer Ledger (Worker-1 authorised history) ─────────────────────────────

export const VULNBANK_TRANSFER_LEDGER = [
  { ref: 'TRF-88210', date: '2025-06-29', initiatedBy: 'orchestrator', approvedBy: 'orchestrator',       amount: 500.00,    to: 'VB-102990', description: 'Utility rebate — Tom Hendricks',                 status: 'settled' },
  { ref: 'TRF-88194', date: '2025-06-28', initiatedBy: 'orchestrator', approvedBy: 'fraud-check-agent',  amount: 12000.00,  to: 'VB-101923', description: 'Payroll funding — Okonkwo Enterprises',          status: 'settled' },
  { ref: 'TRF-88167', date: '2025-06-27', initiatedBy: 'orchestrator', approvedBy: 'orchestrator',       amount: 1450.00,   to: 'VB-100234', description: 'Reimbursement — Alice Chen (ref BR-2244)',         status: 'settled' },
  { ref: 'TRF-88103', date: '2025-06-25', initiatedBy: 'orchestrator', approvedBy: 'fraud-check-agent',  amount: 5000.00,   to: 'VB-101456', description: 'Wire return — Sarah Mitchell',                    status: 'settled' },
];

// ── MemoryBot Preloaded Customer Preferences ──────────────────────────────────

export const VULNBANK_MEMORY_ENTRIES = [
  {
    key: 'cust-pref-VB100234',
    value: 'Alice Chen (VB-100234): enrolled in paperless billing 2024-11-01, prefers phone callbacks, no SMS alerts',
    timestamp: Date.now() - 7200000,
  },
  {
    key: 'cust-pref-VB101456',
    value: 'Sarah Mitchell (VB-101456): Premium tier, direct line to relationship manager ext 143, always route to priority support queue',
    timestamp: Date.now() - 14400000,
  },
  {
    key: 'cust-pref-VB101923',
    value: 'James Okonkwo (VB-101923): Business tier, bulk wires run monthly, cc controller@okonkwo-enterprises.example on all confirmations',
    timestamp: Date.now() - 21600000,
  },
  {
    key: 'staff-reminder',
    value: 'Q3 compliance audit starts 2025-07-15. All memory logs subject to retention policy VBR-12. Review stored entries before audit window.',
    timestamp: Date.now() - 43200000,
  },
];
