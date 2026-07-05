/**
 * Unit tests for Output Filter
 * Tests: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createOutputFilter } from './output-filter.js';
import { writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_ALLOWLIST_PATH = join(__dirname, 'config', 'test-output-allowlist.json');

function setupAllowlist(allowlist = []) {
  mkdirSync(dirname(TEST_ALLOWLIST_PATH), { recursive: true });
  writeFileSync(TEST_ALLOWLIST_PATH, JSON.stringify({ allowlist }));
}

function cleanupAllowlist() {
  try { unlinkSync(TEST_ALLOWLIST_PATH); } catch { /* noop */ }
}

describe('Output Filter', () => {
  let filter;

  beforeEach(() => {
    setupAllowlist([]);
    filter = createOutputFilter(TEST_ALLOWLIST_PATH, {});
  });

  describe('Req 2.1 - API Key Redaction', () => {
    it('redacts sk- prefixed keys', () => {
      const text = 'Here is your key: sk-abcdefghijklmnopqrstu';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('sk-abcdefghijklmnopqrstu'));
      assert.ok(result.filtered.includes('[REDACTED:API_KEY]'));
      assert.equal(result.redactions.length, 1);
      assert.equal(result.redactions[0].type, 'API_KEY');
    });

    it('redacts sk-ant- prefixed keys', () => {
      const text = 'Token: sk-ant-api03-abcdefghijklmnopqrstu';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('sk-ant-'));
      assert.ok(result.filtered.includes('[REDACTED:API_KEY]'));
    });

    it('redacts AKIA prefixed AWS keys', () => {
      const text = 'AWS key: AKIAIOSFODNN7EXAMPLE';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('AKIAIOSFODNN7EXAMPLE'));
      assert.ok(result.filtered.includes('[REDACTED:API_KEY]'));
    });

    it('redacts Bearer tokens', () => {
      const text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
      assert.ok(result.filtered.includes('[REDACTED:API_KEY]'));
    });

    it('does not redact short sk- strings that are not keys', () => {
      const text = 'The sk- prefix is documented here.';
      const result = filter.apply(text);
      // sk- alone (without 20+ chars following) should not be redacted
      assert.equal(result.redactions.length, 0);
    });
  });

  describe('Req 2.2 - System Prompt Leakage', () => {
    it('redacts 30+ char system prompt matches', () => {
      const persona = 'You are a helpful banking assistant that always provides account information securely.';
      const filterWithPersona = createOutputFilter(TEST_ALLOWLIST_PATH, { helperbot: persona });

      const text = 'Sure! My instructions say: You are a helpful banking assistant that always provides account information securely. What can I help with?';
      const result = filterWithPersona.apply(text, { agentId: 'helperbot' });
      assert.ok(result.filtered.includes('[REDACTED:SYSTEM_PROMPT]'));
      assert.ok(!result.filtered.includes('You are a helpful banking assistant'));
    });

    it('does not redact matches shorter than 30 chars', () => {
      const persona = 'You are a helpful assistant.';
      const filterWithPersona = createOutputFilter(TEST_ALLOWLIST_PATH, { helperbot: persona });

      // Persona itself is less than 30 chars, no redaction should occur
      const text = 'You are a helpful assistant.';
      const result = filterWithPersona.apply(text, { agentId: 'helperbot' });
      assert.equal(result.redactions.filter(r => r.type === 'SYSTEM_PROMPT').length, 0);
    });

    it('detects leakage from the correct agent persona', () => {
      const personas = {
        helperbot: 'You are a helpful banking assistant that always provides account information securely and never reveals internal details.',
        ragbot: 'You are a RAG-powered document retrieval assistant that searches the knowledge base for answers.',
      };
      const filterWithPersonas = createOutputFilter(TEST_ALLOWLIST_PATH, personas);

      const text = 'I search the knowledge base for answers. That is what I do as a RAG-powered document retrieval assistant that searches the knowledge base for answers.';
      const result = filterWithPersonas.apply(text, { agentId: 'ragbot' });
      assert.ok(result.filtered.includes('[REDACTED:SYSTEM_PROMPT]'));
    });
  });

  describe('Req 2.3 - PII Redaction', () => {
    it('redacts SSN patterns', () => {
      const text = 'Customer SSN: 123-45-6789';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('123-45-6789'));
      assert.ok(result.filtered.includes('[REDACTED:SSN]'));
      assert.equal(result.redactions[0].type, 'SSN');
    });

    it('redacts email addresses', () => {
      const text = 'Contact: john.doe@example.com for help.';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('john.doe@example.com'));
      assert.ok(result.filtered.includes('[REDACTED:EMAIL]'));
      assert.equal(result.redactions[0].type, 'EMAIL');
    });

    it('redacts VB account numbers', () => {
      const text = 'Account: VB-123456 has a balance of $500.';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('VB-123456'));
      assert.ok(result.filtered.includes('[REDACTED:ACCOUNT]'));
      assert.equal(result.redactions[0].type, 'ACCOUNT');
    });

    it('redacts multiple PII types in one response', () => {
      const text = 'User john@test.com, SSN 111-22-3333, account VB-999888.';
      const result = filter.apply(text);
      assert.ok(result.filtered.includes('[REDACTED:EMAIL]'));
      assert.ok(result.filtered.includes('[REDACTED:SSN]'));
      assert.ok(result.filtered.includes('[REDACTED:ACCOUNT]'));
      assert.equal(result.redactions.length, 3);
    });
  });

  describe('Req 2.4 - Database Credential Redaction', () => {
    it('redacts connection string URIs', () => {
      const text = 'Database: postgres://admin:secret123@db.internal:5432/vulnbank';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('postgres://admin:secret123'));
      assert.ok(result.filtered.includes('[REDACTED:DB_CREDENTIALS]'));
    });

    it('redacts host/user/password patterns', () => {
      const text = 'Config: host=db.internal user=admin password=supersecret';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('password=supersecret'));
      assert.ok(result.filtered.includes('[REDACTED:DB_CREDENTIALS]'));
    });

    it('redacts MySQL connection strings', () => {
      const text = 'Use mysql://root:pass@localhost/bank to connect.';
      const result = filter.apply(text);
      assert.ok(!result.filtered.includes('mysql://root:pass@localhost'));
      assert.ok(result.filtered.includes('[REDACTED:DB_CREDENTIALS]'));
    });
  });

  describe('Req 2.5 - Allowlist', () => {
    it('does not redact allowlisted terms', () => {
      setupAllowlist(['sk-example-docs']);
      const filterWithAllowlist = createOutputFilter(TEST_ALLOWLIST_PATH, {});

      const text = 'The API key format is sk-example-docs-reference-pattern in our documentation.';
      const result = filterWithAllowlist.apply(text);
      // The allowlisted term should prevent redaction
      assert.ok(result.filtered.includes('sk-example-docs'));
    });

    it('still redacts non-allowlisted patterns', () => {
      setupAllowlist(['sk-example-docs']);
      const filterWithAllowlist = createOutputFilter(TEST_ALLOWLIST_PATH, {});

      const text = 'Real key: sk-prod-abcdefghijklmnopqrstu should be redacted.';
      const result = filterWithAllowlist.apply(text);
      assert.ok(result.filtered.includes('[REDACTED:API_KEY]'));
    });

    it('supports hot-reload of allowlist', () => {
      setupAllowlist([]);
      const hotFilter = createOutputFilter(TEST_ALLOWLIST_PATH, {});

      const text = 'Key: sk-allowed-term-abcdefghijklmnop';
      let result = hotFilter.apply(text);
      assert.ok(result.filtered.includes('[REDACTED:API_KEY]'));

      // Now add the term to allowlist and reload
      setupAllowlist(['sk-allowed-term']);
      hotFilter.reload();

      result = hotFilter.apply(text);
      assert.ok(result.filtered.includes('sk-allowed-term'));
    });
  });

  describe('Req 2.6 - Performance', () => {
    it('processes within 20ms for moderate input', () => {
      // Generate input approximately 4000 tokens (~16000 chars)
      const text = 'This is a normal response without sensitive data. '.repeat(320);
      const start = performance.now();
      filter.apply(text);
      const elapsed = performance.now() - start;
      // Allow generous margin but still verify reasonable performance
      assert.ok(elapsed < 20, `Processing took ${elapsed.toFixed(2)}ms, expected < 20ms`);
    });

    it('handles empty input gracefully', () => {
      const result = filter.apply('');
      assert.equal(result.filtered, '');
      assert.deepEqual(result.redactions, []);
    });

    it('handles null/undefined input gracefully', () => {
      const result = filter.apply(null);
      assert.equal(result.filtered, '');
      assert.deepEqual(result.redactions, []);
    });
  });

  describe('FilterResult structure', () => {
    it('returns correct FilterResult shape', () => {
      const text = 'Key sk-abcdefghijklmnopqrstuv and SSN 123-45-6789';
      const result = filter.apply(text);
      assert.ok('filtered' in result);
      assert.ok('redactions' in result);
      assert.ok(Array.isArray(result.redactions));
      for (const r of result.redactions) {
        assert.ok('type' in r);
        assert.ok('position' in r);
        assert.equal(typeof r.type, 'string');
        assert.equal(typeof r.position, 'number');
      }
    });

    it('positions are correct character offsets', () => {
      const text = 'Start: 123-45-6789 end.';
      const result = filter.apply(text);
      assert.equal(result.redactions[0].position, 7);
    });
  });

  // Cleanup
  describe('cleanup', () => {
    it('cleanup test files', () => {
      cleanupAllowlist();
    });
  });
});
