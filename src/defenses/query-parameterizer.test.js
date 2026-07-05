/**
 * Unit tests for Query Parameterizer
 * Tests: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createQueryParameterizer } from './query-parameterizer.js';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEMPLATES_PATH = join(__dirname, 'config', 'query-templates.json');

describe('Query Parameterizer', () => {
  let parameterizer;

  beforeEach(() => {
    parameterizer = createQueryParameterizer(TEMPLATES_PATH);
  });

  describe('Req 8.1 - Parameterization', () => {
    it('extracts string literals into params array', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 'acc123'",
        'databot'
      );
      assert.equal(result.allowed, true);
      assert.ok(result.params.includes('acc123'));
      assert.ok(result.template.includes('?'));
      assert.ok(!result.template.includes("'acc123'"));
    });

    it('extracts numeric literals into params array', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 42",
        'databot'
      );
      assert.equal(result.allowed, true);
      assert.ok(result.params.includes(42));
      assert.ok(result.template.includes('?'));
    });

    it('returns positional placeholders in template', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 'test'",
        'databot'
      );
      assert.equal(result.allowed, true);
      assert.equal(result.template, 'SELECT balance FROM accounts WHERE account_id = ?');
    });
  });

  describe('Req 8.2 - SQL Comment Rejection', () => {
    it('rejects queries with -- comments', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1' -- drop table",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'comment');
    });

    it('rejects queries with /* block comments', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1' /* comment */",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'comment');
    });

    it('rejects queries with */ comment end', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1' */",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'comment');
    });
  });

  describe('Req 8.3 - Multiple Statement Rejection', () => {
    it('rejects queries with semicolons', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1'; DROP TABLE accounts",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'multiple_statements');
    });

    it('does not reject semicolons within string literals', () => {
      // Semicolons inside quoted strings should not trigger rejection
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 'val;ue'",
        'databot'
      );
      // This should pass the multiple_statements check (but may fail template match)
      assert.notEqual(result.rejectionType, 'multiple_statements');
    });
  });

  describe('Req 8.4 - Unauthorized UNION Rejection', () => {
    it('rejects queries with UNION not in approved template', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1' UNION SELECT password FROM users",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'unauthorized_union');
    });

    it('rejects UNION ALL', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1' UNION ALL SELECT secret FROM admin",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'unauthorized_union');
    });
  });

  describe('Req 8.5 - Template Registry', () => {
    it('allows queries matching registered templates', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 'acc001'",
        'databot'
      );
      assert.equal(result.allowed, true);
      assert.ok(result.template);
      assert.ok(result.params);
    });

    it('rejects queries not matching any registered template', () => {
      const result = parameterizer.parameterize(
        "SELECT secret FROM admin_table WHERE user = 'admin'",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'unregistered_template');
    });

    it('supports reload of templates', () => {
      // Should not throw
      parameterizer.reload();
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 'acc001'",
        'databot'
      );
      assert.equal(result.allowed, true);
    });
  });

  describe('Req 8.6 - Tautology Rejection', () => {
    it('rejects 1=1 tautology', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE 1=1",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'tautology');
    });

    it("rejects 'a'='a' tautology", () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE 'a'='a'",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'tautology');
    });

    it('rejects OR TRUE tautology', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1' OR TRUE",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'tautology');
    });

    it('rejects OR 1=1 tautology', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = '1' OR 1=1",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'tautology');
    });
  });

  describe('Req 8.7 - Performance', () => {
    it('returns rejection within 100ms', () => {
      const start = performance.now();
      parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE 1=1",
        'databot'
      );
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 100, `Processing took ${elapsed.toFixed(2)}ms, expected < 100ms`);
    });

    it('returns successful result within 100ms', () => {
      const start = performance.now();
      parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 'test123'",
        'databot'
      );
      const elapsed = performance.now() - start;
      assert.ok(elapsed < 100, `Processing took ${elapsed.toFixed(2)}ms, expected < 100ms`);
    });
  });

  describe('Req 8.8 - Non-SELECT Rejection', () => {
    it('rejects INSERT queries', () => {
      const result = parameterizer.parameterize(
        "INSERT INTO accounts (account_id, balance) VALUES ('acc1', 1000)",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'non_select');
    });

    it('rejects UPDATE queries', () => {
      const result = parameterizer.parameterize(
        "UPDATE accounts SET balance = 999999 WHERE account_id = '1'",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'non_select');
    });

    it('rejects DELETE queries', () => {
      const result = parameterizer.parameterize(
        "DELETE FROM accounts WHERE account_id = '1'",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'non_select');
    });

    it('rejects DROP TABLE', () => {
      const result = parameterizer.parameterize(
        "DROP TABLE accounts",
        'databot'
      );
      assert.equal(result.allowed, false);
      assert.equal(result.rejectionType, 'non_select');
    });

    it('handles empty input', () => {
      const result = parameterizer.parameterize('', 'databot');
      assert.equal(result.allowed, false);
    });

    it('handles null/undefined input', () => {
      const result = parameterizer.parameterize(null, 'databot');
      assert.equal(result.allowed, false);
    });
  });

  describe('ParameterizeResult structure', () => {
    it('returns correct shape on success', () => {
      const result = parameterizer.parameterize(
        "SELECT balance FROM accounts WHERE account_id = 'x'",
        'databot'
      );
      assert.ok('allowed' in result);
      assert.ok('template' in result);
      assert.ok('params' in result);
      assert.equal(result.allowed, true);
      assert.ok(Array.isArray(result.params));
    });

    it('returns correct shape on rejection', () => {
      const result = parameterizer.parameterize(
        "DROP TABLE accounts",
        'databot'
      );
      assert.ok('allowed' in result);
      assert.ok('error' in result);
      assert.ok('rejectionType' in result);
      assert.equal(result.allowed, false);
      assert.equal(typeof result.error, 'string');
    });
  });
});
