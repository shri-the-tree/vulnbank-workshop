/**
 * Unit tests for Identity Verifier
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import { createIdentityVerifier, signToken } from './identity-verifier.js';

describe('Identity Verifier', () => {
  let keyPairA;
  let keyPairB;
  let keyRegistry;
  let acceptsFrom;
  let verifier;

  beforeEach(() => {
    // Generate key pairs for test agents
    keyPairA = nacl.sign.keyPair();
    keyPairB = nacl.sign.keyPair();

    keyRegistry = {
      'agent-a': Buffer.from(keyPairA.publicKey).toString('base64'),
      'agent-b': Buffer.from(keyPairB.publicKey).toString('base64'),
    };

    acceptsFrom = {
      'agent-b': ['agent-a'],
      'agent-a': ['agent-b'],
    };

    verifier = createIdentityVerifier(keyRegistry, acceptsFrom);
  });

  describe('Valid token verification (Req 5.1)', () => {
    it('should verify a valid token', () => {
      const token = signToken('agent-a', keyPairA.secretKey);
      const result = verifier.verify(token, 'agent-b');
      assert.equal(result.verified, true);
      assert.equal(result.identity, 'agent-a');
      assert.equal(result.error, undefined);
    });

    it('should verify with custom iat within TTL', () => {
      const now = Math.floor(Date.now() / 1000);
      const token = signToken('agent-a', keyPairA.secretKey, { iat: now - 30 });
      const result = verifier.verify(token, 'agent-b');
      assert.equal(result.verified, true);
      assert.equal(result.identity, 'agent-a');
    });
  });

  describe('Missing/malformed token rejection (Req 5.2)', () => {
    it('should reject missing token (null)', () => {
      const result = verifier.verify(null, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /missing/i);
    });

    it('should reject missing token (undefined)', () => {
      const result = verifier.verify(undefined, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /missing/i);
    });

    it('should reject empty string token', () => {
      const result = verifier.verify('', 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /missing/i);
    });

    it('should reject malformed structure (no dots)', () => {
      const result = verifier.verify('not-a-jwt', 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /malformed/i);
    });

    it('should reject malformed structure (only two parts)', () => {
      const result = verifier.verify('part1.part2', 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /malformed/i);
    });

    it('should reject invalid header JSON', () => {
      const result = verifier.verify('!!!.payload.sig', 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /malformed/i);
    });

    it('should reject token missing sub claim', () => {
      // Build a token manually without sub
      const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const payload = Buffer.from(JSON.stringify({ iat: Math.floor(Date.now() / 1000) })).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const sig = Buffer.from('fake-signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const result = verifier.verify(`${header}.${payload}.${sig}`, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /sub/i);
    });

    it('should reject token missing iat claim', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const payload = Buffer.from(JSON.stringify({ sub: 'agent-a' })).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const sig = Buffer.from('fake-signature').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const result = verifier.verify(`${header}.${payload}.${sig}`, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /iat/i);
    });
  });

  describe('Invalid signature rejection (Req 5.3)', () => {
    it('should reject token signed with wrong key', () => {
      // Sign with agent-b's key but claim to be agent-a
      const token = signToken('agent-a', keyPairB.secretKey);
      const result = verifier.verify(token, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /signature/i);
    });

    it('should reject token with tampered payload', () => {
      const token = signToken('agent-a', keyPairA.secretKey);
      const parts = token.split('.');
      // Tamper with payload
      const tampered = Buffer.from(JSON.stringify({ sub: 'agent-a', iat: 999999999 })).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const tamperedToken = `${parts[0]}.${tampered}.${parts[2]}`;
      const result = verifier.verify(tamperedToken, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /signature/i);
    });

    it('should reject token for unknown agent (no key in registry)', () => {
      const unknownKeyPair = nacl.sign.keyPair();
      const token = signToken('unknown-agent', unknownKeyPair.secretKey);
      const result = verifier.verify(token, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /no key found/i);
    });
  });

  describe('Expired token rejection (Req 5.4)', () => {
    it('should reject expired token (iat + TTL exceeded)', () => {
      const now = Math.floor(Date.now() / 1000);
      // Token issued 120 seconds ago (default TTL is 60s)
      const token = signToken('agent-a', keyPairA.secretKey, { iat: now - 120 });
      const result = verifier.verify(token, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /expired/i);
    });

    it('should reject token exactly at expiration boundary', () => {
      const now = Math.floor(Date.now() / 1000);
      // Token issued exactly TTL+1 seconds ago
      const token = signToken('agent-a', keyPairA.secretKey, { iat: now - 61 });
      const result = verifier.verify(token, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /expired/i);
    });

    it('should accept token within custom TTL', () => {
      const customVerifier = createIdentityVerifier(keyRegistry, acceptsFrom, { ttlSeconds: 300 });
      const now = Math.floor(Date.now() / 1000);
      const token = signToken('agent-a', keyPairA.secretKey, { iat: now - 120 });
      const result = customVerifier.verify(token, 'agent-b');
      assert.equal(result.verified, true);
    });
  });

  describe('Unauthorized sender rejection (Req 5.5)', () => {
    it('should reject sender not in acceptsFrom allowlist', () => {
      const acceptsFromRestricted = {
        'agent-b': ['some-other-agent'],
      };
      const restrictedVerifier = createIdentityVerifier(keyRegistry, acceptsFromRestricted);
      const token = signToken('agent-a', keyPairA.secretKey);
      const result = restrictedVerifier.verify(token, 'agent-b');
      assert.equal(result.verified, false);
      assert.match(result.error, /unauthorized/i);
    });

    it('should reject when receiver has no acceptsFrom config', () => {
      const token = signToken('agent-a', keyPairA.secretKey);
      const result = verifier.verify(token, 'unknown-receiver');
      assert.equal(result.verified, false);
      assert.match(result.error, /unauthorized|no delegation/i);
    });
  });

  describe('Failed attempt logging (Req 5.6)', () => {
    it('should call logger on verification failure', () => {
      const loggedEvents = [];
      const mockLogger = {
        logAuthEvent: (event) => loggedEvents.push(event),
      };
      const loggingVerifier = createIdentityVerifier(keyRegistry, acceptsFrom, { logger: mockLogger });

      loggingVerifier.verify(null, 'agent-b', { sourceIP: '192.168.1.100' });

      assert.equal(loggedEvents.length, 1);
      assert.equal(loggedEvents[0].claimedIdentity, 'unknown');
      assert.equal(loggedEvents[0].sourceIP, '192.168.1.100');
      assert.equal(loggedEvents[0].failureReason, 'missing_token');
    });

    it('should log claimed identity and failure reason for expired tokens', () => {
      const loggedEvents = [];
      const mockLogger = {
        logAuthEvent: (event) => loggedEvents.push(event),
      };
      const loggingVerifier = createIdentityVerifier(keyRegistry, acceptsFrom, { logger: mockLogger });

      const now = Math.floor(Date.now() / 1000);
      const token = signToken('agent-a', keyPairA.secretKey, { iat: now - 120 });
      loggingVerifier.verify(token, 'agent-b', { sourceIP: '10.0.0.1' });

      assert.equal(loggedEvents.length, 1);
      assert.equal(loggedEvents[0].claimedIdentity, 'agent-a');
      assert.equal(loggedEvents[0].sourceIP, '10.0.0.1');
      assert.equal(loggedEvents[0].failureReason, 'token_expired');
    });
  });

  describe('signToken helper (Req 5.7)', () => {
    it('should produce a valid three-part JWT', () => {
      const token = signToken('agent-a', keyPairA.secretKey);
      const parts = token.split('.');
      assert.equal(parts.length, 3);
    });

    it('should encode EdDSA algorithm in header', () => {
      const token = signToken('agent-a', keyPairA.secretKey);
      const headerB64 = token.split('.')[0];
      let base64 = headerB64.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4 !== 0) base64 += '=';
      const header = JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
      assert.equal(header.alg, 'EdDSA');
      assert.equal(header.typ, 'JWT');
    });

    it('should include sub and iat claims in payload', () => {
      const token = signToken('my-agent', keyPairA.secretKey);
      const payloadB64 = token.split('.')[1];
      let base64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4 !== 0) base64 += '=';
      const payload = JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
      assert.equal(payload.sub, 'my-agent');
      assert.equal(typeof payload.iat, 'number');
    });

    it('should respect custom iat option', () => {
      const customIat = 1700000000;
      const token = signToken('agent-a', keyPairA.secretKey, { iat: customIat });
      const payloadB64 = token.split('.')[1];
      let base64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4 !== 0) base64 += '=';
      const payload = JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
      assert.equal(payload.iat, customIat);
    });
  });
});
