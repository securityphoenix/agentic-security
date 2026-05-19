// FR-XSAT-7 IAM policy reachability tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanIamPolicies, _internals } from '../src/posture/iam-policy.js';

test('scanIamPolicies flags Action=iam:* on Resource=* with Effect=Allow', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
  });
  const r = scanIamPolicies({ 'iam/admin-policy.json': policy });
  assert.equal(r.length, 1);
  assert.equal(r[0].family, 'iam-overpermissive');
  assert.equal(r[0].severity, 'critical');
});

test('scanIamPolicies flags s3:* with wildcard resource', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['s3:*'], Resource: ['*'] }],
  });
  const r = scanIamPolicies({ 'role-policy.json': policy });
  assert.ok(r.some(f => f.vuln.includes('s3:*')));
});

test('scanIamPolicies does NOT flag narrowly-scoped Action+Resource with Condition', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::my-bucket/*',
      Condition: { StringEquals: { 'aws:RequestedRegion': 'us-east-1' } },
    }],
  });
  const r = scanIamPolicies({ 'iam-policy-narrow.json': policy });
  assert.equal(r.length, 0);
});

test('scanIamPolicies ignores Effect=Deny', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Deny', Action: 'iam:*', Resource: '*' }],
  });
  const r = scanIamPolicies({ 'iam-policy-deny.json': policy });
  assert.equal(r.length, 0);
});

test('scanIamPolicies handles malformed JSON gracefully', () => {
  const r = scanIamPolicies({ 'broken.json': '{not valid json' });
  assert.deepEqual(r, []);
});

test('scanIamPolicies skips files without IAM policy hints', () => {
  const r = scanIamPolicies({ 'config.json': JSON.stringify({ foo: 'bar' }) });
  assert.equal(r.length, 0);
});

test('DANGEROUS_ACTIONS covers IAM, S3, Lambda, EC2, DynamoDB, RDS, Secrets Manager, KMS', () => {
  const families = new Set(_internals.DANGEROUS_ACTIONS.map(r => r.action.source.split(':')[0].slice(1)));
  for (const svc of ['iam', 's3', 'lambda', 'ec2', 'dynamodb', 'rds', 'secretsmanager', 'kms']) {
    assert.ok(families.has(svc), `service ${svc} should be in dangerous-actions list`);
  }
});

test('null/empty input is safe', () => {
  assert.deepEqual(scanIamPolicies(null), []);
  assert.deepEqual(scanIamPolicies({}), []);
});
