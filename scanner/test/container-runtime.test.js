// FR-XSAT-8 container runtime config tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanContainerRuntime } from '../src/posture/container-runtime.js';

test('Dockerfile USER root is flagged', () => {
  const fc = { 'Dockerfile': `FROM node:22\nUSER root\nRUN npm ci\nCMD ["node", "app.js"]` };
  const r = scanContainerRuntime(fc);
  assert.ok(r.some(f => f.vuln.includes('USER root')));
});

test('Dockerfile with no USER directive flags missing-user warning', () => {
  const fc = { 'Dockerfile': `FROM node:22\nRUN npm ci\nCMD ["node", "app.js"]` };
  const r = scanContainerRuntime(fc);
  assert.ok(r.some(f => f.vuln.includes('no USER directive')));
});

test('Dockerfile with non-root USER does NOT flag missing-user', () => {
  const fc = { 'Dockerfile': `FROM node:22\nUSER node\nRUN npm ci\nCMD ["node", "app.js"]` };
  const r = scanContainerRuntime(fc);
  assert.ok(!r.some(f => f.vuln.includes('no USER directive')));
});

test('Dockerfile ADD with URL is flagged', () => {
  const fc = { 'Dockerfile': `FROM alpine\nUSER nobody\nADD https://example.com/tarball.tar.gz /tmp/` };
  const r = scanContainerRuntime(fc);
  assert.ok(r.some(f => f.vuln.includes('ADD with remote URL')));
});

test('k8s privileged: true is flagged', () => {
  const fc = { 'pod.yaml': `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n` };
  const r = scanContainerRuntime(fc);
  assert.ok(r.some(f => f.vuln.includes('privileged: true')));
  assert.equal(r.find(f => f.vuln.includes('privileged: true')).severity, 'critical');
});

test('k8s hostNetwork + runAsUser: 0 + capabilities ALL are all flagged', () => {
  const yaml = `
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: app
    securityContext:
      runAsUser: 0
      capabilities:
        add: ["ALL"]
`;
  const r = scanContainerRuntime({ 'pod.yaml': yaml });
  assert.ok(r.some(f => f.vuln.includes('hostNetwork')));
  assert.ok(r.some(f => f.vuln.includes('runAsUser: 0')));
  assert.ok(r.some(f => f.vuln.includes('capabilities.add: ALL')));
});

test('k8s docker.sock hostPath is critical', () => {
  const yaml = `
apiVersion: v1
kind: Pod
spec:
  volumes:
  - name: dock
    hostPath:
      path: /var/run/docker.sock
`;
  const r = scanContainerRuntime({ 'pod.yaml': yaml });
  const f = r.find(x => x.vuln.includes('docker.sock'));
  assert.ok(f);
  assert.equal(f.severity, 'critical');
});

test('non-k8s yaml is ignored', () => {
  const fc = { 'config.yaml': `foo: bar\nprivileged: true\n` };
  const r = scanContainerRuntime(fc);
  assert.equal(r.length, 0);
});

test('ECS task def privileged: true is flagged', () => {
  const td = JSON.stringify({
    family: 'mytask',
    containerDefinitions: [{ name: 'app', image: 'app:latest', privileged: true, user: 'root' }],
  });
  const r = scanContainerRuntime({ 'task-definition.json': td });
  assert.ok(r.some(f => f.vuln.includes('ECS container privileged')));
  assert.ok(r.some(f => f.vuln.includes('ECS container user')));
});

test('null/empty input is safe', () => {
  assert.deepEqual(scanContainerRuntime(null), []);
  assert.deepEqual(scanContainerRuntime({}), []);
});
