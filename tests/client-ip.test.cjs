const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const ts = require('typescript');

require.extensions['.ts'] = (module, filename) => {
  const source = fs.readFileSync(filename, 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
  }).outputText;
  module._compile(output, filename);
};

process.env.DATABASE_URL = 'postgresql://user:password@localhost:5432/scandev';
process.env.JWT_SECRET = 'test-secret-with-more-than-thirty-two-characters';
process.env.NODE_ENV = 'production';
process.env.TRUSTED_PROXY_HOPS = '2';

const { getClientIp } = require('../src/lib/client-ip.ts');

function requestWithForwardedFor(value) {
  return { headers: new Headers(value ? { 'x-forwarded-for': value } : {}) };
}

test('uses the client address before the configured proxy hops', () => {
  assert.equal(
    getClientIp(requestWithForwardedFor('198.51.100.27, 192.0.2.123')),
    '198.51.100.27',
  );
});

test('rejects missing, invalid, or too-short forwarded chains in production', () => {
  assert.equal(getClientIp(requestWithForwardedFor('')), null);
  assert.equal(getClientIp(requestWithForwardedFor('invalid-address')), null);
  assert.equal(getClientIp(requestWithForwardedFor('invalid-address, 192.0.2.123')), null);
});
