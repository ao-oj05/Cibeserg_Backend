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

const { calculateRateLimit } = require('../src/lib/rate-limit-policy.ts');

test('rate-limit status counts only persisted hits in the active window', () => {
  const now = Date.now();
  const windowMs = 15 * 60_000;
  const hits = [new Date(now - 1_000), new Date(now - windowMs - 1)];

  assert.deepEqual(calculateRateLimit(hits, now, 5, windowMs), {
    success: true,
    remaining: 4,
    resetMs: windowMs - 1_000,
  });
});

test('blocks a key at five hits and allows it after the 15-minute window expires', () => {
  const now = Date.now();
  const windowMs = 15 * 60_000;
  const hits = Array.from({ length: 5 }, (_, index) => new Date(now - index));

  assert.equal(calculateRateLimit(hits, now, 5, windowMs).success, false);
  assert.equal(
    calculateRateLimit([new Date(now - windowMs - 1)], now, 5, windowMs).success,
    true,
  );
});
