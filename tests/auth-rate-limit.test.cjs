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

const { getRateLimitStatus, recordRateLimitHit } = require('../src/lib/rate-limit.ts');

test('login status checks do not count as failed attempts', () => {
  const key = `login:test-${Date.now()}`;
  const options = { limit: 5, windowMs: 15 * 60_000 };

  assert.equal(getRateLimitStatus(key, options).remaining, 5);
  assert.equal(getRateLimitStatus(key, options).remaining, 5);
  recordRateLimitHit(key, options);
  assert.equal(getRateLimitStatus(key, options).remaining, 4);
});

test('blocks login after five failures until the 15-minute window expires', (t) => {
  const key = `login-window:test-${Date.now()}`;
  const options = { limit: 5, windowMs: 15 * 60_000 };
  const originalNow = Date.now;
  let now = originalNow();
  Date.now = () => now;
  t.after(() => {
    Date.now = originalNow;
  });

  for (let attempt = 0; attempt < 5; attempt += 1) {
    recordRateLimitHit(key, options);
  }
  assert.equal(getRateLimitStatus(key, options).success, false);

  now += options.windowMs + 1;
  assert.equal(getRateLimitStatus(key, options).success, true);
});
