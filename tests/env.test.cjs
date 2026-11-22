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

const { parseEnvironment } = require('../src/lib/env.ts');

test('requires a PostgreSQL URL and a sufficiently long session secret', () => {
  assert.throws(
    () => parseEnvironment({ DATABASE_URL: '', JWT_SECRET: '' }),
    /DATABASE_URL.*JWT_SECRET/,
  );
  assert.throws(
    () => parseEnvironment({
      DATABASE_URL: 'https://database.invalid',
      JWT_SECRET: 'test-secret-with-more-than-thirty-two-characters',
    }),
    /protocolo PostgreSQL/,
  );
});
