const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
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

const { sanitizeCsvCell } = require('../src/lib/validators.ts');
const { readStoredReport } = require('../src/lib/report-storage.ts');

test('neutralizes CSV formulas and leading control whitespace', () => {
  for (const value of ['=1+1', '+1', '-1', '@SUM(A1)', '\t=2', '\r=2', '\n=2', '  =2', '\uFEFF=2']) {
    const sanitized = sanitizeCsvCell(value);
    assert.ok(
      sanitized.startsWith("'") || sanitized.startsWith("\"'"),
      `Expected ${JSON.stringify(value)} to be neutralized`,
    );
  }

  assert.equal(sanitizeCsvCell('plain text'), 'plain text');
  assert.equal(sanitizeCsvCell('=1,2'), "\"'=1,2\"");
});

test('reads reports only from their resolved storage directory', async (t) => {
  const temporaryDirectory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'scandev-report-test-'));
  t.after(() => fs.promises.rm(temporaryDirectory, { recursive: true, force: true }));

  const storageDirectory = path.join(temporaryDirectory, 'reports');
  const reportPath = path.join(storageDirectory, 'report.pdf');
  const outsidePath = path.join(temporaryDirectory, 'report.pdf');
  await fs.promises.mkdir(storageDirectory);
  await fs.promises.writeFile(reportPath, 'report');
  await fs.promises.writeFile(outsidePath, 'outside');

  assert.equal((await readStoredReport(storageDirectory, reportPath)).toString(), 'report');
  await assert.rejects(readStoredReport(storageDirectory, outsidePath), /FORBIDDEN/);
  await assert.rejects(readStoredReport(storageDirectory, storageDirectory), /FORBIDDEN/);
});
