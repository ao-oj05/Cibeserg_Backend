const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const test = require('node:test');
const ts = require('typescript');

const projectRoot = path.resolve(__dirname, '..');
const storageDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'scandev-api-test-'));

process.env.DATABASE_URL = 'postgresql://user:password@localhost:5432/scandev';
process.env.JWT_SECRET = 'test-secret-with-more-than-thirty-two-characters';
process.env.NODE_ENV = 'test';
process.env.STORAGE_REPORTS_DIR = storageDirectory;

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

const originalResolveFilename = Module._resolveFilename;
const mockDbPath = path.join(__dirname, 'fixtures', 'mock-db.cjs');
Module._resolveFilename = function (request, parent, isMain, options) {
  if (request === '@/lib/db') return mockDbPath;
  if (request.startsWith('@/')) {
    const candidate = path.join(projectRoot, 'src', request.slice(2).replace(/\//g, path.sep)) + '.ts';
    if (fs.existsSync(candidate)) {
      return originalResolveFilename.call(this, candidate, parent, isMain, options);
    }
  }
  return originalResolveFilename.call(this, request, parent, isMain, options);
};

const { prisma } = require('./fixtures/mock-db.cjs');
const { AUTH_COOKIE_NAME, createSessionToken } = require('../src/lib/auth.ts');
const { GET: exportCsv } = require('../src/app/api/reports/export-csv/route.ts');
const { GET: downloadReport } = require('../src/app/api/reports/[id]/download/route.ts');

function requestWithToken(token) {
  return {
    cookies: {
      get: (name) => name === AUTH_COOKIE_NAME ? { value: token } : undefined,
    },
  };
}

function sampleScan() {
  return {
    id: 'scan-1',
    host: '=1+1',
    targetUrl: 'https://example.test',
    ipAddress: null,
    riskScore: 90,
    status: 'COMPLETED',
    responseTimeMs: null,
    httpsRedirect: false,
    sslValid: true,
    sslIssuer: null,
    sslDaysLeft: null,
    sslProtocol: null,
    _count: { findings: 2 },
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
  };
}

test('authenticated export and report download enforce account and resource ownership', async (t) => {
  t.after(async () => {
    Module._resolveFilename = originalResolveFilename;
    await fs.promises.rm(storageDirectory, { recursive: true, force: true });
  });

  const activeToken = await createSessionToken({
    userId: 'owner-1',
    email: 'owner@example.test',
    role: 'USER',
  });
  const suspendedToken = await createSessionToken({
    userId: 'suspended-1',
    email: 'suspended@example.test',
    role: 'USER',
  });

  let scanQuery;
  let scanQueries = 0;
  prisma.user.findUnique = async ({ where }) => ({
    suspendedAt: where.id === 'suspended-1' ? new Date() : null,
  });
  prisma.scan.findMany = async (query) => {
    scanQueries += 1;
    scanQuery = query;
    return [sampleScan()];
  };

  const anonymousResponse = await exportCsv({ cookies: { get: () => undefined } });
  assert.equal(anonymousResponse.status, 401);
  assert.equal(scanQueries, 0, 'anonymous requests must not reach the export query');

  const suspendedResponse = await exportCsv(requestWithToken(suspendedToken));
  assert.equal(suspendedResponse.status, 401);
  assert.equal(scanQueries, 0, 'suspended accounts must not reach the export query');

  const exportResponse = await exportCsv(requestWithToken(activeToken));
  assert.equal(exportResponse.status, 200);
  assert.equal(exportResponse.headers.get('content-type'), 'text/csv; charset=utf-8');
  assert.equal(scanQuery.where.userId, 'owner-1');
  assert.match(await exportResponse.text(), /,'=1\+1,/);

  const pdfPath = path.join(storageDirectory, 'report.pdf');
  const outsidePath = `${storageDirectory}-outside.pdf`;
  await fs.promises.writeFile(pdfPath, 'owned report');
  await fs.promises.writeFile(outsidePath, 'outside report');

  let reportQuery;
  prisma.report.findFirst = async (query) => {
    reportQuery = query;
    if (query.where.userId !== 'owner-1') return null;
    return {
      id: 'report-1',
      userId: 'owner-1',
      fileName: 'report.pdf',
      filePath: pdfPath,
      expiresAt: new Date(Date.now() + 60_000),
    };
  };

  const downloadResponse = await downloadReport(requestWithToken(activeToken), {
    params: Promise.resolve({ id: 'report-1' }),
  });
  assert.equal(downloadResponse.status, 200);
  assert.equal(reportQuery.where.userId, 'owner-1');
  assert.equal(await downloadResponse.text(), 'owned report');

  const otherOwnerToken = await createSessionToken({
    userId: 'owner-2',
    email: 'other@example.test',
    role: 'USER',
  });
  const forbiddenOwnerResponse = await downloadReport(requestWithToken(otherOwnerToken), {
    params: Promise.resolve({ id: 'report-1' }),
  });
  assert.equal(forbiddenOwnerResponse.status, 404);
  assert.equal(reportQuery.where.userId, 'owner-2');

  prisma.report.findFirst = async () => ({
    id: 'report-2',
    userId: 'owner-1',
    fileName: 'outside.pdf',
    filePath: outsidePath,
    expiresAt: new Date(Date.now() + 60_000),
  });
  const traversalResponse = await downloadReport(requestWithToken(activeToken), {
    params: Promise.resolve({ id: 'report-2' }),
  });
  assert.equal(traversalResponse.status, 403);

  prisma.report.findFirst = async () => ({
    id: 'report-3',
    userId: 'owner-1',
    fileName: 'expired.pdf',
    filePath: pdfPath,
    expiresAt: new Date(Date.now() - 1),
  });
  const expiredResponse = await downloadReport(requestWithToken(activeToken), {
    params: Promise.resolve({ id: 'report-3' }),
  });
  assert.equal(expiredResponse.status, 410);
});
