const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const dns = require('node:dns/promises');
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

function fakeRequest(responseFactory) {
  return (options, onResponse) => {
    const request = new EventEmitter();
    request.end = () => {
      process.nextTick(() => {
        const response = new EventEmitter();
        const plan = responseFactory(options);
        response.statusCode = plan.status;
        response.headers = plan.headers ?? {};
        response.destroy = () => response;
        onResponse(response);
        for (const chunk of plan.body ?? []) {
          response.emit('data', chunk);
        }
        if (plan.ended !== false) response.emit('end');
      });
    };
    request.destroy = (error) => {
      if (error) process.nextTick(() => request.emit('error', error));
      return request;
    };
    return request;
  };
}

test('blocks private and IPv4-mapped loopback targets before connecting', async () => {
  const { validateTargetAgainstSSRF } = require('../src/services/scanner/ssrf-guard.ts');

  for (const url of [
    'http://127.0.0.1',
    'http://10.0.0.1',
    'http://[::1]',
    'http://[::ffff:7f00:1]',
  ]) {
    await assert.rejects(validateTargetAgainstSSRF(url), /bloqueado/);
  }
});

test('allows at most ten scans per user during one hour', () => {
  const { checkRateLimit } = require('../src/lib/rate-limit.ts');
  const key = `scan:test-${Date.now()}`;

  for (let attempt = 0; attempt < 10; attempt += 1) {
    assert.equal(
      checkRateLimit(key, { limit: 10, windowMs: 60 * 60_000 }).success,
      true,
    );
  }
  assert.equal(
    checkRateLimit(key, { limit: 10, windowMs: 60 * 60_000 }).success,
    false,
  );
});

test('rejects a response larger than 1 MB', async (t) => {
  const originalLookup = dns.lookup;
  const originalRequest = http.request;
  t.after(() => {
    dns.lookup = originalLookup;
    http.request = originalRequest;
  });

  dns.lookup = async () => [{ address: '93.184.216.34', family: 4 }];
  http.request = fakeRequest(() => ({
    status: 200,
    body: [Buffer.alloc(1_048_577)],
    ended: false,
  }));
  const { safeHttpRequest } = require('../src/services/scanner/safe-http.ts');

  await assert.rejects(
    safeHttpRequest('http://scanner.test'),
    /exceeded 1 MB/,
  );
});

test('stops after five redirects', async (t) => {
  const originalLookup = dns.lookup;
  const originalRequest = http.request;
  let requests = 0;
  t.after(() => {
    dns.lookup = originalLookup;
    http.request = originalRequest;
  });

  dns.lookup = async () => [{ address: '93.184.216.34', family: 4 }];
  http.request = fakeRequest(() => {
    requests += 1;
    return {
      status: 302,
      headers: { location: `http://redirect-${requests}.test/` },
      ended: false,
    };
  });
  const { safeHttpRequest } = require('../src/services/scanner/safe-http.ts');

  await assert.rejects(safeHttpRequest('http://scanner.test'), /Too many redirects/);
  assert.equal(requests, 6);
});

test('sends and evaluates a literal null Origin in the CORS probes', async (t) => {
  const originalLookup = dns.lookup;
  const originalRequest = http.request;
  const origins = [];
  t.after(() => {
    dns.lookup = originalLookup;
    http.request = originalRequest;
  });

  dns.lookup = async () => [{ address: '93.184.216.34', family: 4 }];
  http.request = fakeRequest((options) => {
    const origin = Object.entries(options.headers).find(
      ([name]) => name.toLowerCase() === 'origin',
    )?.[1];
    origins.push(origin);
    return {
      status: 200,
      headers: {
        'access-control-allow-origin': origin,
        'access-control-allow-credentials': 'true',
      },
    };
  });
  const { auditHttpHeaders } = require('../src/services/scanner/http-headers.ts');

  const findings = await auditHttpHeaders('http://scanner.test', {});
  const corsFinding = findings.find((finding) => finding.checkKey === 'CORS');
  const nullProbe = corsFinding.evidence.probes.find((probe) => probe.label === 'S3_null_origin');

  assert.ok(origins.includes('null'));
  assert.equal(corsFinding.status, 'FAILED');
  assert.equal(nullProbe.originSent, 'null');
  assert.equal(nullProbe.acao, 'null');
  assert.equal(nullProbe.reflected, true);
});
