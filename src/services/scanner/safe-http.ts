import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { validateTargetAgainstSSRF } from './ssrf-guard';

const REQUEST_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_REDIRECTS = 5;

export interface SafeHttpResponse {
  status: number;
  url: string;
  headers: Headers;
}

interface SafeHttpOptions {
  method?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

interface SingleRequestResult extends SafeHttpResponse {
  redirectUrl?: string;
}

function toHeaders(rawHeaders: Record<string, string | string[] | undefined>): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(rawHeaders)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(', ') : value);
  }
  return headers;
}

async function requestOnce(
  url: URL,
  address: string,
  method: string,
  headers: Headers,
  signal: AbortSignal | undefined,
  deadline: number,
): Promise<SingleRequestResult> {
  if (signal?.aborted) throw new Error('HTTP request aborted');
  const remainingMs = deadline - Date.now();
  if (remainingMs <= 0) throw new Error('HTTP request timed out');

  const ipFamily = isIP(address);
  const requestHeaders = new Headers(headers);
  requestHeaders.set('host', url.host);
  const options = {
    hostname: address,
    port: url.port ? Number(url.port) : undefined,
    path: `${url.pathname}${url.search}`,
    method,
    headers: Object.fromEntries(requestHeaders.entries()),
    ...(url.protocol === 'https:' && !isIP(url.hostname.replace(/^\[|\]$/g, ''))
      ? { servername: url.hostname.replace(/^\[|\]$/g, '') }
      : {}),
    family: ipFamily,
  };
  const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout>;
    const finish = (error?: Error, result?: SingleRequestResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (error) reject(error);
      else if (result) resolve(result);
    };
    const abort = () => request.destroy(new Error('HTTP request aborted'));
    const request = transport(options, (response) => {
      const status = response.statusCode ?? 0;
      const location = response.headers.location;
      if ([301, 302, 303, 307, 308].includes(status) && location) {
        response.destroy();
        finish(undefined, {
          status,
          url: url.toString(),
          headers: toHeaders(response.headers),
          redirectUrl: new URL(location, url).toString(),
        });
        return;
      }

      let receivedBytes = 0;
      response.on('data', (chunk: Buffer | string) => {
        receivedBytes += Buffer.byteLength(chunk);
        if (receivedBytes > MAX_RESPONSE_BYTES) {
          response.destroy();
          request.destroy(new Error('HTTP response exceeded 1 MB'));
        }
      });
      response.on('end', () => {
        finish(undefined, {
          status,
          url: url.toString(),
          headers: toHeaders(response.headers),
        });
      });
      response.on('error', (error) => finish(error));
    });

    timer = setTimeout(
      () => request.destroy(new Error('HTTP request timed out')),
      remainingMs,
    );
    signal?.addEventListener('abort', abort, { once: true });
    request.on('error', (error) => finish(error));
    request.end();
  });
}

export async function safeHttpRequest(
  input: string | URL,
  options: SafeHttpOptions = {},
): Promise<SafeHttpResponse> {
  const deadline = Date.now() + REQUEST_TIMEOUT_MS;
  let url = new URL(input);
  let method = options.method ?? 'GET';
  const headers = new Headers(options.headers);

  for (let redirects = 0; ; redirects += 1) {
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('Redirect protocol is not allowed');
    }

    const { ipAddress } = await validateTargetAgainstSSRF(url.toString(), options.signal);
    const response = await requestOnce(
      url,
      ipAddress,
      method,
      headers,
      options.signal,
      deadline,
    );
    if (!response.redirectUrl) {
      return { status: response.status, url: url.toString(), headers: response.headers };
    }
    if (redirects >= MAX_REDIRECTS) throw new Error('Too many redirects');

    const redirectedUrl = new URL(response.redirectUrl);
    if (redirectedUrl.origin !== url.origin) {
      headers.delete('authorization');
      headers.delete('cookie');
    }
    if (response.status === 303 && method !== 'HEAD') method = 'GET';
    if ((response.status === 301 || response.status === 302) && method === 'POST') {
      method = 'GET';
    }
    url = redirectedUrl;
  }
}
