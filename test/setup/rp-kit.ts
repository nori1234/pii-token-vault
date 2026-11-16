// rp-kit を、テストの中の idp と company-api につなぐための補助（ADR 0029）。
// - idpSend：fetch で送る（リダイレクトに従わない）。テストの補助なので、lint の fetch の制限の外。
// - companySend：company-api は inject で立てているので、Fastify の inject に渡す（ソケットを開かない）。

import { exportJWK, type JWK } from 'jose';
import type { HttpRequest, HttpResponse, Send } from '../../packages/rp-kit/src/transport.ts';
import { HOST, type TestCompanyApi, type TestTenant } from './company-api.ts';
import type { TestClient } from './idp.ts';

export const idpSend: Send = async (request: HttpRequest): Promise<HttpResponse> => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
    ...(request.body === undefined ? {} : { body: request.body }),
    redirect: 'manual',
  });
  return {
    status: response.status,
    headers: { 'content-type': response.headers.get('content-type') ?? '' },
    body: await response.text(),
  };
};

export function companySend(company: TestCompanyApi): Send {
  return async (request) => {
    const url = new URL(request.url);
    const res = await company.api.app.inject({
      method: request.method,
      url: `${url.pathname}${url.search}`,
      headers: { ...request.headers, host: HOST },
      ...(request.body === undefined ? {} : { payload: request.body }),
    });
    return {
      status: res.statusCode,
      headers: { 'content-type': String(res.headers['content-type'] ?? '') },
      body: res.body,
    };
  };
}

export async function jwkOf(
  key: TestClient['privateKey'] | TestTenant['client']['privateKey'],
): Promise<JWK> {
  return exportJWK(key);
}
