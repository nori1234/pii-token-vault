// sender のテストの補助（ADR 0022）。
// - startTestSender：模擬の DNS と、テストの中で立てた TLS と SMTP のサーバーで、sender を立てる。
//   sender の宛先の検査（URL の形、名前解決、公開のアドレスか）は本物のまま。差し替えるのは最後の接続だけで、
//   どのアドレスにつなごうとしたかを記録する（接続先は、テストの中で立てた 127.0.0.1 のサーバーだけ）。
// - 証明書は、テストのたびに openssl で作る（リポジトリに秘密鍵を置かない）。

import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { connect as netConnect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect as tlsConnect } from 'node:tls';
import { SMTPServer } from 'smtp-server';
import { type SenderHandle, startSender } from '../../packages/sender/src/sender.ts';
import { createLogger } from '../../packages/warifu-core/src/log/logger.ts';

export const WEBHOOK_HOST = 'hooks.company.example';
/** 模擬の DNS で、公開のアドレスとして返す値（テストの中の 127.0.0.1 のサーバーに写す）。 */
export const PUBLIC_V4 = '93.184.216.34';
export const PUBLIC_V6 = '2606:2800:220:1:248:1893:25c8:1946';

export interface DnsTable {
  A?: Record<string, string[]>;
  AAAA?: Record<string, string[]>;
  MX?: Record<string, { exchange: string; priority: number }[]>;
  TXT?: Record<string, string[][]>;
}

export interface FakeResolver {
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<{ exchange: string; priority: number }[]>;
  resolveTxt(name: string): Promise<string[][]>;
  /** 問い合わせの記録（`種類:名前`）。 */
  readonly queries: string[];
  /** 表を差し替える（DNS rebinding の模擬など）。 */
  table: DnsTable;
}

function dnsError(code: string): Error {
  const error = new Error(code) as Error & { code: string };
  error.code = code;
  return error;
}

export function fakeResolver(table: DnsTable): FakeResolver {
  const resolver: FakeResolver = {
    queries: [],
    table,
    async resolve4(name) {
      return lookup('A', name);
    },
    async resolve6(name) {
      return lookup('AAAA', name);
    },
    async resolveMx(name) {
      return lookup('MX', name);
    },
    async resolveTxt(name) {
      return lookup('TXT', name);
    },
  };
  // 名前がどの種類にもなければ ENOTFOUND、ほかの種類にだけあれば ENODATA。
  function lookup<K extends keyof DnsTable>(type: K, name: string) {
    resolver.queries.push(`${type}:${name}`);
    const value = resolver.table[type]?.[name];
    if (value !== undefined) return structuredClone(value) as NonNullable<DnsTable[K]>[string];
    const known = Object.values(resolver.table).some(
      (records) => records !== undefined && Object.hasOwn(records, name),
    );
    throw dnsError(known ? 'ENODATA' : 'ENOTFOUND');
  }
  return resolver;
}

export interface TlsFixture {
  readonly cert: string;
  readonly key: string;
}

/** WEBHOOK_HOST の名前の、1日だけの自己署名の証明書。 */
export async function makeTlsFixture(host = WEBHOOK_HOST): Promise<TlsFixture> {
  const dir = await mkdtemp(join(tmpdir(), 'warifu-tls-'));
  try {
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-keyout',
        join(dir, 'key.pem'),
        '-out',
        join(dir, 'cert.pem'),
        '-days',
        '1',
        '-subj',
        `/CN=${host}`,
        '-addext',
        `subjectAltName=DNS:${host}`,
      ],
      { stdio: 'ignore' },
    );
    return {
      cert: await readFile(join(dir, 'cert.pem'), 'utf8'),
      key: await readFile(join(dir, 'key.pem'), 'utf8'),
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export interface ReceivedRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

export interface ReceivedMail {
  readonly from: string;
  readonly to: readonly string[];
  readonly raw: Buffer;
}

export interface TestSender {
  readonly sender: SenderHandle;
  readonly resolver: FakeResolver;
  readonly credentials: { readonly relay: string; readonly 'company-api': string };
  /** sender がつなごうとした（確かめた後の）アドレス。 */
  readonly connections: { readonly kind: 'tls' | 'tcp'; readonly address: string }[];
  readonly requests: ReceivedRequest[];
  readonly mails: ReceivedMail[];
  readonly logs: string[];
  /** Webhook の受け口の応答を変える（本文の既定は `{}`）。 */
  respondWith(status: number, headers?: Record<string, string>, body?: string): void;
  stop(): Promise<void>;
}

export async function startTestSender(table: DnsTable, fixture: TlsFixture): Promise<TestSender> {
  const dir = await mkdtemp(join(tmpdir(), 'warifu-sender-'));
  const secrets = { relay: randomBytes(32), 'company-api': randomBytes(32) };
  const resolver = fakeResolver(table);
  const connections: TestSender['connections'] = [];
  const requests: ReceivedRequest[] = [];
  const mails: ReceivedMail[] = [];
  const logs: string[] = [];
  let response = { status: 202, headers: {} as Record<string, string>, body: '{}' };

  const https: HttpsServer = createHttpsServer(
    { cert: fixture.cert, key: fixture.key },
    (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        requests.push({
          method: req.method ?? '',
          url: req.url ?? '',
          headers: req.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
        res.writeHead(response.status, response.headers);
        res.end(response.body);
      });
    },
  );
  await new Promise<void>((resolve) => https.listen(0, '127.0.0.1', () => resolve()));
  const httpsPort = (https.address() as { port: number }).port;

  const smtp = new SMTPServer({
    authOptional: true,
    disabledCommands: ['STARTTLS', 'AUTH'],
    logger: false,
    onData(stream, session, callback) {
      const chunks: Buffer[] = [];
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => {
        mails.push({
          from: session.envelope.mailFrom === false ? '' : session.envelope.mailFrom.address,
          to: session.envelope.rcptTo.map((r) => r.address),
          raw: Buffer.concat(chunks),
        });
        callback();
      });
    },
  });
  await new Promise<void>((resolve) => smtp.listen(0, '127.0.0.1', () => resolve()));
  const smtpPort = (smtp.server.address() as { port: number }).port;

  const sender = await startSender({
    socketPath: join(dir, 'sender.sock'),
    credentials: secrets,
    heloName: 'mx.relay.warifu.test',
    resolver,
    log: createLogger({ component: 'sender', write: (line) => logs.push(line) }),
    connectTls: ({ address, servername }) => {
      connections.push({ kind: 'tls', address });
      return tlsConnect({ host: '127.0.0.1', port: httpsPort, servername, ca: fixture.cert });
    },
    connectTcp: ({ address }) => {
      connections.push({ kind: 'tcp', address });
      return netConnect({ host: '127.0.0.1', port: smtpPort });
    },
  });

  return {
    sender,
    resolver,
    credentials: {
      relay: `relay.${secrets.relay.toString('base64url')}`,
      'company-api': `company-api.${secrets['company-api'].toString('base64url')}`,
    },
    connections,
    requests,
    mails,
    logs,
    respondWith(status, headers = {}, body = '{}') {
      response = { status, headers, body };
    },
    async stop() {
      await sender.close();
      await new Promise<void>((resolve) => https.close(() => resolve()));
      await new Promise<void>((resolve) => smtp.close(() => resolve()));
      await rm(dir, { recursive: true, force: true });
    },
  };
}
