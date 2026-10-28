// relay のテストの補助（ADR 0021）。ワーカーの DB と globalSetup の鍵サービスを使う。
// - startTestRelay：テナント（企業の DKIM の鍵はテストの中で作る）と relay を立てる。外への配送はメモリの送信箱。
// - addUser：idp と同じ境界（withWarifuUser、withTenant）で、利用者、暗号化した本物のメール、別名の世代を作る。
// - rotateAlias：company-api と同じ境界で、次の世代の別名を足す（前の世代は廃番になる）。
// - smtp：生の SMTP の会話（RCPT の応答とその所要時間を、そのまま見るため）。宛先はテストの中で立てた relay だけ。
// - signCompanyMail：企業の送信サーバーの代わりに、登録した鍵で DKIM の署名を付ける。

import {
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { connect, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dkimSign } from 'mailauth/lib/dkim/sign.js';
import { MemoryOutbound } from '../../packages/relay/src/outbound.ts';
import { type RelayHandle, startRelay } from '../../packages/relay/src/relay.ts';
import { aliasLookupMessage } from '../../packages/warifu-core/src/aliases.ts';
import { sql } from '../../packages/warifu-core/src/db/sql.ts';
import {
  parseTenantId,
  parseWarifuUserId,
  type TenantId,
  type WarifuUserId,
} from '../../packages/warifu-core/src/ids.ts';
import { createCompanyApiKeyClient } from '../../packages/warifu-core/src/keys/company-api.ts';
import { createIdpKeyClient } from '../../packages/warifu-core/src/keys/idp.ts';
import { serviceDb } from './db.ts';
import { keysvcConnection } from './keys.ts';
import { workerDatabase } from './worker-db.ts';

export interface TestCompany {
  readonly tenantId: TenantId;
  readonly displayName: string;
  readonly relayDomain: string;
  readonly senderDomain: string;
  readonly selector: string;
  readonly privateKey: KeyObject;
}

export interface TestRelay {
  readonly relay: RelayHandle;
  readonly outbound: MemoryOutbound;
  readonly companies: readonly TestCompany[];
  readonly idpCredential: string;
  readonly logs: string[];
  /** relay の DKIM の公開鍵を載せた、受信側の模擬の DNS（追加の記録を足せる）。 */
  dns(
    extra?: Readonly<Record<string, string>>,
  ): (name: string, rrtype: string) => Promise<string[][]>;
  stop(): Promise<void>;
}

export const RELAY_SELECTOR = 'warifu1';
export const NOTICE_DOMAIN = 'notice.warifu.test';
export const AUTHSERV_ID = 'mx.relay.warifu.test';

function resolverOf(records: Readonly<Record<string, string>>) {
  return async (name: string, rrtype: string) => {
    const value = records[`${rrtype}:${name.toLowerCase()}`];
    if (value === undefined) {
      const error = new Error('not found') as Error & { code: string };
      error.code = 'ENOTFOUND';
      throw error;
    }
    return [[value]];
  };
}

export async function startTestRelay(options?: {
  readonly companies?: number;
  readonly now?: () => Date;
  /** 返信の DMARC の検証に使う DNS の記録（`TXT:名前` → 値）。なければリゾルバを渡さない。 */
  readonly replyDns?: Readonly<Record<string, string>>;
}): Promise<TestRelay> {
  const companies: TestCompany[] = Array.from({ length: options?.companies ?? 1 }, (_, i) => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const label = randomBytes(4).toString('hex');
    return {
      tenantId: parseTenantId(randomUUID()),
      displayName: `テスト企業${i + 1}`,
      relayDomain: `t${label}.relay.warifu.test`,
      senderDomain: `mail${label}.company.example`,
      selector: `s${i + 1}`,
      privateKey,
    };
  });
  const db = await workerDatabase();
  const dir = await mkdtemp(join(tmpdir(), 'relay-'));
  const idpSecret = new Uint8Array(randomBytes(32));
  const outbound = new MemoryOutbound();
  const logs: string[] = [];
  const replyDns = options?.replyDns;
  const relay = await startRelay({
    config: {
      tenants: companies.map((c) => ({
        tenantId: c.tenantId,
        displayName: c.displayName,
        relayDomain: c.relayDomain,
        sender: {
          domain: c.senderDomain,
          selector: c.selector,
          publicKey: createPublicKey(c.privateKey)
            .export({ type: 'spki', format: 'der' })
            .toString('base64'),
        },
      })),
      selector: RELAY_SELECTOR,
      authservId: AUTHSERV_ID,
      noticeDomain: NOTICE_DOMAIN,
    },
    db: { host: String(db.host), port: Number(db.port), database: String(db.database) },
    keysvc: keysvcConnection('relay'),
    outbound,
    ...(replyDns === undefined ? {} : { resolver: resolverOf(replyDns) }),
    internalApi: { socketPath: join(dir, 'relay.sock'), credentials: { idp: idpSecret } },
    ...(options?.now === undefined ? {} : { now: options.now }),
    logWrite: (line) => logs.push(line),
  });
  const relayKey = await relay.dkimPublicKey();
  return {
    relay,
    outbound,
    companies,
    idpCredential: `idp.${Buffer.from(idpSecret).toString('base64url')}`,
    logs,
    dns(extra) {
      const records: Record<string, string> = {
        [`TXT:_dmarc.${NOTICE_DOMAIN}`]: 'v=DMARC1; p=reject',
      };
      records[`TXT:${RELAY_SELECTOR}._domainkey.${NOTICE_DOMAIN}`] =
        `v=DKIM1; k=rsa; p=${relayKey}`;
      for (const c of companies) {
        records[`TXT:${RELAY_SELECTOR}._domainkey.${c.relayDomain}`] =
          `v=DKIM1; k=rsa; p=${relayKey}`;
        records[`TXT:_dmarc.${c.relayDomain}`] = 'v=DMARC1; p=reject';
      }
      return resolverOf({ ...records, ...(extra ?? {}) });
    },
    async stop() {
      await relay.stop();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

export interface TestUser {
  readonly userId: WarifuUserId;
  readonly email: string;
  /** テナントの番号 → 別名（ローカル部@relay のドメイン）。 */
  readonly aliases: readonly string[];
}

/** 利用者を作る。本物のメールは idp の鍵で暗号化し、別名は第1世代を登録する（idp と同じ境界を通す）。 */
export async function addUser(
  companies: readonly TestCompany[],
  email?: string,
): Promise<TestUser> {
  const userId = parseWarifuUserId(randomUUID());
  const address = email ?? `u${randomBytes(6).toString('hex')}@users.example`;
  const keys = createIdpKeyClient(keysvcConnection('idp'));
  const idp = await serviceDb('idp');
  try {
    const ciphertext = await keys.encryptContact({
      userId,
      plaintext: new TextEncoder().encode(address),
    });
    await idp.withWarifuUser(userId, async (tx) => {
      await tx.execute(sql`INSERT INTO idp.users (user_id) VALUES (${userId})`);
      await tx.execute(
        sql`INSERT INTO contacts.email (user_id, ciphertext, updated_at) VALUES (${userId}, ${ciphertext}, ${new Date()})`,
      );
    });
    const aliases: string[] = [];
    for (const c of companies) {
      const local = await keys.deriveAlias({ tenantId: c.tenantId, userId, generation: 1 });
      const lookupMac = await keys.mac('alias_lookup', aliasLookupMessage(local));
      await idp.withTenant(c.tenantId, (tx) =>
        tx.execute(
          sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
              VALUES (${c.tenantId}, ${userId}, 1, ${lookupMac})`,
        ),
      );
      aliases.push(`${local}@${c.relayDomain}`);
    }
    return { userId, email: address, aliases };
  } finally {
    await idp.close();
  }
}

/** 別名を再発行する（company-api と同じ境界で、第2世代を足す）。新しい別名を返す。前の世代は廃番になる。 */
export async function rotateAlias(company: TestCompany, userId: WarifuUserId): Promise<string> {
  const keys = createCompanyApiKeyClient(keysvcConnection('company-api'));
  const local = await keys.deriveAlias({ tenantId: company.tenantId, userId, generation: 2 });
  const lookupMac = await keys.mac('alias_lookup', aliasLookupMessage(local));
  const db = await serviceDb('company-api');
  try {
    await db.withTenant(company.tenantId, (tx) =>
      tx.execute(
        sql`INSERT INTO aliases.generation (tenant_id, user_id, generation, lookup_mac)
            VALUES (${company.tenantId}, ${userId}, 2, ${lookupMac})`,
      ),
    );
  } finally {
    await db.close();
  }
  return `${local}@${company.relayDomain}`;
}

/** 企業の送信サーバーの代わりに、登録した鍵で DKIM の署名を付ける。 */
export async function signCompanyMail(
  company: TestCompany,
  raw: string,
  options?: {
    readonly headerList?: string;
    readonly signingDomain?: string;
    readonly key?: KeyObject;
    readonly signTime?: Date;
    readonly maxBodyLength?: number;
  },
): Promise<Buffer> {
  const result = await dkimSign(Buffer.from(raw.replace(/\r?\n/g, '\r\n')), {
    canonicalization: 'relaxed/relaxed',
    signTime: options?.signTime ?? new Date(),
    signatureData: [
      {
        signingDomain: options?.signingDomain ?? company.senderDomain,
        selector: company.selector,
        privateKey: (options?.key ?? company.privateKey)
          .export({ type: 'pkcs8', format: 'pem' })
          .toString(),
        headerList:
          options?.headerList ??
          'From:From:To:To:Subject:Subject:Date:Message-ID:Reply-To:Content-Type:MIME-Version:List-Unsubscribe',
        ...(options?.maxBodyLength === undefined ? {} : { maxBodyLength: options.maxBodyLength }),
      },
    ],
  });
  return Buffer.concat([
    Buffer.from(result.signatures),
    Buffer.from(raw.replace(/\r?\n/g, '\r\n')),
  ]);
}

/** 企業から利用者へのメールの見本（本文は企業が書いた任意のバイト列）。 */
export function companyMail(
  company: TestCompany,
  to: string,
  extraHeaders: readonly string[] = [],
  body = 'ご予約を承りました。\r\n',
): string {
  return [
    `From: "${company.displayName}" <info@${company.senderDomain}>`,
    `To: ${to}`,
    'Subject: =?UTF-8?B?44GU5LqI57SE44Gu56K66KqN?=',
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${randomUUID()}@${company.senderDomain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    ...extraHeaders,
    '',
    body,
  ].join('\r\n');
}

export interface SmtpReply {
  readonly code: number;
  readonly text: string;
  readonly ms: number;
}

/** 生の SMTP の会話。テストの中で立てた relay（127.0.0.1）にだけつなぐ。 */
export class SmtpSession {
  readonly #socket: Socket;
  #buffer = '';
  readonly #waiters: ((reply: { code: number; text: string }) => void)[] = [];

  private constructor(socket: Socket) {
    this.#socket = socket;
    socket.on('data', (chunk) => {
      this.#buffer += chunk.toString('latin1');
      for (;;) {
        const lines = this.#buffer.split('\r\n');
        const end = lines.findIndex((l) => /^\d{3} /.test(l));
        if (end < 0) break;
        const text = lines.slice(0, end + 1).join('\n');
        this.#buffer = lines.slice(end + 1).join('\r\n');
        this.#waiters.shift()?.({ code: Number((lines[end] ?? '').slice(0, 3)), text });
      }
    });
  }

  static async open(port: number): Promise<SmtpSession> {
    const session = new SmtpSession(connect({ host: '127.0.0.1', port }));
    await session.#next(); // バナー
    return session;
  }

  #next(): Promise<{ code: number; text: string }> {
    return new Promise((resolve) => this.#waiters.push(resolve));
  }

  async command(line: string): Promise<SmtpReply> {
    const started = performance.now();
    const pending = this.#next();
    this.#socket.write(`${line}\r\n`);
    return { ...(await pending), ms: performance.now() - started };
  }

  /** DATA の中身を送る（行頭の . を二重にし、終わりの . を付ける）。 */
  async data(raw: Buffer): Promise<SmtpReply> {
    const started = performance.now();
    const pending = this.#next();
    const dotted = raw.toString('latin1').replace(/\r\n\./g, '\r\n..');
    this.#socket.write(
      Buffer.from(`${dotted}${dotted.endsWith('\r\n') ? '' : '\r\n'}.\r\n`, 'latin1'),
    );
    return { ...(await pending), ms: performance.now() - started };
  }

  close(): void {
    this.#socket.end('QUIT\r\n');
  }
}

/** 1通を送る（EHLO、MAIL FROM、RCPT TO、DATA）。RCPT が 250 でなければ、DATA は送らない。 */
export async function sendMail(
  port: number,
  envelope: { readonly from: string; readonly to: string },
  raw: Buffer,
): Promise<{ readonly rcpt: SmtpReply; readonly data: SmtpReply | undefined }> {
  const session = await SmtpSession.open(port);
  try {
    await session.command('EHLO sender.example');
    await session.command(`MAIL FROM:<${envelope.from}>`);
    const rcpt = await session.command(`RCPT TO:<${envelope.to}>`);
    if (rcpt.code !== 250) return { rcpt, data: undefined };
    const go = await session.command('DATA');
    if (go.code !== 354) return { rcpt, data: go };
    return { rcpt, data: await session.data(raw) };
  } finally {
    session.close();
  }
}
