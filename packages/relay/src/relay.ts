// relay（plan 3-2・8章、ADR 0021）。本物の連絡先を復号できる唯一のサービス（不変条件3）。
//
// 受け口：
// - SMTP（smtp-server）。別名あてと返信用のアドレスあてのメールを受ける。1つのトランザクションの宛先は1つ。
//   RCPT の応答は、生きている別名、廃番、存在しないもの、知らない返信用のアドレスで同じ（不変条件10）。
//   名前の逆引きはしない（不変条件7）。STARTTLS と AUTH は M4 では使わない（本番の TLS は P1）。
// - 内部配送 API（Unix ドメインソケットの HTTP。idp だけ。internal-api.ts）。
//
// 受け取ったメールの件名と本文は DB に置かない。DATA の応答を返した後に、メモリの中で処理する
// （別名が生きているかどうかで、応答と所要時間を変えないため）。外への配送は Outbound（メモリか、送信サービスの内部 API。ADR 0022）。
// テナントの範囲の表（relay.replay、relay.threads、relay.delivery_log）は withTenant で、本物のアドレスは
// withWarifuUser で読む。テナントを横断するのは、解決関数（relay.resolve_alias）だけ（不変条件8）。

import {
  ALIAS_LOCAL_PART_PATTERN,
  aliasLookupMessage,
  lengthPrefixed,
  randomBytesOf,
  randomUuid,
  type TenantId,
  toBase32Lower,
  utf8,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { type DbConnection, sql } from '@pii-token-vault/warifu-core/db';
import { createRelayDb, type RelayDb } from '@pii-token-vault/warifu-core/db/relay';
import type { KeysvcConnection } from '@pii-token-vault/warifu-core/keys/protocol';
import { createRelayKeyClient, type RelayKeyClient } from '@pii-token-vault/warifu-core/keys/relay';
import { createLogger, type Logger, type LogLevel } from '@pii-token-vault/warifu-core/log';
import { authenticate, type DNSResolver } from 'mailauth';
import { SMTPServer, type SMTPServerDataStream, type SMTPServerSession } from 'smtp-server';
import {
  type ParsedRelayConfig,
  parseRelayConfig,
  type RelayConfig,
  type RelayTenant,
} from './config.ts';
import { signAndSeal, signOnly } from './dkim.ts';
import { inspectReply } from './inspect.ts';
import { type InternalApi, startInternalApi } from './internal-api.ts';
import {
  buildMessage,
  encodeWord,
  field,
  fieldsNamed,
  headerValue,
  type ParsedMessage,
  parseMessage,
  singleAddress,
} from './mime.ts';
import type { Outbound } from './outbound.ts';
import { rewriteToCompany, rewriteToUser } from './rewrite.ts';
import { type SenderLockResult, SIGNATURE_MAX_AGE_MS, verifySenderLock } from './sender-lock.ts';
import { bodyOf, type NoticeKind, subjectOf } from './templates.ts';

/** 返信用のアドレスのローカル部：`r-` と、128ビットの乱数の base32（26文字）。別名（16文字）とは形が違う。 */
export const THREAD_LOCAL_PART_PATTERN = /^r-[a-z2-7]{26}$/;
const DAY_MS = 24 * 60 * 60 * 1000;
/** 返信用のアドレスの有効期間（ADR 0021 の仮置き）。 */
export const THREAD_TTL_MS = 30 * DAY_MS;
/** 配送ログを残す期間（ADR 0021 の仮置き）。 */
export const DELIVERY_LOG_TTL_MS = 30 * DAY_MS;
/**
 * リプレイの記録は、その署名を受け付ける間（t= から7日と x= の早いほう）だけ要る。その後は送信元ロックが
 * 署名の時刻で断る。時計の境目の取りこぼしを避けるため、1時間の余裕を足す（ADR 0021）。
 */
const REPLAY_MARGIN_MS = 60 * 60 * 1000;
const PURGE_INTERVAL_MS = 60 * 60 * 1000;
/** SMTP の同時接続の上限と、無通信で切るまでの時間（ADR 0021。送信元ごとの上限は P1 の受信の前段で決める）。 */
const SMTP_MAX_CLIENTS = 100;
const SMTP_SOCKET_TIMEOUT_MS = 60_000;
const MAX_ADDRESS_BYTES = 254;

export interface RelayOptions {
  readonly config: RelayConfig;
  readonly db: DbConnection;
  readonly keysvc: KeysvcConnection;
  readonly outbound: Outbound;
  /**
   * 返信の DMARC の検証に使う DNS のリゾルバ。送信サービスの名前解決の口（senderResolver。ADR 0022）。
   * ないときは、利用者からの返信を中継しない（確かめられないものは通さない）。
   */
  readonly resolver?: DNSResolver;
  /** SMTP の待ち受け。既定は 127.0.0.1 の空いているポート。 */
  readonly smtp?: { readonly host?: string; readonly port?: number };
  /** 内部配送 API のソケットと、呼び出し元の資格情報（32バイト）。 */
  readonly internalApi: {
    readonly socketPath: string;
    readonly credentials: Readonly<Record<'idp', Uint8Array>>;
  };
  readonly now?: () => Date;
  readonly logLevel?: LogLevel;
  readonly logWrite?: (line: string) => void;
}

export interface RelayHandle {
  readonly smtpPort: number;
  readonly socketPath: string;
  /** DATA の後の処理が、すべて終わるまで待つ（テスト用）。 */
  idle(): Promise<void>;
  /** relay の DKIM の公開鍵（SubjectPublicKeyInfo の DER の base64）。DNS の p= に載せる。 */
  dkimPublicKey(): Promise<string>;
  stop(): Promise<void>;
}

function smtpError(code: number, text: string): Error & { responseCode: number } {
  const error = new Error(text) as Error & { responseCode: number };
  error.responseCode = code;
  return error;
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export async function startRelay(options: RelayOptions): Promise<RelayHandle> {
  const config: ParsedRelayConfig = parseRelayConfig(options.config);
  const now = options.now ?? (() => new Date());
  const log: Logger = createLogger({
    component: 'relay',
    level: options.logLevel ?? 'info',
    ...(options.logWrite ? { write: options.logWrite } : {}),
  });
  const db: RelayDb = createRelayDb({ connection: options.db });
  const keys: RelayKeyClient = createRelayKeyClient(options.keysvc);
  const pending = new Set<Promise<void>>();

  const schedule = (task: () => Promise<void>) => {
    const run = task()
      .catch((err: unknown) => log.error({ event: 'relay.process_failed', err }))
      .finally(() => pending.delete(run));
    pending.add(run);
  };

  const sign = async (data: Uint8Array) => (await keys.signDkim(data)).signature;

  function parseRecipient(
    address: string,
  ): { readonly tenant: RelayTenant; readonly local: string } | undefined {
    const text = address.toLowerCase();
    const at = text.lastIndexOf('@');
    const tenant = at > 0 ? config.byRelayDomain.get(text.slice(at + 1)) : undefined;
    return tenant === undefined ? undefined : { tenant, local: text.slice(0, at) };
  }

  function recipientOf(
    session: SMTPServerSession,
  ): { readonly tenant: RelayTenant; readonly local: string } | undefined {
    const rcpt = session.envelope.rcptTo;
    return rcpt.length === 1 && rcpt[0] !== undefined ? parseRecipient(rcpt[0].address) : undefined;
  }

  async function realAddressOf(
    userId: WarifuUserId,
    table: 'email' | 'email_pending' | 'email_previous',
  ): Promise<string | undefined> {
    const rows = await db.withWarifuUser(userId, (tx) => {
      switch (table) {
        case 'email':
          return tx.query<{ ciphertext: Uint8Array }>(
            sql`SELECT ciphertext FROM contacts.email WHERE user_id = ${userId}`,
          );
        case 'email_pending':
          return tx.query<{ ciphertext: Uint8Array }>(
            sql`SELECT ciphertext FROM contacts.email_pending WHERE user_id = ${userId}`,
          );
        case 'email_previous':
          return tx.query<{ ciphertext: Uint8Array }>(
            sql`SELECT ciphertext FROM contacts.email_previous WHERE user_id = ${userId}`,
          );
      }
    });
    const row = rows[0];
    if (row === undefined) return undefined;
    return decode(
      await keys.decryptContact({ userId, ciphertext: new Uint8Array(row.ciphertext) }),
    );
  }

  async function messageIdMac(message: ParsedMessage): Promise<Uint8Array> {
    const header = fieldsNamed(message.headers, 'message-id')[0];
    const value = header === undefined ? randomUuid() : headerValue(header);
    return keys.mac('message_id', lengthPrefixed(['warifu/message-id/v1', value]));
  }

  async function logDelivery(
    tenantId: TenantId,
    message: ParsedMessage,
    direction: 'to_user' | 'to_company',
    outcome: 'delivered' | 'failed',
  ): Promise<void> {
    const mac = await messageIdMac(message);
    const expiresAt = new Date(now().getTime() + DELIVERY_LOG_TTL_MS);
    await db.withTenant(tenantId, (tx) =>
      tx.execute(
        sql`INSERT INTO relay.delivery_log (log_id, tenant_id, message_id_mac, direction, outcome, expires_at)
            VALUES (${randomUuid()}, ${tenantId}, ${mac}, ${direction}, ${outcome}, ${expiresAt})`,
      ),
    );
  }

  async function createThread(
    tenant: RelayTenant,
    userId: WarifuUserId,
    target: string,
  ): Promise<string> {
    if (Buffer.byteLength(target) > MAX_ADDRESS_BYTES) throw new RangeError('アドレスが長すぎる');
    const token = toBase32Lower(randomBytesOf(16));
    const threadId = randomUuid();
    const tokenMac = await keys.mac(
      'relay_thread',
      lengthPrefixed(['warifu/relay-thread/v1', token]),
    );
    const ciphertext = await keys.encryptQueueItem({
      queueItemId: threadId,
      plaintext: utf8(target),
    });
    const expiresAt = new Date(now().getTime() + THREAD_TTL_MS);
    await db.withTenant(tenant.tenantId, (tx) =>
      tx.execute(
        sql`INSERT INTO relay.threads (thread_id, tenant_id, user_id, token_mac, target_ciphertext, expires_at)
            VALUES (${threadId}, ${tenant.tenantId}, ${userId}, ${tokenMac}, ${ciphertext}, ${expiresAt})`,
      ),
    );
    return `r-${token}@${tenant.relayDomain}`;
  }

  /** リプレイなら false。(d=, s=, b=, 宛先のローカル部) の MAC を、署名を受け付ける間だけ残す（plan 3-2）。 */
  async function recordReplay(
    tenant: RelayTenant,
    lock: Extract<SenderLockResult, { ok: true }>,
    local: string,
  ): Promise<boolean> {
    const mac = await keys.mac(
      'relay_replay',
      lengthPrefixed([
        'warifu/relay-replay/v1',
        tenant.sender.domain,
        tenant.sender.selector,
        lock.signature,
        local,
      ]),
    );
    const until =
      Math.min(
        lock.signedAt.getTime() + SIGNATURE_MAX_AGE_MS,
        lock.expiresAt?.getTime() ?? Number.POSITIVE_INFINITY,
      ) + REPLAY_MARGIN_MS;
    const rows = await db.withTenant(tenant.tenantId, (tx) =>
      tx.query(
        sql`INSERT INTO relay.replay (tenant_id, replay_mac, expires_at)
            VALUES (${tenant.tenantId}, ${mac}, ${new Date(until)})
            ON CONFLICT (tenant_id, replay_mac) DO NOTHING RETURNING replay_mac`,
      ),
    );
    return rows.length === 1;
  }

  async function forwardToUser(input: {
    readonly tenant: RelayTenant;
    readonly userId: WarifuUserId;
    readonly recipient: string;
    readonly message: ParsedMessage;
    readonly lock: Extract<SenderLockResult, { ok: true }>;
  }): Promise<void> {
    const real = await realAddressOf(input.userId, 'email');
    if (real === undefined) return;
    // Reply-To は、企業が署名したものだけを使う（署名の外で足された Reply-To に、返信を向けさせない）。
    const replyToFields = fieldsNamed(input.message.headers, 'reply-to');
    const replyToField = replyToFields.length === 1 ? replyToFields[0] : undefined;
    const replyTo =
      replyToField !== undefined && input.lock.signedHeaders.includes('reply-to')
        ? singleAddress(headerValue(replyToField))
        : undefined;
    const headers = await rewriteToUser({
      message: input.message,
      displayName: input.tenant.displayName,
      alias: input.recipient,
      threadFor: (target) => createThread(input.tenant, input.userId, target),
      fromAddress: input.lock.fromAddress,
      replyTo,
    });
    const sealed = await signAndSeal(buildMessage(headers, input.message.body), {
      domain: input.tenant.relayDomain,
      selector: config.selector,
      sign,
      now: now(),
      authservId: config.authservId,
      authResults: `dkim=pass header.d=${input.tenant.sender.domain} header.s=${input.tenant.sender.selector}`,
    });
    let outcome: 'delivered' | 'failed' = 'delivered';
    try {
      await options.outbound.send({
        mailFrom: `bounces@${input.tenant.relayDomain}`,
        rcptTo: real,
        raw: sealed,
      });
    } catch (err) {
      outcome = 'failed';
      log.warn({ event: 'relay.outbound_failed', err });
    }
    await logDelivery(input.tenant.tenantId, input.message, 'to_user', outcome);
  }

  async function sendNotice(rcpt: string, kind: NoticeKind, code?: string): Promise<void> {
    const text = bodyOf(kind, code);
    const body = Buffer.from(
      `${(
        Buffer.from(text, 'utf8')
          .toString('base64')
          .match(/.{1,76}/g) ?? []
      ).join('\r\n')}\r\n`,
    );
    const headers = [
      field('From', `${encodeWord('割符')} <notices@${config.noticeDomain}>`),
      field('To', `<${rcpt}>`),
      field('Subject', encodeWord(subjectOf(kind))),
      field('Date', now().toUTCString()),
      field('Message-ID', `<${toBase32Lower(randomBytesOf(16))}@${config.noticeDomain}>`),
      field('MIME-Version', '1.0'),
      field('Content-Type', 'text/plain; charset=utf-8'),
      field('Content-Transfer-Encoding', 'base64'),
    ];
    const signed = await signOnly(buildMessage(headers, body), {
      domain: config.noticeDomain,
      selector: config.selector,
      sign,
      now: now(),
    });
    await options.outbound.send({
      mailFrom: `bounces@${config.noticeDomain}`,
      rcptTo: rcpt,
      raw: signed,
    });
  }

  async function handleAlias(
    tenant: RelayTenant,
    local: string,
    message: ParsedMessage,
    lock: Extract<SenderLockResult, { ok: true }>,
  ) {
    if (!ALIAS_LOCAL_PART_PATTERN.test(local)) return;
    const lookup = await keys.mac('alias_lookup', aliasLookupMessage(local));
    const resolved = await db.resolveAlias(lookup);
    // テナント ID は配送の判断だけに使う（不変条件1(e)）。別のテナントのドメインに来た別名は届けない。
    if (resolved === undefined || resolved.tenantId !== tenant.tenantId) return;
    await forwardToUser({
      tenant,
      userId: resolved.userId,
      recipient: `${local}@${tenant.relayDomain}`,
      message,
      lock,
    });
  }

  async function handleThread(
    tenant: RelayTenant,
    local: string,
    raw: Buffer,
    message: ParsedMessage,
    smtp: { readonly ip: string; readonly helo: string; readonly mailFrom: string },
  ) {
    const token = local.slice(2);
    const tokenMac = await keys.mac(
      'relay_thread',
      lengthPrefixed(['warifu/relay-thread/v1', token]),
    );
    const rows = await db.withTenant(tenant.tenantId, (tx) =>
      tx.query<{ thread_id: string; user_id: string; target_ciphertext: Uint8Array }>(
        sql`SELECT thread_id, user_id, target_ciphertext FROM relay.threads
             WHERE token_mac = ${tokenMac} AND expires_at > ${now()}`,
      ),
    );
    const thread = rows[0];
    if (thread === undefined) return;
    const userId = thread.user_id as WarifuUserId;
    const recipient = `${local}@${tenant.relayDomain}`;

    // 企業から返信用のアドレスに来たもの：送信元ロックを通れば、利用者へ届ける。
    const lock = await verifySenderLock(raw, message, tenant, now());
    if (lock.ok) {
      if (await recordReplay(tenant, lock, local)) {
        await forwardToUser({ tenant, userId, recipient, message, lock });
      }
      return;
    }

    // 利用者からの返信：From が本物のアドレスと一致し、そのドメインで DMARC が整合して pass したものだけ（plan 3-2）。
    if (options.resolver === undefined) return;
    const real = await realAddressOf(userId, 'email');
    if (real === undefined) return;
    const auth = await authenticate(raw, {
      ip: smtp.ip,
      helo: smtp.helo,
      sender: smtp.mailFrom,
      mta: config.authservId,
      resolver: options.resolver,
      disableBimi: true,
      minBitLength: 2048,
      rejectRsaSha1: true,
      curTime: now(),
    } as Parameters<typeof authenticate>[1]);
    const from = auth.dkim.headerFrom;
    if (
      auth.dkim.fromFields !== 1 ||
      from.length !== 1 ||
      from[0]?.toLowerCase() !== real.toLowerCase()
    ) {
      return;
    }
    const dmarc = auth.dmarc || undefined;
    if (dmarc?.status.result !== 'pass') return;
    const target = decode(
      await keys.decryptQueueItem({
        queueItemId: thread.thread_id,
        ciphertext: new Uint8Array(thread.target_ciphertext),
      }),
    );
    const headers = rewriteToCompany({
      message,
      replyAddress: recipient,
      target,
      messageId: `${toBase32Lower(randomBytesOf(16))}@${tenant.relayDomain}`,
      userDomain: real.slice(real.lastIndexOf('@') + 1),
    });
    // 企業へ送るもの（残すヘッダーと本文）に本物のアドレスがあれば、送らずに利用者へ差し戻す。中身を確かめられない
    // 部分（添付ファイルなど）があるときも差し戻す（plan 3-2、ADR 0021）。
    const inspected = inspectReply(headers, message, real);
    if (inspected !== 'clean') {
      log.info({ event: 'relay.reply_returned', reason: inspected });
      await sendNotice(
        real,
        inspected === 'contains_address' ? 'reply_returned' : 'reply_unsupported',
      );
      return;
    }
    // ARC の結果には、利用者のドメインを書かない（企業へ、利用者のメールの事業者を伝えない）。
    const sealed = await signAndSeal(buildMessage(headers, message.body), {
      domain: tenant.relayDomain,
      selector: config.selector,
      sign,
      now: now(),
      authservId: config.authservId,
      authResults: 'dmarc=pass',
    });
    let outcome: 'delivered' | 'failed' = 'delivered';
    try {
      await options.outbound.send({
        mailFrom: `bounces@${tenant.relayDomain}`,
        rcptTo: target,
        raw: sealed,
      });
    } catch (err) {
      outcome = 'failed';
      log.warn({ event: 'relay.outbound_failed', err });
    }
    await logDelivery(tenant.tenantId, message, 'to_company', outcome);
  }

  async function onData(stream: SMTPServerDataStream, session: SMTPServerSession): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk as Buffer);
    if (stream.sizeExceeded) throw smtpError(552, '5.3.4 Message too big');
    // 宛先は、smtp-server がトランザクションごとに持つ封筒から読む（DATA の後と RSET で空になる）。
    const recipient = recipientOf(session);
    if (recipient === undefined) throw smtpError(503, '5.5.1 Bad sequence of commands');
    const { tenant, local } = recipient;
    const raw = Buffer.concat(chunks);
    const message = parseMessage(raw);
    if (THREAD_LOCAL_PART_PATTERN.test(local)) {
      // 返信用のアドレス：送り主が企業か利用者かは、応答の後に決める。応答は一律に 250。
      const smtp = {
        ip: session.remoteAddress,
        helo: session.hostNameAppearsAs ?? '',
        mailFrom: session.envelope.mailFrom === false ? '' : session.envelope.mailFrom.address,
      };
      schedule(() => handleThread(tenant, local, raw, message, smtp));
      return;
    }
    // 別名あて（と、どちらの形でもないもの）：送信元ロックとリプレイの判定は、別名が生きているかどうかに関係しない。
    const lock = await verifySenderLock(raw, message, tenant, now());
    if (!lock.ok) {
      log.info({ event: 'relay.sender_lock_failed', reason: lock.reason });
      throw smtpError(550, '5.7.1 Message not accepted');
    }
    if (!(await recordReplay(tenant, lock, local))) {
      // 同じ内容の再試行は 2xx で受けて捨てる（plan 3-2）。
      log.info({ event: 'relay.replay_dropped' });
      return;
    }
    schedule(() => handleAlias(tenant, local, message, lock));
  }

  const server = new SMTPServer({
    name: config.authservId,
    banner: 'Warifu relay',
    authOptional: true,
    disabledCommands: ['AUTH', 'STARTTLS'],
    hideSTARTTLS: true,
    disableReverseLookup: true,
    size: config.maxMessageBytes,
    maxClients: SMTP_MAX_CLIENTS,
    socketTimeout: SMTP_SOCKET_TIMEOUT_MS,
    logger: false,
    onRcptTo(address, session, callback) {
      // 1つのトランザクションの宛先は1つ（封筒は、トランザクションが終わるか RSET で空になる）。
      if (session.envelope.rcptTo.length > 0) {
        callback(smtpError(452, '4.5.3 Too many recipients'));
        return;
      }
      if (parseRecipient(address.address) === undefined) {
        callback(smtpError(550, '5.1.2 Recipient domain not accepted'));
        return;
      }
      callback();
    },
    onData(stream, session, callback) {
      onData(stream, session).then(
        () => callback(),
        (err: unknown) => {
          if (err instanceof Error && 'responseCode' in err) callback(err);
          else {
            log.error({ event: 'relay.data_failed', err });
            callback(smtpError(451, '4.3.0 Temporary failure'));
          }
        },
      );
    },
  });
  server.on('error', (err: unknown) => log.warn({ event: 'relay.smtp_error', err }));

  const smtpPort = await new Promise<number>((resolveListen, reject) => {
    server.server.once('error', reject);
    server.listen(options.smtp?.port ?? 0, options.smtp?.host ?? '127.0.0.1', () => {
      const address = server.server.address();
      resolveListen(typeof address === 'object' && address !== null ? address.port : 0);
    });
  });

  const internal: InternalApi = await startInternalApi({
    socketPath: options.internalApi.socketPath,
    credentials: options.internalApi.credentials,
    log,
    async deliver(request) {
      if (request.kind === 'email_verification') {
        const rcpt = await realAddressOf(request.userId, 'email_pending');
        if (rcpt !== undefined) await sendNotice(rcpt, 'email_verification', request.code);
      } else {
        const rcpt = await realAddressOf(request.userId, 'email_previous');
        if (rcpt !== undefined) await sendNotice(rcpt, 'email_changed_notice');
      }
    },
  });

  const purge = async () => {
    for (const tenant of config.tenants) {
      await db.withTenant(tenant.tenantId, async (tx) => {
        const at = now();
        await tx.execute(sql`DELETE FROM relay.replay WHERE expires_at <= ${at}`);
        await tx.execute(sql`DELETE FROM relay.threads WHERE expires_at <= ${at}`);
        await tx.execute(sql`DELETE FROM relay.delivery_log WHERE expires_at <= ${at}`);
      });
    }
  };
  const purgeTimer = setInterval(() => {
    purge().catch((err: unknown) => log.warn({ event: 'relay.purge_failed', err }));
  }, PURGE_INTERVAL_MS);
  purgeTimer.unref();
  await purge();

  log.info({ event: 'relay.ready' });

  return Object.freeze({
    smtpPort,
    socketPath: options.internalApi.socketPath,
    async idle() {
      while (pending.size > 0) await Promise.allSettled([...pending]);
    },
    async dkimPublicKey() {
      return Buffer.from((await keys.dkimPublicKey()).spki).toString('base64');
    },
    async stop() {
      clearInterval(purgeTimer);
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      await internal.close();
      while (pending.size > 0) await Promise.allSettled([...pending]);
      await db.close();
      log.info({ event: 'relay.stopped' });
    },
  });
}
