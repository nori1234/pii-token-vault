// 署名と封印を付けたメッセージの配送（plan 8章、CAP-22・26、ADR 0021、ADR 0022）。relay だけが呼ぶ。
//
// - 宛先のドメインの MX を引く。MX がなければ（ENODATA）、ドメインそのものを MX とみなす（RFC 5321 5.1）。
//   null MX（RFC 7505）なら送らない。
// - MX のホストごとに A と AAAA を引き、1つでも公開でないアドレスがあれば、そのホストには送らない（内部の IP を
//   指す MX を拒否する）。接続は、確かめたアドレスに直接つなぐ。
// - SMTP は nodemailer の SMTPConnection。STARTTLS は相手が対応していれば使う（証明書は検査しない。MTA-STS と
//   DANE は P1）。配送の再試行はしない（呼び出し元の relay の永続化と再試行は、実配送の前に作る。ADR 0021 の O-19）。
// - テストでは、最後の接続（TCP のソケット）だけを差し替えられる。宛先の検査は差し替えられない。

import { connect, type Socket } from 'node:net';
import type { SenderRejectReason } from '@pii-token-vault/warifu-core/sender/protocol';
import SMTPConnection from 'nodemailer/lib/smtp-connection';
import { isHostName, parseEnvelopeAddress } from './names.ts';
import { type DnsResolver, dnsCodeOf, ResolveError, resolvePublicAddresses } from './resolve.ts';

const SMTP_PORT = 25;
const MAX_MX_HOSTS = 5;
const CONNECT_TIMEOUT_MS = 10_000;
const SOCKET_TIMEOUT_MS = 30_000;

/** 確かめたアドレスへの TCP の接続を作る。既定は node:net。 */
export type TcpConnector = (input: { readonly address: string; readonly port: number }) => Socket;

export const defaultTcpConnector: TcpConnector = ({ address, port }) =>
  connect({ host: address, port });

export interface MailDeps {
  readonly resolver: DnsResolver;
  readonly connectTcp: TcpConnector;
  /** EHLO で名乗る名前（relay の MX の名前など）。 */
  readonly heloName: string;
}

export type MailOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: SenderRejectReason };

async function mxHostsOf(
  resolver: DnsResolver,
  domain: string,
): Promise<readonly string[] | SenderRejectReason> {
  let records: { exchange: string; priority: number }[];
  try {
    records = await resolver.resolveMx(domain);
  } catch (error) {
    const code = dnsCodeOf(error);
    if (code === 'ENODATA') return [domain];
    if (code === 'ENOTFOUND') return 'no_address';
    return code === 'ETIMEOUT' ? 'timeout' : 'dns_failed';
  }
  if (records.length === 0) return [domain];
  if (records.some((r) => r.exchange === '' || r.exchange === '.')) return 'null_mx';
  return [...records]
    .sort((a, b) => a.priority - b.priority)
    .slice(0, MAX_MX_HOSTS)
    .map((r) => r.exchange.toLowerCase().replace(/\.$/, ''));
}

function openSocket(deps: MailDeps, address: string): Promise<Socket> {
  return new Promise((resolveOpen, reject) => {
    const socket = deps.connectTcp({ address, port: SMTP_PORT });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('connect timeout'));
    }, CONNECT_TIMEOUT_MS);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.removeAllListeners('error');
      resolveOpen(socket);
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function smtpSend(
  deps: MailDeps,
  socket: Socket,
  mxHost: string,
  envelope: { readonly from: string; readonly to: string },
  raw: Buffer,
): Promise<MailOutcome> {
  return new Promise((resolveSend) => {
    const connection = new SMTPConnection({
      connection: socket,
      host: mxHost,
      port: SMTP_PORT,
      name: deps.heloName,
      opportunisticTLS: true,
      tls: { servername: mxHost, rejectUnauthorized: false, minVersion: 'TLSv1.2' },
      connectionTimeout: CONNECT_TIMEOUT_MS,
      greetingTimeout: CONNECT_TIMEOUT_MS,
      socketTimeout: SOCKET_TIMEOUT_MS,
      logger: false,
    });
    let settled = false;
    const finish = (outcome: MailOutcome) => {
      if (settled) return;
      settled = true;
      if (outcome.ok) connection.quit();
      else connection.close();
      resolveSend(outcome);
    };
    connection.on('error', () => finish({ ok: false, reason: 'smtp_failed' }));
    connection.connect((connectError) => {
      if (connectError) {
        finish({ ok: false, reason: 'smtp_failed' });
        return;
      }
      connection.send({ from: envelope.from, to: [envelope.to] }, raw, (sendError) => {
        if (sendError) {
          const code = (sendError as { responseCode?: unknown }).responseCode;
          const permanent = typeof code === 'number' && code >= 500 && code < 600;
          finish({ ok: false, reason: permanent ? 'smtp_rejected' : 'smtp_failed' });
          return;
        }
        finish({ ok: true });
      });
    });
  });
}

/** 宛先のドメインの MX に送る。宛先が検査に通らなければ、つながずに断る。 */
export async function deliverMail(
  deps: MailDeps,
  input: { readonly mailFrom: string; readonly rcptTo: string; readonly raw: Buffer },
): Promise<MailOutcome> {
  const from = parseEnvelopeAddress(input.mailFrom);
  const to = parseEnvelopeAddress(input.rcptTo);
  if (from === undefined || to === undefined) return { ok: false, reason: 'invalid_destination' };
  const hosts = await mxHostsOf(deps.resolver, to.domain);
  if (typeof hosts === 'string') return { ok: false, reason: hosts };
  let last: MailOutcome = { ok: false, reason: 'no_address' };
  let blocked = false;
  for (const host of hosts) {
    if (!isHostName(host)) {
      last = { ok: false, reason: 'invalid_destination' };
      continue;
    }
    let addresses: readonly string[];
    try {
      addresses = await resolvePublicAddresses(deps.resolver, host);
    } catch (error) {
      if (!(error instanceof ResolveError)) throw error;
      if (error.reason === 'blocked_address') blocked = true;
      last = { ok: false, reason: error.reason };
      continue;
    }
    const [address] = addresses;
    if (address === undefined) continue;
    let socket: Socket;
    try {
      socket = await openSocket(deps, address);
    } catch {
      last = { ok: false, reason: 'connect_failed' };
      continue;
    }
    const outcome = await smtpSend(
      deps,
      socket,
      host,
      { from: input.mailFrom, to: input.rcptTo },
      input.raw,
    );
    // 受け取りを断られたら（5xx）、ほかの MX にも送らない。
    if (outcome.ok || outcome.reason === 'smtp_rejected') return outcome;
    last = outcome;
  }
  // 内部の IP を指す MX があったときは、その理由を返す（ほかの失敗で隠さない）。
  return blocked && !last.ok && last.reason !== 'smtp_rejected'
    ? { ok: false, reason: 'blocked_address' }
    : last;
}
