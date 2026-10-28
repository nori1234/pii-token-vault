// 送信サービス（外向きの通信の唯一の出口。不変条件7、ADR 0022）。
export { isPublicAddress } from './address.ts';
export type { TcpConnector } from './mail.ts';
export { isDnsQueryName, isHostName, parseWebhookUrl } from './names.ts';
export type { DnsResolver } from './resolve.ts';
export { type SenderHandle, type SenderOptions, startSender } from './sender.ts';
export type { TlsConnector } from './webhook.ts';
