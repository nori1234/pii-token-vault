// メール中継（decrypt できる唯一のサービス。不変条件3、ADR 0021）。
export {
  type ParsedRelayConfig,
  parseRelayConfig,
  type RelayConfig,
  RelayConfigError,
  type RelayTenant,
} from './config.ts';
export { MemoryOutbound, type Outbound, type OutboundMessage } from './outbound.ts';
export {
  type RelayHandle,
  type RelayOptions,
  startRelay,
  THREAD_LOCAL_PART_PATTERN,
} from './relay.ts';
