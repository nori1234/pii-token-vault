// idp：OIDC、パスキー、step-up、PWA（M3）。CIBA は M7、回復は M8。

export { createIdp, type Idp, type IdpOptions } from './app.ts';
export { type Mailer, type MailRequest, MemoryOutbox } from './mailer.ts';
export { ACR_PASSKEY, OIDC_COOKIES, OIDC_MOUNT, TTL } from './provider.ts';
export { RATE_LIMITS } from './rate-limit.ts';
export {
  type AliasClaim,
  type ClientEntry,
  OUTBOUND_CLIENT_METADATA,
  parseRegistry,
  type Registry,
  RegistryError,
  type TenantEntry,
} from './registry.ts';
export {
  PWA_SESSION_COOKIE,
  SESSION_ABSOLUTE_SECONDS,
  SESSION_IDLE_SECONDS,
  STEP_UP_SECONDS,
} from './sessions.ts';
export { deriveSub, SUB_LABEL, subjectMessage } from './subject.ts';
export { SUPPORTED_ALGORITHM_IDS } from './webauthn.ts';
