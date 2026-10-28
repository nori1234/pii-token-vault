// idp：OIDC、パスキー、step-up、PWA（M3）。端末の受信箱と承認用のオリジン（M6）。CIBA は M7、回復は M8。

export { createIdp, type Idp, type IdpOptions } from './app.ts';
export {
  APPROVAL_TTL_MAX_SECONDS,
  APPROVAL_TTL_MIN_SECONDS,
  type ApprovalChannel,
  type ApprovalDecision,
  type ApprovalType,
  type DisplayLine,
  type InboxContent,
  MAX_PENDING_APPROVALS,
  NOTICE_TYPES,
} from './inbox.ts';
export { type Mailer, type MailRequest, MemoryOutbox, RelayMailer } from './mailer.ts';
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
  APPROVAL_SESSION_COOKIE,
  PWA_SESSION_COOKIE,
  SESSION_ABSOLUTE_SECONDS,
  SESSION_IDLE_SECONDS,
  STEP_UP_SECONDS,
} from './sessions.ts';
export { deriveSub, SUB_LABEL, subjectMessage } from './subject.ts';
export { SUPPORTED_ALGORITHM_IDS } from './webauthn.ts';
