// 企業向け SDK（rp-kit。plan 3-3、spec 02、ADR 0029）。企業のサーバーで動かす。
// SDK は自分ではつながない。企業は、1つの要求を送って1つの応答を返す関数（Send）だけを書いて渡す。
// 要求の組み立て、応答の検証、エラーの扱いは SDK が受け持つ。

export {
  type CompanyApiClient,
  type CompanyApiConfig,
  type CompanyApiScope,
  createCompanyApiClient,
  INITIAL_LINK_PROOF_TYP,
  type InitialLinkProofClaims,
  type VerifiedSet,
} from './company-api.ts';
export { RpKitError, type RpKitErrorCode } from './errors.ts';
export { type JtiStore, memoryJtiStore } from './jti.ts';
export {
  ACR_PASSKEY,
  createWarifuClient,
  type DeskAction,
  type DeskApproval,
  INITIAL_LINK_APPROVAL_TYP,
  type InitialLinkAction,
  type InitialLinkOutcome,
  OP_APPROVAL_TYP,
  OPERATION_APPROVAL_TYP,
  type OperationAction,
  type OperationApproval,
  type PayoutDestinationContent,
  type PendingAuthorization,
  type WarifuClient,
  type WarifuClientConfig,
  type WarifuLogin,
} from './oidc.ts';
export type { HttpRequest, HttpResponse, Send } from './transport.ts';
