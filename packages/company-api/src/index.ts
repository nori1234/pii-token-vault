// 企業向け API（plan 3-1・3-2、RP-73、ADR 0022）。
export { type CompanyApi, type CompanyApiOptions, createCompanyApi } from './app.ts';
export {
  type CompanyApiConfig,
  CompanyApiConfigError,
  type CompanyTenant,
  parseCompanyApiConfig,
} from './config.ts';
export { VERIFICATION_EVENT_URI } from './set.ts';
