// 適合テストキット（plan 3-3、spec 02 の 15-1、ADR 0029）。企業が自分の手元で動かす。
export {
  type CheckId,
  type CheckResult,
  type DeclaredRoute,
  ENTRY_IDS,
  type EntryId,
  judge,
  type KitParticipation,
  type KitReport,
  type Observations,
  type RouteTag,
} from './checks.ts';
export {
  createMockOp,
  MOCK_OP_ORIGIN,
  MOCK_PERSONAS,
  type MockOp,
  type MockPersona,
} from './mock-op.ts';
export { collect, type RpTestHooks, runConformanceKit } from './run.ts';
