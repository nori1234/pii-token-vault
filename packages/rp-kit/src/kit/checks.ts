// 適合テストキットの判定（spec 02 の 15-1、plan 3-3、ADR 0010、ADR 0028 の O-104）。
// 観測（Observations）から合否を決める純粋な関数。観測を集める部分（run.ts）と分けて、作り物の観測を与えて
// 不合格になることを示せるようにする（悪い振る舞いをする RP は作らない。ADR 0010）。
// キットの結果は企業の報告の一部で、割符が確かめたことにはならない（spec 02 の14章）。

/** 入り口の一覧（spec 02 の14章）。 */
export type EntryId = 'ENT-01' | 'ENT-02' | 'ENT-03';
export const ENTRY_IDS: readonly EntryId[] = Object.freeze(['ENT-01', 'ENT-02', 'ENT-03']);

/** キットを動かす企業が与える、参加の状態の設定。 */
export type KitParticipation =
  | { readonly mode: 'full' }
  | {
      readonly mode: 'migrating';
      /** 企業が閉じたと報告した入り口。ここにない入り口に対応する検査だけを緩める。 */
      readonly reportedClosed: readonly EntryId[];
    };

export type LegacyOutcome = 'accepted' | 'refused' | 'absent';

/** 企業が申告するルートの性質（申告の印）。 */
export type RouteTag = 'sub_rewrite' | 'account_merge' | 'guest_lookup' | 'other';

export interface DeclaredRoute {
  readonly method: string;
  readonly path: string;
  readonly tags: readonly RouteTag[];
}

export interface Observations {
  /** 模擬 OP の alpha と beta（同じ別名、違う sub）でログインしたときの、RP の内部のアカウントの参照。ログインを断ったら空文字。 */
  readonly sameAliasAccounts: readonly [string, string];
  /** 紐付けの後の旧ログイン（ENT-02）と、メールや SMS による再設定（ENT-01）。 */
  readonly legacyLogin: LegacyOutcome;
  readonly legacyReset: LegacyOutcome;
  /** 漏れたメールで旧アカウントを奪い、攻撃者の sub を紐付けようとした結果。 */
  readonly linkAttack: 'linked' | 'refused';
  /** 企業が申告したルート（公開・管理・内部）。 */
  readonly routes: readonly DeclaredRoute[];
}

export type CheckId =
  | 'same_alias_two_subs'
  | 'legacy_login'
  | 'legacy_reset'
  | 'link_attack'
  | 'sub_rewrite'
  | 'guest_lookup';

export interface CheckResult {
  readonly check: CheckId;
  /**
   * - pass：観測が要件どおり。
   * - fail：要件に反する観測、または禁止した機能があるとの申告。
   * - relaxed：移行中の企業が閉じたと報告していない入り口のために緩めた（不合格にしない）。
   * - review：要確認。申告の印はないが、ルートの名前が禁止した機能に似ている。名前だけでは違反と断定しない。
   * - unverified：検査できなかった（フックが未実装、例外、想定外の値を返した）。合格にしない。
   */
  readonly status: 'pass' | 'fail' | 'relaxed' | 'review' | 'unverified';
  readonly requirements: readonly string[];
}

export interface KitReport {
  /**
   * fail（不合格がある）、incomplete（不合格はないが、検査できなかった項目がある）、review（要確認の項目だけがある）、
   * pass の順に決める。
   */
  readonly outcome: 'fail' | 'incomplete' | 'review' | 'pass';
  /** 不合格も、検査できなかった項目もない（要確認の項目は、企業が確かめる）。 */
  readonly passed: boolean;
  readonly results: readonly CheckResult[];
}

/** 申告の印がないときに、パスの名前から「要確認」として拾う（申告の書き漏らしに備える。不合格にはしない）。 */
const SUSPICIOUS: Readonly<Record<'sub_rewrite' | 'guest_lookup', RegExp>> = Object.freeze({
  sub_rewrite:
    /(^|[/_-])(rebind|relink|re-?link|merge|reassign|change-?sub|set-?sub|subject)([/_-]|$)/i,
  guest_lookup: /(^|[/_-])(guest|lookup|by-?(email|phone|tel|name|order|reservation))([/_-]|$)/i,
});

const LEGACY_OUTCOMES: ReadonlySet<unknown> = new Set(['accepted', 'refused', 'absent']);
const LINK_OUTCOMES: ReadonlySet<unknown> = new Set(['linked', 'refused']);
const ROUTE_TAGS: ReadonlySet<unknown> = new Set([
  'sub_rewrite',
  'account_merge',
  'guest_lookup',
  'other',
]);

/** 1つの検査の観測の読み方。invalid は、検査できなかった（フックの応答が想定外）。 */
type Verdict = 'ok' | 'bad' | 'suspect' | 'invalid';

function relaxedFor(participation: KitParticipation, entry: EntryId): boolean {
  return participation.mode === 'migrating' && !participation.reportedClosed.includes(entry);
}

function isAccountRef(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 256;
}

/** 申告されたルートが、決めた形か（実行時にも確かめる。型だけに頼らない）。 */
function validRoutes(value: unknown): value is readonly DeclaredRoute[] {
  return (
    Array.isArray(value) &&
    value.every(
      (route) =>
        typeof route === 'object' &&
        route !== null &&
        typeof route.method === 'string' &&
        typeof route.path === 'string' &&
        route.path.startsWith('/') &&
        Array.isArray(route.tags) &&
        route.tags.length > 0 &&
        route.tags.every((tag: unknown) => ROUTE_TAGS.has(tag)),
    )
  );
}

function routeVerdict(routes: unknown, tag: 'sub_rewrite' | 'guest_lookup'): Verdict {
  if (!validRoutes(routes)) return 'invalid';
  const declared = routes.some(
    (route) =>
      route.tags.includes(tag) || (tag === 'sub_rewrite' && route.tags.includes('account_merge')),
  );
  if (declared) return 'bad';
  return routes.some((route) => SUSPICIOUS[tag].test(route.path)) ? 'suspect' : 'ok';
}

function outcomeVerdict(value: unknown, allowed: ReadonlySet<unknown>, bad: string): Verdict {
  if (!allowed.has(value)) return 'invalid';
  return value === bad ? 'bad' : 'ok';
}

/** 観測から合否を決める。観測の値は、フックから来たものとして、実行時にも形を確かめる。 */
export function judge(observations: Observations, participation: KitParticipation): KitReport {
  const results: CheckResult[] = [];
  const add = (
    check: CheckId,
    verdict: Verdict,
    requirements: readonly string[],
    entry?: EntryId,
  ) => {
    const relaxed = entry !== undefined && relaxedFor(participation, entry);
    const status: CheckResult['status'] =
      verdict === 'ok'
        ? 'pass'
        : verdict === 'invalid'
          ? 'unverified'
          : relaxed
            ? 'relaxed'
            : verdict === 'suspect'
              ? 'review'
              : 'fail';
    results.push({ check, status, requirements });
  };
  const accounts = (observations as { sameAliasAccounts?: unknown }).sameAliasAccounts;
  const [alpha, beta] = Array.isArray(accounts) ? accounts : [];
  // 同じ別名で sub の違う2人は、移行中も緩めない（RP-05）。2人目のログインを断る（別名がすでにある、など）のも不合格。
  add(
    'same_alias_two_subs',
    !Array.isArray(accounts) || accounts.length !== 2 || !isAccountRef(alpha) || !isAccountRef(beta)
      ? 'invalid'
      : alpha === beta || alpha === '' || beta === ''
        ? 'bad'
        : 'ok',
    ['RP-01', 'RP-03', 'RP-05'],
  );
  add(
    'legacy_login',
    outcomeVerdict(observations.legacyLogin, LEGACY_OUTCOMES, 'accepted'),
    ['RP-04', 'RP-31'],
    'ENT-02',
  );
  add(
    'legacy_reset',
    outcomeVerdict(observations.legacyReset, LEGACY_OUTCOMES, 'accepted'),
    ['RP-30', 'RP-31'],
    'ENT-01',
  );
  add(
    'link_attack',
    outcomeVerdict(observations.linkAttack, LINK_OUTCOMES, 'linked'),
    ['RP-32'],
    'ENT-01',
  );
  // sub の書き換えは、移行中も緩めない（RP-33）。
  add('sub_rewrite', routeVerdict(observations.routes, 'sub_rewrite'), ['RP-33']);
  add('guest_lookup', routeVerdict(observations.routes, 'guest_lookup'), ['RP-40'], 'ENT-03');
  const has = (status: CheckResult['status']) => results.some((r) => r.status === status);
  const outcome: KitReport['outcome'] = has('fail')
    ? 'fail'
    : has('unverified')
      ? 'incomplete'
      : has('review')
        ? 'review'
        : 'pass';
  return { outcome, passed: outcome === 'pass' || outcome === 'review', results };
}
