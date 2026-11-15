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
  /** relaxed は、移行中の企業が閉じたと報告していない入り口のために緩めた（不合格にしない）。 */
  readonly status: 'pass' | 'fail' | 'relaxed';
  readonly requirements: readonly string[];
}

export interface KitReport {
  readonly passed: boolean;
  readonly results: readonly CheckResult[];
}

/** 申告の印がなくても、パスの名前から怪しいルートを拾う（申告の書き漏らしに備える。拾ったら不合格にする）。 */
const SUSPICIOUS: Readonly<Record<'sub_rewrite' | 'guest_lookup', RegExp>> = Object.freeze({
  sub_rewrite:
    /(^|[/_-])(rebind|relink|re-?link|merge|reassign|change-?sub|set-?sub|subject)([/_-]|$)/i,
  guest_lookup: /(^|[/_-])(guest|lookup|by-?(email|phone|tel|name|order|reservation))([/_-]|$)/i,
});

function relaxedFor(participation: KitParticipation, entry: EntryId): boolean {
  return participation.mode === 'migrating' && !participation.reportedClosed.includes(entry);
}

function routesTagged(
  routes: readonly DeclaredRoute[],
  tag: 'sub_rewrite' | 'guest_lookup',
): boolean {
  return routes.some(
    (route) =>
      route.tags.includes(tag) ||
      (tag === 'sub_rewrite' && route.tags.includes('account_merge')) ||
      SUSPICIOUS[tag].test(route.path),
  );
}

/** 観測から合否を決める。 */
export function judge(observations: Observations, participation: KitParticipation): KitReport {
  const results: CheckResult[] = [];
  const add = (
    check: CheckId,
    failed: boolean,
    requirements: readonly string[],
    entry?: EntryId,
  ) => {
    const status: CheckResult['status'] = !failed
      ? 'pass'
      : entry !== undefined && relaxedFor(participation, entry)
        ? 'relaxed'
        : 'fail';
    results.push({ check, status, requirements });
  };
  const [alpha, beta] = observations.sameAliasAccounts;
  // 同じ別名で sub の違う2人は、移行中も緩めない（RP-05）。2人目のログインを断る（別名がすでにある、など）のも不合格。
  add('same_alias_two_subs', alpha === beta || alpha === '' || beta === '', [
    'RP-01',
    'RP-03',
    'RP-05',
  ]);
  add('legacy_login', observations.legacyLogin === 'accepted', ['RP-04', 'RP-31'], 'ENT-02');
  add('legacy_reset', observations.legacyReset === 'accepted', ['RP-30', 'RP-31'], 'ENT-01');
  add('link_attack', observations.linkAttack === 'linked', ['RP-32'], 'ENT-01');
  // sub の書き換えは、移行中も緩めない（RP-33）。
  add('sub_rewrite', routesTagged(observations.routes, 'sub_rewrite'), ['RP-33']);
  add('guest_lookup', routesTagged(observations.routes, 'guest_lookup'), ['RP-40'], 'ENT-03');
  return { passed: results.every((r) => r.status !== 'fail'), results };
}
