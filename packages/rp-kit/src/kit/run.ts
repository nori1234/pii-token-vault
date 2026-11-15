// 適合テストキットの観測を集める部分（spec 02 の 15-1、ADR 0029）。企業は、自分の RP のテスト環境で、次のフック
// （RpTestHooks）を実装して渡す。キットはフックを呼んで観測を集め、checks.ts の judge で合否を決める。
// フックは企業のテスト環境の中だけで動かし、本番の会員の値を使わない。キットは結果を外へ送らない。

import { judge, type KitParticipation, type KitReport, type Observations } from './checks.ts';
import type { MockOp, MockPersona } from './mock-op.ts';

export interface RpTestHooks {
  /**
   * 模擬 OP の固定の利用者で、RP のふだんのログインを1回通し、RP の内部のアカウントの参照（不透明な文字列）を返す。
   * RP は、SDK の authorize() で作った URL を complete に渡して、戻りの URL を受け取り、finish() から先の自分の処理を行う。
   * ログインを断ったら空文字を返す。
   */
  signIn(persona: MockPersona, complete: (authorizationUrl: string) => string): Promise<string>;
  /** 初回紐付けを済ませた会員で、旧ログイン（ENT-02）を試す。RP に旧ログインがなければ absent。 */
  legacyLogin(): Promise<'accepted' | 'refused' | 'absent'>;
  /** 同じ会員で、メールや SMS による再設定（ENT-01）を試す。 */
  legacyReset(): Promise<'accepted' | 'refused' | 'absent'>;
  /** 漏れたメールで旧アカウントを奪い、攻撃者の sub を紐付けようとする（ENT-01 の紐付けの攻撃）。 */
  linkAttack(): Promise<'linked' | 'refused'>;
  /** RP のルート（公開、管理、内部、バッチの入口）を、性質の印と一緒に申告する。 */
  routes(): Promise<Observations['routes']>;
}

export async function collect(hooks: RpTestHooks, mockOp: MockOp): Promise<Observations> {
  const signIn = async (persona: MockPersona) => {
    try {
      return await hooks.signIn(persona, (url) => mockOp.complete(url, persona));
    } catch {
      return '';
    }
  };
  const alpha = await signIn('alpha');
  const beta = await signIn('beta');
  return {
    sameAliasAccounts: [alpha, beta],
    legacyLogin: await hooks.legacyLogin(),
    legacyReset: await hooks.legacyReset(),
    linkAttack: await hooks.linkAttack(),
    routes: await hooks.routes(),
  };
}

/** 観測を集めて判定する。 */
export async function runConformanceKit(input: {
  readonly hooks: RpTestHooks;
  readonly mockOp: MockOp;
  readonly participation: KitParticipation;
}): Promise<KitReport> {
  return judge(await collect(input.hooks, input.mockOp), input.participation);
}
