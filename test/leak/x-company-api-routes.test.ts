// 企業向け API のルート一覧の固定（不変条件2、CAP-30〜32、ADR 0010、ADR 0022）。plan 11章 テスト6。
// 逆引き（sub・別名から本物の連絡先や属性を返す）ルート、参加の状態や連絡先を書き換えるルート、管理用のルートがない。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startTestCompanyApi, type TestCompanyApi } from '../setup/company-api.ts';

let api: TestCompanyApi;

beforeAll(async () => {
  api = await startTestCompanyApi({ tenants: [{}] });
});

afterAll(async () => {
  await api.stop();
});

describe('漏えい：企業向け API のルート一覧（plan 11章 テスト6）', () => {
  it('ルートは4つだけ。逆引き、連絡先・参加の状態の変更、管理用のルートはない', () => {
    // 攻撃者が持っている情報：企業向け API の正規の資格情報（侵害されたテナント ATK-03）
    // 試す経路：company-api に登録されたルートの一覧を、期待の一覧と比べる
    // 期待する結果：トークン、別名の入れ替え、検証の SET の依頼、SET の検証の鍵だけ。sub・別名から本物の連絡先や
    //               属性を返すもの、参加の状態・連絡先・認証器・協力者・回復の設定を変えるもの、管理用のものはない
    // plan 11章：テスト6
    expect(api.api.routes()).toEqual([
      'GET /jwks',
      'HEAD /jwks',
      'POST /token',
      'POST /v1/aliases/rotate',
      'POST /v1/events/verification',
    ]);
  });

  it('知らないパス、違う Host は、受け取った値を返さない固定の本文で断る', async () => {
    // 攻撃者が持っている情報：なし（公開の入口を探る）
    // 試す経路：sub や別名を載せたパス、管理用らしいパス、違う Host（DNS リバインディング）
    // 期待する結果：404 と 421 で、本文に受け取ったパスや値が入らない
    // plan 11章：テスト6
    const probe = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    for (const path of [
      `/v1/users/${probe}`,
      `/v1/aliases/${probe}`,
      '/v1/admin/tenants',
      '/v1/tenants/participation',
      '/.well-known/openid-configuration',
    ]) {
      const res = await api.request({ method: 'GET', path });
      expect([path, res.status, res.text]).toEqual([path, 404, '{"error":"not_found"}']);
    }
    const misdirected = await api.request({
      method: 'GET',
      path: '/jwks',
      headers: { host: 'evil.example' },
    });
    expect([misdirected.status, misdirected.text]).toEqual([421, '{"error":"misdirected"}']);
  });
});
