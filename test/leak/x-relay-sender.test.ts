// relay から送信サービスへの配送と名前解決（不変条件7、CAP-24・26、ADR 0021、ADR 0022）。
// relay は外へつながず、署名と封印を付けたメッセージを sender の内部 API に渡す。sender が MX を引き、内部の IP を
// 指す宛先を拒否して送る。返信の DMARC の判定の名前解決も、sender の内部 API を通す。

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SenderOutbound, senderResolver } from '../../packages/relay/src/sender-outbound.ts';
import { createSenderMailClient } from '../../packages/warifu-core/src/sender/client.ts';
import {
  addUser,
  companyMail,
  sendMail,
  signCompanyMail,
  startTestRelay,
  type TestRelay,
} from '../setup/relay.ts';
import { makeTlsFixture, PUBLIC_V4, startTestSender, type TestSender } from '../setup/sender.ts';

let sender: TestSender;
let relay: TestRelay;

beforeAll(async () => {
  sender = await startTestSender(
    {
      MX: {
        'users.example': [{ exchange: 'mx.users.example', priority: 10 }],
        'inside.example': [{ exchange: 'mx.inside.example', priority: 10 }],
      },
      A: { 'mx.users.example': [PUBLIC_V4], 'mx.inside.example': ['10.20.30.40'] },
      TXT: { '_dmarc.users.example': [['v=DMARC1; p=reject']] },
    },
    await makeTlsFixture(),
  );
  const client = createSenderMailClient({
    socketPath: sender.sender.socketPath,
    credential: sender.credentials.relay,
  });
  relay = await startTestRelay({ companies: 1, outbound: new SenderOutbound(client) });
});

afterAll(async () => {
  await relay.stop();
  await sender.stop();
});

async function companySends(to: string) {
  const [company] = relay.companies;
  if (company === undefined) throw new Error('準備に失敗した');
  const raw = await signCompanyMail(company, companyMail(company, to));
  const { data } = await sendMail(
    relay.relay.smtpPort,
    { from: `bounce@${company.senderDomain}`, to },
    raw,
  );
  expect(data?.code).toBe(250);
  await relay.relay.idle();
}

describe('漏えい：relay から送信サービスへ（plan 11章 テスト11）', () => {
  it('別名あてのメールは、sender が MX を引いて、本物のアドレスへ送る（relay は外へつながない）', async () => {
    // 攻撃者が持っている情報：なし（正規の経路の確認）
    // 試す経路：企業の正規の署名で別名あてに送る
    // 期待する結果：sender が MX のホストの公開のアドレスにつなぎ、本物のアドレスあてに、relay の DKIM の署名が
    //               付いたメッセージを送る
    // plan 11章：テスト11（配送の経路）
    const user = await addUser(relay.companies);
    const [alias] = user.aliases;
    if (alias === undefined) throw new Error('準備に失敗した');
    const before = sender.mails.length;
    await companySends(alias);
    const delivered = sender.mails.slice(before);
    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.to).toEqual([user.email]);
    expect(delivered[0]?.raw.toString('latin1')).toMatch(/^DKIM-Signature: /im);
    expect(sender.connections.at(-1)).toEqual({ kind: 'tcp', address: PUBLIC_V4 });
  });

  it('本物のアドレスのドメインの MX が内部の IP を指すなら、送らない', async () => {
    // 攻撃者が持っている情報：自分のメールのドメインの DNS を操れる利用者（MX を内部の IP に向ける）
    // 試す経路：MX が 10.20.30.40 を指すドメインのアドレスを本物のアドレスにして、別名あてに送らせる
    // 期待する結果：sender は接続しない。relay のログには理由の種類（blocked_address）だけが残り、宛先は残らない
    // plan 11章：テスト11
    const user = await addUser(relay.companies, `u${Date.now()}@inside.example`);
    const [alias] = user.aliases;
    if (alias === undefined) throw new Error('準備に失敗した');
    const connections = sender.connections.length;
    const mails = sender.mails.length;
    await companySends(alias);
    expect(sender.connections.length).toBe(connections);
    expect(sender.mails.length).toBe(mails);
    const logs = relay.logs.join('\n');
    expect(logs).toContain('blocked_address');
    expect(logs).not.toContain(user.email);
    expect(logs).not.toContain('10.20.30.40');
  });

  it('返信の DMARC の判定の名前解決は、sender の口を通り、TXT・MX・A・AAAA のほかは引かない', async () => {
    // 攻撃者が持っている情報：返信を送れる利用者（DMARC の判定で、relay に名前を引かせる）
    // 試す経路：mailauth に渡すリゾルバで、_dmarc の TXT、知らない名前、PTR、localhost を引く
    // 期待する結果：TXT は答えが返る。知らない名前は ENOTFOUND。PTR と localhost は、sender に問い合わせずに ENOTFOUND
    // plan 11章：テスト11
    const resolve = senderResolver(
      createSenderMailClient({
        socketPath: sender.sender.socketPath,
        credential: sender.credentials.relay,
      }),
    );
    expect(await resolve('_dmarc.users.example', 'TXT')).toEqual([['v=DMARC1; p=reject']]);
    const before = sender.resolver.queries.length;
    for (const [name, type] of [
      ['nothing.users.example', 'TXT'],
      ['34.216.184.93.in-addr.arpa', 'PTR'],
      ['localhost', 'A'],
    ] as const) {
      await expect(resolve(name, type)).rejects.toMatchObject({ code: 'ENOTFOUND' });
    }
    expect(sender.resolver.queries.slice(before)).toEqual(['TXT:nothing.users.example']);
  });
});
