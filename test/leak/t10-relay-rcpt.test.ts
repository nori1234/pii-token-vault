// テスト10（SMTP の RCPT への応答。plan 11章、不変条件10、ADR 0021）。relay の SMTP の応答は、別名が生きているか、
// 廃番か、存在しないか、返信用のアドレスが生きているかで、本文・ステータス・所要時間を変えない。

import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { toBase32Lower } from '../../packages/warifu-core/src/encoding.ts';
import {
  addUser,
  companyMail,
  rotateAlias,
  SmtpSession,
  sendMail,
  signCompanyMail,
  startTestRelay,
  type TestCompany,
  type TestRelay,
} from '../setup/relay.ts';

let t: TestRelay;
let company: TestCompany;
const targets: Record<string, string> = {};

beforeAll(async () => {
  t = await startTestRelay();
  const [c] = t.companies;
  if (c === undefined) throw new Error('準備に失敗した');
  company = c;
  const live = await addUser(t.companies);
  const retiredUser = await addUser(t.companies);
  const [liveAlias] = live.aliases;
  const [retiredAlias] = retiredUser.aliases;
  if (liveAlias === undefined || retiredAlias === undefined) throw new Error('準備に失敗した');
  await rotateAlias(company, retiredUser.userId);
  // 生きている返信用のアドレスを1つ作る（企業から別名へ1通送ると、From が返信用のアドレスになる）。
  await sendMail(
    t.relay.smtpPort,
    { from: `bounce@${company.senderDomain}`, to: liveAlias },
    await signCompanyMail(company, companyMail(company, liveAlias)),
  );
  await t.relay.idle();
  const from = t.outbound
    .all()[0]
    ?.raw.toString('latin1')
    .match(/^From: .*<([^<>]+)>/m)?.[1];
  if (from === undefined) throw new Error('返信用のアドレスがない');
  targets.live = liveAlias;
  targets.retired = retiredAlias;
  targets.unknown = `${toBase32Lower(new Uint8Array(randomBytes(10)))}@${company.relayDomain}`;
  targets.malformed = `info@${company.relayDomain}`;
  targets.liveThread = from;
  targets.unknownThread = `r-${toBase32Lower(new Uint8Array(randomBytes(16)))}@${company.relayDomain}`;
});

afterAll(async () => {
  await t.stop();
});

function record(timings: Record<string, number[]>, kind: string, ms: number): void {
  const list = timings[kind] ?? [];
  list.push(ms);
  timings[kind] = list;
}

const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)] ?? 0;

describe('漏えい：SMTP の応答で別名を列挙させない（plan 11章 テスト10）', () => {
  it('RCPT、VRFY、2つ目の RCPT の応答が、宛先の状態によらず同じ', async () => {
    // 攻撃者が持っている情報：relay のドメイン（企業から届いたメールで分かる）と、推測した、または漏れた別名の一覧
    // 試す経路：SMTP で、生きている別名、廃番の別名、存在しない別名、別名の形でないもの、生きている返信用のアドレス、
    //           存在しない返信用のアドレスに、RCPT と VRFY を送る。続けて、2つ目の RCPT を送る
    // 期待する結果：RCPT はすべて 250 で同じ本文、VRFY はすべて 252 で同じ本文、2つ目の RCPT はすべて 452。
    //               RCPT の所要時間の中央値の差は小さい（50ミリ秒未満）
    // plan 11章：テスト10（SMTP の RCPT への応答も一律）
    const replies = new Map<string, Set<string>>();
    const timings: Record<string, number[]> = {};
    for (let round = 0; round < 5; round += 1) {
      for (const [kind, address] of Object.entries(targets)) {
        const session = await SmtpSession.open(t.relay.smtpPort);
        try {
          await session.command('EHLO prober.example');
          const vrfy = await session.command(`VRFY ${address}`);
          await session.command(`MAIL FROM:<x@prober.example>`);
          const rcpt = await session.command(`RCPT TO:<${address}>`);
          const second = await session.command(`RCPT TO:<${targets.unknown}>`);
          record(timings, kind, rcpt.ms);
          for (const [step, reply] of [
            ['vrfy', vrfy],
            ['rcpt', rcpt],
            ['second', second],
          ] as const) {
            const seen = replies.get(step) ?? new Set<string>();
            seen.add(reply.text);
            replies.set(step, seen);
          }
        } finally {
          session.close();
        }
      }
    }
    expect([...(replies.get('rcpt') ?? [])].map((r) => r.slice(0, 3))).toEqual(['250']);
    expect(replies.get('rcpt')?.size).toBe(1);
    expect([...(replies.get('vrfy') ?? [])].map((r) => r.slice(0, 3))).toEqual(['252']);
    expect([...(replies.get('second') ?? [])].map((r) => r.slice(0, 3))).toEqual(['452']);
    const medians = Object.values(timings).map(median);
    expect(Math.max(...medians) - Math.min(...medians)).toBeLessThan(50);
  });

  it('正しく署名したメールの DATA の応答が、別名の状態によらず同じ', async () => {
    // 攻撃者が持っている情報：企業の正規の送信の経路（企業の中の者）と、推測した、または漏れた別名の一覧
    // 試す経路：生きている別名、廃番の別名、存在しない別名、別名の形でないものへ、正しく署名したメールを送る
    // 期待する結果：DATA はすべて 250 で同じ本文。所要時間の中央値の差は小さい（100ミリ秒未満）。
    //               届くのは、生きている別名あてのものだけ
    // plan 11章：テスト10（SMTP の応答も一律）、テスト5
    const kinds = ['live', 'retired', 'unknown', 'malformed'] as const;
    const texts = new Set<string>();
    const timings: Record<string, number[]> = {};
    const before = t.outbound.all().length;
    for (let round = 0; round < 4; round += 1) {
      for (const kind of kinds) {
        const to = targets[kind] ?? '';
        const raw = await signCompanyMail(company, companyMail(company, to));
        const { rcpt, data } = await sendMail(
          t.relay.smtpPort,
          { from: `bounce@${company.senderDomain}`, to },
          raw,
        );
        expect(rcpt.code).toBe(250);
        if (data === undefined) throw new Error('DATA の応答がない');
        texts.add(data.text);
        record(timings, kind, data.ms);
      }
    }
    await t.relay.idle();
    expect([...texts].map((r) => r.slice(0, 3))).toEqual(['250']);
    expect(texts.size).toBe(1);
    const medians = Object.values(timings).map(median);
    expect(Math.max(...medians) - Math.min(...medians)).toBeLessThan(100);
    expect(t.outbound.all().slice(before)).toHaveLength(4);
  });

  it('relay のドメインでない宛先は、ローカル部によらず同じ 550 で断る', async () => {
    // 攻撃者が持っている情報：本物のアドレスの一覧（漏えいから）
    // 試す経路：relay を、本物のアドレスあての中継（オープンリレー）に使う。別名のローカル部を別のドメインに付ける
    // 期待する結果：どれも 550 で同じ本文。何も届かない
    // plan 11章：テスト10、テスト5
    const before = t.outbound.all().length;
    const texts = new Set<string>();
    for (const address of [
      `u${randomBytes(4).toString('hex')}@users.example`,
      `${(targets.live ?? '').split('@')[0]}@users.example`,
      `${(targets.live ?? '').split('@')[0]}@relay.warifu.test`,
    ]) {
      const session = await SmtpSession.open(t.relay.smtpPort);
      try {
        await session.command('EHLO prober.example');
        await session.command('MAIL FROM:<x@prober.example>');
        const rcpt = await session.command(`RCPT TO:<${address}>`);
        texts.add(rcpt.text);
      } finally {
        session.close();
      }
    }
    expect([...texts].map((r) => r.slice(0, 3))).toEqual(['550']);
    expect(texts.size).toBe(1);
    expect(t.outbound.all()).toHaveLength(before);
  });
});
