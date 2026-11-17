// テスト7（plan 11章）の補助：ワーカーの DB を pg_dump で丸ごと取り出し、ログと合わせて、平文の値を探す。
// - dumpWorkerDatabase：割符の全サービスのスキーマ（idp、relay、company_api、audit など）の行を、pg_dump のテキストで
//   返す。DB を読める攻撃者（ATK-06）を模すので、アプリの境界（RLS）を通さない。不変条件8の例外のうち
//   「pg_dump による漏えいテスト」に当たり、ブートストラップのロールで、読むだけを行う（書き込みはしない）。
// - leaksIn：値を、DB とログに現れうる形（そのまま、小文字、16進、base64、base64url、URL の符号化）にして探し、
//   見つかった値の番号と場所だけを返す（値そのものは、テストの出力に出さない）。

import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { workerDatabase } from './worker-db.ts';

const run = promisify(execFile);

/**
 * 探す形の最短の長さ。これより短い形は探さない（大きな DB の中では、6桁の数字などは、たまたま現れるため）。
 * 短い値は、その値を持つ表と列を、テストの中で個別に確かめる。
 */
export const MIN_FORM_LENGTH = 10;

/** ワーカーの DB の全スキーマの行（pg_dump のテキスト。スキーマの定義は含めない）。 */
export async function dumpWorkerDatabase(): Promise<string> {
  const db = await workerDatabase();
  const { stdout } = await run(
    join(process.env.PG_BIN ?? '/usr/lib/postgresql/16/bin', 'pg_dump'),
    ['--data-only', '--no-owner', '--no-privileges', '--dbname', String(db.database)],
    {
      env: {
        ...process.env,
        PGHOST: String(db.host),
        PGPORT: String(db.port),
        PGUSER: String(db.user),
      },
      maxBuffer: 512 * 1024 * 1024,
    },
  );
  return stdout;
}

/** 値が DB とログに現れうる形（MIN_FORM_LENGTH 未満の形は除く）。 */
export function formsOf(value: string): readonly string[] {
  const bytes = Buffer.from(value, 'utf8');
  return [
    ...new Set([
      value,
      value.toLowerCase(),
      bytes.toString('hex'),
      bytes.toString('base64'),
      bytes.toString('base64url'),
      encodeURIComponent(value),
    ]),
  ].filter((form) => form.length >= MIN_FORM_LENGTH);
}

/**
 * sources（場所の名前 → テキスト）の中に、needles のどれかの形があれば、`値の番号:場所` の一覧を返す。
 * 大文字と小文字は区別しない。値そのものは返さない（テストが落ちたときの出力に、値を出さない）。
 */
export function leaksIn(
  sources: Readonly<Record<string, string>>,
  needles: readonly string[],
): string[] {
  const texts = Object.entries(sources).map(([name, text]) => [name, text.toLowerCase()] as const);
  const found = new Set<string>();
  needles.forEach((needle, index) => {
    for (const form of formsOf(needle)) {
      const lowered = form.toLowerCase();
      for (const [name, text] of texts) {
        if (text.includes(lowered)) found.add(`${index}:${name}`);
      }
    }
  });
  return [...found];
}
