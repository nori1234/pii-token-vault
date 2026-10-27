// 返信の検査の境目（ADR 0021）。SMTP を通した検査は test/leak/t05-relay-reply。

import { describe, expect, it } from 'vitest';
import { inspectReply } from '../src/inspect.ts';
import { field, parseMessage } from '../src/mime.ts';

const ADDRESS = 'u1a2b3c@users.example';

function message(contentType: string, body: string) {
  return parseMessage(Buffer.from(`Content-Type: ${contentType}\r\n\r\n${body}`, 'utf8'));
}

function nested(depth: number): string {
  let body = 'text';
  let type = 'text/plain';
  for (let i = 0; i < depth; i += 1) {
    body = `--b${i}\r\nContent-Type: ${type}\r\n\r\n${body}\r\n--b${i}--\r\n`;
    type = `multipart/mixed; boundary="b${i}"`;
  }
  return `${type}\n${body}`;
}

describe('返信の検査（ADR 0021）', () => {
  it('multipart の前置きと後置きにあるアドレスも見つける', () => {
    const body = `${ADDRESS}\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\nafter\r\n`;
    expect(inspectReply([], message('multipart/mixed; boundary="b"', body), ADDRESS)).toBe(
      'contains_address',
    );
    const epilogue = `--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n${ADDRESS.toUpperCase()}\r\n`;
    expect(inspectReply([], message('multipart/mixed; boundary="b"', epilogue), ADDRESS)).toBe(
      'contains_address',
    );
  });

  it('残すヘッダーの encoded-word を戻して見る', () => {
    const subject = field(
      'Subject',
      `=?UTF-8?B?${Buffer.from(`件名 ${ADDRESS}`).toString('base64')}?=`,
    );
    expect(inspectReply([subject], message('text/plain', 'hi'), ADDRESS)).toBe('contains_address');
  });

  it('入れ子が深すぎるものは、確かめられないとして扱う', () => {
    const [type, ...rest] = nested(6).split('\n');
    expect(inspectReply([], message(type ?? '', rest.join('\n')), ADDRESS)).toBe('clean');
    const [deepType, ...deepRest] = nested(10).split('\n');
    expect(inspectReply([], message(deepType ?? '', deepRest.join('\n')), ADDRESS)).toBe(
      'uninspectable',
    );
  });

  it('部分が多すぎるものは、確かめられないとして扱う', () => {
    const parts = Array.from(
      { length: 120 },
      () => '--b\r\nContent-Type: text/plain\r\n\r\nx',
    ).join('\r\n');
    expect(
      inspectReply([], message('multipart/mixed; boundary="b"', `${parts}\r\n--b--\r\n`), ADDRESS),
    ).toBe('uninspectable');
  });

  it('アドレスを含まない文字だけの返信は clean。HTML の「metadata:」やリンクでは止めない', () => {
    const html = '<p>R&amp;D: metadata: none <a href="https://company.example/a?b=c">x</a></p>';
    expect(inspectReply([], message('text/html; charset=utf-8', html), ADDRESS)).toBe('clean');
  });

  it('終わりの境界がない multipart は、最後の部分を含めて確かめられないとして扱う', () => {
    const hidden = Buffer.from(ADDRESS).toString('base64');
    const truncated = `--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n${hidden}\r\n`;
    expect(inspectReply([], message('multipart/mixed; boundary="b"', truncated), ADDRESS)).toBe(
      'uninspectable',
    );
    const noDelimiter = 'hi\r\n';
    expect(inspectReply([], message('multipart/mixed; boundary="b"', noDelimiter), ADDRESS)).toBe(
      'uninspectable',
    );
  });

  it('添付ファイル（attachment の指定か、ファイル名の付いた部分）は、文字の形式でも確かめられないとして扱う', () => {
    for (const headers of [
      'Content-Type: text/plain\r\nContent-Disposition: attachment',
      'Content-Type: text/plain\r\nContent-Disposition: inline; filename="memo.txt"',
      'Content-Type: text/plain; name="memo.txt"',
    ]) {
      const body = `--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\n${headers}\r\n\r\nmemo\r\n--b--\r\n`;
      expect(inspectReply([], message('multipart/mixed; boundary="b"', body), ADDRESS)).toBe(
        'uninspectable',
      );
    }
  });
});
