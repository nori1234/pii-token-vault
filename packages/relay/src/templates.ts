// 割符から利用者の本物のアドレスへ送る知らせの、固定の文面（plan 4章、ADR 0021）。
// 旧アドレスへの知らせと、差し戻しの知らせには、操作のリンクもコードも入れない。
// 確認コードは、宛先確認のときだけ入れる。文面に、ほかの値（企業名、アドレス、利用者の情報）を差し込まない。

export type NoticeKind = 'email_verification' | 'email_changed_notice' | 'reply_returned';

const SUBJECTS: Readonly<Record<NoticeKind, string>> = Object.freeze({
  email_verification: '割符：メールアドレスの確認コード',
  email_changed_notice: '割符：メールアドレスが変更されました',
  reply_returned: '割符：返信を中継しませんでした',
});

export function subjectOf(kind: NoticeKind): string {
  return SUBJECTS[kind];
}

export function bodyOf(kind: NoticeKind, code?: string): string {
  switch (kind) {
    case 'email_verification':
      if (code === undefined || !/^[0-9]{8}$/.test(code)) throw new RangeError('コードの形が違う');
      return [
        '割符のアプリで、次の確認コードを入力してください。',
        '',
        `確認コード：${code.slice(0, 4)} ${code.slice(4)}`,
        '',
        'このコードを、電話やメッセージで人に伝えないでください。',
        '心当たりがない場合は、このメールを無視してください。',
        '',
      ].join('\r\n');
    case 'email_changed_notice':
      return [
        '割符に登録したメールアドレスが、別のアドレスに変更されました。',
        '',
        '心当たりがない場合は、割符のアプリを開いて、登録している端末とパスキーを確かめてください。',
        'このメールにはリンクがありません。リンクの入った同じ件名のメールは、割符からのものではありません。',
        '',
      ].join('\r\n');
    case 'reply_returned':
      return [
        'あなたの返信に、あなたのメールアドレスが含まれていたため、企業へ中継しませんでした。',
        '',
        '署名や引用の中のアドレスを消してから、もう一度返信してください。',
        '',
      ].join('\r\n');
  }
}
