// 窓口（demo-rp。spec 02 の RP-20〜RP-27、DESIGN.md 2章「demo-rp：利用者の窓口受付」「demo-rp：窓口担当者」）。
//
// - 受付番号は、企業が応対ごとに発行する参照。認証や許可の根拠にしない（RP-22）。割符には渡さない。
// - 利用者は、ログイン済みの画面で、受付番号と、対象（自分の注文1件）と操作を選び、割符の窓口の承認で、その1件の
//   状態の照会だけを許す（RP-20・RP-21）。高リスクの操作（出金先の変更など）には使えない。
// - 窓口担当者の画面には、連絡先や番号での検索も、代わりの本人確認も置かない（RP-27）。

import { newRandomId, type PendingAuthorization, RpKitError } from '@pii-token-vault/rp-kit';
import type { Ctx } from './app.ts';
import { esc, FIXED_S, postButton, STAFF_FAILED, STAFF_HIGH_RISK, WARNING_B } from './pages.ts';

/** 応対（受付番号）の有効期間。 */
const DESK_SESSION_TTL_MS = 30 * 60_000;
/** 受付番号の入力の上限（利用者ごと。値は仮置き）。 */
const DESK_ATTEMPT_LIMIT = 5;
const DESK_ATTEMPT_WINDOW_MS = 10 * 60_000;
const RECEIPT_PATTERN = /^\d{8}$/;
const OPERATION_LABEL = '注文1件の状態を窓口に伝える';

/** 受付番号（8桁の数字）。乱数の文字から数字を作る。 */
function newReceiptNo(): string {
  let digits = '';
  while (digits.length < 8) {
    for (const ch of newRandomId(16)) {
      const code = ch.charCodeAt(0);
      // 英数字と - _ の64種から、偏りなく 0〜9 を取る（60 未満だけを使う）。
      const index =
        code >= 65 && code <= 90
          ? code - 65
          : code >= 97 && code <= 122
            ? code - 71
            : code >= 48 && code <= 57
              ? code + 4
              : 62;
      if (index < 60 && digits.length < 8) digits += String(index % 10);
    }
  }
  return digits;
}

export function registerDeskRoutes(ctx: Ctx): void {
  const { app, config, store, warifu, nowMs } = ctx;
  const desk = config.desk;
  if (desk === undefined) return;
  const noticeOf = (query: unknown) => {
    const n = (query as { n?: unknown }).n;
    return typeof n === 'string' ? n : undefined;
  };

  // ---- 利用者の窓口受付 ----

  app.get('/desk', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    if (account === undefined) return ctx.go(reply, '/', 'login_required');
    const orders = await store.read((state) =>
      [...state.orders.values()].filter((order) => order.accountKey === account.key),
    );
    return ctx.html(reply, {
      title: '窓口に連絡するとき',
      notice: noticeOf(request.query),
      body: [
        `<p>公式窓口：${esc(desk.name)}。自分から公式窓口に連絡し、担当者から伝えられた受付番号を入力してください。</p>`,
        `<p class="warning" id="warning-b">${esc(WARNING_B)}</p>`,
        '<form method="post" action="/desk/confirm">',
        '<label>受付番号（8桁）<input name="receiptNo" inputmode="numeric" pattern="[0-9]{8}" required autocomplete="off"></label>',
        '<label>窓口に状態を伝える注文<select name="orderId" required>',
        ...orders.map((o) => `<option value="${esc(o.orderId)}">${esc(o.label)}</option>`),
        '</select></label>',
        '<button type="submit">内容を確かめる</button>',
        '</form>',
        '<p><a href="/">戻る</a></p>',
      ].join('\n'),
    });
  });

  /** 受付番号と対象を確かめる。受付番号の入力は、利用者ごとに回数を数える。 */
  async function checkDeskInput(accountKey: string, body: Record<string, unknown>) {
    const { receiptNo, orderId } = body;
    const now = nowMs();
    return store.transaction((state) => {
      const attempts = (state.deskAttempts.get(accountKey) ?? []).filter(
        (at) => at > now - DESK_ATTEMPT_WINDOW_MS,
      );
      if (attempts.length >= DESK_ATTEMPT_LIMIT)
        return { ok: false, notice: 'desk_limited' } as const;
      const order = typeof orderId === 'string' ? state.orders.get(orderId) : undefined;
      const found =
        typeof receiptNo === 'string' && RECEIPT_PATTERN.test(receiptNo)
          ? state.deskSessions.get(receiptNo)
          : undefined;
      // 対象は、自分の注文だけ（RP-08）。受付番号は、期限内で、まだ許可のないものだけ。
      if (
        order === undefined ||
        order.accountKey !== accountKey ||
        found === undefined ||
        found.expiresAt <= now ||
        found.grant !== null
      ) {
        state.deskAttempts.set(accountKey, [...attempts, now]);
        return { ok: false, notice: 'desk_not_found' } as const;
      }
      return { ok: true, order, desk: found } as const;
    });
  }

  app.post('/desk/confirm', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    if (account === undefined) return ctx.go(reply, '/', 'login_required');
    const checked = await checkDeskInput(account.key, ctx.bodyOf(request));
    if (!checked.ok) return ctx.go(reply, '/desk', checked.notice);
    return ctx.html(reply, {
      title: '窓口への許可の確認',
      body: [
        '<dl id="desk-confirm">',
        `<dt>入力した受付番号</dt><dd>${esc(checked.desk.receiptNo)}</dd>`,
        `<dt>窓口</dt><dd>${esc(checked.desk.desk)}</dd>`,
        `<dt>担当者</dt><dd>${esc(checked.desk.staff)}</dd>`,
        `<dt>対象</dt><dd>${esc(checked.order.label)}</dd>`,
        `<dt>操作</dt><dd>${esc(OPERATION_LABEL)}</dd>`,
        '</dl>',
        `<p class="warning" id="warning-b">${esc(WARNING_B)}</p>`,
        postButton('/desk/approve', '割符で確認して許可する', {
          receiptNo: checked.desk.receiptNo,
          orderId: checked.order.orderId,
        }),
        '<p><a href="/desk">入力し直す</a></p>',
      ].join('\n'),
    });
  });

  app.post('/desk/approve', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    if (account === undefined) return ctx.go(reply, '/', 'login_required');
    const checked = await checkDeskInput(account.key, ctx.bodyOf(request));
    if (!checked.ok) return ctx.go(reply, '/desk', checked.notice);
    // 申請ID は、この承認のための乱数。受付番号は、割符に渡さない（RP-22）。
    let started: { readonly url: string; readonly pending: PendingAuthorization };
    try {
      started = await warifu.pushDesk({
        action: 'desk.order.status.read',
        requestId: newRandomId(),
        sub: account.sub,
      });
    } catch (error) {
      if (!(error instanceof RpKitError)) throw error;
      // 割符が要求を断った、または割符につながらない（出金先の変更や引き継ぎの申請と同じ扱い）。
      return ctx.go(reply, '/desk', 'failed');
    }
    const ref = JSON.stringify({
      receiptNo: checked.desk.receiptNo,
      orderId: checked.order.orderId,
    });
    return ctx.begin(reply, session, 'desk', ref, started);
  });

  ctx.onCallback('desk', async ({ login, pending, ref, account }) => {
    const { receiptNo, orderId } = JSON.parse(ref ?? '{}') as {
      receiptNo?: string;
      orderId?: string;
    };
    // 窓口の承認（用途 desk）だけを受け取る。高リスクの操作の承認や、ログインの結果では通らない（RP-21）。
    const approval = await warifu.verifyDeskApproval(login, pending as PendingAuthorization);
    const now = nowMs();
    const granted = await store.transaction((state) => {
      const found = receiptNo === undefined ? undefined : state.deskSessions.get(receiptNo);
      const order = orderId === undefined ? undefined : state.orders.get(orderId);
      if (
        found === undefined ||
        found.grant !== null ||
        found.expiresAt <= now ||
        order === undefined ||
        order.accountKey !== account.key ||
        approval.action !== 'desk.order.status.read'
      ) {
        return false;
      }
      found.grant = {
        accountKey: account.key,
        action: approval.action,
        targetId: order.orderId,
        grantedAt: now,
        expiresAt: approval.expiresAt,
        used: false,
      };
      return true;
    });
    return granted ? '/desk?n=desk_granted' : '/desk?n=failed';
  });

  // ---- 窓口担当者の画面 ----

  app.get('/staff', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    if (!session.staff) {
      return ctx.html(reply, {
        title: '窓口担当者の画面（デモ）',
        notice: noticeOf(request.query),
        body: [
          '<p>デモ用の合言葉を入力してください（本番の企業では、従業員の認証に置き換えます）。</p>',
          '<form method="post" action="/staff/login"><label>合言葉<input name="key" type="password" required autocomplete="off"></label><button type="submit">開く</button></form>',
        ].join('\n'),
      });
    }
    const now = nowMs();
    const sessions = await store.read((state) =>
      [...state.deskSessions.values()].filter((s) => s.expiresAt > now),
    );
    return ctx.html(reply, {
      title: '窓口担当者の画面（デモ）',
      notice: noticeOf(request.query),
      body: [
        `<p class="warning" id="fixed-s">${esc(FIXED_S)}</p>`,
        `<p id="high-risk">出金先の変更などの手続き：${esc(STAFF_HIGH_RISK)}</p>`,
        postButton('/staff/sessions', '新しい応対を始める（受付番号を発行する）'),
        '<ul id="desk-sessions">',
        ...sessions.map((s) =>
          [
            `<li>受付番号 ${esc(s.receiptNo)}：`,
            s.grant === null
              ? '利用者の承認待ち'
              : s.grant.used || s.grant.expiresAt <= now
                ? '照会済み、または期限切れ'
                : `承認済み（注文1件の状態の照会だけ）${postButton('/staff/read', '注文の状態を見る', { receiptNo: s.receiptNo })}`,
            '</li>',
          ].join(''),
        ),
        '</ul>',
      ].join('\n'),
    });
  });

  app.post('/staff/login', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const key = ctx.bodyOf(request).key;
    if (config.staffKey === undefined || typeof key !== 'string' || key !== config.staffKey) {
      return ctx.go(reply, '/staff', 'failed');
    }
    // 担当者の権限を付けるときは、セッションの ID を作り直す（利用者のログインと同じ。固定されたセッションを使わせない）。
    await ctx.renewSession(reply, session, (s) => {
      s.staff = true;
    });
    return ctx.go(reply, '/staff');
  });

  app.post('/staff/sessions', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    if (!session.staff) return ctx.go(reply, '/staff', 'failed');
    const now = nowMs();
    await store.transaction((state) => {
      let receiptNo = newReceiptNo();
      while (state.deskSessions.has(receiptNo)) receiptNo = newReceiptNo();
      state.deskSessions.set(receiptNo, {
        receiptNo,
        desk: desk.name,
        staff: desk.staff,
        createdAt: now,
        expiresAt: now + DESK_SESSION_TTL_MS,
        grant: null,
      });
    });
    return ctx.go(reply, '/staff');
  });

  /** 承認済みの応対で、注文1件の状態だけを見る（1回だけ）。商品名、金額、届け先、連絡先は出さない。 */
  app.post('/staff/read', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    if (!session.staff) return ctx.go(reply, '/staff', 'failed');
    const receiptNo = ctx.bodyOf(request).receiptNo;
    const now = nowMs();
    const status = await store.transaction((state) => {
      const found = typeof receiptNo === 'string' ? state.deskSessions.get(receiptNo) : undefined;
      const grant = found?.grant;
      if (
        found === undefined ||
        grant === null ||
        grant === undefined ||
        grant.used ||
        grant.expiresAt <= now
      ) {
        return undefined;
      }
      const order = state.orders.get(grant.targetId);
      if (order === undefined || order.accountKey !== grant.accountKey) return undefined;
      grant.used = true;
      return order.status;
    });
    return ctx.html(reply, {
      title: '窓口担当者の画面（デモ）',
      body: [
        `<p class="warning" id="fixed-s">${esc(FIXED_S)}</p>`,
        status === undefined
          ? `<p id="staff-result">${esc(STAFF_FAILED)}</p>`
          : `<p id="staff-result">注文の状態：${esc(status)}</p>`,
        '<p><a href="/staff">戻る</a></p>',
      ].join('\n'),
    });
  });
}
