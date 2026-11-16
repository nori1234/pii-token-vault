// 旧会員の引き継ぎ（A社。既存会員の初回紐付けの、企業の側の参照実装。ADR 0020、ADR 0028 の O-86〜O-91・O-103・O-104）。
//
// 1. 利用者は、割符でログインしたうえで、旧パスキーで旧会員であることを確かめる（legacy.ts。5分だけ有効）。
// 2. 企業は、申請ID と会員参照（どちらも申請ごとの乱数）を作り、割符に仮申請と証跡を出して、PAR で本人の承認を求める。
// 3. 割符から待機の知らせ（SET）が届いたら、旧会員の側に知らせを出す。知らせは、旧パスキーで確かめた人にだけ見せ、
//    その人は申請を取り消せる（盗まれた旧パスキーで、他人の割符のアカウントに結び付けられるのを、持ち主が止められる）。
// 4. 待機の後、旧パスキーをもう一度確かめて2つ目の証跡を出し、割符の最終の承認（紐付けの承認の JWT）を受ける。
// 5. 紐付けと、旧パスキーの確かめを閉じること（RP-31）と、認証世代の更新を、1つのトランザクションで確定させる。
// 6. 結果（linked、not_linked、cancelled）の報告は、確定と同じトランザクションで送信待ちに残し、割符が 204 を
//    返すまで送り直す（O-91。割符の正本は、最終の承認の後と取消の受理の後は、期限では終わらず、報告で終わる）。
//
// 申請ID、会員参照、移行専用ID は、サーバーのメモリにだけ置き、ログ、URL、画面に出さない（O-87）。
// メールや SMS のリンクやコードでは、承認も取消もさせない。

import {
  type CompanyApiClient,
  newRandomId,
  type PendingAuthorization,
  RpKitError,
} from '@pii-token-vault/rp-kit';
import type { Ctx } from './app.ts';
import {
  LEGACY_VERIFICATION_TTL_MS,
  type LegacyRp,
  legacyAuthenticationOptions,
  legacyRegistrationOptions,
  verifyLegacyAssertion,
  verifyLegacyRegistration,
} from './legacy.ts';
import { esc, postButton } from './pages.ts';
import type { DemoState, LinkAttempt, PendingReport, Session } from './state.ts';

const WAITING_EVENT = 'urn:warifu:secevent:initial-link-waiting';
const CANCELLATION_EVENT = 'urn:warifu:secevent:initial-link-cancellation';
const OPEN_STATES: ReadonlySet<string> = new Set([
  'proof_submitted',
  'pending_notice',
  'waiting',
  'final_proof_submitted',
]);

/** 結果の報告を送り直す間隔（届かなかった回数ごとに倍にし、1時間で止める）。 */
const REPORT_RETRY = Object.freeze({ firstMs: 30_000, maxMs: 3600_000 });
/**
 * 送り直せば届きうる失敗か（割符に届かない、5xx、応答の喪失、応答の形の違い、レート制限の 429）。ほかの 4xx は、
 * 送り直しても答えが変わらない。429 を送り直すのは、割符の SET の送信待ちと同じ扱い（spec 02 の SET の受け口）。
 */
function retryable(error: RpKitError): boolean {
  return (
    error.code === 'unavailable' ||
    error.code === 'invalid_response' ||
    (error.code === 'rejected' && error.reason === 'rate_limited')
  );
}

/** 結果の報告の送信待ちを1回送った結果（件数）。 */
export interface ReportFlush {
  readonly sent: number;
  readonly retry: number;
  readonly held: number;
}

function openAttemptOf(state: DemoState, memberId: string): LinkAttempt | undefined {
  return [...state.linkAttempts.values()].find(
    (attempt) => attempt.memberId === memberId && OPEN_STATES.has(attempt.state),
  );
}

export function registerLegacyRoutes(
  ctx: Ctx,
  company: CompanyApiClient,
  initialLink: { readonly profileVersion: number },
): { readonly flushReports: () => Promise<ReportFlush> } {
  const { app, config, store, warifu, nowMs } = ctx;
  const rp: LegacyRp = {
    rpId: new URL(config.origin).hostname,
    rpName: config.displayName,
    origin: config.origin,
  };

  /** 旧パスキーで確かめた旧会員（5分以内）。なければ undefined。 */
  function verifiedMemberId(session: Session): string | undefined {
    const legacy = session.legacy;
    return legacy !== null && legacy.verifiedAt > nowMs() - LEGACY_VERIFICATION_TTL_MS
      ? legacy.memberId
      : undefined;
  }

  const proofOf = (attempt: LinkAttempt) => ({
    initialLinkId: attempt.initialLinkId,
    memberRef: attempt.memberRef,
    credentialKind: 'passkey' as const,
    profileVersion: initialLink.profileVersion,
    authEpoch: attempt.authEpoch,
  });

  /**
   * 結果の報告を、送信待ちに残す（確定や取消の適用と同じ transaction の中で呼ぶ。ADR 0028 の O-91）。
   * 割符の正本は、approved と cancel_requested では期限で終わらないので、報告が届かないと、正本が開いたまま残り、
   * その利用者の次の申請が断られ続ける。送信待ちは、割符が 204 を返すまで消さない。
   */
  function enqueueReport(
    state: DemoState,
    initialLinkId: string,
    result: PendingReport['result'],
  ): void {
    if (state.pendingReports.has(initialLinkId)) return;
    const now = nowMs();
    state.pendingReports.set(initialLinkId, {
      initialLinkId,
      result,
      createdAt: now,
      failures: 0,
      nextAt: now,
      held: false,
    });
  }

  /**
   * 送ってよい時刻になった報告を、1件ずつ送る。204 なら消す（同じ報告の再送も 204）。届かなければ、間隔をあけて
   * 送り直す（レート制限の 429 も）。ほかの 4xx で断られたら、送り直しても答えが変わらないので、保留にして企業が
   * 調べる。
   */
  async function flushOnce(): Promise<ReportFlush> {
    const now = nowMs();
    const due = await store.read((state) =>
      [...state.pendingReports.values()].filter((r) => !r.held && r.nextAt <= now),
    );
    const counts = { sent: 0, retry: 0, held: 0 };
    for (const report of due) {
      let outcome: keyof typeof counts;
      try {
        await company.initialLink.report({
          initialLinkId: report.initialLinkId,
          result: report.result,
        });
        outcome = 'sent';
      } catch (error) {
        if (!(error instanceof RpKitError)) throw error;
        outcome = retryable(error) ? 'retry' : 'held';
      }
      counts[outcome] += 1;
      await store.transaction((state) => {
        const stored = state.pendingReports.get(report.initialLinkId);
        if (stored === undefined) return;
        if (outcome === 'sent') {
          state.pendingReports.delete(report.initialLinkId);
        } else if (outcome === 'held') {
          stored.held = true;
        } else {
          stored.failures += 1;
          stored.nextAt =
            nowMs() +
            Math.min(REPORT_RETRY.firstMs * 2 ** (stored.failures - 1), REPORT_RETRY.maxMs);
        }
      });
    }
    return counts;
  }

  /** 送信待ちを送る。同時に呼ばれても、1回ずつ順に動かす（同じ報告を、並べて送らない）。 */
  let flushing: Promise<unknown> = Promise.resolve();
  function flushReports(): Promise<ReportFlush> {
    const next = flushing.then(flushOnce, flushOnce);
    flushing = next.catch(() => undefined);
    return next;
  }

  /** 割符の正本で終わっている状態（企業の側の申請も閉じる）。 */
  const ENDED: ReadonlySet<string> = new Set(['expired', 'cancelled', 'not_linked']);

  /**
   * 企業の側で開いたままの申請を、割符の正本の状態と照らして閉じる（ADR 0028 の O-90）。
   * - 正本が expired・cancelled・not_linked なら、企業の側も閉じる。正本の行が保存期間を過ぎて消えていたとき
   *   （別の移行専用ID が返る）も、閉じる。閉じた後は、同じ旧会員と割符のアカウントで、新しい申請ができる。
   * - 閉じるかどうかは、正本の状態だけで決める。企業の側の時計だけでは閉じない（承認済みや紐付け済みの申請を、
   *   時刻だけで取り消さない）。割符に確かめられないときは、開いたままにする。
   */
  async function reconcile(match: (attempt: LinkAttempt) => boolean): Promise<void> {
    const open = await store.read((state) =>
      [...state.linkAttempts.values()].filter((a) => OPEN_STATES.has(a.state) && match(a)),
    );
    for (const attempt of open) {
      let current: { initialLinkId: string; state: string };
      try {
        current = await company.initialLink.status({
          requestId: attempt.requestId,
          memberRef: attempt.memberRef,
        });
      } catch (error) {
        if (!(error instanceof RpKitError)) throw error;
        continue;
      }
      const gone = current.initialLinkId !== attempt.initialLinkId;
      if (!gone && !ENDED.has(current.state)) continue;
      await store.transaction((state) => {
        const stored = state.linkAttempts.get(attempt.requestId);
        if (stored !== undefined && OPEN_STATES.has(stored.state)) {
          stored.state = !gone && current.state === 'cancelled' ? 'cancelled' : 'expired';
        }
      });
    }
  }

  /** この画面の人（旧パスキーで確かめた旧会員と、ログイン中のアカウント）に関わる申請を、正本と照らす。 */
  const reconcileFor = (memberId: string | undefined, accountKey: string | undefined) =>
    reconcile((a) => a.memberId === memberId || a.accountKey === accountKey);

  app.get('/legacy', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    const memberId = verifiedMemberId(session);
    await reconcileFor(memberId, account?.key);
    const n = (request.query as { n?: unknown }).n;
    const view = await store.read((state) => {
      const member = memberId === undefined ? undefined : state.legacyMembers.get(memberId);
      return {
        member,
        attempt: member === undefined ? undefined : openAttemptOf(state, member.memberId),
      };
    });
    const body: string[] = [
      '<p>以前からの会員（旧会員）を、割符のアカウントに引き継ぎます。引き継ぎは1回だけで、後から付け替えることはできません。</p>',
    ];
    if (view.member === undefined) {
      body.push(
        '<p>はじめに、旧会員のパスキーで確かめます。</p>',
        '<button type="button" id="legacy-verify">旧パスキーで確かめる</button>',
        config.demoSeed === true
          ? '<p>デモ用：<button type="button" id="legacy-seed">旧会員と旧パスキーを用意する</button></p>'
          : '',
        '<p id="legacy-status" role="status"></p>',
      );
    } else {
      body.push('<p id="legacy-verified">旧パスキーで確かめました（5分の間だけ有効です）。</p>');
      const attempt = view.attempt;
      if (attempt !== undefined) {
        // 旧会員の側の知らせ（O-103）。旧パスキーで確かめた人にだけ見せる。
        body.push(
          `<p class="warning" id="legacy-notice">この旧会員を、割符のアカウントに引き継ぐ申請が出ています（申請の日時：${esc(new Date(attempt.createdAt).toISOString())}）。心当たりがなければ、取り消してください。</p>`,
          postButton('/legacy/cancel', '申請を取り消す'),
        );
        const mine = account !== undefined && attempt.accountKey === account.key;
        if (mine && (attempt.state === 'waiting' || attempt.state === 'final_proof_submitted')) {
          body.push(
            '<p>待機の時間が終わっていれば、引き継ぎを確定できます。</p>',
            postButton('/legacy/link/finalize', '割符で確認して、引き継ぎを確定する'),
          );
        }
      } else if (account === undefined) {
        body.push(
          '<p>引き継ぎを始めるには、先に割符でログインしてください。</p>',
          postButton('/login', '割符でログイン'),
        );
      } else if (account.legacyMemberId === null) {
        body.push(postButton('/legacy/link/start', '割符で確認して、引き継ぎを申請する'));
      }
    }
    body.push('<p><a href="/">戻る</a></p>');
    return ctx.html(reply, {
      title: '旧会員の引き継ぎ',
      notice: typeof n === 'string' ? n : undefined,
      body: body.join('\n'),
      script: true,
    });
  });

  // ---- 旧パスキーの確かめ（毎回、新しいチャレンジ） ----

  app.post('/legacy/options', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const options = await legacyAuthenticationOptions(rp);
    await ctx.updateSession(session.sessionId, (s) => {
      s.challenge = options.challenge;
    });
    return options;
  });

  app.post('/legacy/verify', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const challenge = session.challenge;
    await ctx.updateSession(session.sessionId, (s) => {
      s.challenge = null;
    });
    const response = ctx.bodyOf(request).response as { id?: unknown } | undefined;
    const member =
      typeof response?.id === 'string'
        ? await store.read((state) =>
            [...state.legacyMembers.values()].find((m) => m.credentialId === response.id),
          )
        : undefined;
    // 知らない資格情報、引き継ぎ済みの旧会員、検証の失敗は、同じ応答にする。
    const verified =
      challenge === null || member === undefined
        ? { ok: false as const }
        : await verifyLegacyAssertion(rp, member, challenge, response);
    if (!verified.ok || member === undefined) return reply.code(401).send({ error: 'failed' });
    const now = nowMs();
    await store.transaction((state) => {
      const stored = state.legacyMembers.get(member.memberId);
      const s = state.sessions.get(session.sessionId);
      if (stored === undefined || stored.closed || s === undefined) return;
      stored.counter = verified.counter;
      s.legacy = { memberId: member.memberId, verifiedAt: now };
    });
    return { ok: true };
  });

  if (config.demoSeed === true) {
    app.post('/legacy/demo/options', async (request, reply) => {
      const session = await ctx.sessionOf(request, reply);
      const options = await legacyRegistrationOptions(rp);
      await ctx.updateSession(session.sessionId, (s) => {
        s.challenge = options.challenge;
      });
      return options;
    });

    app.post('/legacy/demo/verify', async (request, reply) => {
      const session = await ctx.sessionOf(request, reply);
      const challenge = session.challenge;
      await ctx.updateSession(session.sessionId, (s) => {
        s.challenge = null;
      });
      const member =
        challenge === null
          ? undefined
          : await verifyLegacyRegistration(rp, challenge, ctx.bodyOf(request).response);
      if (member === undefined) return reply.code(400).send({ error: 'failed' });
      await store.transaction((state) => {
        state.legacyMembers.set(member.memberId, member);
      });
      return { ok: true };
    });
  }

  // ---- 引き継ぎの申請（仮申請、初回の証跡、本人の承認） ----

  app.post('/legacy/link/start', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    const memberId = verifiedMemberId(session);
    if (account === undefined) return ctx.go(reply, '/legacy', 'login_required');
    if (memberId === undefined) return ctx.go(reply, '/legacy', 'legacy_required');
    // 期限切れなどで終わった前の申請が、新しい申請を塞がないようにする。
    await reconcileFor(memberId, account.key);
    const member = await store.read((state) => {
      const found = state.legacyMembers.get(memberId);
      const busy =
        found === undefined ||
        found.closed ||
        found.linkBlocked ||
        found.linkedAccountKey !== null ||
        state.accounts.get(account.key)?.legacyMemberId !== null ||
        openAttemptOf(state, memberId) !== undefined ||
        [...state.linkAttempts.values()].some(
          (a) => a.accountKey === account.key && OPEN_STATES.has(a.state),
        );
      return busy ? undefined : found;
    });
    if (member === undefined) return ctx.go(reply, '/legacy', 'link_refused');
    try {
      // 申請ID と会員参照は、申請ごとの乱数。恒久の会員番号や、連絡先から作った値にしない（O-88）。
      const requestId = newRandomId();
      const memberRef = newRandomId();
      const initialLinkId = await company.initialLink.prepare({ requestId, memberRef });
      const attempt: LinkAttempt = {
        requestId,
        memberRef,
        initialLinkId,
        memberId: member.memberId,
        accountKey: account.key,
        authEpoch: member.authEpoch,
        createdAt: nowMs(),
        state: 'proof_submitted',
        noticeAt: null,
      };
      await company.initialLink.submitProof({ ...proofOf(attempt), stage: 'initial' });
      await store.transaction((state) => {
        state.linkAttempts.set(requestId, attempt);
      });
      const started = await warifu.pushInitialLink({
        action: 'initial_link.approve',
        initialLinkId,
        sub: account.sub,
      });
      return await ctx.begin(reply, session, 'link_approve', requestId, started);
    } catch (error) {
      if (!(error instanceof RpKitError)) throw error;
      return ctx.go(reply, '/legacy', 'failed');
    }
  });

  ctx.onCallback('link_approve', async ({ login, pending, ref, account }) => {
    const outcome = await warifu.readInitialLink(login, pending as PendingAuthorization);
    if (outcome.stage !== 'approve' || ref === null) return '/legacy?n=failed';
    await store.transaction((state) => {
      const attempt = state.linkAttempts.get(ref);
      // 待機の知らせ（SET）が先に届いていれば、waiting のままにする。
      if (
        attempt !== undefined &&
        attempt.accountKey === account.key &&
        attempt.state === 'proof_submitted'
      ) {
        attempt.state = 'pending_notice';
      }
    });
    return '/legacy?n=link_waiting';
  });

  // ---- 最終の確かめ（2つ目の証跡と、最終の承認） ----

  app.post('/legacy/link/finalize', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    const memberId = verifiedMemberId(session);
    if (account === undefined) return ctx.go(reply, '/legacy', 'login_required');
    // 旧パスキーを、待機の後にもう一度確かめていること（新しいチャレンジ。O-86 の手順6）。
    if (memberId === undefined) return ctx.go(reply, '/legacy', 'legacy_required');
    await reconcileFor(memberId, account.key);
    const attempt = await store.read((state) => {
      const found = openAttemptOf(state, memberId);
      const member = state.legacyMembers.get(memberId);
      return found !== undefined &&
        found.accountKey === account.key &&
        member !== undefined &&
        // 待機の間に認証世代が変わっていれば、進めない（O-88）。
        member.authEpoch === found.authEpoch &&
        (found.state === 'waiting' || found.state === 'final_proof_submitted')
        ? found
        : undefined;
    });
    if (attempt === undefined) return ctx.go(reply, '/legacy', 'link_not_ready');
    try {
      if (attempt.state === 'waiting') {
        await company.initialLink.submitProof({ ...proofOf(attempt), stage: 'final' });
        await store.transaction((state) => {
          const stored = state.linkAttempts.get(attempt.requestId);
          if (stored !== undefined && stored.state === 'waiting')
            stored.state = 'final_proof_submitted';
        });
      }
      const started = await warifu.pushInitialLink({
        action: 'initial_link.finalize',
        initialLinkId: attempt.initialLinkId,
        sub: account.sub,
      });
      return await ctx.begin(reply, session, 'link_finalize', attempt.requestId, started);
    } catch (error) {
      if (!(error instanceof RpKitError)) throw error;
      // 待機がまだ終わっていない、など（割符が断った）。
      return ctx.go(reply, '/legacy', error.code === 'rejected' ? 'link_not_ready' : 'failed');
    }
  });

  ctx.onCallback('link_finalize', async ({ login, pending, ref, account }) => {
    // 紐付けの承認の JWT（鍵 initial_link、5分、一度だけ）を確かめる。窓口やログインの結果では通らない。
    const outcome = await warifu.readInitialLink(login, pending as PendingAuthorization);
    if (outcome.stage !== 'finalize' || ref === null) return '/legacy?n=failed';
    // 紐付け、旧パスキーの確かめを閉じること、認証世代の更新を、まとめて確定する（O-86 の手順8、RP-30・RP-31）。
    const decided = await store.transaction((state) => {
      const attempt = state.linkAttempts.get(ref);
      const member = attempt === undefined ? undefined : state.legacyMembers.get(attempt.memberId);
      const stored = state.accounts.get(account.key);
      if (
        attempt === undefined ||
        member === undefined ||
        stored === undefined ||
        attempt.state !== 'final_proof_submitted' ||
        attempt.accountKey !== account.key ||
        attempt.initialLinkId !== outcome.initialLinkId ||
        member.linkedAccountKey !== null ||
        member.closed ||
        stored.legacyMemberId !== null
      ) {
        return undefined;
      }
      // 確定の時点で、認証世代が、申請のときと同じかを確かめる（確定の前の確かめの後に、旧会員の側で認証器の追加や
      // 削除、回復があったかもしれない）。違えば紐付けない。割符の正本は、最終の承認の後（approved）は期限で
      // 終わらないので、not_linked を報告して終わらせる（ADR 0028 の O-88・O-91）。
      if (member.authEpoch !== attempt.authEpoch) {
        attempt.state = 'not_linked';
        enqueueReport(state, attempt.initialLinkId, 'not_linked');
        return 'not_linked' as const;
      }
      stored.legacyMemberId = member.memberId;
      member.linkedAccountKey = account.key;
      member.closed = true;
      member.authEpoch += 1;
      attempt.state = 'linked';
      enqueueReport(state, attempt.initialLinkId, 'linked');
      for (const s of state.sessions.values()) {
        if (s.legacy?.memberId === member.memberId) s.legacy = null;
      }
      return 'linked' as const;
    });
    if (decided === undefined) return '/legacy?n=failed';
    // 報告は、送信待ちから送る。届かなくても、確定は戻さない（送信待ちに残り、後で送り直す）。
    await flushReports();
    return decided === 'linked' ? '/?n=link_done' : '/legacy?n=failed';
  });

  // ---- 取消（旧会員の側。旧パスキーで確かめた人だけ） ----

  app.post('/legacy/cancel', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const memberId = verifiedMemberId(session);
    if (memberId === undefined) return ctx.go(reply, '/legacy', 'legacy_required');
    await reconcileFor(memberId, undefined);
    const attempt = await store.read((state) => openAttemptOf(state, memberId));
    if (attempt === undefined) return ctx.go(reply, '/legacy', 'link_closed');
    try {
      // 旧会員の側の新しい確かめを添えた取消（証跡の stage は cancel）。
      await company.initialLink.cancel(proofOf(attempt));
    } catch (error) {
      if (!(error instanceof RpKitError)) throw error;
      return ctx.go(reply, '/legacy', 'failed');
    }
    await store.transaction((state) => {
      const stored = state.linkAttempts.get(attempt.requestId);
      if (stored !== undefined && OPEN_STATES.has(stored.state)) stored.state = 'cancelled';
      // 旧会員の側からの取消は、不正の疑いとして扱う。同じ旧パスキーでの申請のやり直しを止める。
      const member = state.legacyMembers.get(memberId);
      if (member !== undefined) member.linkBlocked = true;
    });
    return ctx.go(reply, '/legacy', 'link_cancelled');
  });

  // ---- 割符からの知らせ（待機の始まりと、利用者の取消） ----

  ctx.onSet(async (set) => {
    const waiting = set.events[WAITING_EVENT];
    const cancellation = set.events[CANCELLATION_EVENT];
    const id = (waiting ?? cancellation)?.initial_link_id;
    if (typeof id !== 'string') return;
    const now = nowMs();
    const cancelled = await store.transaction((state) => {
      const attempt = [...state.linkAttempts.values()].find((a) => a.initialLinkId === id);
      if (attempt === undefined) return false;
      if (waiting !== undefined) {
        // 旧会員の側に、知らせを出す（/legacy の画面。旧パスキーで確かめた人に見せる。O-103）。
        if (attempt.state === 'proof_submitted' || attempt.state === 'pending_notice') {
          attempt.state = 'waiting';
          attempt.noticeAt = now;
        }
        return false;
      }
      if (!OPEN_STATES.has(attempt.state)) return false;
      attempt.state = 'cancelled';
      enqueueReport(state, attempt.initialLinkId, 'cancelled');
      return true;
    });
    // SET には、届かなくても 202 を返す（取消の適用と報告の送信待ちは、もう残してある）。
    if (cancelled) await flushReports();
  });

  return { flushReports };
}
