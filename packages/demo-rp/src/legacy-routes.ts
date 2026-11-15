// 旧会員の引き継ぎ（A社。既存会員の初回紐付けの、企業の側の参照実装。ADR 0020、ADR 0028 の O-86〜O-91・O-103・O-104）。
//
// 1. 利用者は、割符でログインしたうえで、旧パスキーで旧会員であることを確かめる（legacy.ts。5分だけ有効）。
// 2. 企業は、申請ID と会員参照（どちらも申請ごとの乱数）を作り、割符に仮申請と証跡を出して、PAR で本人の承認を求める。
// 3. 割符から待機の知らせ（SET）が届いたら、旧会員の側に知らせを出す。知らせは、旧パスキーで確かめた人にだけ見せ、
//    その人は申請を取り消せる（盗まれた旧パスキーで、他人の割符のアカウントに結び付けられるのを、持ち主が止められる）。
// 4. 待機の後、旧パスキーをもう一度確かめて2つ目の証跡を出し、割符の最終の承認（紐付けの承認の JWT）を受ける。
// 5. 紐付けと、旧パスキーの確かめを閉じること（RP-31）と、認証世代の更新を、1つのトランザクションで確定させる。
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
import type { DemoState, LinkAttempt, Session } from './state.ts';

const WAITING_EVENT = 'urn:warifu:secevent:initial-link-waiting';
const CANCELLATION_EVENT = 'urn:warifu:secevent:initial-link-cancellation';
const OPEN_STATES: ReadonlySet<string> = new Set([
  'proof_submitted',
  'pending_notice',
  'waiting',
  'final_proof_submitted',
]);

function openAttemptOf(state: DemoState, memberId: string): LinkAttempt | undefined {
  return [...state.linkAttempts.values()].find(
    (attempt) => attempt.memberId === memberId && OPEN_STATES.has(attempt.state),
  );
}

export function registerLegacyRoutes(
  ctx: Ctx,
  company: CompanyApiClient,
  initialLink: { readonly profileVersion: number },
): void {
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

  /** 結果の報告。届かなくても、企業の側の状態は変えない（割符の側は、期限で終わる）。 */
  async function report(initialLinkId: string, result: 'linked' | 'cancelled' | 'not_linked') {
    try {
      await company.initialLink.report({ initialLinkId, result });
    } catch (error) {
      if (!(error instanceof RpKitError)) throw error;
    }
  }

  app.get('/legacy', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const account = await ctx.accountOf(session);
    const memberId = verifiedMemberId(session);
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
    const linked = await store.transaction((state) => {
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
      stored.legacyMemberId = member.memberId;
      member.linkedAccountKey = account.key;
      member.closed = true;
      member.authEpoch += 1;
      attempt.state = 'linked';
      for (const s of state.sessions.values()) {
        if (s.legacy?.memberId === member.memberId) s.legacy = null;
      }
      return attempt.initialLinkId;
    });
    if (linked === undefined) return '/legacy?n=failed';
    await report(linked, 'linked');
    return '/?n=link_done';
  });

  // ---- 取消（旧会員の側。旧パスキーで確かめた人だけ） ----

  app.post('/legacy/cancel', async (request, reply) => {
    const session = await ctx.sessionOf(request, reply);
    const memberId = verifiedMemberId(session);
    if (memberId === undefined) return ctx.go(reply, '/legacy', 'legacy_required');
    const attempt = await store.read((state) => openAttemptOf(state, memberId));
    if (attempt === undefined) return ctx.go(reply, '/legacy', 'failed');
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
      return true;
    });
    if (cancelled) await report(id, 'cancelled');
  });
}
