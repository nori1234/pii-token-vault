// 承認用のオリジン：回復と協力者（ADR 0003、ADR 0027。DESIGN.md 2章の回復と協力者の画面）。
//
// 画面：GET /recover（新しい端末での回復）、/recovery（回復の設定と、進行中の回復の取消）、/helper（協力者として）。
// 持ち主（承認用のセッション）：
// - GET /api/recovery/settings、POST /api/recovery-code/options|verify（回復コードの作成と作り直し）
// - POST /api/helpers/invite、/api/helpers/invite/status、/api/helpers/confirm/options|verify、
//   /api/helpers/remove/options|verify（協力者の招待、確定、削除）
// - POST /api/recovery/cancel/options|verify（登録済みの端末からの取消）
// 協力者（承認用のセッション）：
// - POST /api/helpers/accept（招待の受け入れ）、/api/recovery/helper/view|options|verify（協力者の承認）
// 新しい端末（セッションなし）：
// - POST /api/recovery/start、/api/recovery/register（回復の開始と、回復待ちのパスキーの作成）
// - POST /api/recovery/resume/options|verify（回復待ちのパスキーで、状態を読み直す。待機の後は成立させる）
//
// どの操作も、内容に結び付いた UV 付きのパスキー（ADR 0023 と同じ形）で確かめる。応答の本文は固定の形だけで、
// 回復コード、招待と結び付けのコードは、作った応答で1回だけ返し、ログに出さない（不変条件4）。

import {
  lengthPrefixed,
  randomBytesOf,
  randomUuid,
  toBase64Url,
  type WarifuUserId,
} from '@pii-token-vault/warifu-core';
import { DeskClientError } from '@pii-token-vault/warifu-core/desk/client';
import { encode } from 'uqr';
import { bodyOf, FAILED, RATE_LIMITED, RESTRICTED } from '../http.ts';
import { DEVICE_KINDS, deviceKindOf } from '../inbox.ts';
import { renderPage } from '../pages.ts';
import {
  activeRecovery,
  approveRecovery,
  BINDING_KIND,
  cancelRecovery,
  checkRecoveryStart,
  completeRecovery,
  createBinding,
  createInvite,
  helperRelationship,
  INVITE_KIND,
  isRecoveryRestricted,
  issueRecoveryCode,
  listHelping,
  loadBinding,
  loadInvite,
  parseRecoveryCode,
  pendingRecoveryOf,
  type RecoveryAttemptView,
  type RecoveryBinding,
  type RecoveryInvite,
  recoveredDayOf,
  recoverySettings,
  removeHelper,
  setHelper,
  startRecovery,
} from '../recovery.ts';
import { findCredential, listConnections } from '../repo.ts';
import { APPROVAL_SESSION_COOKIE } from '../sessions.ts';
import type { RouteContext } from './context.ts';

const NOT_ELIGIBLE = Object.freeze({ error: 'helper_not_eligible' });

/** QR（白黒の行列）。区切りのない正規の形を入れる（英数字モードで小さくなる）。画面が canvas に描く（O-82）。 */
function qrOf(code: string): string[] {
  const { data } = encode(code.replace(/-/g, ''), { border: 1 });
  return data.map((row) => row.map((dark) => (dark ? '1' : '0')).join(''));
}

function attemptJson(attempt: RecoveryAttemptView) {
  return {
    id: attempt.attemptId,
    state: attempt.state,
    device: DEVICE_KINDS[attempt.device],
    startedAt: attempt.startedAt.toISOString(),
    helperDeadline: attempt.helperDeadline.toISOString(),
    readyAt: attempt.readyAt === null ? null : attempt.readyAt.toISOString(),
  };
}

/** PWA の受信箱に出す、進行中の回復の要約（inbox.ts から呼ぶ）。取消は承認用のオリジンで行う。 */
export async function recoverySummary(ctx: RouteContext, userId: WarifuUserId) {
  const attempt = await activeRecovery(ctx.repo, userId);
  return attempt === undefined ? null : attemptJson(attempt);
}

export function registerRecoveryRoutes(ctx: RouteContext): void {
  const { app, onApproval, repo, keys, limiter, ceremonies, store } = ctx;

  async function challengeOf(parts: readonly string[]): Promise<Uint8Array> {
    return keys.mac('approval_challenge', lengthPrefixed(parts));
  }

  function remainingSeconds(expiresAt: number): number {
    return Math.max(1, Math.ceil((expiresAt - ctx.nowMs()) / 1000));
  }

  // ---- 画面 ----

  for (const [path, page] of [
    ['/recover', 'recover'],
    ['/recovery', 'recovery'],
    ['/helper', 'helper'],
  ] as const) {
    app.get(path, onApproval, async (request, reply) =>
      ctx.sendHtml(request, reply, (nonce) => renderPage({ nonce, page }), {
        camera: page === 'helper',
      }),
    );
  }

  // ---- 持ち主：回復の設定 ----

  app.get('/api/recovery/settings', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId } = current.session;
    if (!limiter.take('inboxByUser', userId)) return reply.code(429).send(RATE_LIMITED);
    const settings = await recoverySettings(repo, userId);
    return {
      code:
        settings.codeCreatedAt === null
          ? null
          : { createdAt: settings.codeCreatedAt.toISOString() },
      helper:
        settings.helper === null
          ? null
          : {
              relationshipId: settings.helper.relationshipId,
              createdAt: settings.helper.createdAt.toISOString(),
            },
      restrictedUntil: settings.restrictedUntil?.toISOString() ?? null,
      attempt: settings.attempt === null ? null : attemptJson(settings.attempt),
      helping: (await listHelping(repo, userId)).map((row) => ({
        relationshipId: row.relationshipId,
        createdAt: row.createdAt.toISOString(),
      })),
    };
  });

  async function codeCreatedAtOf(userId: WarifuUserId): Promise<string> {
    return (await recoverySettings(repo, userId)).codeCreatedAt?.toISOString() ?? '';
  }

  app.post('/api/recovery-code/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip) || !limiter.take('recoveryCodeByUser', userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const createdAt = await codeCreatedAtOf(userId);
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'recovery_code_issue',
      challenge: await challengeOf([
        'warifu/recovery-code-issue/v1',
        userId,
        ref,
        nonce,
        createdAt,
      ]),
      bind: ref,
      userId,
      ref: createdAt,
      nonce,
    });
  });

  app.post('/api/recovery-code/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'recovery_code_issue',
      bind: ref,
      expectedUserId: userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      // 選択肢を出した後にコードが作り直されていたら、通さない（同じ確認で2回作らせない）。
      recompute: async ({ ref: createdAt, nonce }) =>
        (await codeCreatedAtOf(userId)) === createdAt
          ? toBase64Url(
              await challengeOf(['warifu/recovery-code-issue/v1', userId, ref, nonce, createdAt]),
            )
          : undefined,
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    const issued = await issueRecoveryCode(repo, keys, userId);
    request.log.info({ event: 'idp.recovery_code_issued' });
    return { code: issued.code, reissued: issued.reissued };
  });

  // ---- 持ち主：協力者の招待、確定、削除（O-74） ----

  app.post('/api/helpers/invite', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId } = current.session;
    if (!limiter.take('helperInviteByUser', userId)) return reply.code(429).send(RATE_LIMITED);
    if (await isRecoveryRestricted(repo, userId)) return reply.code(409).send(RESTRICTED);
    const invite = await createInvite(store, userId, ctx.nowMs());
    return {
      code: invite.code,
      qr: qrOf(invite.code),
      expiresAt: new Date(invite.expiresAt).toISOString(),
    };
  });

  async function ownInvite(
    userId: WarifuUserId,
    code: unknown,
  ): Promise<{ key: string; invite: RecoveryInvite } | undefined> {
    const found = await loadInvite(store, code, ctx.nowMs());
    return found !== undefined && found.invite.ownerUserId === userId ? found : undefined;
  }

  app.post('/api/helpers/invite/status', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    if (!limiter.take('inboxByUser', current.session.userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const found = await ownInvite(current.session.userId, bodyOf(request).code);
    if (found === undefined) return reply.code(400).send(FAILED);
    return { state: found.invite.state };
  });

  function confirmChallenge(
    invite: RecoveryInvite,
    sessionRef: string,
    nonce: string,
  ): Promise<Uint8Array> {
    return challengeOf([
      'warifu/helper-confirm/v1',
      invite.ownerUserId,
      invite.helperUserId ?? '',
      invite.relationshipId ?? '',
      sessionRef,
      nonce,
    ]);
  }

  app.post('/api/helpers/confirm/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const found = await ownInvite(userId, bodyOf(request).code);
    if (found === undefined || found.invite.state !== 'accepted') {
      return reply.code(400).send(FAILED);
    }
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'helper_confirm',
      challenge: await confirmChallenge(found.invite, ref, nonce),
      bind: ref,
      userId,
      ref: found.key,
      nonce,
    });
  });

  app.post('/api/helpers/confirm/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    let target: { key: string; invite: RecoveryInvite } | undefined;
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'helper_confirm',
      bind: ref,
      expectedUserId: userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref: key, nonce }) => {
        const found = await ownInvite(userId, key);
        if (found === undefined || found.invite.state !== 'accepted') return undefined;
        target = found;
        return toBase64Url(await confirmChallenge(found.invite, ref, nonce));
      },
    });
    if (!result.ok || target === undefined) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    const { key, invite } = target;
    if (invite.helperUserId === undefined || invite.relationshipId === undefined) {
      return reply.code(400).send(FAILED);
    }
    const set = await setHelper(repo, {
      ownerUserId: userId,
      helperUserId: invite.helperUserId,
      relationshipId: invite.relationshipId,
    });
    await store.delete(INVITE_KIND, key);
    if (!set) return reply.code(409).send(RESTRICTED);
    request.log.info({ event: 'idp.recovery_helper_set' });
    return { ok: true };
  });

  async function helperOf(userId: WarifuUserId): Promise<string | undefined> {
    return (await recoverySettings(repo, userId)).helper?.relationshipId;
  }

  app.post('/api/helpers/remove/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const relationshipId = await helperOf(userId);
    if (relationshipId === undefined) return reply.code(400).send(FAILED);
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'helper_remove',
      challenge: await challengeOf(['warifu/helper-remove/v1', userId, relationshipId, ref, nonce]),
      bind: ref,
      userId,
      ref: relationshipId,
      nonce,
    });
  });

  app.post('/api/helpers/remove/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'helper_remove',
      bind: ref,
      expectedUserId: userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref: relationshipId, nonce }) =>
        (await helperOf(userId)) === relationshipId
          ? toBase64Url(
              await challengeOf(['warifu/helper-remove/v1', userId, relationshipId, ref, nonce]),
            )
          : undefined,
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    if (!(await removeHelper(repo, userId))) return reply.code(409).send(RESTRICTED);
    return { ok: true };
  });

  // ---- 協力者：招待の受け入れ ----

  function takeCodeLimit(userId: WarifuUserId, ip: string): boolean {
    return limiter.take('helperCodeByIp', ip) && limiter.take('helperCodeByUser', userId);
  }

  app.post('/api/helpers/accept', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId } = current.session;
    if (!takeCodeLimit(userId, request.ip)) return reply.code(429).send(RATE_LIMITED);
    const found = await loadInvite(store, bodyOf(request).code, ctx.nowMs());
    if (
      found === undefined ||
      found.invite.state !== 'open' ||
      found.invite.ownerUserId === userId
    ) {
      return reply.code(400).send(FAILED);
    }
    const relationshipId = randomUuid();
    const accepted: RecoveryInvite = {
      ...found.invite,
      state: 'accepted',
      helperUserId: userId,
      relationshipId,
    };
    await store.set(INVITE_KIND, found.key, accepted, remainingSeconds(found.invite.expiresAt));
    return { relationshipId };
  });

  // ---- 新しい端末：回復の開始（O-75） ----

  app.post('/api/recovery/start', onApproval, async (request, reply) => {
    if (!limiter.take('recoveryStartByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const code = bodyOf(request).code;
    const parsed = parseRecoveryCode(code);
    if (parsed !== undefined && !limiter.take('recoveryStartByUser', parsed.userId)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const check = await checkRecoveryStart(repo, keys, code);
    if (!check.ok) return reply.code(400).send(FAILED);
    return ceremonies.registrationOptions({
      purpose: 'recovery',
      userId: check.userId,
      bind: '',
      ref: check.codeCreatedAt,
    });
  });

  async function newBinding(
    userId: WarifuUserId,
    attemptId: string,
    credentialId: Uint8Array,
    helperUserId: WarifuUserId,
  ) {
    const binding = await createBinding(
      store,
      { userId, attemptId, credentialId: toBase64Url(credentialId), helperUserId },
      ctx.nowMs(),
    );
    return {
      code: binding.code,
      qr: qrOf(binding.code),
      expiresAt: new Date(binding.expiresAt).toISOString(),
    };
  }

  app.post('/api/recovery/register', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyRegistration({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'recovery',
      bind: '',
    });
    if (!result.ok || result.ref === undefined) return reply.code(400).send(FAILED);
    const started = await startRecovery(repo, {
      userId: result.userId,
      codeCreatedAt: result.ref,
      credential: result.credential,
      device: deviceKindOf(request.headers['user-agent']),
    });
    if (started === undefined) return reply.code(400).send(FAILED);
    request.log.info({ event: 'idp.recovery_started' });
    return {
      state: 'awaiting_helper',
      binding: await newBinding(
        result.userId,
        started.attemptId,
        result.credential.credentialId,
        started.helperUserId,
      ),
    };
  });

  app.post('/api/recovery/resume/options', onApproval, async (request, reply) => {
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    return ceremonies.authenticationOptions({ purpose: 'recovery_resume', bind: '' });
  });

  app.post('/api/recovery/resume/verify', onApproval, async (request, reply) => {
    const body = bodyOf(request);
    const result = await ceremonies.verifyAuthentication({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'recovery_resume',
      bind: '',
      // 回復待ちのパスキーだけ（有効なパスキーや一時停止したものでは、回復の状態を読めない）。
      find: (userId, credentialId) => findCredential(repo, userId, credentialId, 'pending'),
      admit: ctx.admitLogin(request.ip),
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    const { userId, credentialId } = result;
    const pending = await pendingRecoveryOf(repo, userId, credentialId);
    if (pending === undefined) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    if (pending.state === 'awaiting_helper') {
      return {
        state: 'awaiting_helper',
        binding: await newBinding(userId, pending.attemptId, credentialId, pending.helperUserId),
      };
    }
    const at = new Date(ctx.nowMs());
    if (pending.readyAt === null || pending.readyAt > at) {
      return { state: 'waiting', readyAt: pending.readyAt?.toISOString() ?? null };
    }
    // 企業への知らせを、成立の前に送信待ちに入れる（届かなければ成立させない。O-79）。
    const tenantIds = (await listConnections(repo, userId)).map((c) => c.tenantId);
    if (tenantIds.length > 0) {
      if (ctx.desk === undefined) return reply.code(503).send({ error: 'unavailable' });
      try {
        await ctx.desk.accountRecovered({
          userId,
          attemptId: pending.attemptId,
          tenantIds,
          recoveredDay: recoveredDayOf(at),
        });
      } catch (error) {
        if (!(error instanceof DeskClientError)) throw error;
        return reply.code(503).send({ error: 'unavailable' });
      }
    }
    const done = await completeRecovery(repo, keys, {
      userId,
      attemptId: pending.attemptId,
      credentialId,
      at,
    });
    if (done === undefined) return reply.code(409).send(FAILED);
    // 持ち主のセッションをすべて消し（O-79）、新しい端末だけを承認用のオリジンでログインさせる。
    ctx.sessions.revokeUser(userId);
    ctx.approvalSessions.revokeUser(userId);
    store.deleteWhere(
      BINDING_KIND,
      (value) => (value as RecoveryBinding | undefined)?.attemptId === pending.attemptId,
    );
    ctx.setCookie(reply, APPROVAL_SESSION_COOKIE, await ctx.approvalSessions.create(userId));
    request.log.info({ event: 'idp.recovery_completed' });
    return { state: 'completed', recoveryCode: done.code };
  });

  // ---- 協力者：回復の承認（O-76） ----

  async function helperView(
    helperUserId: WarifuUserId,
    code: unknown,
  ): Promise<
    { key: string; binding: RecoveryBinding; relationshipId: string } | 'not_eligible' | undefined
  > {
    const found = await loadBinding(store, code, ctx.nowMs());
    if (found === undefined || found.binding.helperUserId !== helperUserId) return undefined;
    const relationship = await helperRelationship(repo, helperUserId, found.binding.userId);
    if (relationship === undefined) return undefined;
    if (!relationship.eligible) return 'not_eligible';
    return { ...found, relationshipId: relationship.relationshipId };
  }

  function helperChallenge(
    binding: RecoveryBinding,
    sessionRef: string,
    nonce: string,
  ): Promise<Uint8Array> {
    return challengeOf([
      'warifu/recovery-helper/v1',
      binding.attemptId,
      binding.userId,
      binding.helperUserId,
      binding.credentialId,
      sessionRef,
      nonce,
    ]);
  }

  app.post('/api/recovery/helper/view', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId } = current.session;
    if (!takeCodeLimit(userId, request.ip)) return reply.code(429).send(RATE_LIMITED);
    const view = await helperView(userId, bodyOf(request).code);
    if (view === undefined) return reply.code(400).send(FAILED);
    if (view === 'not_eligible') return reply.code(409).send(NOT_ELIGIBLE);
    return {
      relationshipId: view.relationshipId,
      readyAt: new Date(ctx.nowMs() + ctx.recoveryWaitSeconds * 1000).toISOString(),
    };
  });

  app.post('/api/recovery/helper/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip) || !takeCodeLimit(userId, request.ip)) {
      return reply.code(429).send(RATE_LIMITED);
    }
    const view = await helperView(userId, bodyOf(request).code);
    if (view === undefined) return reply.code(400).send(FAILED);
    if (view === 'not_eligible') return reply.code(409).send(NOT_ELIGIBLE);
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'recovery_helper_approve',
      challenge: await helperChallenge(view.binding, ref, nonce),
      bind: ref,
      userId,
      ref: view.key,
      nonce,
    });
  });

  app.post('/api/recovery/helper/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    let target: { key: string; binding: RecoveryBinding } | undefined;
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'recovery_helper_approve',
      bind: ref,
      expectedUserId: userId,
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref: key, nonce }) => {
        const view = await helperView(userId, key);
        if (view === undefined || view === 'not_eligible') return undefined;
        target = view;
        return toBase64Url(await helperChallenge(view.binding, ref, nonce));
      },
    });
    if (!result.ok || target === undefined) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    const { key, binding } = target;
    // 結び付けは1回だけ（承認の成否によらず、ここで消す）。
    await store.delete(BINDING_KIND, key);
    const readyAt = await approveRecovery(repo, {
      userId: binding.userId,
      attemptId: binding.attemptId,
      helperUserId: userId,
      waitSeconds: ctx.recoveryWaitSeconds,
    });
    if (readyAt === undefined) return reply.code(409).send(FAILED);
    request.log.info({ event: 'idp.recovery_helper_approved' });
    return { readyAt: readyAt.toISOString() };
  });

  // ---- 持ち主の登録済みの端末：取消（O-78） ----

  async function cancelChallenge(
    attempt: RecoveryAttemptView,
    userId: WarifuUserId,
    sessionRef: string,
    nonce: string,
  ): Promise<Uint8Array> {
    return challengeOf([
      'warifu/recovery-cancel/v1',
      attempt.attemptId,
      userId,
      attempt.startedAt.toISOString(),
      sessionRef,
      nonce,
    ]);
  }

  app.post('/api/recovery/cancel/options', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    if (!limiter.take('ceremonyByIp', request.ip)) return reply.code(429).send(RATE_LIMITED);
    const attempt = await activeRecovery(repo, userId);
    if (attempt === undefined || attempt.attemptId !== bodyOf(request).id) {
      return reply.code(400).send(FAILED);
    }
    const nonce = toBase64Url(randomBytesOf(16));
    return ceremonies.boundOptions({
      purpose: 'recovery_cancel',
      challenge: await cancelChallenge(attempt, userId, ref, nonce),
      bind: ref,
      userId,
      ref: attempt.attemptId,
      nonce,
    });
  });

  app.post('/api/recovery/cancel/verify', onApproval, async (request, reply) => {
    const current = await ctx.requireApprovalSession(request, reply);
    if (current === undefined) return reply;
    const { userId, ref } = current.session;
    const body = bodyOf(request);
    const result = await ceremonies.verifyBound({
      ceremonyId: body.ceremonyId,
      response: body.response,
      purpose: 'recovery_cancel',
      bind: ref,
      expectedUserId: userId,
      // 有効なパスキーだけ（回復待ちのパスキーでは取り消せない）。
      find: ctx.findForLogin,
      admit: ctx.admitLogin(request.ip),
      recompute: async ({ ref: attemptId, nonce }) => {
        const attempt = await activeRecovery(repo, userId);
        if (attempt === undefined || attempt.attemptId !== attemptId) return undefined;
        return toBase64Url(await cancelChallenge(attempt, userId, ref, nonce));
      },
    });
    if (!result.ok) return reply.code(401).send(FAILED);
    await ctx.recordUse(result);
    const attempt = await activeRecovery(repo, userId);
    if (attempt === undefined) return reply.code(409).send(FAILED);
    if (!(await cancelRecovery(repo, { userId, attemptId: attempt.attemptId }))) {
      return reply.code(409).send(FAILED);
    }
    store.deleteWhere(
      BINDING_KIND,
      (value) => (value as RecoveryBinding | undefined)?.attemptId === attempt.attemptId,
    );
    request.log.info({ event: 'idp.recovery_cancelled' });
    return { ok: true };
  });
}
