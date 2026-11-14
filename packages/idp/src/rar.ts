// authorization_details（RFC 9396）の2つの型を見分ける（ADR 0026 の O-60、ADR 0028 の O-86）。
// - warifu_desk：窓口の操作別承認。クライアントに許した操作（deskActions）だけ。
// - warifu_initial_link：既存会員の初回紐付け。クライアントに許したとき（initialLink）だけ。
// どちらも、配列で1件だけ。2つの型を混ぜた要求、許していない型は受け付けない。

import {
  DESK_DETAIL_TYPE,
  INITIAL_LINK_DETAIL_TYPE,
} from '@pii-token-vault/warifu-core/desk/protocol';
import {
  type DeskDetail,
  deskDetailFromParam,
  deskDetailJson,
  parseDeskDetail,
  sameDeskDetail,
} from './desk.ts';
import {
  type InitialLinkDetail,
  initialLinkDetailJson,
  parseInitialLinkDetail,
  sameInitialLinkDetail,
} from './initial-link.ts';
import type { ClientEntry } from './registry.ts';

export type RequestedDetail =
  | { readonly kind: 'desk'; readonly detail: DeskDetail }
  | { readonly kind: 'initial_link'; readonly detail: InitialLinkDetail };

/** このクライアントが送れる RAR の型。 */
export function detailTypesOf(entry: ClientEntry): string[] {
  return [
    ...(entry.deskActions.length > 0 ? [DESK_DETAIL_TYPE] : []),
    ...(entry.initialLink ? [INITIAL_LINK_DETAIL_TYPE] : []),
  ];
}

/** 1件の検査（型ごと）。 */
export function parseRequestedDetail(
  value: unknown,
  entry: ClientEntry,
): RequestedDetail | undefined {
  const desk = parseDeskDetail(value, entry.deskActions);
  if (desk !== undefined) return { kind: 'desk', detail: desk };
  if (!entry.initialLink) return undefined;
  const initialLink = parseInitialLinkDetail(value);
  return initialLink === undefined ? undefined : { kind: 'initial_link', detail: initialLink };
}

/** oidc-provider の params.authorization_details（JSON の文字列）から。配列で1件だけ。 */
export function requestedDetailFromParam(
  param: unknown,
  entry: ClientEntry,
): RequestedDetail | undefined {
  const desk = deskDetailFromParam(param, entry.deskActions);
  if (desk !== undefined) return { kind: 'desk', detail: desk };
  if (!entry.initialLink || typeof param !== 'string' || param.length > 4096) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(param);
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) return undefined;
  const detail = parseInitialLinkDetail(parsed[0]);
  return detail === undefined ? undefined : { kind: 'initial_link', detail };
}

export function requestedDetailJson(requested: RequestedDetail): Record<string, unknown> {
  return requested.kind === 'desk'
    ? deskDetailJson(requested.detail)
    : initialLinkDetailJson(requested.detail);
}

export function sameRequestedDetail(a: RequestedDetail, b: RequestedDetail): boolean {
  if (a.kind === 'desk' && b.kind === 'desk') return sameDeskDetail(a.detail, b.detail);
  if (a.kind === 'initial_link' && b.kind === 'initial_link') {
    return sameInitialLinkDetail(a.detail, b.detail);
  }
  return false;
}

/**
 * Grant に入れた1件が、要求と同じ申請で、承認の結果を持つか。窓口と最終の承認は、承認の JWT（approval）を持つ。
 * 初回紐付けの最初の承認は、正本の状態（state）だけを持ち、JWT を持たない（ADR 0028 の O-103）。
 */
export function isApprovedGrantDetail(
  granted: unknown,
  requested: RequestedDetail,
  entry: ClientEntry,
): boolean {
  if (typeof granted !== 'object' || granted === null || Array.isArray(granted)) return false;
  const { approval, state, ...rest } = granted as Record<string, unknown>;
  const approved = parseRequestedDetail(rest, entry);
  if (approved === undefined || !sameRequestedDetail(approved, requested)) return false;
  if (requested.kind === 'initial_link' && requested.detail.action === 'initial_link.approve') {
    return approval === undefined && state === 'pending_notice';
  }
  return typeof approval === 'string' && state === undefined;
}
