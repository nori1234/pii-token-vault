#!/usr/bin/env bash
# Claude Code のクラウドのセッションを始めるときに、lint・typecheck・test を実行できる状態にする。
#
# - クラウドのセッション（CLAUDE_CODE_REMOTE=true）でだけ動く。貢献者の手元では何もしない。
# - node_modules が無いか、package-lock.json より古いときだけ npm ci を実行する。
#   --ignore-scripts は CI（.github/workflows/ci.yml）と同じ理由で付ける。
# - `npx playwright install` は実行しない。この環境の Chromium は revision 1194 だけで、
#   ブラウザの CDN にもつながらない（CLAUDE.md「環境の注意」）。
# - 環境変数やトークンなど、秘密になりうる値は出力しない。
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

stamp=node_modules/.package-lock.json
if [ ! -d node_modules ] || [ ! -f "$stamp" ] || [ package-lock.json -nt "$stamp" ]; then
  echo 'session-start: node_modules が無いか古いので、npm ci を実行する。'
  npm ci --ignore-scripts --no-audit --no-fund --loglevel=error >&2
  echo 'session-start: npm ci が終わった。'
else
  echo 'session-start: node_modules は package-lock.json と合っているので、npm ci を省いた。'
fi
