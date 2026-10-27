#!/usr/bin/env bash
# Codex のセットアップ段階で実行する。使い方は docs/codex-environment.md。
set -euo pipefail

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repo_root"

command -v node >/dev/null || fail 'Node 22.18 以降の 22 系を環境設定で選んでください。'
node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major === 22 && minor >= 18 ? 0 : 1)' \
  || fail 'Node 22.18 以降の 22 系が必要です。環境設定の Node の版を変更してください。'
for required_command in npm npx apt-get; do
  command -v "$required_command" >/dev/null || fail "必要なコマンドがありません: $required_command"
done

privilege=()
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || fail 'OS の依存を入れるには root またはパスワードなしの sudo が必要です。'
  sudo -n -k true || fail 'パスワードなしの sudo が必要です。'
  privilege=(sudo -n)
fi
as_root() { "${privilege[@]}" "$@"; }

pg_bin=${PG_BIN:-/usr/lib/postgresql/16/bin}
verify_postgres() {
  local binary
  for binary in initdb pg_ctl postgres psql pg_dump; do
    [ -x "$pg_bin/$binary" ] || fail "PostgreSQL のバイナリがありません: $pg_bin/$binary"
  done
  [[ $("$pg_bin/initdb" --version) == 'initdb (PostgreSQL) 16.'* ]] \
    || fail 'PG_BIN の PostgreSQL は 16 系ではありません。'
  if [ "$(id -u)" -eq 0 ]; then
    command -v runuser >/dev/null || fail 'root でテストを動かすには runuser が必要です。'
    id postgres >/dev/null || fail 'root でテストを動かすには postgres ユーザーが必要です。'
  fi
}
need_postgres=0
if [ ! -x "$pg_bin/initdb" ]; then
  [ "$pg_bin" = /usr/lib/postgresql/16/bin ] \
    || fail 'PG_BIN には、配置済みの PostgreSQL 16 の bin ディレクトリを指定してください。'
  need_postgres=1
else
  verify_postgres
fi

# 依存のインストールスクリプトは実行しない。Playwright は lockfile の版を使う。
npm ci --ignore-scripts --no-audit --no-fund
[ -x node_modules/.bin/playwright ] || fail 'ローカルの Playwright がインストールされていません。'

# apt と Playwright の OS 依存のインストール中だけサービス起動を止める。
# 既存の policy-rc.d は、内容・モード・シンボリックリンクを保ったまま戻す。
backup_dir=$(as_root mktemp -d /tmp/warifu-codex-setup.XXXXXX)
policy=/usr/sbin/policy-rc.d
policy_changed=0
policy_saved=0
cluster_config=''
cleanup() {
  local status=$? cleanup_failed=0
  trap - EXIT HUP INT TERM
  set +e
  if [ -n "$cluster_config" ]; then
    as_root rm -f -- "$cluster_config" || cleanup_failed=1
  fi
  if [ "$policy_changed" -eq 1 ]; then
    as_root rm -f -- "$policy" || cleanup_failed=1
    if [ "$policy_saved" -eq 1 ]; then
      as_root cp -a -- "$backup_dir/policy-rc.d" "$policy" || cleanup_failed=1
    fi
  fi
  if [ "$cleanup_failed" -eq 0 ]; then
    as_root rm -rf -- "$backup_dir" || cleanup_failed=1
  fi
  if [ "$cleanup_failed" -ne 0 ]; then
    printf '一時設定の復元に失敗しました。保存先: %s\n' "$backup_dir" >&2
    [ "$status" -ne 0 ] || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if as_root test -e "$policy" || as_root test -L "$policy"; then
  as_root test ! -d "$policy" || fail 'policy-rc.d がディレクトリを指しています。環境を確認してください。'
  as_root cp -a -- "$policy" "$backup_dir/policy-rc.d"
  policy_saved=1
fi
policy_changed=1
as_root rm -f -- "$policy"
printf '#!/bin/sh\nexit 101\n' | as_root tee "$policy" >/dev/null
as_root chmod 0755 "$policy"

if [ "$need_postgres" -eq 1 ]; then
  as_root install -d /etc/postgresql-common/createcluster.d
  cluster_config=$(as_root mktemp /etc/postgresql-common/createcluster.d/zz-codex-XXXXXX.conf)
  printf 'create_main_cluster = false\n' | as_root tee "$cluster_config" >/dev/null
  as_root apt-get update
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends postgresql-16
fi

verify_postgres

# 非 root では Playwright が OS 依存だけ sudo で入れる。ブラウザは実行ユーザーのキャッシュに置く。
npx --no playwright install --with-deps chromium
"$pg_bin/initdb" --version
printf '%s\n' 'セットアップ完了。作業段階で lint・typecheck・test・e2e を実行してください。'
