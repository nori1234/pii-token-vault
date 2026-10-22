// 捨てスパイク1：CDP の仮想認証器で、パスキーの登録とログインを通すための最小のサーバー。
// 本番で使わない（DO NOT USE IN PRODUCTION）。省いた守りは spikes/README.md を参照。
// M3 で packages/idp に置き換える。本実装から import しない。
//
// 不変条件のうち、このスパイクで形にしておくもの：
// - 連絡先も氏名も聞かない、持たない。user.name と displayName は乱数のラベルにする（不変条件1(d)、4）。
// - パスキーは UV 付きのアサーションだけを根拠にする（不変条件1(b)）。
// - 発見可能な資格情報を必須にし、ログインでは allowCredentials を出さない。
//   アカウントは、アサーションの資格情報 ID と userHandle だけで決める。ほかの手がかりでは探さない。
// - アルゴリズムは ES256 と RS256 だけ。それ以外は登録時に拒否する（不変条件9）。
// - ログは出さない（チャレンジ、資格情報 ID、リクエストの本文を残さない。不変条件4）。
// - 外へはつながない（不変条件7）。証明書の失効確認でライブラリが外へ取りに行かないよう、
//   アテステーションは "none" だけを受け付ける（README の「分かったこと」を参照）。
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  type AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import { COSEALG, decodeAttestationObject, isoBase64URL } from '@simplewebauthn/server/helpers';
import fastify, { type FastifyReply } from 'fastify';

const port = parsePort(process.env.SPIKE_PASSKEY_PORT ?? '4101');

const RP_ID = 'localhost';
const RP_NAME = '割符（パスキーのスパイク）';
// expectedOrigin はポート込みで固定する（CLAUDE.md「環境の注意」）。
const ORIGIN = `http://localhost:${port}`;
const EXPECTED_HOST = `localhost:${port}`;
// 不変条件9：WebAuthn は ES256 と RS256 だけ。登録の選択肢と検証の両方に同じ値を渡す。
// 検証の側に渡し忘れると、ライブラリの既定（EdDSA を含む）で検証されてしまう。
const SUPPORTED_ALGORITHM_IDS: number[] = [COSEALG.ES256, COSEALG.RS256];
const WEBAUTHN_TIMEOUT_MS = 60_000;
// チャレンジの有効期限。ブラウザ側の timeout に少しだけ余裕を足す。
const CEREMONY_TTL_MS = WEBAUTHN_TIMEOUT_MS + 15_000;
const MAX_PENDING_CEREMONIES = 1_000;
const MAX_CREDENTIALS = 10_000;

type Ceremony =
  | { kind: 'register'; challenge: string; userHandle: string; expiresAt: number }
  | { kind: 'login'; challenge: string; expiresAt: number };

type StoredCredential = {
  // userHandle は登録のときに割符が乱数で作った値（base64url）。連絡先からは作らない。
  userHandle: string;
  credential: WebAuthnCredential;
  // plan 6章：BE/BS を記録し、同期パスキーかどうかの変化をリスクの信号にする。ここでは記録だけ。
  backupEligible: boolean;
  backedUp: boolean;
};

// 保存はメモリだけ。サーバーを止めれば消える。
const ceremonies = new Map<string, Ceremony>();
const credentials = new Map<string, StoredCredential>();

const publicDir = new URL('./public/', import.meta.url);
const indexHtml = readFileSync(new URL('index.html', publicDir));
const appJs = readFileSync(new URL('app.js', publicDir));
const vendorJs = loadSimpleWebAuthnBrowserBundle();

const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "connect-src 'self'",
  "img-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
  // ポリシーを1つも作らせない（innerHTML などの文字列の代入は、すべて拒否される）。
  "trusted-types 'none'",
].join('; ');

const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': CONTENT_SECURITY_POLICY,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

const verifyBodySchema = {
  type: 'object',
  required: ['ceremonyId', 'response'],
  additionalProperties: false,
  properties: {
    ceremonyId: { type: 'string', pattern: '^[A-Za-z0-9_-]{43}$' },
    response: { type: 'object' },
  },
} as const;

type VerifyBody = { ceremonyId: string; response: unknown };

// logger は切る。チャレンジ、資格情報 ID、本文を、どこにも書かないため。
const app = fastify({ logger: false, bodyLimit: 16 * 1024, return503OnClosing: true });

// JSON 以外の本文は受け付けない（Fastify は既定で text/plain も解析する）。
app.removeContentTypeParser('text/plain');

app.addHook('onRequest', async (request, reply) => {
  // DNS リバインディング対策：Host は localhost:<port> だけを受け付ける。
  if (request.headers.host !== EXPECTED_HOST) {
    return reply.code(421).send({ error: 'misdirected_request' });
  }
  // POST は同じオリジンからだけ受け付ける（クッキーは使わないが、念のため）。
  if (request.method === 'POST' && request.headers.origin !== ORIGIN) {
    return reply.code(403).send({ error: 'forbidden' });
  }
});

// 404 やエラーの応答を含め、すべての応答に同じ見出しを付ける。
app.addHook('onSend', async (_request, reply, payload) => {
  reply.headers(SECURITY_HEADERS);
  return payload;
});

app.setErrorHandler((error, _request, reply) => {
  // ライブラリやスキーマ検証のメッセージには、受け取った値が入ることがあるので、外に出さない。
  const statusCode =
    typeof error === 'object' && error !== null && 'statusCode' in error
      ? Number(error.statusCode)
      : 500;
  if (statusCode >= 400 && statusCode < 500) {
    return reply.code(400).send({ error: 'bad_request' });
  }
  return reply.code(500).send({ error: 'internal_error' });
});

app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: 'not_found' }));

app.get('/', (_request, reply) => reply.type('text/html; charset=utf-8').send(indexHtml));
app.get('/app.js', (_request, reply) => reply.type('text/javascript; charset=utf-8').send(appJs));
app.get('/vendor/simplewebauthn-browser.js', (_request, reply) =>
  reply.type('text/javascript; charset=utf-8').send(vendorJs),
);

app.post('/register/options', async (_request, reply) => {
  // ユーザーハンドルは乱数。連絡先、氏名、生年月日などからは作らない（不変条件1(d)）。
  const userHandle = new Uint8Array(randomBytes(32));
  // 認証器の画面に出る名前。個人を指す情報を入れず、乱数のラベルにする。
  const label = `spike-${randomBytes(4).toString('hex')}`;
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: userHandle,
    userName: label,
    userDisplayName: label,
    timeout: WEBAUTHN_TIMEOUT_MS,
    // 認証器の型番を集めない。"none" 以外は検証でも拒否する（下の isNoneAttestation）。
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
  });
  const ceremonyId = putCeremony({
    kind: 'register',
    challenge: options.challenge,
    userHandle: options.user.id,
    expiresAt: Date.now() + CEREMONY_TTL_MS,
  });
  if (ceremonyId === undefined) {
    return reply.code(503).send({ error: 'busy' });
  }
  return { ceremonyId, options };
});

app.post<{ Body: VerifyBody }>(
  '/register/verify',
  { schema: { body: verifyBodySchema } },
  async (request, reply) => {
    const ceremony = takeCeremony(request.body.ceremonyId);
    if (ceremony?.kind !== 'register') {
      return rejectRegistration(reply);
    }
    const response = request.body.response as RegistrationResponseJSON;
    try {
      if (!isNoneAttestation(response)) {
        return rejectRegistration(reply);
      }
      const result = await verifyRegistrationResponse({
        response,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        expectedType: 'webauthn.create',
        requireUserPresence: true,
        requireUserVerification: true,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
      });
      if (!result.verified || !result.registrationInfo.userVerified) {
        return rejectRegistration(reply);
      }
      const info = result.registrationInfo;
      // 同じ資格情報 ID を上書きしない。
      if (credentials.has(info.credential.id) || credentials.size >= MAX_CREDENTIALS) {
        return rejectRegistration(reply);
      }
      credentials.set(info.credential.id, {
        userHandle: ceremony.userHandle,
        credential: {
          id: info.credential.id,
          publicKey: info.credential.publicKey,
          counter: info.credential.counter,
          transports: info.credential.transports,
        },
        backupEligible: info.credentialDeviceType === 'multiDevice',
        backedUp: info.credentialBackedUp,
      });
      return { ok: true };
    } catch {
      // 理由（アルゴリズム、UV、チャレンジの不一致など）は外に出さず、ログにも書かない。
      return rejectRegistration(reply);
    }
  },
);

app.post('/login/options', async (_request, reply) => {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    timeout: WEBAUTHN_TIMEOUT_MS,
    userVerification: 'required',
    // allowCredentials は渡さない。発見可能な資格情報だけで、誰かを決める。
  });
  const ceremonyId = putCeremony({
    kind: 'login',
    challenge: options.challenge,
    expiresAt: Date.now() + CEREMONY_TTL_MS,
  });
  if (ceremonyId === undefined) {
    return reply.code(503).send({ error: 'busy' });
  }
  return { ceremonyId, options };
});

app.post<{ Body: VerifyBody }>(
  '/login/verify',
  { schema: { body: verifyBodySchema } },
  async (request, reply) => {
    const ceremony = takeCeremony(request.body.ceremonyId);
    if (ceremony?.kind !== 'login') {
      return rejectLogin(reply);
    }
    const response = request.body.response as AuthenticationResponseJSON;
    try {
      // アカウントは資格情報 ID だけで引く。見つからなければ、ほかの手がかりでは探さない。
      const stored = typeof response.id === 'string' ? credentials.get(response.id) : undefined;
      if (stored === undefined) {
        return rejectLogin(reply);
      }
      // WebAuthn L3 7.2 の手順6：userHandle が、その資格情報の持ち主と一致することを確かめる。
      // ライブラリの verifyAuthenticationResponse はこれを確かめない。
      // 発見可能な資格情報なので userHandle は必ず返る。返らなければ拒否する。
      if (response.response?.userHandle !== stored.userHandle) {
        return rejectLogin(reply);
      }
      const result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        expectedType: 'webauthn.get',
        credential: stored.credential,
        requireUserVerification: true,
      });
      if (!result.verified || !result.authenticationInfo.userVerified) {
        return rejectLogin(reply);
      }
      stored.credential.counter = result.authenticationInfo.newCounter;
      stored.backedUp = result.authenticationInfo.credentialBackedUp;
      return { ok: true };
    } catch {
      return rejectLogin(reply);
    }
  },
);

function rejectRegistration(reply: FastifyReply): FastifyReply {
  return reply.code(400).send({ error: 'registration_failed' });
}

function rejectLogin(reply: FastifyReply): FastifyReply {
  return reply.code(401).send({ error: 'login_failed' });
}

function putCeremony(ceremony: Ceremony): string | undefined {
  const now = Date.now();
  for (const [id, pending] of ceremonies) {
    if (pending.expiresAt <= now) {
      ceremonies.delete(id);
    }
  }
  if (ceremonies.size >= MAX_PENDING_CEREMONIES) {
    return undefined;
  }
  const ceremonyId = randomBytes(32).toString('base64url');
  ceremonies.set(ceremonyId, ceremony);
  return ceremonyId;
}

// チャレンジは使い捨て。検証の結果を問わず、取り出した時点で消す。
function takeCeremony(ceremonyId: string): Ceremony | undefined {
  const ceremony = ceremonies.get(ceremonyId);
  ceremonies.delete(ceremonyId);
  if (ceremony === undefined || ceremony.expiresAt <= Date.now()) {
    return undefined;
  }
  return ceremony;
}

// "none" 以外のアテステーションは、検証に渡す前に拒否する。
// @simplewebauthn/server 14.0.3 は、x5c の証明書チェーンを検証するとき、証明書の CRL 配布点へ
// fetch する（helpers/isCertRevoked.js）。android-key では、利用者が送ったチェーンの末尾を信頼の
// 起点にして経路を組むので、送り手が決めた URL へつながりうる（不変条件7）。
function isNoneAttestation(response: RegistrationResponseJSON): boolean {
  const attestationObject = decodeAttestationObject(
    isoBase64URL.toBuffer(response.response.attestationObject),
  );
  return attestationObject.get('fmt') === 'none' && attestationObject.get('attStmt').size === 0;
}

// @simplewebauthn/browser の UMD 版（グローバルの SimpleWebAuthnBrowser を定義する1ファイル）を読む。
// esm/ は21個のファイルに分かれているので、1ファイルで済む UMD 版を配る。
function loadSimpleWebAuthnBrowserBundle(): Buffer {
  const entry = import.meta.resolve('@simplewebauthn/browser');
  const packageJson: unknown = JSON.parse(readFileSync(new URL('../package.json', entry), 'utf8'));
  const version =
    typeof packageJson === 'object' && packageJson !== null && 'version' in packageJson
      ? String(packageJson.version)
      : '';
  const bundle = readFileSync(new URL('../dist/bundle/index.umd.min.js', entry));
  // 配るファイルが、インストールされた版と同じビルドであることを確かめる。
  const banner = `/* [@simplewebauthn/browser@${version}] */`;
  if (version === '' || !bundle.subarray(0, banner.length).equals(Buffer.from(banner))) {
    throw new Error('@simplewebauthn/browser の UMD 版が見つからないか、版が一致しません');
  }
  return bundle;
}

function parsePort(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1024 || parsed > 65_535) {
    throw new Error('SPIKE_PASSKEY_PORT は 1024〜65535 の整数にしてください');
  }
  return parsed;
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void app.close().then(() => process.exit(0));
  });
}

await app.listen({ host: '127.0.0.1', port });
