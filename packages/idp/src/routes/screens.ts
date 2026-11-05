// 画面と配信物：GET /（オリジンごとの画面）と /assets/*。

import { renderPage } from '../pages.ts';
import type { RouteContext } from './context.ts';

export function registerScreenRoutes(ctx: RouteContext): void {
  const { app, onMain, onApproval, assets } = ctx;

  app.get('/', onMain, async (request, reply) =>
    ctx.sendHtml(request, reply, (nonce) =>
      renderPage({ nonce, page: 'home', approvalOrigin: ctx.approvalOrigin }),
    ),
  );
  app.get('/', onApproval, async (request, reply) =>
    ctx.sendHtml(request, reply, (nonce) => renderPage({ nonce, page: 'approval' })),
  );
  // 配信物は、どちらのオリジンにも同じものを置く（中身に資格情報や鍵はない）。
  for (const site of [onMain, onApproval]) {
    app.get('/assets/app.js', site, async (_request, reply) =>
      reply.type('text/javascript; charset=utf-8').send(assets.appJs),
    );
    app.get('/assets/app.css', site, async (_request, reply) =>
      reply.type('text/css; charset=utf-8').send(assets.appCss),
    );
    app.get('/assets/webauthn.js', site, async (_request, reply) =>
      reply.type('text/javascript; charset=utf-8').send(assets.webauthnJs),
    );
  }
}
