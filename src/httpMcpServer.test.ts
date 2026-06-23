// Copyright (c) 2025 Nulab inc.
// Licensed under the MIT License.

import { describe, it, expect, beforeEach } from 'vitest';
import { createMcpHonoApp, type SessionTransports } from './httpMcpServer.js';
import { BACKLOG_FAVICON_SVG } from './favicon.js';
import type { BacklogMCPServer } from './utils/wrapServerWithToolRegistry.js';

// The favicon route never touches the MCP server, so a stub satisfies the type.
const createServer = () => ({}) as unknown as BacklogMCPServer;

describe('createMcpHonoApp favicon route', () => {
  let app: Awaited<ReturnType<typeof createMcpHonoApp>>;

  beforeEach(async () => {
    const transports: SessionTransports = {};
    app = await createMcpHonoApp({
      path: '/mcp',
      version: '1.0.0',
      enableJsonResponse: true,
      createServer,
      transports,
    });
  });

  it('GET /favicon.ico は Backlog の favicon SVG を返す', async () => {
    const res = await app.request('/favicon.ico');

    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('image/svg+xml');
    const body = await res.text();
    expect(body).toBe(BACKLOG_FAVICON_SVG);
    expect(body).toContain('#42CE9F');
  });

  it('GET /favicon.svg も同じ favicon SVG を返す', async () => {
    const res = await app.request('/favicon.svg');

    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('image/svg+xml');
    expect(await res.text()).toBe(BACKLOG_FAVICON_SVG);
  });
});
