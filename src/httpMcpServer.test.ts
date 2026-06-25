// Copyright (c) 2025 Nulab inc.
// Licensed under the MIT License.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createMcpHonoApp, type SessionTransports } from './httpMcpServer.js';
import { BACKLOG_FAVICON_SVG } from './favicon.js';
import { createTokenStore } from './auth/tokenStore.js';
import type { BacklogOAuthConfig } from './auth/backlogOAuthConfig.js';
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

vi.mock('./auth/backlogOAuthClient.js', () => ({
  verifyBacklogToken: vi.fn(),
}));

const oauthConfig: BacklogOAuthConfig = {
  clientId: 'cid',
  clientSecret: 'csecret',
  backlogDomain: 'example.backlog.com',
  serverBaseUrl: 'https://mcp.example.com',
};

const MCP_HEADERS = {
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream',
};

const rpc = (method: string, params: unknown = {}, id = 1) =>
  JSON.stringify({ jsonrpc: '2.0', id, method, params });

const INITIALIZE_BODY = rpc('initialize', {
  protocolVersion: '2025-06-18',
  capabilities: {},
  clientInfo: { name: 'test-client', version: '1.0.0' },
});

/** Builds an MCP server exposing a single tool that does not touch Backlog. */
const createTestServer = () => {
  const server = new McpServer({ name: 'backlog', version: '1.0.0' });
  server.registerTool(
    'echo',
    { description: 'Echoes input', inputSchema: { value: z.string() } },
    async ({ value }) => ({ content: [{ type: 'text', text: value }] })
  );
  return server as unknown as BacklogMCPServer;
};

describe('createMcpHonoApp lazy authentication', () => {
  let app: Awaited<ReturnType<typeof createMcpHonoApp>>;
  let store: ReturnType<typeof createTokenStore>;

  beforeEach(async () => {
    vi.clearAllMocks();
    store = createTokenStore();
    app = await createMcpHonoApp({
      path: '/mcp',
      version: '1.0.0',
      enableJsonResponse: true,
      createServer: createTestServer,
      transports: {},
      oauthConfig,
      tokenStore: store,
    });
  });

  /** Runs an unauthenticated initialize and returns the issued session id. */
  const initializeSession = async (): Promise<string> => {
    const res = await app.request('/mcp', {
      method: 'POST',
      headers: MCP_HEADERS,
      body: INITIALIZE_BODY,
    });
    expect(res.status).toBe(200);
    const sessionId = res.headers.get('mcp-session-id');
    expect(sessionId).toBeTruthy();
    return sessionId as string;
  };

  it('allows an unauthenticated initialize and issues a session', async () => {
    const res = await app.request('/mcp', {
      method: 'POST',
      headers: MCP_HEADERS,
      body: INITIALIZE_BODY,
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('mcp-session-id')).toBeTruthy();
    const payload = await res.json();
    expect(payload.result.serverInfo.name).toBe('backlog');
  });

  it('lists tools without authentication so clients can render the catalog', async () => {
    const sessionId = await initializeSession();

    const res = await app.request('/mcp', {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sessionId },
      body: rpc('tools/list', {}, 2),
    });

    expect(res.status).toBe(200);
    const payload = await res.json();
    const names = payload.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain('echo');
  });

  it('rejects an unauthenticated tools/call with a 401 challenge', async () => {
    const sessionId = await initializeSession();

    const res = await app.request('/mcp', {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sessionId },
      body: rpc('tools/call', { name: 'echo', arguments: { value: 'hi' } }, 3),
    });

    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('resource_metadata');
    const payload = await res.json();
    expect(payload.error).toBe('invalid_token');
  });

  it('executes tools/call when a valid Bearer token is presented', async () => {
    const sessionId = await initializeSession();
    store.storeMcpToken('valid-token', {
      backlogAccessToken: 'bl-token',
      clientId: 'c1',
      expiresAt: Date.now() + 3600_000,
    });
    store.cacheVerification(
      'valid-token',
      { token: 'bl-token', clientId: '1', scopes: [], expiresAt: 0 },
      300_000
    );

    const res = await app.request('/mcp', {
      method: 'POST',
      headers: {
        ...MCP_HEADERS,
        'mcp-session-id': sessionId,
        Authorization: 'Bearer valid-token',
      },
      body: rpc('tools/call', { name: 'echo', arguments: { value: 'hi' } }, 4),
    });

    expect(res.status).toBe(200);
    const payload = await res.json();
    expect(payload.result.content[0].text).toBe('hi');
  });
});

describe('createMcpHonoApp stateless mode', () => {
  let app: Awaited<ReturnType<typeof createMcpHonoApp>>;
  let store: ReturnType<typeof createTokenStore>;

  beforeEach(async () => {
    vi.clearAllMocks();
    store = createTokenStore();
    app = await createMcpHonoApp({
      path: '/mcp',
      version: '1.0.0',
      enableJsonResponse: false,
      createServer: createTestServer,
      transports: {},
      oauthConfig,
      tokenStore: store,
      stateless: true,
    });
  });

  it('lists tools without any session id (no initialize handshake)', async () => {
    const res = await app.request('/mcp', {
      method: 'POST',
      headers: MCP_HEADERS,
      body: rpc('tools/list', {}, 1),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('mcp-session-id')).toBeNull();
    const payload = await res.json();
    const names = payload.result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain('echo');
  });

  it('still gates tools/call behind authentication', async () => {
    const res = await app.request('/mcp', {
      method: 'POST',
      headers: MCP_HEADERS,
      body: rpc('tools/call', { name: 'echo', arguments: { value: 'hi' } }, 2),
    });

    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('resource_metadata');
  });

  it('executes an authenticated tools/call without a session id', async () => {
    store.storeMcpToken('valid-token', {
      backlogAccessToken: 'bl-token',
      clientId: 'c1',
      expiresAt: Date.now() + 3600_000,
    });
    store.cacheVerification(
      'valid-token',
      { token: 'bl-token', clientId: '1', scopes: [], expiresAt: 0 },
      300_000
    );

    const res = await app.request('/mcp', {
      method: 'POST',
      headers: { ...MCP_HEADERS, Authorization: 'Bearer valid-token' },
      body: rpc('tools/call', { name: 'echo', arguments: { value: 'hi' } }, 3),
    });

    expect(res.status).toBe(200);
    const payload = await res.json();
    expect(payload.result.content[0].text).toBe('hi');
  });

  it('rejects GET because there is no standalone stream to attach', async () => {
    const res = await app.request('/mcp', {
      method: 'GET',
      headers: MCP_HEADERS,
    });

    expect(res.status).toBe(405);
  });
});
