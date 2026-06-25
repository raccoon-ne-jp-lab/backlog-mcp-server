// Copyright (c) 2025 Nulab inc.
// Licensed under the MIT License.

import { randomUUID } from 'node:crypto';

import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { type Context, Hono } from 'hono';
import { runWithAccessToken } from './auth/backlogAuthContext.js';
import type { BearerAuthResult } from './auth/bearerAuth.js';
import type { BacklogOAuthConfig } from './auth/backlogOAuthConfig.js';
import type { TokenStore } from './auth/tokenStore.js';
import {
  BACKLOG_FAVICON_CONTENT_TYPE,
  BACKLOG_FAVICON_SVG,
} from './favicon.js';
import { logger } from './utils/logger.js';
import type { BacklogMCPServer } from './utils/wrapServerWithToolRegistry.js';

export type SessionTransports = Record<
  string,
  WebStandardStreamableHTTPServerTransport
>;

export type CreateMcpHonoAppOptions = {
  path: string;
  version: string;
  enableJsonResponse: boolean;
  /**
   * Host header values accepted as a DNS-rebinding guard. When omitted, the
   * Host header is not checked (appropriate when fronted by a platform that
   * controls the hostname, e.g. Cloudflare Workers).
   */
  allowedHosts?: string[];
  createServer: () => BacklogMCPServer;
  /**
   * Session-id keyed transport registry. Owned by the caller so its lifetime
   * (and therefore session statefulness) is controlled externally — a Durable
   * Object instance for Workers, or a process-lifetime object for Node.
   */
  transports: SessionTransports;
  oauthConfig?: BacklogOAuthConfig;
  tokenStore?: TokenStore;
  /**
   * When true, each request is served by a fresh server + transport with no
   * session id. Required on runtimes whose instance memory is volatile (e.g. a
   * Cloudflare Durable Object that hibernates), where an in-memory session would
   * be lost between a client's `initialize` and its later `tools/list` calls.
   */
  stateless?: boolean;
};

type JsonRpcErrorBody = {
  jsonrpc: '2.0';
  error: { code: number; message: string };
  id: null;
};

const jsonRpcError = (code: number, message: string): JsonRpcErrorBody => {
  return { jsonrpc: '2.0', error: { code, message }, id: null };
};

const bodyContainsInitialize = (body: unknown): boolean => {
  return (Array.isArray(body) ? body : [body]).some(isInitializeRequest);
};

/**
 * JSON-RPC methods that execute tools and therefore require a verified token.
 * Everything else (`initialize`, `tools/list`, `ping`, notifications, …) is part
 * of the unauthenticated discovery surface so clients can preview the catalog.
 */
const AUTH_REQUIRED_METHODS = new Set(['tools/call']);

/**
 * Reports whether any JSON-RPC message in the (possibly batched) body invokes a
 * method that requires authentication.
 */
const bodyRequiresAuth = (body: unknown): boolean => {
  return (Array.isArray(body) ? body : [body]).some(
    (message) =>
      typeof message === 'object' &&
      message !== null &&
      AUTH_REQUIRED_METHODS.has((message as { method?: string }).method ?? '')
  );
};

/**
 * Responds with the Backlog favicon SVG and a long-lived cache header.
 */
const serveFavicon = (c: Context): Response => {
  c.header('Content-Type', BACKLOG_FAVICON_CONTENT_TYPE);
  c.header('Cache-Control', 'public, max-age=86400');
  return c.body(BACKLOG_FAVICON_SVG);
};

const parseHostname = (hostHeader: string): string | null => {
  try {
    return new URL(`http://${hostHeader}`).hostname;
  } catch {
    return null;
  }
};

const checkHostHeader = (
  hostHeader: string | null,
  allowedHostnames: string[]
): JsonRpcErrorBody | null => {
  if (!hostHeader) return jsonRpcError(-32000, 'Missing Host header');
  const hostname = parseHostname(hostHeader);
  if (hostname === null) {
    return jsonRpcError(-32000, `Invalid Host header: ${hostHeader}`);
  }
  return allowedHostnames.includes(hostname)
    ? null
    : jsonRpcError(-32000, `Invalid Host: ${hostname}`);
};

const startNewSession = async (
  req: Request,
  body: unknown,
  enableJsonResponse: boolean,
  transports: SessionTransports,
  createServer: () => BacklogMCPServer,
  authInfo?: AuthInfo
): Promise<Response> => {
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableJsonResponse,
    onsessioninitialized: (sid) => {
      transports[sid] = transport;
    },
  });

  transport.onclose = () => {
    const sid = transport.sessionId;
    if (sid) delete transports[sid];
  };

  await createServer().connect(transport);
  return transport.handleRequest(req, { parsedBody: body, authInfo });
};

/**
 * Serves a single MCP request with a throwaway server + session-less transport.
 *
 * Nothing is retained between requests, so the handler is immune to instance
 * eviction; the trade-off is that server-to-client streaming (notifications,
 * progress) is unavailable. Responses are always JSON.
 */
const handleStatelessRequest = async (
  req: Request,
  body: unknown,
  createServer: () => BacklogMCPServer,
  authInfo?: AuthInfo
): Promise<Response> => {
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await createServer().connect(transport);
  return transport.handleRequest(req, { parsedBody: body, authInfo });
};

/**
 * Builds the Web-standard Hono application that serves the MCP endpoint and,
 * when OAuth is configured, the OAuth authorization-server routes.
 *
 * The returned app is runtime-agnostic (`app.fetch(Request) => Response`) so it
 * can be served directly from a Cloudflare Workers / Durable Object `fetch`
 * handler, or any other Web-standard fetch runtime.
 */
export const createMcpHonoApp = async (
  options: CreateMcpHonoAppOptions
): Promise<Hono<{ Variables: { authInfo?: AuthInfo } }>> => {
  const {
    path: mcpPath,
    version,
    enableJsonResponse,
    allowedHosts,
    createServer,
    transports,
    oauthConfig,
    tokenStore,
    stateless = false,
  } = options;

  const app = new Hono<{ Variables: { authInfo?: AuthInfo } }>();
  const allowedHostnames = allowedHosts?.length ? allowedHosts : undefined;
  const oauthEnabled = !!(oauthConfig && tokenStore);

  if (allowedHostnames) {
    app.use('*', async (c, next) => {
      const hostError = checkHostHeader(
        c.req.raw.headers.get('host'),
        allowedHostnames
      );
      if (hostError) return c.json(hostError, 403);
      await next();
    });
  }

  app.get('/health', (c) =>
    c.json({ status: 'healthy', timestamp: new Date().toISOString(), version })
  );

  // Serve the Backlog favicon for browser requests that hit the server during
  // the OAuth flow. Both paths return the same SVG; modern browsers honor the
  // Content-Type over the `.ico` extension.
  app.get('/favicon.ico', (c) => serveFavicon(c));
  app.get('/favicon.svg', (c) => serveFavicon(c));

  let resolveAuth:
    | ((authHeader: string | undefined) => Promise<BearerAuthResult>)
    | undefined;
  if (oauthEnabled) {
    const { createOAuthRoutes } = await import('./auth/oauthRoutes.js');
    const { createBearerAuthResolver } = await import('./auth/bearerAuth.js');

    app.route('/', createOAuthRoutes(oauthConfig, tokenStore, mcpPath));
    resolveAuth = createBearerAuthResolver(tokenStore, oauthConfig, mcpPath);
  }

  app.all(mcpPath, async (c) => {
    const req = c.req.raw;
    const sessionId = req.headers.get('mcp-session-id');

    try {
      // Parse the JSON-RPC body up front for POST requests: it drives both
      // session routing and the lazy-auth gate, and the stream can only be read
      // once, so the parsed value is forwarded to the transport as `parsedBody`.
      let body: unknown;
      if (req.method === 'POST') {
        const parsed = await req.json().then(
          (value: unknown) => ({ value }),
          () => null
        );
        if (!parsed) {
          return c.json(jsonRpcError(-32700, 'Parse error: Invalid JSON'), 400);
        }
        body = parsed.value;
      }

      // Lazy authentication: discovery and listing flow through unauthenticated
      // so clients can render the tool catalog; only tool execution requires a
      // verified token (a 401 there triggers the OAuth flow).
      let authInfo: AuthInfo | undefined;
      if (resolveAuth) {
        const result = await resolveAuth(c.req.header('authorization'));
        if (result.authenticated) {
          authInfo = result.authInfo;
        } else if (bodyRequiresAuth(body)) {
          c.header('WWW-Authenticate', result.wwwAuthenticate);
          return c.json(
            {
              error: 'invalid_token',
              error_description: result.errorDescription,
            },
            401
          );
        }
      }
      const accessToken = authInfo?.token;

      // Stateless mode: serve every request with a throwaway server/transport so
      // nothing depends on retained session state. Session-less transports only
      // handle POST; there is no standalone SSE stream to attach a GET/DELETE to.
      if (stateless) {
        if (req.method !== 'POST') {
          return c.json(
            jsonRpcError(
              -32000,
              'Method Not Allowed: stateless server accepts POST only.'
            ),
            405
          );
        }
        const handleStateless = () =>
          handleStatelessRequest(req, body, createServer, authInfo);
        return accessToken
          ? runWithAccessToken(accessToken, handleStateless)
          : handleStateless();
      }

      if (sessionId && transports[sessionId]) {
        const options =
          body === undefined ? { authInfo } : { parsedBody: body, authInfo };
        const handleExisting = () =>
          transports[sessionId].handleRequest(req, options);
        return accessToken
          ? runWithAccessToken(accessToken, handleExisting)
          : handleExisting();
      }

      if (sessionId) {
        return c.json(
          jsonRpcError(
            -32000,
            'Bad Request: Unknown or expired session ID. Send a new initialize request without mcp-session-id.'
          ),
          400
        );
      }

      if (req.method !== 'POST') {
        return c.json(
          jsonRpcError(-32000, 'Bad Request: No mcp-session-id header.'),
          400
        );
      }

      if (!bodyContainsInitialize(body)) {
        const err = jsonRpcError(
          -32000,
          'Bad Request: No mcp-session-id header and body is not an initialize request.'
        );
        return c.json(Array.isArray(body) ? [err] : err, 400);
      }

      const handleNew = () =>
        startNewSession(
          req,
          body,
          enableJsonResponse,
          transports,
          createServer,
          authInfo
        );

      return accessToken
        ? runWithAccessToken(accessToken, handleNew)
        : handleNew();
    } catch (error) {
      logger.error({ err: error }, 'Error handling MCP request');
      return c.json(jsonRpcError(-32603, 'Internal server error'), 500);
    }
  });

  return app;
};
