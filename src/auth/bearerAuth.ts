// Copyright (c) 2025 Nulab inc.
// Licensed under the MIT License.

import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BacklogOAuthConfig } from './backlogOAuthConfig.js';
import { verifyBacklogToken } from './backlogOAuthClient.js';
import type { TokenStore } from './tokenStore.js';
import { logger } from '../utils/logger.js';

const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Outcome of resolving the `Authorization` header on an MCP request.
 *
 * `authenticated: true` carries the verified {@link AuthInfo}; the failure
 * variant carries the `WWW-Authenticate` challenge the caller must send when it
 * decides the request actually requires authentication. Resolving is decoupled
 * from enforcing so the MCP handler can allow unauthenticated discovery
 * (`initialize`, `tools/list`) while still gating tool execution (lazy auth).
 */
export type BearerAuthResult =
  | { authenticated: true; authInfo: AuthInfo }
  | { authenticated: false; errorDescription: string; wwwAuthenticate: string };

/**
 * Builds a resolver that verifies the Bearer token on an MCP request without
 * enforcing authentication itself.
 *
 * The returned function never throws and never short-circuits the request; it
 * reports whether a valid token was presented so the caller can decide, per
 * JSON-RPC method, whether to require it.
 */
export function createBearerAuthResolver(
  store: TokenStore,
  config: BacklogOAuthConfig,
  mcpPath: string
): (authHeader: string | undefined) => Promise<BearerAuthResult> {
  const prmPath = mcpPath === '/' ? '' : mcpPath;
  const resourceMetadataUrl = `${config.serverBaseUrl}/.well-known/oauth-protected-resource${prmPath}`;

  const challenge = (challengeDescription?: string): string =>
    challengeDescription
      ? `Bearer error="invalid_token", error_description="${challengeDescription}", resource_metadata="${resourceMetadataUrl}"`
      : `Bearer resource_metadata="${resourceMetadataUrl}"`;

  const failure = (
    errorDescription: string,
    challengeDescription?: string
  ): BearerAuthResult => ({
    authenticated: false,
    errorDescription,
    wwwAuthenticate: challenge(challengeDescription),
  });

  return async (authHeader) => {
    if (!authHeader) {
      return failure('Missing Authorization header');
    }

    const [type, mcpToken] = authHeader.split(' ');
    if (type?.toLowerCase() !== 'bearer' || !mcpToken) {
      return failure(
        'Expected Bearer token',
        'Invalid Authorization header format'
      );
    }

    const tokenEntry = store.getMcpToken(mcpToken);
    if (!tokenEntry) {
      logger.info(
        {},
        'MCP access token unknown or expired; client should refresh'
      );
      return failure('Unknown or expired token', 'Unknown or expired token');
    }

    const cached = store.getCachedVerification(mcpToken);
    if (cached) {
      return { authenticated: true, authInfo: cached };
    }

    try {
      const user = await verifyBacklogToken(
        config.backlogDomain,
        tokenEntry.backlogAccessToken
      );
      const authInfo: AuthInfo = {
        token: tokenEntry.backlogAccessToken,
        clientId: String(user.id),
        scopes: [],
        expiresAt: Math.floor(Date.now() / 1000) + CACHE_TTL_MS / 1000,
      };
      store.cacheVerification(mcpToken, authInfo, CACHE_TTL_MS);
      return { authenticated: true, authInfo };
    } catch (err) {
      logger.warn({ err }, 'Bearer token verification failed');
      return failure('Token verification failed', 'Token verification failed');
    }
  };
}
