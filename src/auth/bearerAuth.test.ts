// Copyright (c) 2025 Nulab inc.
// Licensed under the MIT License.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createBearerAuthResolver } from './bearerAuth.js';
import { createTokenStore } from './tokenStore.js';
import type { BacklogOAuthConfig } from './backlogOAuthConfig.js';

vi.mock('./backlogOAuthClient.js', () => ({
  verifyBacklogToken: vi.fn(),
}));

import { verifyBacklogToken } from './backlogOAuthClient.js';

const config: BacklogOAuthConfig = {
  clientId: 'cid',
  clientSecret: 'csecret',
  backlogDomain: 'example.backlog.com',
  serverBaseUrl: 'https://mcp.example.com',
};

describe('createBearerAuthResolver', () => {
  let store: ReturnType<typeof createTokenStore>;
  let resolve: ReturnType<typeof createBearerAuthResolver>;

  beforeEach(() => {
    vi.clearAllMocks();
    store = createTokenStore();
    resolve = createBearerAuthResolver(store, config, '/mcp');
  });

  it('fails with a resource_metadata challenge when the header is missing', async () => {
    const result = await resolve(undefined);

    expect(result.authenticated).toBe(false);
    if (result.authenticated) throw new Error('expected failure');
    expect(result.errorDescription).toBe('Missing Authorization header');
    expect(result.wwwAuthenticate).toContain(
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
    );
  });

  it('fails for a non-Bearer scheme', async () => {
    const result = await resolve('Basic abc123');

    expect(result.authenticated).toBe(false);
    if (result.authenticated) throw new Error('expected failure');
    expect(result.errorDescription).toBe('Expected Bearer token');
    expect(result.wwwAuthenticate).toContain(
      'Invalid Authorization header format'
    );
  });

  it('fails for an unknown MCP token', async () => {
    const result = await resolve('Bearer unknown-mcp-token');

    expect(result.authenticated).toBe(false);
    if (result.authenticated) throw new Error('expected failure');
    expect(result.errorDescription).toBe('Unknown or expired token');
  });

  it('authenticates from cached verification without calling Backlog', async () => {
    store.storeMcpToken('mcp-token-1', {
      backlogAccessToken: 'bl-token-1',
      clientId: 'c1',
      expiresAt: Date.now() + 3600_000,
    });
    const cached = { token: 'bl-token-1', clientId: '1', scopes: [], expiresAt: 0 };
    store.cacheVerification('mcp-token-1', cached, 300_000);

    const result = await resolve('Bearer mcp-token-1');

    expect(result.authenticated).toBe(true);
    if (!result.authenticated) throw new Error('expected success');
    expect(result.authInfo).toEqual(cached);
    expect(vi.mocked(verifyBacklogToken)).not.toHaveBeenCalled();
  });

  it('verifies the Backlog token when valid but not cached', async () => {
    store.storeMcpToken('mcp-token-2', {
      backlogAccessToken: 'bl-token-2',
      clientId: 'c1',
      expiresAt: Date.now() + 3600_000,
    });
    vi.mocked(verifyBacklogToken).mockResolvedValue({
      id: 42,
      userId: 'user42',
      name: 'Test User',
    });

    const result = await resolve('Bearer mcp-token-2');

    expect(result.authenticated).toBe(true);
    if (!result.authenticated) throw new Error('expected success');
    expect(result.authInfo.token).toBe('bl-token-2');
    expect(result.authInfo.clientId).toBe('42');
    expect(verifyBacklogToken).toHaveBeenCalledWith(
      'example.backlog.com',
      'bl-token-2'
    );
  });

  it('fails when Backlog token verification throws', async () => {
    store.storeMcpToken('mcp-token-3', {
      backlogAccessToken: 'bl-bad-token',
      clientId: 'c1',
      expiresAt: Date.now() + 3600_000,
    });
    vi.mocked(verifyBacklogToken).mockRejectedValue(new Error('invalid'));

    const result = await resolve('Bearer mcp-token-3');

    expect(result.authenticated).toBe(false);
    if (result.authenticated) throw new Error('expected failure');
    expect(result.errorDescription).toBe('Token verification failed');
  });
});
