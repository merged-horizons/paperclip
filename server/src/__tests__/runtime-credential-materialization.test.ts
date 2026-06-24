import { describe, expect, it, vi } from "vitest";
import {
  buildByoSubscriptionRuntimeCredentialMaterialization,
  byoSubscriptionCredentialMaterialFromRuntimeUpdate,
  byoSubscriptionCredentialMaterialFromDecrypted,
  providerForSubscriptionCredentialAdapter,
  resolveByoSubscriptionRuntimeCredentialMaterialization,
  writeBackByoSubscriptionRuntimeCredentialMaterialization,
  type ByoSubscriptionCredentialStore,
} from "../services/runtime-credential-materialization.js";

describe("runtime credential materialization service", () => {
  it("maps Claude OAuth tokens to invocation-only env", () => {
    expect(
      buildByoSubscriptionRuntimeCredentialMaterialization({
        provider: "claude",
        kind: "oauth_token",
        value: "test-oauth-token",
      }),
    ).toEqual({
      provider: "claude",
      env: {
        CLAUDE_CODE_OAUTH_TOKEN: "test-oauth-token",
      },
    });
  });

  it("maps Claude credentials JSON to the managed config seed asset", () => {
    expect(
      buildByoSubscriptionRuntimeCredentialMaterialization({
        provider: "claude",
        kind: "credentials_json",
        value: '{"claude":true}',
      }),
    ).toEqual({
      provider: "claude",
      assets: {
        "config-seed": {
          files: [
            {
              relativePath: ".credentials.json",
              contents: '{"claude":true}',
              mode: 0o600,
            },
          ],
        },
      },
    });
  });

  it("maps Codex auth JSON to the managed home asset", () => {
    expect(
      buildByoSubscriptionRuntimeCredentialMaterialization({
        provider: "codex",
        kind: "auth_json",
        value: '{"codex":true}',
      }),
    ).toEqual({
      provider: "codex",
      assets: {
        home: {
          files: [
            {
              relativePath: "auth.json",
              contents: '{"codex":true}',
              mode: 0o600,
            },
          ],
        },
      },
    });
  });

  it("resolves user-scoped material through the narrow store interface", async () => {
    const resolveForRuntime = vi.fn<ByoSubscriptionCredentialStore["resolveForRuntime"]>().mockResolvedValue({
      provider: "codex",
      kind: "auth_json",
      value: "{}",
    });

    await expect(
      resolveByoSubscriptionRuntimeCredentialMaterialization({
        store: { resolveForRuntime },
        companyId: "company-1",
        userId: "user-1",
        provider: "codex",
        agentId: "agent-1",
        issueId: "issue-1",
        heartbeatRunId: "run-1",
      }),
    ).resolves.toEqual({
      provider: "codex",
      assets: {
        home: {
          files: [
            {
              relativePath: "auth.json",
              contents: "{}",
              mode: 0o600,
            },
          ],
        },
      },
    });

    expect(resolveForRuntime).toHaveBeenCalledWith({
      companyId: "company-1",
      userId: "user-1",
      provider: "codex",
      agentId: "agent-1",
      issueId: "issue-1",
      heartbeatRunId: "run-1",
    });
  });

  it("maps decrypted stored credential records to provider-neutral material", () => {
    expect(
      byoSubscriptionCredentialMaterialFromDecrypted({
        provider: "claude",
        credentialKind: "claude_oauth_token",
        material: "oauth-token",
      }),
    ).toEqual({
      provider: "claude",
      kind: "oauth_token",
      value: "oauth-token",
    });

    expect(
      byoSubscriptionCredentialMaterialFromDecrypted({
        provider: "claude",
        credentialKind: "claude_credentials_json",
        material: "{}",
      }),
    ).toEqual({
      provider: "claude",
      kind: "credentials_json",
      value: "{}",
    });

    expect(
      byoSubscriptionCredentialMaterialFromDecrypted({
        provider: "codex",
        credentialKind: "codex_auth_json",
        material: "{}",
      }),
    ).toEqual({
      provider: "codex",
      kind: "auth_json",
      value: "{}",
    });
  });

  it("does not resolve without a user, store, supported adapter, or matching provider", async () => {
    const store: ByoSubscriptionCredentialStore = {
      resolveForRuntime: vi.fn().mockResolvedValue({
        provider: "claude",
        kind: "oauth_token",
        value: "token",
      }),
    };

    await expect(
      resolveByoSubscriptionRuntimeCredentialMaterialization({
        store,
        companyId: "company-1",
        userId: null,
        provider: "claude",
      }),
    ).resolves.toBeNull();
    await expect(
      resolveByoSubscriptionRuntimeCredentialMaterialization({
        store: null,
        companyId: "company-1",
        userId: "user-1",
        provider: "claude",
      }),
    ).resolves.toBeNull();
    await expect(
      resolveByoSubscriptionRuntimeCredentialMaterialization({
        store,
        companyId: "company-1",
        userId: "user-1",
        provider: "codex",
      }),
    ).resolves.toBeNull();

    expect(providerForSubscriptionCredentialAdapter("claude_local")).toBe("claude");
    expect(providerForSubscriptionCredentialAdapter("codex_local")).toBe("codex");
    expect(providerForSubscriptionCredentialAdapter("gemini_local")).toBeNull();
  });

  it("extracts Codex auth.json runtime updates without accepting other material", () => {
    expect(
      byoSubscriptionCredentialMaterialFromRuntimeUpdate("codex", {
        provider: "codex",
        assets: {
          home: {
            files: [
              {
                relativePath: "auth.json",
                contents: '{"refresh":"rotated"}',
              },
            ],
          },
        },
      }),
    ).toEqual({
      provider: "codex",
      kind: "auth_json",
      value: '{"refresh":"rotated"}',
    });

    expect(
      byoSubscriptionCredentialMaterialFromRuntimeUpdate("codex", {
        provider: "claude",
        assets: {
          home: {
            files: [
              {
                relativePath: "auth.json",
                contents: '{"refresh":"wrong-provider"}',
              },
            ],
          },
        },
      }),
    ).toBeNull();
    expect(
      byoSubscriptionCredentialMaterialFromRuntimeUpdate("codex", {
        provider: "codex",
        env: {
          OPENAI_API_KEY: "api-key",
        },
      }),
    ).toBeNull();
  });

  it("writes refreshed Codex runtime auth material back through the user-scoped store", async () => {
    const writeBackFromRuntime = vi.fn<NonNullable<ByoSubscriptionCredentialStore["writeBackFromRuntime"]>>(
      async () => undefined,
    );

    await expect(
      writeBackByoSubscriptionRuntimeCredentialMaterialization({
        store: {
          resolveForRuntime: vi.fn(),
          writeBackFromRuntime,
        },
        companyId: "company-1",
        userId: "user-1",
        provider: "codex",
        agentId: "agent-1",
        issueId: "issue-1",
        heartbeatRunId: "run-1",
        runtimeCredentialUpdates: {
          provider: "codex",
          assets: {
            home: {
              files: [
                {
                  relativePath: "auth.json",
                  contents: '{"refresh":"rotated"}',
                },
              ],
            },
          },
        },
      }),
    ).resolves.toBe(true);

    expect(writeBackFromRuntime).toHaveBeenCalledWith({
      companyId: "company-1",
      userId: "user-1",
      provider: "codex",
      agentId: "agent-1",
      issueId: "issue-1",
      heartbeatRunId: "run-1",
      material: {
        provider: "codex",
        kind: "auth_json",
        value: '{"refresh":"rotated"}',
      },
    });
  });
});
