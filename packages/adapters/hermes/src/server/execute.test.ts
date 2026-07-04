import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AdapterExecutionContext } from "@paperclipai/adapter-utils";
import { runChildProcess } from "@paperclipai/adapter-utils/server-utils";

vi.mock("@paperclipai/adapter-utils/server-utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@paperclipai/adapter-utils/server-utils")>();
  return {
    ...actual,
    runChildProcess: vi.fn(),
  };
});

vi.mock("./detect-model.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./detect-model.js")>();
  return {
    ...actual,
    detectModel: vi.fn(async () => null),
  };
});

import { execute } from "./execute.js";

function makeCtx(config: Record<string, unknown> = {}): AdapterExecutionContext {
  return {
    runId: "run-1",
    agent: {
      id: "agent-1",
      companyId: "company-1",
      name: "Hermes",
      adapterType: "hermes_local",
      adapterConfig: config,
    },
    runtime: {
      sessionId: null,
      sessionParams: null,
      sessionDisplayId: null,
      taskKey: null,
    },
    config,
    context: {},
    onLog: vi.fn(async () => undefined),
    onMeta: vi.fn(async () => undefined),
  };
}

const mockedRunChildProcess = vi.mocked(runChildProcess);

beforeEach(() => {
  mockedRunChildProcess.mockReset();
});

describe("execute", () => {
  it("returns hermes_auth_required for xAI OAuth invalid_grant failures", async () => {
    mockedRunChildProcess.mockResolvedValueOnce({
      exitCode: 1,
      signal: null,
      timedOut: false,
      stdout: "",
      stderr: "xAI OAuth provider failed: invalid_grant Authorization: Bearer secret-token",
      pid: 123,
      startedAt: "2026-07-04T00:00:00.000Z",
    });

    const result = await execute(makeCtx());

    expect(result.exitCode).toBe(1);
    expect(result.errorCode).toBe("hermes_auth_required");
    expect(result.errorMessage).toBe("Hermes xAI OAuth login required");
    expect(result.errorMeta).toEqual({
      provider: "xai-oauth",
      reason: "invalid_grant",
      login: {
        supported: true,
        route: "/api/agents/{id}/hermes-login",
      },
    });
    expect(JSON.stringify(result)).not.toContain("secret-token");
  });

  it("leaves generic non-Hermes auth stderr in the existing failure shape", async () => {
    mockedRunChildProcess.mockResolvedValueOnce({
      exitCode: 1,
      signal: null,
      timedOut: false,
      stdout: "",
      stderr: "Error: HTTP 401 unauthorized from Paperclip API",
      pid: 123,
      startedAt: "2026-07-04T00:00:00.000Z",
    });

    const result = await execute(makeCtx());

    expect(result.exitCode).toBe(1);
    expect(result.errorCode).toBeUndefined();
    expect(result.errorMessage).toBe("Error: HTTP 401 unauthorized from Paperclip API");
  });
});
