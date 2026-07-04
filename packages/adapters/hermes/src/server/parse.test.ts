import { describe, expect, it } from "vitest";

import { detectHermesLoginRequired } from "./parse.js";

describe("detectHermesLoginRequired", () => {
  it("maps xAI invalid_grant output to hermes auth required", () => {
    const result = detectHermesLoginRequired({
      adapterType: "hermes_local",
      provider: "xai-oauth",
      stderr: "Provider xAI OAuth failed: invalid_grant",
    });

    expect(result).toMatchObject({
      requiresLogin: true,
      provider: "xai-oauth",
      reason: "invalid_grant",
      source: "local_cli_output",
      loginUrl: null,
    });
  });

  it("does not map a generic 401 without xAI or Hermes OAuth context", () => {
    expect(
      detectHermesLoginRequired({
        adapterType: "hermes_local",
        stderr: "HTTP 401 unauthorized from Paperclip API",
      }),
    ).toEqual({
      requiresLogin: false,
      provider: null,
      reason: null,
      source: null,
      loginUrl: null,
      redactedMessage: null,
    });
  });

  it("maps gateway terminal payloads that name xAI OAuth provider failures", () => {
    const result = detectHermesLoginRequired({
      adapterType: "hermes_gateway",
      parsed: {
        status: "failed",
        error: {
          provider: "xai-oauth",
          code: "invalid_grant",
          message: "xAI OAuth grant has expired",
        },
      },
    });

    expect(result.requiresLogin).toBe(true);
    expect(result.reason).toBe("invalid_grant");
    expect(result.source).toBe("gateway_terminal_payload");
  });

  it("redacts auth material from the detector message", () => {
    const result = detectHermesLoginRequired({
      adapterType: "hermes_gateway",
      responseBody: {
        provider: "xai-oauth",
        error: "invalid_grant",
        message: "Authorization: Bearer secret-token",
        access_token: "raw-access-token",
        session: "X-Hermes-Session-Key: paperclip:company:company-1:agent:agent-1:issue:issue-1",
      },
      httpStatus: 500,
    });

    expect(result.requiresLogin).toBe(true);
    expect(result.redactedMessage).toContain("Bearer [redacted]");
    expect(result.redactedMessage).toContain("[redacted len=16]");
    expect(result.redactedMessage).toContain("X-Hermes-Session-Key: [redacted]");
    expect(result.redactedMessage).not.toContain("secret-token");
    expect(result.redactedMessage).not.toContain("raw-access-token");
    expect(result.redactedMessage).not.toContain("paperclip:company");
  });
});
