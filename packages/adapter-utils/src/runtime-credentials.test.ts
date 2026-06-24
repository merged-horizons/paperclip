import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  adapterExecutionTargetSessionIdentity,
  parseAdapterExecutionTarget,
  adapterExecutionTargetToRemoteSpec,
  materializeAdapterRuntimeCredentialAsset,
  normalizeAdapterRuntimeCredentialMaterialization,
  readAdapterExecutionTargetTextFile,
  type AdapterExecutionTarget,
} from "./execution-target.js";
import { buildInvocationEnvForLogs } from "./server-utils.js";

const tempRoots: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  tempRoots.push(tempDir);
  return tempDir;
}

describe("runtime credential materialization", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((tempRoot) => fs.rm(tempRoot, { recursive: true, force: true })));
  });

  it("overlays credential files as regular files instead of preserving base symlinks", async () => {
    const baseDir = await makeTempDir("paperclip-runtime-credential-base-");
    await fs.writeFile(path.join(baseDir, "host-auth.json"), '{"host":true}', "utf8");
    await fs.symlink("host-auth.json", path.join(baseDir, "auth.json"));

    const materialized = await materializeAdapterRuntimeCredentialAsset({
      baseDir,
      files: [
        {
          relativePath: "auth.json",
          contents: '{"runtime":true}',
          mode: 0o600,
        },
      ],
      tempPrefix: "paperclip-runtime-credential-test-",
    });
    tempRoots.push(materialized.localDir);

    expect(materialized.materialized).toBe(true);
    expect(await fs.readFile(path.join(materialized.localDir, "auth.json"), "utf8")).toBe('{"runtime":true}');
    expect((await fs.lstat(path.join(materialized.localDir, "auth.json"))).isSymbolicLink()).toBe(false);
    expect(await fs.readFile(path.join(baseDir, "auth.json"), "utf8")).toBe('{"host":true}');
  });

  it("rejects absolute and escaping credential file paths", async () => {
    await expect(
      materializeAdapterRuntimeCredentialAsset({
        baseDir: null,
        files: [{ relativePath: "../auth.json", contents: "{}" }],
      }),
    ).rejects.toThrow(/Invalid runtime credential relative path/);

    await expect(
      materializeAdapterRuntimeCredentialAsset({
        baseDir: null,
        files: [{ relativePath: "/auth.json", contents: "{}" }],
      }),
    ).rejects.toThrow(/Invalid runtime credential relative path/);
  });

  it("redacts explicitly sensitive runtime credential env keys in invocation metadata", () => {
    expect(
      buildInvocationEnvForLogs(
        {
          CUSTOM_RUNTIME_TOKEN: "redacted-by-key-pattern",
          PLAIN_CREDENTIAL: "secret-value",
        },
        {
          explicitSensitiveKeys: ["PLAIN_CREDENTIAL"],
        },
      ),
    ).toMatchObject({
      CUSTOM_RUNTIME_TOKEN: "***REDACTED***",
      PLAIN_CREDENTIAL: "***REDACTED***",
    });
  });

  it("keeps runtime credential material out of remote specs and session identity", () => {
    const target: AdapterExecutionTarget = {
      kind: "remote",
      transport: "sandbox",
      providerKey: "fake",
      remoteCwd: "/workspace",
      runtimeCredentialMaterialization: {
        provider: "codex",
        assets: {
          home: {
            files: [{ relativePath: "auth.json", contents: "runtime-secret" }],
          },
        },
      },
    };

    expect(JSON.stringify(adapterExecutionTargetToRemoteSpec(target))).not.toContain("runtime-secret");
    expect(JSON.stringify(adapterExecutionTargetSessionIdentity(target))).not.toContain("runtime-secret");
  });

  it("preserves normalized credential envelopes when execution targets are serialized", () => {
    expect(
      parseAdapterExecutionTarget({
        kind: "remote",
        transport: "sandbox",
        providerKey: "fake",
        environmentId: "env-1",
        leaseId: "lease-1",
        remoteCwd: "/workspace",
        runtimeCredentialMaterialization: {
          provider: "codex",
          env: {
            IGNORED_NON_STRING: 123,
            CODEX_TOKEN: "runtime-secret",
          },
          assets: {
            home: {
              files: [{ relativePath: "auth.json", contents: "{}" }],
            },
          },
        },
      }),
    ).toMatchObject({
      kind: "remote",
      transport: "sandbox",
      runtimeCredentialMaterialization: {
        provider: "codex",
        env: {
          CODEX_TOKEN: "runtime-secret",
        },
        assets: {
          home: {
            files: [{ relativePath: "auth.json", contents: "{}" }],
          },
        },
      },
    });
  });

  it("normalizes valid credential materialization envelopes", () => {
    expect(
      normalizeAdapterRuntimeCredentialMaterialization({
        provider: "codex",
        env: {
          CODEX_TOKEN: "secret",
          IGNORED: 42,
        },
        assets: {
          home: {
            files: [{ relativePath: "auth.json", contents: "{}" }],
          },
        },
      }),
    ).toEqual({
      provider: "codex",
      env: {
        CODEX_TOKEN: "secret",
      },
      assets: {
        home: {
          files: [{ relativePath: "auth.json", contents: "{}" }],
        },
      },
    });
  });

  it("reads bounded local execution-target text files without logging credentials", async () => {
    const baseDir = await makeTempDir("paperclip-runtime-credential-read-");
    const credentialFile = path.join(baseDir, "auth.json");
    await fs.writeFile(credentialFile, '{"refresh_token":"rotated"}', "utf8");

    await expect(
      readAdapterExecutionTargetTextFile("run-1", null, credentialFile, {
        cwd: baseDir,
        env: {},
        maxBytes: 128,
      }),
    ).resolves.toBe('{"refresh_token":"rotated"}');

    await expect(
      readAdapterExecutionTargetTextFile("run-1", null, path.join(baseDir, "missing.json"), {
        cwd: baseDir,
        env: {},
      }),
    ).resolves.toBeNull();

    await expect(
      readAdapterExecutionTargetTextFile("run-1", null, credentialFile, {
        cwd: baseDir,
        env: {},
        maxBytes: 4,
      }),
    ).rejects.toThrow(/Refusing to read/);
  });
});
