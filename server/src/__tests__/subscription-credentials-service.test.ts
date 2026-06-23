import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SubscriptionCredentialProvider } from "@paperclipai/shared";
import { getSecretProvider } from "../secrets/provider-registry.js";
import { subscriptionCredentialService } from "../services/subscription-credentials.js";

const mockSecretProvider = vi.hoisted(() => ({
  createSecret: vi.fn(),
  resolveVersion: vi.fn(),
}));

vi.mock("../secrets/provider-registry.js", () => ({
  getSecretProvider: vi.fn(() => mockSecretProvider),
}));

const NOW = new Date("2026-01-01T00:00:00.000Z");
const ENCRYPTED_MATERIAL = {
  scheme: "local_encrypted",
  ciphertext: "encrypted-token",
};

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function makeCredentialRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    companyId: "22222222-2222-4222-8222-222222222222",
    userId: "user-1",
    provider: "claude",
    credentialKind: "claude_oauth_token",
    secretProvider: "local_encrypted",
    material: ENCRYPTED_MATERIAL,
    valueSha256: sha256Hex("plain-token"),
    redactedMetadata: null,
    status: "active",
    lastTestedAt: null,
    lastTestStatus: null,
    lastResolvedAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function makeFakeDb(options: {
  findFirstRows?: Array<Record<string, unknown> | undefined>;
  findManyRows?: Array<Record<string, unknown>>;
  insertReturningRow?: Record<string, unknown>;
  updateReturningRows?: Array<Record<string, unknown>>;
} = {}) {
  const state = {
    insertedValues: undefined as Record<string, unknown> | undefined,
    conflictUpdate: undefined as Record<string, unknown> | undefined,
    updateValues: [] as Array<Record<string, unknown>>,
  };
  const findFirstRows = [...(options.findFirstRows ?? [])];

  const db = {
    query: {
      userSubscriptionCredentials: {
        findFirst: vi.fn(async () => findFirstRows.shift()),
        findMany: vi.fn(async () => options.findManyRows ?? []),
      },
    },
    insert: vi.fn(() => ({
      values: vi.fn((values: Record<string, unknown>) => {
        state.insertedValues = values;
        const row = options.insertReturningRow ?? makeCredentialRow(values);
        return {
          onConflictDoUpdate: vi.fn((conflict: Record<string, unknown>) => {
            state.conflictUpdate = conflict.set as Record<string, unknown>;
            return {
              returning: vi.fn(async () => [row]),
            };
          }),
        };
      }),
    })),
    update: vi.fn(() => ({
      set: vi.fn((values: Record<string, unknown>) => {
        state.updateValues.push(values);
        return {
          where: vi.fn(() => ({
            returning: vi.fn(async () => options.updateReturningRows ?? []),
            catch: vi.fn(async () => undefined),
          })),
        };
      }),
    })),
    delete: vi.fn(() => ({
      where: vi.fn(async () => undefined),
    })),
  };

  return { db: db as any, state };
}

describe("subscriptionCredentialService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSecretProvider.createSecret.mockResolvedValue({
      material: ENCRYPTED_MATERIAL,
      valueSha256: sha256Hex("plain-token"),
    });
    mockSecretProvider.resolveVersion.mockResolvedValue("plain-token");
  });

  it("encrypts credential material before persistence and returns only a redacted read model", async () => {
    const returnedRow = makeCredentialRow({
      material: ENCRYPTED_MATERIAL,
      redactedMetadata: {
        kind: "claude_oauth_token",
        materialLength: "plain-token".length,
        tokenSuffix: "oken",
      },
    });
    const { db, state } = makeFakeDb({ insertReturningRow: returnedRow });
    const svc = subscriptionCredentialService(db);

    const result = await svc.upsert({
      companyId: returnedRow.companyId,
      userId: returnedRow.userId,
      provider: returnedRow.provider as SubscriptionCredentialProvider,
      credentialKind: "claude_oauth_token",
      material: "plain-token",
    });

    expect(getSecretProvider).toHaveBeenCalledWith("local_encrypted");
    expect(mockSecretProvider.createSecret).toHaveBeenCalledWith({ value: "plain-token" });
    expect(state.insertedValues).toMatchObject({
      material: ENCRYPTED_MATERIAL,
      valueSha256: sha256Hex("plain-token"),
    });
    expect(state.insertedValues).not.toMatchObject({ material: "plain-token" });
    expect(result).toMatchObject({
      id: returnedRow.id,
      provider: "claude",
      credentialKind: "claude_oauth_token",
      redactedMetadata: expect.objectContaining({ tokenSuffix: "oken" }),
    });
    expect(result).not.toHaveProperty("material");
  });

  it("resolves decrypted material through the secret provider and records a redacted resolution timestamp", async () => {
    const row = makeCredentialRow();
    const { db, state } = makeFakeDb({ findFirstRows: [row] });
    const svc = subscriptionCredentialService(db);

    const result = await svc.resolveDecryptedMaterial(
      row.companyId as string,
      row.userId as string,
      "claude",
    );

    expect(getSecretProvider).toHaveBeenCalledWith("local_encrypted");
    expect(mockSecretProvider.resolveVersion).toHaveBeenCalledWith({
      material: ENCRYPTED_MATERIAL,
      externalRef: null,
      context: {
        companyId: row.companyId,
        secretId: row.id,
        secretKey: "subscription_credential:claude",
        version: 1,
      },
    });
    expect(result).toEqual({
      id: row.id,
      companyId: row.companyId,
      userId: row.userId,
      provider: "claude",
      credentialKind: "claude_oauth_token",
      material: "plain-token",
    });
    expect(state.updateValues).toHaveLength(1);
    expect(state.updateValues[0]).toHaveProperty("lastResolvedAt");
    expect(JSON.stringify(state.updateValues)).not.toContain("plain-token");
  });

  it("rejects decrypted material that does not match the stored integrity hash", async () => {
    const row = makeCredentialRow({ valueSha256: sha256Hex("different-token") });
    const { db } = makeFakeDb({ findFirstRows: [row] });
    const svc = subscriptionCredentialService(db);

    await expect(
      svc.resolveDecryptedMaterial(row.companyId as string, row.userId as string, "claude"),
    ).rejects.toThrow(/integrity check/i);
  });

  it("does not return a credential when the id belongs to another company or user", async () => {
    const foreignRow = makeCredentialRow({ companyId: "33333333-3333-4333-8333-333333333333" });
    const { db } = makeFakeDb({ findFirstRows: [foreignRow] });
    const svc = subscriptionCredentialService(db);

    await expect(
      svc.getById("22222222-2222-4222-8222-222222222222", "user-1", foreignRow.id as string),
    ).rejects.toThrow(/not found/i);
  });
});
