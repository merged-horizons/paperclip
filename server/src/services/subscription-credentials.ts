import { createHash } from "node:crypto";
import { and, eq } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { userSubscriptionCredentials } from "@paperclipai/db";
import {
  SUBSCRIPTION_CREDENTIAL_KINDS_BY_PROVIDER,
  type SubscriptionCredentialKind,
  type SubscriptionCredentialProvider,
  type SubscriptionCredentialReadModel,
  type SubscriptionCredentialStatus,
  type SubscriptionCredentialTestStatus,
} from "@paperclipai/shared";
import { badRequest, notFound, unprocessable } from "../errors.js";
import { getSecretProvider } from "../secrets/provider-registry.js";

// The BYO subscription credential layer reuses the existing managed encryption
// provider so credential material is encrypted at rest with the same key
// management as company secrets. Only the local_encrypted (managed) scheme is
// used here; external-reference providers are not applicable to pasted seats.
const ENCRYPTION_PROVIDER = "local_encrypted" as const;

type CredentialRow = typeof userSubscriptionCredentials.$inferSelect;

export interface UpsertSubscriptionCredentialInput {
  companyId: string;
  userId: string;
  provider: SubscriptionCredentialProvider;
  credentialKind: SubscriptionCredentialKind;
  material: string;
  status?: SubscriptionCredentialStatus;
}

export interface DecryptedSubscriptionCredential {
  id: string;
  companyId: string;
  userId: string;
  provider: SubscriptionCredentialProvider;
  credentialKind: SubscriptionCredentialKind;
  // Decrypted credential material (token string or JSON document). This is the
  // narrow server-side surface for downstream runtime injection. Callers must
  // never persist or log this value.
  material: string;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function assertKindMatchesProvider(
  provider: SubscriptionCredentialProvider,
  kind: SubscriptionCredentialKind,
) {
  const allowed = SUBSCRIPTION_CREDENTIAL_KINDS_BY_PROVIDER[provider];
  if (!allowed.includes(kind)) {
    throw badRequest(`Credential kind "${kind}" is not valid for provider "${provider}"`);
  }
}

function assertMaterialMatchesKind(kind: SubscriptionCredentialKind, material: string) {
  if (kind !== "claude_credentials_json" && kind !== "codex_auth_json") return;
  try {
    JSON.parse(material);
  } catch {
    throw badRequest(`Credential kind "${kind}" requires valid JSON material`);
  }
}

// Build redacted metadata from the declared credential kind only. Do not derive
// this record from plaintext credential material; even suffixes, lengths, or
// JSON key names are treated as credential-derived data.
function buildRedactedMetadata(kind: SubscriptionCredentialKind): Record<string, unknown> {
  return {
    kind,
    materialFormat: kind === "claude_oauth_token" ? "token" : "json",
  };
}

function toReadModel(row: CredentialRow): SubscriptionCredentialReadModel {
  return {
    id: row.id,
    companyId: row.companyId,
    userId: row.userId,
    provider: row.provider as SubscriptionCredentialProvider,
    credentialKind: row.credentialKind as SubscriptionCredentialKind,
    status: row.status as SubscriptionCredentialStatus,
    testStatus: (row.lastTestStatus as SubscriptionCredentialTestStatus | null) ?? "untested",
    redactedMetadata: row.redactedMetadata ?? null,
    lastTestedAt: row.lastTestedAt ? row.lastTestedAt.toISOString() : null,
    lastResolvedAt: row.lastResolvedAt ? row.lastResolvedAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function subscriptionCredentialService(db: Db) {
  async function findRow(
    companyId: string,
    userId: string,
    provider: SubscriptionCredentialProvider,
  ): Promise<CredentialRow | undefined> {
    return db.query.userSubscriptionCredentials.findFirst({
      where: and(
        eq(userSubscriptionCredentials.companyId, companyId),
        eq(userSubscriptionCredentials.userId, userId),
        eq(userSubscriptionCredentials.provider, provider),
      ),
    });
  }

  async function findRowById(companyId: string, userId: string, id: string) {
    const row = await db.query.userSubscriptionCredentials.findFirst({
      where: eq(userSubscriptionCredentials.id, id),
    });
    if (!row) return undefined;
    // Enforce company + user isolation: one user/company can never read or
    // mutate another's credential, even with a guessed id.
    if (row.companyId !== companyId || row.userId !== userId) return undefined;
    return row;
  }

  return {
    async list(companyId: string, userId: string): Promise<SubscriptionCredentialReadModel[]> {
      const rows = await db.query.userSubscriptionCredentials.findMany({
        where: and(
          eq(userSubscriptionCredentials.companyId, companyId),
          eq(userSubscriptionCredentials.userId, userId),
        ),
      });
      return rows.map(toReadModel);
    },

    async getById(
      companyId: string,
      userId: string,
      id: string,
    ): Promise<SubscriptionCredentialReadModel> {
      const row = await findRowById(companyId, userId, id);
      if (!row) throw notFound("Subscription credential not found");
      return toReadModel(row);
    },

    // Link or update a credential. Keyed by (company, user, provider) so each
    // employee holds at most one record per provider. Material is encrypted at
    // rest before persistence; plaintext is never stored.
    async upsert(
      input: UpsertSubscriptionCredentialInput,
    ): Promise<SubscriptionCredentialReadModel> {
      assertKindMatchesProvider(input.provider, input.credentialKind);
      assertMaterialMatchesKind(input.credentialKind, input.material);

      const provider = getSecretProvider(ENCRYPTION_PROVIDER);
      const prepared = await provider.createSecret({ value: input.material });
      const now = new Date();
      const redactedMetadata = buildRedactedMetadata(input.credentialKind);

      const [row] = await db
        .insert(userSubscriptionCredentials)
        .values({
          companyId: input.companyId,
          userId: input.userId,
          provider: input.provider,
          credentialKind: input.credentialKind,
          secretProvider: ENCRYPTION_PROVIDER,
          material: prepared.material as Record<string, unknown>,
          valueSha256: prepared.valueSha256,
          redactedMetadata,
          status: input.status ?? "active",
          // A freshly linked/updated credential is untested until verified.
          lastTestStatus: "untested",
          lastTestedAt: null,
          updatedAt: now,
        })
        .onConflictDoUpdate({
          target: [
            userSubscriptionCredentials.companyId,
            userSubscriptionCredentials.userId,
            userSubscriptionCredentials.provider,
          ],
          set: {
            credentialKind: input.credentialKind,
            secretProvider: ENCRYPTION_PROVIDER,
            material: prepared.material as Record<string, unknown>,
            valueSha256: prepared.valueSha256,
            redactedMetadata,
            status: input.status ?? "active",
            lastTestStatus: "untested",
            lastTestedAt: null,
            updatedAt: now,
          },
        })
        .returning();

      return toReadModel(row);
    },

    async updateMaterialFromRuntime(
      companyId: string,
      userId: string,
      provider: SubscriptionCredentialProvider,
      material: string,
    ): Promise<SubscriptionCredentialReadModel> {
      const row = await findRow(companyId, userId, provider);
      if (!row) throw notFound("Subscription credential not found");
      if (row.status !== "active") {
        throw unprocessable("Subscription credential is not active", { code: "credential_inactive" });
      }
      const credentialKind = row.credentialKind as SubscriptionCredentialKind;
      assertKindMatchesProvider(provider, credentialKind);
      assertMaterialMatchesKind(credentialKind, material);

      const encryptionProvider = getSecretProvider(ENCRYPTION_PROVIDER);
      const prepared = await encryptionProvider.createSecret({ value: material });
      const [updated] = await db
        .update(userSubscriptionCredentials)
        .set({
          secretProvider: ENCRYPTION_PROVIDER,
          material: prepared.material as Record<string, unknown>,
          valueSha256: prepared.valueSha256,
          redactedMetadata: buildRedactedMetadata(credentialKind),
          updatedAt: new Date(),
        })
        .where(eq(userSubscriptionCredentials.id, row.id))
        .returning();

      return toReadModel(updated);
    },

    async delete(companyId: string, userId: string, id: string): Promise<void> {
      const row = await findRowById(companyId, userId, id);
      if (!row) throw notFound("Subscription credential not found");
      await db.delete(userSubscriptionCredentials).where(eq(userSubscriptionCredentials.id, row.id));
    },

    // Record the outcome of a downstream readiness/validity test. The actual
    // test (running the official CLI) is a downstream task; this just persists
    // redacted test metadata so the UI can surface readiness.
    async recordTestResult(
      companyId: string,
      userId: string,
      id: string,
      testStatus: SubscriptionCredentialTestStatus,
    ): Promise<SubscriptionCredentialReadModel> {
      const row = await findRowById(companyId, userId, id);
      if (!row) throw notFound("Subscription credential not found");
      const now = new Date();
      const [updated] = await db
        .update(userSubscriptionCredentials)
        .set({ lastTestStatus: testStatus, lastTestedAt: now, updatedAt: now })
        .where(eq(userSubscriptionCredentials.id, row.id))
        .returning();
      return toReadModel(updated);
    },

    // Narrow server-side interface for downstream runtime injection. Returns
    // decrypted credential material. This must only be called by trusted
    // server-side runtime code, never exposed through an HTTP response.
    async resolveDecryptedMaterial(
      companyId: string,
      userId: string,
      provider: SubscriptionCredentialProvider,
    ): Promise<DecryptedSubscriptionCredential> {
      const row = await findRow(companyId, userId, provider);
      if (!row) throw notFound("Subscription credential not found");
      if (row.status !== "active") {
        throw unprocessable("Subscription credential is not active", { code: "credential_inactive" });
      }
      const secretProvider = getSecretProvider(row.secretProvider as "local_encrypted");
      const material = await secretProvider.resolveVersion({
        material: row.material as Record<string, unknown>,
        externalRef: null,
        context: {
          companyId: row.companyId,
          secretId: row.id,
          secretKey: `subscription_credential:${row.provider}`,
          version: 1,
        },
      });

      await db
        .update(userSubscriptionCredentials)
        .set({ lastResolvedAt: new Date() })
        .where(eq(userSubscriptionCredentials.id, row.id))
        .catch(() => undefined);

      // Integrity check against the stored plaintext hash.
      if (sha256Hex(material) !== row.valueSha256) {
        throw unprocessable("Subscription credential failed integrity check", {
          code: "credential_integrity_failed",
        });
      }

      return {
        id: row.id,
        companyId: row.companyId,
        userId: row.userId,
        provider: row.provider as SubscriptionCredentialProvider,
        credentialKind: row.credentialKind as SubscriptionCredentialKind,
        material,
      };
    },
  };
}
