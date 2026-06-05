import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  companies,
  companySecretBindings,
  createDb,
  toolAccessAuditEvents,
  toolApplications,
  toolCatalogEntries,
  toolConnections,
  toolRuntimeSlots,
} from "@paperclipai/db";
import { eq } from "drizzle-orm";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { toolAccessService } from "../services/tool-access.js";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

async function createCompany(db: ReturnType<typeof createDb>) {
  return db
    .insert(companies)
    .values({
      name: `Tool Access CRUD ${randomUUID()}`,
      issuePrefix: `TC${randomUUID().slice(0, 6).toUpperCase()}`,
    })
    .returning()
    .then((rows) => rows[0]!);
}

function mockToolsList(tools: unknown[]) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue({
    ok: true,
    json: async () => ({ jsonrpc: "2.0", id: "paperclip-catalog-refresh", result: { tools } }),
  } as Response);
}

describeEmbeddedPostgres("tool access service", () => {
  let db!: ReturnType<typeof createDb>;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase("paperclip-tool-access-service-");
    db = createDb(tempDb.connectionString);
  }, 20_000);

  afterEach(async () => {
    vi.restoreAllMocks();
    await db.delete(companySecretBindings);
    await db.delete(toolAccessAuditEvents);
    await db.delete(toolRuntimeSlots);
    await db.delete(toolCatalogEntries);
    await db.delete(toolConnections);
    await db.delete(toolApplications);
    await db.delete(companies);
  });

  afterAll(async () => {
    await tempDb?.cleanup();
  });

  it("registers a remote MCP connection and quarantines new or changed write tools during catalog refresh", async () => {
    const company = await createCompany(db);
    const service = toolAccessService(db);
    const fetchMock = mockToolsList([
      {
        name: "search_notes",
        description: "Search notes.",
        inputSchema: { type: "object", properties: { q: { type: "string" } } },
        annotations: { readOnlyHint: true },
      },
      {
        name: "send_email",
        description: "Send an email.",
        inputSchema: { type: "object", properties: { to: { type: "string" } } },
        annotations: { readOnlyHint: false },
      },
    ]);

    const connection = await service.createConnection(company.id, {
      name: "Remote fixture",
      transport: "remote_http",
      config: { url: "https://fixture.example/mcp" },
      enabled: true,
      status: "active",
    });
    const firstRefresh = await service.refreshCatalog(connection.id, { actorType: "user", actorId: "board" });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://fixture.example/mcp",
      expect.objectContaining({ method: "POST" }),
    );
    expect(firstRefresh.discoveredCount).toBe(2);
    expect(firstRefresh.quarantinedCount).toBe(1);
    expect(firstRefresh.catalog).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ toolName: "search_notes", status: "active", riskLevel: "read" }),
        expect.objectContaining({
          toolName: "send_email",
          status: "quarantined",
          riskLevel: "write",
          quarantineReason: "new_write_tool",
        }),
      ]),
    );

    await db
      .update(toolCatalogEntries)
      .set({ status: "active", reviewedAt: new Date(), quarantineReason: null, quarantinedAt: null })
      .where(eq(toolCatalogEntries.toolName, "send_email"));
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        jsonrpc: "2.0",
        id: "paperclip-catalog-refresh",
        result: {
          tools: [
            {
              name: "send_email",
              description: "Send an email with attachments.",
              inputSchema: { type: "object", properties: { to: { type: "string" }, attachment: { type: "string" } } },
              annotations: { readOnlyHint: false },
            },
          ],
        },
      }),
    } as Response);

    const secondRefresh = await service.refreshCatalog(connection.id);

    expect(secondRefresh.quarantinedCount).toBe(1);
    expect(secondRefresh.catalog).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          toolName: "send_email",
          status: "quarantined",
          quarantineReason: "changed_write_tool",
        }),
      ]),
    );
  });

  it("registers an approved local stdio template and exposes its runtime slot", async () => {
    const company = await createCompany(db);
    const service = toolAccessService(db);

    const connection = await service.createConnection(company.id, {
      name: "Local echo fixture",
      transport: "local_stdio",
      config: { templateId: "paperclip.echo-calculator-time" },
      enabled: true,
      status: "active",
    });
    const health = await service.checkHealth(connection.id);
    const refresh = await service.refreshCatalog(connection.id);
    const runtimeSlots = await service.listRuntimeSlots(company.id);

    expect(health.runtimeSlot).toMatchObject({
      connectionId: connection.id,
      runtimeKind: "local_stdio",
      status: "stopped",
      commandTemplateKey: "paperclip.echo-calculator-time",
    });
    expect(refresh.catalog.map((entry) => entry.toolName).sort()).toEqual(["add", "echo", "fail_with_code", "now"]);
    expect(runtimeSlots).toEqual([
      expect.objectContaining({
        connectionId: connection.id,
        providerRef: "template:paperclip.echo-calculator-time",
        healthStatus: "ok",
      }),
    ]);
  });

  it("previews mcp.json imports as draft managed connection records without carrying raw header values", async () => {
    const company = await createCompany(db);
    const preview = await toolAccessService(db).previewMcpJsonImport({
      mcpJson: {
        mcpServers: {
          github: {
            url: "https://mcp.example/github",
            headers: { Authorization: "Bearer should-not-be-stored" },
          },
          local: {
            command: "npx",
            args: ["-y", "@example/local-mcp"],
          },
        },
      },
    });

    expect(company.id).toBeTruthy();
    expect(JSON.stringify(preview)).not.toContain("should-not-be-stored");
    expect(preview.drafts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "github",
          transport: "remote_http",
          status: "draft",
          config: { url: "https://mcp.example/github" },
          warnings: [expect.stringContaining("Paperclip secret")],
        }),
        expect.objectContaining({
          name: "local",
          transport: "local_stdio",
          status: "draft",
          config: { importedCommand: "npx", importedArgs: ["-y", "@example/local-mcp"] },
          warnings: [expect.stringContaining("approved Paperclip template")],
        }),
      ]),
    );
  });

  it("fails closed when credential secrets cannot be resolved and writes value-free audit", async () => {
    const company = await createCompany(db);
    const service = toolAccessService(db);
    const connection = await service.createConnection(company.id, {
      name: "Secret-backed remote",
      transport: "remote_http",
      config: { url: "https://fixture.example/mcp" },
      enabled: true,
      status: "active",
    });
    await db
      .update(toolConnections)
      .set({
        credentialRefs: [
          {
            name: "authorization",
            secretId: randomUUID(),
            version: "latest",
            placement: "header",
            key: "Authorization",
            prefix: "Bearer ",
          },
        ],
      })
      .where(eq(toolConnections.id, connection.id));

    await expect(service.checkHealth(connection.id, { actorType: "user", actorId: "board" })).rejects.toMatchObject({
      status: 422,
      details: expect.objectContaining({ code: "secret_missing" }),
    });
    const [updatedConnection] = await db.select().from(toolConnections).where(eq(toolConnections.id, connection.id));
    const [audit] = await db.select().from(toolAccessAuditEvents);

    expect(updatedConnection).toMatchObject({
      healthStatus: "missing_secret",
      healthMessage: "A configured credential secret could not be resolved.",
    });
    expect(audit).toMatchObject({
      action: "tool_connection.health_check",
      outcome: "failure",
      reasonCode: "secret_missing",
      details: { status: "missing_secret", transport: "remote_http" },
    });
    expect(JSON.stringify(audit)).not.toContain("Bearer ");
    expect(JSON.stringify(audit)).not.toContain("Authorization");
  });
});
