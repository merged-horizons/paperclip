import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  activityLog,
  agents,
  companies,
  companySecrets,
  createDb,
  heartbeatRuns,
  issues,
  principalPermissionGrants,
  toolAccessAuditEvents,
  toolActionRequests,
  toolApplications,
  toolCatalogEntries,
  toolCallEvents,
  toolConnections,
  toolInvocations,
  toolPolicies,
  toolProfileBindings,
  toolProfileEntries,
  toolProfiles,
  toolRateLimitCounters,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { toolAccessPolicyService } from "../services/tool-access-policy.js";
import { toolAccessService } from "../services/tool-access.js";
import { createToolGatewayService, ToolGatewayHttpError } from "../services/tool-gateway.js";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

async function createCompany(db: ReturnType<typeof createDb>) {
  return db.insert(companies).values({
    name: `Tool Access ${randomUUID()}`,
    issuePrefix: `TA${randomUUID().slice(0, 6).toUpperCase()}`,
  }).returning().then((rows) => rows[0]!);
}

async function createAgent(
  db: ReturnType<typeof createDb>,
  companyId: string,
  permissions: Record<string, unknown> = {},
) {
  return db.insert(agents).values({
    companyId,
    name: `Agent ${randomUUID()}`,
    role: "engineer",
    adapterType: "process",
    adapterConfig: {},
    runtimeConfig: {},
    permissions,
  }).returning().then((rows) => rows[0]!);
}

async function createRun(
  db: ReturnType<typeof createDb>,
  companyId: string,
  agentId: string,
  contextSnapshot: Record<string, unknown> = {},
) {
  return db.insert(heartbeatRuns).values({
    companyId,
    agentId,
    invocationSource: "assignment",
    status: "running",
    contextSnapshot,
  }).returning().then((rows) => rows[0]!);
}

async function createIssue(db: ReturnType<typeof createDb>, companyId: string, title = "Tool issue") {
  return db.insert(issues).values({
    companyId,
    title: `${title} ${randomUUID()}`,
    status: "in_progress",
  }).returning().then((rows) => rows[0]!);
}

async function createTool(db: ReturnType<typeof createDb>, companyId: string) {
  const application = await db.insert(toolApplications).values({
    companyId,
    applicationKey: `fixture-${randomUUID()}`,
    name: `Fixture ${randomUUID()}`,
    type: "mcp_http",
    status: "active",
  }).returning().then((rows) => rows[0]!);
  const connection = await db.insert(toolConnections).values({
    companyId,
    applicationId: application.id,
    name: `Connection ${randomUUID()}`,
    transport: "remote_http",
    status: "active",
    enabled: true,
    config: { url: "https://example.invalid/mcp" },
  }).returning().then((rows) => rows[0]!);
  const catalogEntry = await db.insert(toolCatalogEntries).values({
    companyId,
    applicationId: application.id,
    connectionId: connection.id,
    name: "send_email",
    toolName: "send_email",
    riskLevel: "write",
    versionHash: randomUUID(),
  }).returning().then((rows) => rows[0]!);
  return { application, connection, catalogEntry };
}

describeEmbeddedPostgres("tool access policy service", () => {
  let db!: ReturnType<typeof createDb>;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase("paperclip-tool-access-policy-");
    db = createDb(tempDb.connectionString);
  }, 20_000);

  afterEach(async () => {
    await db.delete(toolRateLimitCounters);
    await db.delete(toolActionRequests);
    await db.delete(toolInvocations);
    await db.delete(toolCallEvents);
    await db.delete(toolAccessAuditEvents);
    await db.delete(toolPolicies);
    await db.delete(toolProfileEntries);
    await db.delete(toolProfileBindings);
    await db.delete(toolProfiles);
    await db.delete(toolCatalogEntries);
    await db.delete(toolConnections);
    await db.delete(toolApplications);
    await db.delete(companySecrets);
    await db.delete(principalPermissionGrants);
    await db.delete(issues);
    await db.delete(activityLog);
    await db.delete(heartbeatRuns);
    await db.delete(agents);
    await db.delete(companies);
  });

  afterAll(async () => {
    await tempDb?.cleanup();
  });

  it("denies direct execution without an effective profile or grant", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { connection, catalogEntry } = await createTool(db, company.id);

    const result = await toolAccessPolicyService(db).decide({
      companyId: company.id,
      actor: { actorType: "agent", actorId: agent.id, agentId: agent.id },
      request: { connectionId: connection.id, catalogEntryId: catalogEntry.id, toolName: "send_email" },
    });

    expect(result).toMatchObject({
      allowed: false,
      decision: "deny",
      reasonCode: "deny_default",
    });
  });

  it("allows calls through an effective agent profile", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { connection, catalogEntry } = await createTool(db, company.id);
    const profile = await db.insert(toolProfiles).values({
      companyId: company.id,
      profileKey: `profile-${randomUUID()}`,
      name: "Write tools",
      defaultAction: "deny",
    }).returning().then((rows) => rows[0]!);
    await db.insert(toolProfileBindings).values({
      companyId: company.id,
      profileId: profile.id,
      targetType: "agent",
      targetId: agent.id,
    });
    await db.insert(toolProfileEntries).values({
      companyId: company.id,
      profileId: profile.id,
      selectorType: "tool_name",
      effect: "include",
      toolName: "send_email",
    });

    const result = await toolAccessPolicyService(db).decide({
      companyId: company.id,
      actor: { actorType: "agent", actorId: agent.id, agentId: agent.id },
      request: { connectionId: connection.id, catalogEntryId: catalogEntry.id, toolName: "send_email" },
    });

    expect(result).toMatchObject({
      allowed: true,
      decision: "allow",
      reasonCode: "allow_profile",
      effectiveProfileIds: [profile.id],
    });
  });

  it("rejects agent-supplied run context that belongs to another agent", async () => {
    const company = await createCompany(db);
    const actorAgent = await createAgent(db, company.id);
    const otherAgent = await createAgent(db, company.id);
    const { connection } = await createTool(db, company.id);
    const run = await db.insert(heartbeatRuns).values({
      companyId: company.id,
      agentId: otherAgent.id,
      invocationSource: "assignment",
      status: "running",
    }).returning().then((rows) => rows[0]!);

    const result = await toolAccessPolicyService(db).decide({
      companyId: company.id,
      actor: { actorType: "agent", actorId: actorAgent.id, agentId: actorAgent.id },
      runContext: { heartbeatRunId: run.id },
      request: { connectionId: connection.id, toolName: "send_email" },
    });

    expect(result).toMatchObject({
      allowed: false,
      reasonCode: "deny_run_context_mismatch",
    });
  });

  it("rejects agent-supplied issue context that differs from the stored heartbeat context", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const canonicalIssue = await createIssue(db, company.id, "Canonical");
    const escalatedIssue = await createIssue(db, company.id, "Escalated");
    const { connection } = await createTool(db, company.id);
    const run = await createRun(db, company.id, agent.id, { issueId: canonicalIssue.id });

    const result = await toolAccessPolicyService(db).decide({
      companyId: company.id,
      actor: { actorType: "agent", actorId: agent.id, agentId: agent.id },
      runContext: { heartbeatRunId: run.id, issueId: escalatedIssue.id },
      request: { connectionId: connection.id, toolName: "send_email" },
    });

    expect(result).toMatchObject({
      allowed: false,
      reasonCode: "deny_run_context_mismatch",
    });
  });

  it("audits denied calls without storing secret argument values", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { connection } = await createTool(db, company.id);
    const input = {
      companyId: company.id,
      actor: { actorType: "agent" as const, actorId: agent.id, agentId: agent.id },
      request: {
        connectionId: connection.id,
        toolName: "send_email",
        arguments: { to: "ops@example.com", apiKey: "sk-test-secret-value-123456" },
      },
    };

    const decision = await toolAccessPolicyService(db).decide(input);
    await toolAccessPolicyService(db).writeAudit(input, decision);
    const [legacyAudit] = await db.select().from(toolAccessAuditEvents);
    const [callEvent] = await db.select().from(toolCallEvents);
    const serialized = JSON.stringify({ legacy: legacyAudit.details, dedicated: callEvent });

    expect(decision.reasonCode).toBe("deny_default");
    expect(callEvent).toMatchObject({
      eventType: "policy_decision",
      outcome: "denied",
      reasonCode: "deny_default",
      decision: "deny",
      matchedPolicyIds: [],
      requestHash: expect.any(String),
    });
    expect(serialized).not.toContain("sk-test-secret-value");
    expect(serialized).toContain("[REDACTED]");
  });

  it("records approval-required invocations and action requests with matched policy IDs", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { connection } = await createTool(db, company.id);
    const policy = await db.insert(toolPolicies).values({
      companyId: company.id,
      name: "Review writes",
      policyType: "require_approval",
      selectors: { toolName: "send_email" },
      description: "Writes require board review.",
    }).returning().then((rows) => rows[0]!);
    const input = {
      companyId: company.id,
      actor: { actorType: "agent" as const, actorId: agent.id, agentId: agent.id },
      request: {
        connectionId: connection.id,
        toolName: "send_email",
        arguments: { to: "ops@example.com", body: "ship it" },
        sideEffecting: true,
      },
    };

    const decision = await toolAccessPolicyService(db).decide(input);
    const recorded = await toolAccessPolicyService(db).recordInvocation(input, decision);
    await toolAccessPolicyService(db).writeAudit(input, decision);
    const [callEvent] = await db.select().from(toolCallEvents);

    expect(decision).toMatchObject({
      allowed: false,
      decision: "require_approval",
      reasonCode: "requires_approval_policy",
      matchedPolicyIds: [policy.id],
    });
    expect(recorded.actionRequest).toMatchObject({
      invocationId: recorded.invocation.id,
      requestedByAgentId: agent.id,
      status: "pending",
    });
    expect(recorded.invocation).toMatchObject({
      approvalState: "pending",
      status: "awaiting_approval",
      matchedPolicyIds: [policy.id],
    });
    expect(callEvent).toMatchObject({
      eventType: "policy_decision",
      outcome: "pending",
      decision: "require_approval",
      matchedPolicyIds: [policy.id],
      requestSummary: expect.objectContaining({ summary: expect.any(String) }),
    });
  });

  it("replays side-effecting calls with the same idempotency key instead of creating a new invocation", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { connection } = await createTool(db, company.id);
    await db.insert(principalPermissionGrants).values({
      companyId: company.id,
      principalType: "agent",
      principalId: agent.id,
      permissionKey: "tools:use",
      scope: { toolName: "send_email" },
    });
    const input = {
      companyId: company.id,
      actor: { actorType: "agent" as const, actorId: agent.id, agentId: agent.id },
      request: {
        connectionId: connection.id,
        toolName: "send_email",
        arguments: { to: "ops@example.com" },
        sideEffecting: true,
        idempotencyKey: "send-email-1",
      },
    };

    const decision = await toolAccessPolicyService(db).decide(input);
    const first = await toolAccessPolicyService(db).recordInvocation(input, decision);
    const replay = await toolAccessPolicyService(db).recordInvocation(input, decision);

    expect(first.replayed).toBe(false);
    expect(replay.replayed).toBe(true);
    expect(replay.invocation.id).toBe(first.invocation.id);
  });

  it("derives a canonical idempotency key for side-effecting calls without caller-supplied keys", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { connection } = await createTool(db, company.id);
    await db.insert(principalPermissionGrants).values({
      companyId: company.id,
      principalType: "agent",
      principalId: agent.id,
      permissionKey: "tools:use",
      scope: { toolName: "send_email" },
    });
    const input = {
      companyId: company.id,
      actor: { actorType: "agent" as const, actorId: agent.id, agentId: agent.id },
      request: {
        connectionId: connection.id,
        toolName: "send_email",
        arguments: { to: "ops@example.com", body: "only once" },
        sideEffecting: true,
      },
    };

    const decision = await toolAccessPolicyService(db).decide(input);
    const first = await toolAccessPolicyService(db).recordInvocation(input, decision);
    const replay = await toolAccessPolicyService(db).recordInvocation(input, decision);

    expect(first.replayed).toBe(false);
    expect(first.invocation.idempotencyKey).toMatch(/^side_effect:/);
    expect(replay.replayed).toBe(true);
    expect(replay.invocation.id).toBe(first.invocation.id);
  });

  it("enforces rate-limit policies before explicit grants", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { connection } = await createTool(db, company.id);
    await db.insert(principalPermissionGrants).values({
      companyId: company.id,
      principalType: "agent",
      principalId: agent.id,
      permissionKey: "tools:use",
      scope: { toolName: "send_email" },
    });
    await db.insert(toolPolicies).values({
      companyId: company.id,
      name: "One send per minute",
      policyType: "rate_limit",
      selectors: { toolName: "send_email" },
      config: { limit: 1, windowSeconds: 60, keyBy: ["agent", "tool"] },
    });
    const input = {
      companyId: company.id,
      actor: { actorType: "agent" as const, actorId: agent.id, agentId: agent.id },
      request: { connectionId: connection.id, toolName: "send_email" },
      consumeRateLimit: true,
    };

    const first = await toolAccessPolicyService(db).decide(input);
    const second = await toolAccessPolicyService(db).decide(input);

    expect(first.allowed).toBe(true);
    expect(second).toMatchObject({
      allowed: false,
      decision: "rate_limited",
      reasonCode: "rate_limited",
    });
  });

  it("routes gateway execution through policy decisions instead of legacy gateway permissions", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id, { toolGateway: { allowAll: true } });
    const run = await createRun(db, company.id, agent.id);
    const gateway = createToolGatewayService(db);
    const session = await gateway.createSession({
      companyId: company.id,
      agentId: agent.id,
      runId: run.id,
    });

    await expect(gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-remote-fixture:echo",
      parameters: { message: "hello" },
    })).rejects.toMatchObject({
      status: 403,
      reasonCode: "deny_default",
    } satisfies Partial<ToolGatewayHttpError>);

    const [invocation] = await db.select().from(toolInvocations);
    expect(invocation).toMatchObject({
      toolName: "mcp-remote-fixture:echo",
      policyDecision: "deny",
      status: "denied",
    });
  });

  it("replays idempotent side-effecting gateway calls without creating a second invocation", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const run = await createRun(db, company.id, agent.id);
    await db.insert(principalPermissionGrants).values({
      companyId: company.id,
      principalType: "agent",
      principalId: agent.id,
      permissionKey: "tools:use",
      scope: { toolName: "mcp-remote-fixture:update_note" },
    });
    const gateway = createToolGatewayService(db);
    const session = await gateway.createSession({
      companyId: company.id,
      agentId: agent.id,
      runId: run.id,
    });

    const first = await gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-remote-fixture:update_note",
      parameters: { noteId: "n1", body: "ship" },
      idempotencyKey: "note-update-1",
    });
    const replay = await gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-remote-fixture:update_note",
      parameters: { noteId: "n1", body: "ship" },
      idempotencyKey: "note-update-1",
    });

    expect(first).toMatchObject({ status: "completed", tool: "mcp-remote-fixture:update_note" });
    expect(replay).toMatchObject({ status: "replayed", invocationId: first.invocationId });
    const invocations = await db.select().from(toolInvocations);
    expect(invocations).toHaveLength(1);
    expect(invocations[0]).toMatchObject({
      idempotencyKey: "note-update-1",
      status: "succeeded",
      resultSummary: expect.objectContaining({ summary: expect.any(String) }),
    });
  });

  it("rejects cross-company owner agents and credential secret refs before persisting tool access records", async () => {
    const company = await createCompany(db);
    const otherCompany = await createCompany(db);
    const otherAgent = await createAgent(db, otherCompany.id);
    const [otherSecret] = await db.insert(companySecrets).values({
      companyId: otherCompany.id,
      key: `secret-${randomUUID()}`,
      name: `Secret ${randomUUID()}`,
    }).returning();
    const svc = toolAccessService(db);

    await expect(svc.createApplication(company.id, {
      name: "Wrong owner",
      type: "mcp_http",
      ownerAgentId: otherAgent.id,
    })).rejects.toThrow(/same company/);

    await expect(svc.createConnection(company.id, {
      name: "Wrong secret",
      transport: "remote_http",
      transportConfig: { url: "https://example.invalid/mcp" },
      credentialSecretRefs: [{
        secretId: otherSecret.id,
        configPath: "headers.Authorization",
      }],
    })).rejects.toThrow(/same company/);
  });
});
