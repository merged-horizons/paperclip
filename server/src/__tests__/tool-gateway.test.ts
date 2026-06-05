import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  activityLog,
  agents,
  companies,
  createDb,
  heartbeatRuns,
  issueThreadInteractions,
  issues,
  projects,
  toolAccessAuditEvents,
  toolActionRequests,
  toolCallEvents,
  toolInvocations,
  toolPolicies,
  toolProfileBindings,
  toolProfileEntries,
  toolProfiles,
} from "@paperclipai/db";
import type { PluginToolDispatcher } from "../services/plugin-tool-dispatcher.js";
import { createToolGatewayService, ToolGatewayHttpError } from "../services/tool-gateway.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

type Db = ReturnType<typeof createDb>;

async function createCompany(db: Db) {
  return db
    .insert(companies)
    .values({
      name: `Gateway ${randomUUID()}`,
      issuePrefix: `TG${randomUUID().slice(0, 6).toUpperCase()}`,
    })
    .returning()
    .then((rows) => rows[0]!);
}

async function createAgent(db: Db, companyId: string, permissions: Record<string, unknown> = {}) {
  return db
    .insert(agents)
    .values({
      companyId,
      name: `Agent ${randomUUID()}`,
      role: "engineer",
      adapterType: "process",
      adapterConfig: {},
      runtimeConfig: {},
      permissions,
    })
    .returning()
    .then((rows) => rows[0]!);
}

async function createIssueAndRun(db: Db, companyId: string, agentId: string) {
  const project = await db
    .insert(projects)
    .values({ companyId, name: `Project ${randomUUID()}` })
    .returning()
    .then((rows) => rows[0]!);
  const issue = await db
    .insert(issues)
    .values({
      companyId,
      projectId: project.id,
      title: `Gateway issue ${randomUUID()}`,
      status: "in_progress",
      assigneeAgentId: agentId,
    })
    .returning()
    .then((rows) => rows[0]!);
  const run = await db
    .insert(heartbeatRuns)
    .values({
      companyId,
      agentId,
      invocationSource: "assignment",
      status: "running",
      contextSnapshot: { issueId: issue.id, projectId: project.id },
    })
    .returning()
    .then((rows) => rows[0]!);
  return { project, issue, run };
}

async function allowToolsForAgent(db: Db, companyId: string, agentId: string, toolNames: string[]) {
  const profile = await db
    .insert(toolProfiles)
    .values({
      companyId,
      profileKey: `gateway-${randomUUID()}`,
      name: `Gateway profile ${randomUUID()}`,
      defaultAction: "deny",
    })
    .returning()
    .then((rows) => rows[0]!);
  await db.insert(toolProfileBindings).values({
    companyId,
    profileId: profile.id,
    targetType: "agent",
    targetId: agentId,
  });
  if (toolNames.length > 0) {
    await db.insert(toolProfileEntries).values(toolNames.map((toolName) => ({
      companyId,
      profileId: profile.id,
      selectorType: "tool_name" as const,
      effect: "include" as const,
      toolName,
    })));
  }
  return profile;
}

function expectGatewayError(error: unknown, status: number, reasonCode: string) {
  expect(error).toBeInstanceOf(ToolGatewayHttpError);
  const gatewayError = error as ToolGatewayHttpError;
  expect(gatewayError.status).toBe(status);
  expect(gatewayError.reasonCode).toBe(reasonCode);
}

describeEmbeddedPostgres("tool gateway service", () => {
  let db!: Db;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase("paperclip-tool-gateway-");
    db = createDb(tempDb.connectionString);
  }, 20_000);

  afterEach(async () => {
    await db.delete(activityLog);
    await db.delete(toolCallEvents);
    await db.delete(toolActionRequests);
    await db.delete(toolInvocations);
    await db.delete(toolAccessAuditEvents);
    await db.delete(toolPolicies);
    await db.delete(toolProfileEntries);
    await db.delete(toolProfileBindings);
    await db.delete(toolProfiles);
    await db.delete(issueThreadInteractions);
    await db.delete(heartbeatRuns);
    await db.delete(issues);
    await db.delete(projects);
    await db.delete(agents);
    await db.delete(companies);
  });

  afterAll(async () => {
    await tempDb?.cleanup();
  });

  it("hides and denies every external tool when an agent has no gateway profile", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { issue, run } = await createIssueAndRun(db, company.id, agent.id);
    const gateway = createToolGatewayService(db);
    const session = await gateway.createSession({
      companyId: company.id,
      agentId: agent.id,
      runId: run.id,
    });

    await expect(gateway.listToolsForSession(session.token)).resolves.toEqual([]);
    await gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-remote-fixture:echo",
      parameters: { message: "not allowed" },
    }).then(
      () => {
        throw new Error("Expected unauthorized tool call to fail");
      },
      (error) => expectGatewayError(error, 403, "deny_default"),
    );

    const [deniedAudit] = await db
      .select()
      .from(activityLog)
      .where(eq(activityLog.action, "tool_gateway.call_denied"));
    expect(deniedAudit).toMatchObject({
      companyId: company.id,
      entityType: "issue",
      entityId: issue.id,
      agentId: agent.id,
      runId: run.id,
    });
  });

  it("filters discovery, executes a remote HTTP fixture, and audits run and issue links", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { issue, run } = await createIssueAndRun(db, company.id, agent.id);
    await allowToolsForAgent(db, company.id, agent.id, [
      "mcp-remote-fixture:add",
      "mcp-stdio-fixture:increment_counter",
      "mcp-stdio-fixture:runtime_status",
    ]);
    const gateway = createToolGatewayService(db);
    const session = await gateway.createSession({
      companyId: company.id,
      agentId: agent.id,
      runId: run.id,
    });

    const toolNames = (await gateway.listToolsForSession(session.token)).map((tool) => tool.name);
    expect(toolNames).toContain("mcp-remote-fixture:add");
    expect(toolNames).toContain("mcp-stdio-fixture:increment_counter");
    expect(toolNames).not.toContain("mcp-remote-fixture:echo");

    const result = await gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-remote-fixture:add",
      parameters: { a: 4, b: 7 },
    });
    expect(result).toMatchObject({
      status: "completed",
      tool: "mcp-remote-fixture:add",
      result: {
        content: "11",
        data: {
          result: 11,
          transport: "mcp_http",
          spawnedLocalProcess: false,
        },
      },
    });

    const [invocation] = await db.select().from(toolInvocations);
    expect(invocation).toMatchObject({
      companyId: company.id,
      agentId: agent.id,
      issueId: issue.id,
      runId: run.id,
      toolName: "mcp-remote-fixture:add",
      status: "succeeded",
    });
    const [callEvent] = await db.select().from(toolCallEvents);
    expect(callEvent).toMatchObject({
      companyId: company.id,
      agentId: agent.id,
      issueId: issue.id,
      runId: run.id,
      toolName: "mcp-remote-fixture:add",
      outcome: "success",
    });
    const [dedicatedAudit] = await db
      .select()
      .from(toolCallEvents)
      .where(eq(toolCallEvents.eventType, "call_completed"));
    expect(dedicatedAudit).toMatchObject({
      issueId: issue.id,
      runId: run.id,
      toolName: "mcp-remote-fixture:add",
    });
  });

  it("lazy-starts, reuses, and idles down the local stdio fixture slot", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { run } = await createIssueAndRun(db, company.id, agent.id);
    await allowToolsForAgent(db, company.id, agent.id, [
      "mcp-stdio-fixture:increment_counter",
      "mcp-stdio-fixture:runtime_status",
    ]);
    const gateway = createToolGatewayService(db);
    const session = await gateway.createSession({
      companyId: company.id,
      agentId: agent.id,
      runId: run.id,
    });

    const first = await gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-stdio-fixture:increment_counter",
      parameters: {},
    });
    const second = await gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-stdio-fixture:runtime_status",
      parameters: {},
    });

    const firstData = (first.result as { data: Record<string, unknown> }).data;
    const secondData = (second.result as { data: Record<string, unknown> }).data;
    expect(firstData).toMatchObject({ lazyStarted: true, reusedRuntimeSlot: false, counter: 1 });
    expect(secondData).toMatchObject({ lazyStarted: false, reusedRuntimeSlot: true, counter: 1 });
    expect(secondData.slotId).toBe(firstData.slotId);
    expect(gateway.listRuntimeSlots(company.id)).toHaveLength(1);

    await new Promise((resolve) => setTimeout(resolve, 1_100));
    expect(gateway.listRuntimeSlots(company.id)).toEqual([]);
  });

  it("defers write-risk tool calls into issue-thread approval requests", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { issue, run } = await createIssueAndRun(db, company.id, agent.id);
    await allowToolsForAgent(db, company.id, agent.id, ["mcp-remote-fixture:update_note"]);
    await db.insert(toolPolicies).values({
      companyId: company.id,
      name: "Review note updates",
      policyType: "require_approval",
      selectors: { toolName: "mcp-remote-fixture:update_note" },
      description: "Note updates require review.",
    });
    const gateway = createToolGatewayService(db);
    const session = await gateway.createSession({
      companyId: company.id,
      agentId: agent.id,
      runId: run.id,
    });

    await gateway.executeTool({
      sessionToken: session.token,
      tool: "mcp-remote-fixture:update_note",
      parameters: { noteId: "n1", body: "review this write" },
    }).then(
      () => {
        throw new Error("Expected write-risk tool call to request approval");
      },
      (error) => expectGatewayError(error, 409, "approval_required"),
    );

    const [actionRequest] = await db.select().from(toolActionRequests);
    const [interaction] = await db.select().from(issueThreadInteractions);
    expect(actionRequest).toMatchObject({
      companyId: company.id,
      issueId: issue.id,
      status: "pending",
      requestedByAgentId: agent.id,
    });
    expect(interaction).toMatchObject({
      companyId: company.id,
      issueId: issue.id,
      kind: "request_confirmation",
      status: "pending",
      continuationPolicy: "wake_assignee_on_accept",
    });
  });

  it("wraps plugin tool discovery and execution behind the same gateway policy", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const { run, project } = await createIssueAndRun(db, company.id, agent.id);
    const calls: unknown[] = [];
    const dispatcher: PluginToolDispatcher = {
      initialize: async () => {},
      teardown: () => {},
      listToolsForAgent: () => [
        {
          name: "demo-plugin:read_status",
          displayName: "Read status",
          description: "Read status through a plugin tool.",
          parametersSchema: { type: "object" },
          pluginId: "demo-plugin",
        },
      ],
      getTool: () => null,
      executeTool: async (tool, parameters, runContext) => {
        calls.push({ tool, parameters, runContext });
        return {
          pluginId: "demo-plugin",
          toolName: "read_status",
          result: { content: "plugin ok", data: { ok: true } },
        };
      },
      registerPluginTools: () => {},
      unregisterPluginTools: () => {},
      toolCount: () => 1,
      getRegistry: () => {
        throw new Error("not used");
      },
    };
    const gateway = createToolGatewayService(db, { pluginToolDispatcher: dispatcher });

    await expect(gateway.listPluginToolsForAgent({ companyId: company.id, agentId: agent.id })).resolves.toEqual([]);
    await gateway.executePluginTool({
      actor: { type: "agent", companyId: company.id, agentId: agent.id, runId: run.id },
      tool: "demo-plugin:read_status",
      parameters: {},
      runContext: { companyId: company.id, agentId: agent.id, runId: run.id, projectId: project.id },
    }).then(
      () => {
        throw new Error("Expected plugin tool call without profile to fail");
      },
      (error) => expectGatewayError(error, 403, "deny_default"),
    );

    await allowToolsForAgent(db, company.id, agent.id, ["demo-plugin:read_status"]);

    await expect(gateway.listPluginToolsForAgent({ companyId: company.id, agentId: agent.id })).resolves.toEqual([
      expect.objectContaining({ name: "demo-plugin:read_status" }),
    ]);
    await expect(gateway.executePluginTool({
      actor: { type: "agent", companyId: company.id, agentId: agent.id, runId: run.id },
      tool: "demo-plugin:read_status",
      parameters: { id: "1" },
      runContext: { companyId: company.id, agentId: agent.id, runId: run.id, projectId: project.id },
    })).resolves.toMatchObject({
      pluginId: "demo-plugin",
      toolName: "read_status",
      result: { content: "plugin ok", data: { ok: true } },
    });
    expect(calls).toEqual([
      expect.objectContaining({
        tool: "demo-plugin:read_status",
        parameters: { id: "1" },
      }),
    ]);
  });

  it("rejects caller-supplied issue context outside the run company", async () => {
    const company = await createCompany(db);
    const agent = await createAgent(db, company.id);
    const run = await db
      .insert(heartbeatRuns)
      .values({
        companyId: company.id,
        agentId: agent.id,
        invocationSource: "assignment",
        status: "running",
        contextSnapshot: {},
      })
      .returning()
      .then((rows) => rows[0]!);
    const otherCompany = await createCompany(db);
    const otherAgent = await createAgent(db, otherCompany.id);
    const { issue: otherIssue } = await createIssueAndRun(db, otherCompany.id, otherAgent.id);
    const gateway = createToolGatewayService(db);

    await gateway.createSession({
      companyId: company.id,
      agentId: agent.id,
      runId: run.id,
      issueId: otherIssue.id,
    }).then(
      () => {
        throw new Error("Expected cross-company issue context to fail");
      },
      (error) => expectGatewayError(error, 403, "run_context_mismatch"),
    );
  });
});
