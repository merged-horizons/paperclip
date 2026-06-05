import { createHash } from "node:crypto";
import { and, asc, eq, inArray } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  agents,
  heartbeatRuns,
  issues,
  principalPermissionGrants,
  projects,
  routines,
  toolAccessAuditEvents,
  toolActionRequests,
  toolApplications,
  toolCatalogEntries,
  toolConnections,
  toolCallEvents,
  toolInvocations,
  toolPolicies,
  toolProfileBindings,
  toolProfileEntries,
  toolProfiles,
  toolRateLimitCounters,
} from "@paperclipai/db";
import type {
  ToolAccessDecision,
  ToolAccessDecisionInput,
  ToolAccessReasonCode,
  ToolAccessSelector,
  ToolAuditEventType,
  ToolPolicyDecision,
  ToolRateLimitRule,
  ToolRedactedValueSummary,
} from "@paperclipai/shared";

type ToolAccessContext = {
  companyId: string;
  actorType: "agent" | "user" | "system" | "plugin";
  actorId: string;
  agentId: string | null;
  heartbeatRunId: string | null;
  issueId: string | null;
  projectId: string | null;
  routineId: string | null;
  applicationId: string | null;
  connectionId: string | null;
  catalogEntryId: string | null;
  toolName: string;
  riskLevel: string | null;
};

type RedactionResult = {
  summary: ToolRedactedValueSummary;
  redactionPlan: { redactedFieldCount: number; redactedFields: string[] };
};

const SENSITIVE_KEY_RE =
  /(^|[_-])(api[_-]?key|authorization|bearer|client[_-]?secret|cookie|credential|jwt|password|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)($|[_-])/i;
const SECRET_VALUE_RE = /\b(sk-[a-z0-9_-]{12,}|ghp_[a-z0-9_]{12,}|xox[baprs]-[a-z0-9-]{12,}|bearer\s+[a-z0-9._-]{12,})\b/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function snapshotString(snapshot: Record<string, unknown>, key: string): string | null {
  const value = snapshot[key];
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function stableStringify(value: unknown): string {
  if (!isRecord(value) && !Array.isArray(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

function sha256(value: unknown): string {
  return createHash("sha256").update(stableStringify(value)).digest("hex");
}

function sideEffectIdempotencyKey(ctx: ToolAccessContext, argumentsHash: string): string {
  return `side_effect:${sha256({
    companyId: ctx.companyId,
    runId: ctx.heartbeatRunId,
    issueId: ctx.issueId,
    applicationId: ctx.applicationId,
    connectionId: ctx.connectionId,
    catalogEntryId: ctx.catalogEntryId,
    toolName: ctx.toolName,
    argumentsHash,
  })}`;
}

function auditOutcome(accessDecision: ToolAccessDecision): "pending" | "success" | "denied" | "timeout" {
  if (accessDecision.decision === "allow") return "success";
  if (accessDecision.decision === "require_approval") return "pending";
  if (accessDecision.decision === "defer_runtime") return "timeout";
  return "denied";
}

function summarizeAndRedact(value: unknown): RedactionResult {
  const redactedFields: string[] = [];
  const visit = (current: unknown, path: string): unknown => {
    if (typeof current === "string") {
      if (SECRET_VALUE_RE.test(current)) {
        redactedFields.push(path || "$");
        return "[REDACTED]";
      }
      return current.length > 500 ? `${current.slice(0, 500)}...[truncated]` : current;
    }
    if (Array.isArray(current)) return current.slice(0, 50).map((entry, index) => visit(entry, `${path}[${index}]`));
    if (!isRecord(current)) return current;
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(current)) {
      const nestedPath = path ? `${path}.${key}` : key;
      if (SENSITIVE_KEY_RE.test(key)) {
        redactedFields.push(nestedPath);
        out[key] = "[REDACTED]";
      } else {
        out[key] = visit(nested, nestedPath);
      }
    }
    return out;
  };
  const redacted = visit(value ?? {}, "");
  const text = stableStringify(redacted);
  return {
    summary: {
      summary: text.length > 4000 ? `${text.slice(0, 4000)}...[truncated]` : text,
      sizeBytes: Buffer.byteLength(text),
      sha256: sha256(redacted),
      redactedFields,
    },
    redactionPlan: {
      redactedFieldCount: redactedFields.length,
      redactedFields,
    },
  };
}

function decision(
  kind: ToolPolicyDecision,
  reasonCode: ToolAccessReasonCode,
  explanation: string,
  effectiveProfileIds: string[],
  matchedPolicyIds: string[],
  extra: Partial<ToolAccessDecision> = {},
): ToolAccessDecision {
  return {
    decision: kind,
    allowed: kind === "allow",
    reasonCode,
    explanation,
    effectiveProfileIds,
    matchedPolicyIds,
    ...extra,
  };
}

function listValues(value: unknown): string[] {
  if (typeof value === "string" && value.trim()) return [value.trim()];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function selectorMatches(selector: ToolAccessSelector | Record<string, unknown> | null | undefined, ctx: ToolAccessContext): boolean {
  if (!selector || Object.keys(selector).length === 0) return true;
  const s = selector as Record<string, unknown>;
  const match = (singleKey: string, pluralKey: string, actual: string | null) => {
    const single = typeof s[singleKey] === "string" ? String(s[singleKey]) : null;
    const many = listValues(s[pluralKey]);
    return (!single || actual === single) && (many.length === 0 || Boolean(actual && many.includes(actual)));
  };
  return (
    match("actorType", "actorTypes", ctx.actorType) &&
    match("agentId", "agentIds", ctx.agentId) &&
    match("projectId", "projectIds", ctx.projectId) &&
    match("routineId", "routineIds", ctx.routineId) &&
    match("issueId", "issueIds", ctx.issueId) &&
    match("applicationId", "applicationIds", ctx.applicationId) &&
    match("connectionId", "connectionIds", ctx.connectionId) &&
    match("catalogEntryId", "catalogEntryIds", ctx.catalogEntryId) &&
    match("toolName", "toolNames", ctx.toolName) &&
    match("riskLevel", "riskLevels", ctx.riskLevel)
  );
}

function profileEntryMatches(entry: typeof toolProfileEntries.$inferSelect, ctx: ToolAccessContext): boolean {
  if (entry.selectorType === "application") return entry.applicationId === ctx.applicationId;
  if (entry.selectorType === "connection") return entry.connectionId === ctx.connectionId;
  if (entry.selectorType === "catalog_entry") return entry.catalogEntryId === ctx.catalogEntryId;
  if (entry.selectorType === "tool_name") return entry.toolName === ctx.toolName;
  if (entry.selectorType === "risk_level") return entry.riskLevel === ctx.riskLevel;
  return false;
}

function targetMatches(binding: typeof toolProfileBindings.$inferSelect, ctx: ToolAccessContext): boolean {
  if (binding.targetType === "company") return binding.targetId === ctx.companyId;
  if (binding.targetType === "agent") return binding.targetId === ctx.agentId;
  if (binding.targetType === "project") return binding.targetId === ctx.projectId;
  if (binding.targetType === "routine") return binding.targetId === ctx.routineId;
  if (binding.targetType === "issue") return binding.targetId === ctx.issueId;
  return false;
}

function rateLimitRule(policy: typeof toolPolicies.$inferSelect): ToolRateLimitRule | null {
  const config = isRecord(policy.config) ? policy.config : {};
  const raw = isRecord(config.rateLimit) ? config.rateLimit : config;
  const limit = typeof raw.limit === "number" ? raw.limit : null;
  const windowSeconds = typeof raw.windowSeconds === "number" ? raw.windowSeconds : null;
  if (!limit || !windowSeconds || limit <= 0 || windowSeconds <= 0) return null;
  return {
    limit: Math.floor(limit),
    windowSeconds: Math.floor(windowSeconds),
    keyBy: Array.isArray(raw.keyBy)
      ? raw.keyBy.filter((item): item is NonNullable<ToolRateLimitRule["keyBy"]>[number] => typeof item === "string")
      : undefined,
  };
}

function windowKind(windowSeconds: number): "minute" | "hour" | "day" | "month" {
  if (windowSeconds <= 60) return "minute";
  if (windowSeconds <= 3600) return "hour";
  if (windowSeconds <= 86400) return "day";
  return "month";
}

function windowStart(now: Date, windowSeconds: number): Date {
  return new Date(Math.floor(now.getTime() / (windowSeconds * 1000)) * windowSeconds * 1000);
}

function rateBucket(rule: ToolRateLimitRule, ctx: ToolAccessContext): string {
  const parts = rule.keyBy?.length ? rule.keyBy : ["company", "agent", "connection", "tool"] as const;
  return parts.map((part) => {
    if (part === "company") return `company:${ctx.companyId}`;
    if (part === "agent") return `agent:${ctx.agentId ?? "none"}`;
    if (part === "application") return `application:${ctx.applicationId ?? "none"}`;
    if (part === "connection") return `connection:${ctx.connectionId ?? "none"}`;
    return `tool:${ctx.toolName}`;
  }).join("|");
}

function scopeAllowsTool(scope: Record<string, unknown> | null, ctx: ToolAccessContext) {
  if (!scope || Object.keys(scope).length === 0) return true;
  const allowed = listValues(scope.allow);
  if (allowed.includes(`tool:${ctx.toolName}`)) return true;
  if (ctx.connectionId && allowed.includes(`connection:${ctx.connectionId}`)) return true;
  if (ctx.applicationId && allowed.includes(`application:${ctx.applicationId}`)) return true;
  return selectorMatches(scope, ctx);
}

export function toolAccessPolicyService(db: Db) {
  async function loadContext(input: ToolAccessDecisionInput): Promise<
    | { ok: true; ctx: ToolAccessContext; redaction: RedactionResult }
    | { ok: false; decision: ToolAccessDecision; redaction: RedactionResult }
  > {
    const redaction = summarizeAndRedact(input.request.arguments ?? {});
    let agentId = input.actor.agentId ?? (input.actor.actorType === "agent" ? input.actor.actorId : null);
    let heartbeatRunId = input.runContext?.heartbeatRunId ?? null;
    let issueId = input.runContext?.issueId ?? null;
    let projectId = input.runContext?.projectId ?? null;
    let routineId = input.runContext?.routineId ?? null;

    if (input.actor.actorType === "agent") {
      const [agent] = await db.select().from(agents).where(and(eq(agents.id, agentId ?? ""), eq(agents.companyId, input.companyId)));
      if (!agent) {
        return { ok: false, redaction, decision: decision("deny", "deny_missing_agent", "Authenticated agent was not found in the company.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      agentId = agent.id;
    }

    if (heartbeatRunId) {
      const [run] = await db.select().from(heartbeatRuns).where(eq(heartbeatRuns.id, heartbeatRunId));
      if (!run || run.companyId !== input.companyId || (input.actor.actorType === "agent" && run.agentId !== agentId)) {
        return { ok: false, redaction, decision: decision("deny", "deny_run_context_mismatch", "Supplied run context does not match the authenticated actor.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      agentId = run.agentId;
      const snapshot = isRecord(run.contextSnapshot) ? run.contextSnapshot : {};
      const runIssueId = snapshotString(snapshot, "issueId");
      const runProjectId = snapshotString(snapshot, "projectId");
      const runRoutineId = snapshotString(snapshot, "routineId");
      if ((issueId && runIssueId && issueId !== runIssueId)
        || (projectId && runProjectId && projectId !== runProjectId)
        || (routineId && runRoutineId && routineId !== runRoutineId)) {
        return { ok: false, redaction, decision: decision("deny", "deny_run_context_mismatch", "Supplied run context does not match the stored heartbeat context.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      issueId = runIssueId ?? issueId;
      projectId = runProjectId ?? projectId;
      routineId = runRoutineId ?? routineId;
    }

    if (issueId) {
      const [issue] = await db.select().from(issues).where(eq(issues.id, issueId));
      if (!issue || issue.companyId !== input.companyId) {
        return { ok: false, redaction, decision: decision("deny", "deny_company_boundary", "Issue context is outside the company.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      if (projectId && projectId !== issue.projectId) {
        return { ok: false, redaction, decision: decision("deny", "deny_run_context_mismatch", "Project context does not match the issue context.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      projectId = projectId ?? issue.projectId;
    }
    if (projectId) {
      const [project] = await db.select().from(projects).where(eq(projects.id, projectId));
      if (!project || project.companyId !== input.companyId) {
        return { ok: false, redaction, decision: decision("deny", "deny_company_boundary", "Project context is outside the company.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
    }
    if (routineId) {
      const [routine] = await db.select().from(routines).where(eq(routines.id, routineId));
      if (!routine || routine.companyId !== input.companyId) {
        return { ok: false, redaction, decision: decision("deny", "deny_company_boundary", "Routine context is outside the company.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
    }

    let applicationId = input.request.applicationId ?? null;
    let connectionId = input.request.connectionId ?? null;
    let catalogEntryId = input.request.catalogEntryId ?? null;
    let riskLevel: string | null = null;

    if (catalogEntryId) {
      const [entry] = await db.select().from(toolCatalogEntries).where(eq(toolCatalogEntries.id, catalogEntryId));
      if (!entry || entry.companyId !== input.companyId || (entry.name !== input.request.toolName && entry.toolName !== input.request.toolName)) {
        return { ok: false, redaction, decision: decision("deny", "deny_missing_tool", "Requested tool is not in the company catalog.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      connectionId = entry.connectionId;
      applicationId = entry.applicationId ?? applicationId;
      riskLevel = entry.riskLevel;
    } else if (connectionId) {
      const [entry] = await db
        .select()
        .from(toolCatalogEntries)
        .where(and(eq(toolCatalogEntries.companyId, input.companyId), eq(toolCatalogEntries.connectionId, connectionId), eq(toolCatalogEntries.name, input.request.toolName)));
      if (entry) {
        catalogEntryId = entry.id;
        applicationId = entry.applicationId ?? applicationId;
        riskLevel = entry.riskLevel;
      }
    }

    if (connectionId) {
      const [connection] = await db.select().from(toolConnections).where(eq(toolConnections.id, connectionId));
      if (!connection || connection.companyId !== input.companyId) {
        return { ok: false, redaction, decision: decision("deny", "deny_company_boundary", "Connection is outside the company.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      if (!connection.enabled || connection.status === "disabled" || connection.status === "archived") {
        return { ok: false, redaction, decision: decision("deny", "deny_disabled_connection", "Connection is disabled.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      applicationId = connection.applicationId;
    }
    if (applicationId) {
      const [application] = await db.select().from(toolApplications).where(eq(toolApplications.id, applicationId));
      if (!application || application.companyId !== input.companyId) {
        return { ok: false, redaction, decision: decision("deny", "deny_company_boundary", "Application is outside the company.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
      if (application.status === "archived") {
        return { ok: false, redaction, decision: decision("deny", "deny_archived_application", "Application is archived.", [], [], { redactionPlan: redaction.redactionPlan }) };
      }
    }

    return {
      ok: true,
      redaction,
      ctx: {
        companyId: input.companyId,
        actorType: input.actor.actorType,
        actorId: input.actor.actorId,
        agentId,
        heartbeatRunId,
        issueId,
        projectId,
        routineId,
        applicationId,
        connectionId,
        catalogEntryId,
        toolName: input.request.toolName,
        riskLevel,
      },
    };
  }

  async function effectiveProfiles(ctx: ToolAccessContext) {
    const bindings = await db.select().from(toolProfileBindings).where(eq(toolProfileBindings.companyId, ctx.companyId));
    const activeBindings = bindings.filter((binding) => targetMatches(binding, ctx));
    if (activeBindings.length === 0) return { profiles: [], entries: [] as Array<typeof toolProfileEntries.$inferSelect> };
    const profileIds = [...new Set(activeBindings.map((binding) => binding.profileId))];
    const profiles = await db.select().from(toolProfiles).where(and(eq(toolProfiles.companyId, ctx.companyId), inArray(toolProfiles.id, profileIds)));
    const activeProfileIds = profiles.filter((profile) => profile.status === "active").map((profile) => profile.id);
    const entries = activeProfileIds.length > 0
      ? await db.select().from(toolProfileEntries).where(and(eq(toolProfileEntries.companyId, ctx.companyId), inArray(toolProfileEntries.profileId, activeProfileIds)))
      : [];
    return { profiles: profiles.filter((profile) => profile.status === "active"), entries };
  }

  async function explicitGrant(ctx: ToolAccessContext): Promise<boolean> {
    const principalType = ctx.actorType === "agent" ? "agent" : ctx.actorType === "user" ? "user" : null;
    const principalId = ctx.actorType === "agent" ? ctx.agentId : ctx.actorId;
    if (!principalType || !principalId) return false;
    const grants = await db
      .select()
      .from(principalPermissionGrants)
      .where(and(
        eq(principalPermissionGrants.companyId, ctx.companyId),
        eq(principalPermissionGrants.principalType, principalType),
        eq(principalPermissionGrants.principalId, principalId),
        eq(principalPermissionGrants.permissionKey, "tools:use"),
      ));
    return grants.some((grant) => scopeAllowsTool(grant.scope, ctx));
  }

  async function enforceRateLimit(policy: typeof toolPolicies.$inferSelect, ctx: ToolAccessContext, consume: boolean) {
    const rule = rateLimitRule(policy);
    if (!rule) return null;
    const now = new Date();
    const start = windowStart(now, rule.windowSeconds);
    const kind = windowKind(rule.windowSeconds);
    const resetAt = new Date(start.getTime() + rule.windowSeconds * 1000);
    const bucketKey = `${policy.id}:${rateBucket(rule, ctx)}`;
    const [existing] = await db.select().from(toolRateLimitCounters).where(and(
      eq(toolRateLimitCounters.companyId, ctx.companyId),
      eq(toolRateLimitCounters.policyId, policy.id),
      eq(toolRateLimitCounters.counterKey, bucketKey),
      eq(toolRateLimitCounters.windowKind, kind),
      eq(toolRateLimitCounters.windowStartAt, start),
    ));
    const count = existing ? Math.max(0, existing.limit - existing.remaining) : 0;
    if (count >= rule.limit) {
      return { limited: true, count, limit: rule.limit, windowSeconds: rule.windowSeconds, bucketKey };
    }
    if (consume) {
      if (existing) {
        await db.update(toolRateLimitCounters).set({
          remaining: Math.max(0, existing.remaining - 1),
          updatedAt: now,
        }).where(eq(toolRateLimitCounters.id, existing.id));
      } else {
        await db.insert(toolRateLimitCounters).values({
          companyId: ctx.companyId,
          policyId: policy.id,
          counterKey: bucketKey,
          scopeType: "policy",
          scopeId: policy.id,
          windowKind: kind,
          windowStartAt: start,
          limit: rule.limit,
          remaining: Math.max(0, rule.limit - 1),
          resetAt,
        });
      }
    }
    return { limited: false, count: consume ? count + 1 : count, limit: rule.limit, windowSeconds: rule.windowSeconds, bucketKey };
  }

  async function decide(input: ToolAccessDecisionInput): Promise<ToolAccessDecision> {
    const loaded = await loadContext(input);
    if (!loaded.ok) return loaded.decision;
    const { ctx, redaction } = loaded;
    const profileState = await effectiveProfiles(ctx);
    const effectiveProfileIds = profileState.profiles.map((profile) => profile.id);
    const policies = await db.select().from(toolPolicies).where(and(eq(toolPolicies.companyId, ctx.companyId), eq(toolPolicies.enabled, true))).orderBy(asc(toolPolicies.priority), asc(toolPolicies.createdAt));
    const matchingPolicies = policies.filter((policy) => selectorMatches(policy.selectors, ctx));
    const block = matchingPolicies.find((policy) => policy.policyType === "block");
    if (block) {
      return decision("deny", "deny_policy_block", block.description ?? "Tool access is blocked by policy.", effectiveProfileIds, [block.id], { redactionPlan: redaction.redactionPlan });
    }
    const approval = matchingPolicies.find((policy) => policy.policyType === "require_approval");
    if (approval) {
      return decision("require_approval", "requires_approval_policy", approval.description ?? "Tool access requires approval.", effectiveProfileIds, [approval.id], { redactionPlan: redaction.redactionPlan });
    }
    for (const policy of matchingPolicies.filter((item) => item.policyType === "rate_limit")) {
      const state = await enforceRateLimit(policy, ctx, input.consumeRateLimit === true);
      if (state?.limited) {
        return decision("rate_limited", "rate_limited", "Tool access rate limit exceeded.", effectiveProfileIds, [policy.id], { rateLimitState: state, redactionPlan: redaction.redactionPlan });
      }
    }

    const policyAllow = matchingPolicies.find((policy) => policy.policyType === "allow");
    if (policyAllow) {
      return decision("allow", "allow_policy", "Tool access allowed by policy.", effectiveProfileIds, [policyAllow.id], { redactionPlan: redaction.redactionPlan });
    }
    if (await explicitGrant(ctx)) {
      return decision("allow", "allow_explicit_grant", "Tool access allowed by explicit grant.", effectiveProfileIds, [], { redactionPlan: redaction.redactionPlan });
    }

    const entriesByProfile = new Map<string, Array<typeof toolProfileEntries.$inferSelect>>();
    for (const entry of profileState.entries) {
      const list = entriesByProfile.get(entry.profileId) ?? [];
      list.push(entry);
      entriesByProfile.set(entry.profileId, list);
    }
    for (const profile of profileState.profiles) {
      const entries = entriesByProfile.get(profile.id) ?? [];
      const matchingEntries = entries.filter((entry) => profileEntryMatches(entry, ctx));
      if (matchingEntries.some((entry) => entry.effect === "exclude")) continue;
      if (profile.defaultAction === "allow" || matchingEntries.some((entry) => entry.effect === "include")) {
        return decision("allow", "allow_profile", "Tool access allowed by effective profile.", effectiveProfileIds, [], { redactionPlan: redaction.redactionPlan });
      }
    }

    return decision("deny", "deny_default", "No effective tool profile, grant, or allow policy permits this call.", effectiveProfileIds, [], { redactionPlan: redaction.redactionPlan });
  }

  async function writeAudit(
    input: ToolAccessDecisionInput,
    accessDecision: ToolAccessDecision,
    eventType: ToolAuditEventType = "policy_decision",
  ) {
    const loaded = await loadContext(input);
    const redaction = loaded.redaction;
    const ctx = loaded.ok ? loaded.ctx : {
      companyId: input.companyId,
      actorType: input.actor.actorType,
      actorId: input.actor.actorId,
      agentId: input.actor.agentId ?? null,
      issueId: input.runContext?.issueId ?? null,
      runId: input.runContext?.heartbeatRunId ?? null,
      connectionId: input.request.connectionId ?? null,
      catalogEntryId: input.request.catalogEntryId ?? null,
      applicationId: input.request.applicationId ?? null,
      toolName: input.request.toolName,
    };
    const runId = "runId" in ctx ? ctx.runId : ctx.heartbeatRunId;
    const [legacyAuditEvent] = await db.insert(toolAccessAuditEvents).values({
      companyId: input.companyId,
      connectionId: ctx.connectionId,
      catalogEntryId: ctx.catalogEntryId,
      actorType: ctx.actorType,
      actorId: ctx.actorId,
      action: `tool_access.${eventType}`,
      outcome: accessDecision.allowed ? "success" : "denied",
      reasonCode: accessDecision.reasonCode,
      details: {
        decision: accessDecision.decision,
        matchedPolicyIds: accessDecision.matchedPolicyIds,
        effectiveProfileIds: accessDecision.effectiveProfileIds,
        applicationId: ctx.applicationId,
        agentId: ctx.agentId,
        issueId: ctx.issueId,
        runId,
        toolName: ctx.toolName,
        argumentsSummary: redaction.summary,
        redactionPlan: redaction.redactionPlan,
        rateLimitState: accessDecision.rateLimitState ?? null,
      },
    }).returning();
    const [toolCallEvent] = await db.insert(toolCallEvents).values({
      companyId: input.companyId,
      eventType: eventType as typeof toolCallEvents.$inferInsert["eventType"],
      actorType: ctx.actorType,
      actorId: ctx.actorId,
      agentId: ctx.agentId,
      runId,
      issueId: ctx.issueId,
      applicationId: ctx.applicationId,
      connectionId: ctx.connectionId,
      catalogEntryId: ctx.catalogEntryId,
      toolName: ctx.toolName,
      decision: accessDecision.decision,
      matchedPolicyIds: accessDecision.matchedPolicyIds,
      reasonCode: accessDecision.reasonCode,
      outcome: auditOutcome(accessDecision),
      argumentsSummary: redaction.summary,
      requestHash: redaction.summary.sha256 ?? null,
      requestSummary: redaction.summary,
      redactionPlan: redaction.redactionPlan,
      rateLimitState: accessDecision.rateLimitState ?? null,
      metadata: {
        legacyAuditEventId: legacyAuditEvent.id,
        effectiveProfileIds: accessDecision.effectiveProfileIds,
        explanation: accessDecision.explanation,
      },
    }).returning();
    return { legacyAuditEvent, toolCallEvent };
  }

  async function recordInvocation(input: ToolAccessDecisionInput, accessDecision: ToolAccessDecision) {
    const loaded = await loadContext(input);
    if (!loaded.ok) throw new Error("Cannot record invocation for invalid tool access context");
    const { ctx, redaction } = loaded;
    const argumentsHash = redaction.summary.sha256 ?? sha256(input.request.arguments ?? {});
    const idempotencyKey = input.request.idempotencyKey
      ?? (input.request.sideEffecting ? sideEffectIdempotencyKey(ctx, argumentsHash) : null);
    if (idempotencyKey) {
      const [existing] = await db.select().from(toolInvocations).where(and(
        eq(toolInvocations.companyId, input.companyId),
        eq(toolInvocations.idempotencyKey, idempotencyKey),
      ));
      if (existing) return { invocation: existing, replayed: true, actionRequest: null };
    }
    const status = accessDecision.decision === "allow"
      ? "authorized"
      : accessDecision.decision === "require_approval"
        ? "awaiting_approval"
        : accessDecision.decision === "rate_limited"
          ? "rate_limited"
          : "denied";
    const [invocation] = await db.insert(toolInvocations).values({
      companyId: ctx.companyId,
      idempotencyKey,
      actorType: ctx.actorType,
      actorId: ctx.actorId,
      agentId: ctx.agentId,
      issueId: ctx.issueId,
      runId: ctx.heartbeatRunId,
      applicationId: ctx.applicationId,
      connectionId: ctx.connectionId,
      catalogEntryId: ctx.catalogEntryId,
      toolName: ctx.toolName,
      argumentsHash,
      argumentsSummary: redaction.summary,
      policyDecision: accessDecision.decision,
      matchedPolicyIds: accessDecision.matchedPolicyIds,
      approvalState: accessDecision.decision === "require_approval" ? "pending" : "not_required",
      status,
    }).returning();
    let actionRequest = null;
    if (accessDecision.decision === "require_approval") {
      [actionRequest] = await db.insert(toolActionRequests).values({
        companyId: ctx.companyId,
        invocationId: invocation.id,
        issueId: ctx.issueId,
        status: "pending",
        canonicalArgumentsHash: invocation.argumentsHash ?? argumentsHash,
        canonicalArgumentsSummary: redaction.summary,
        requestedByAgentId: ctx.actorType === "agent" ? ctx.agentId : null,
        requestedByUserId: ctx.actorType === "user" ? ctx.actorId : null,
      }).returning();
    }
    return { invocation, replayed: false, actionRequest };
  }

  return {
    decide,
    writeAudit,
    recordInvocation,
    summarizeAndRedact,
  };
}
