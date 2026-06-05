import type {
  ToolActionRequestStatus,
  ToolApplicationStatus,
  ToolApplicationType,
  ToolAuditEventType,
  ToolAuditOutcome,
  ToolCatalogEntryKind,
  ToolCatalogEntryStatus,
  ToolConnectionHealthStatus,
  ToolConnectionKind,
  ToolInvocationApprovalState,
  ToolInvocationStatus,
  ToolPolicyDecision,
  ToolPolicyType,
  ToolProfileBindingTargetType,
  ToolProfileDefaultAction,
  ToolProfileEntryEffect,
  ToolProfileEntrySelectorType,
  ToolProfileStatus,
  ToolRateLimitWindowKind,
  ToolRiskLevel,
  ToolRuntimeKind,
  ToolRuntimeSlotStatus,
} from "../constants.js";

export type {
  ToolActionRequestStatus,
  ToolApplicationStatus,
  ToolApplicationType,
  ToolAuditEventType,
  ToolAuditOutcome,
  ToolCatalogEntryKind,
  ToolCatalogEntryStatus,
  ToolConnectionHealthStatus,
  ToolConnectionKind,
  ToolInvocationApprovalState,
  ToolInvocationStatus,
  ToolPolicyDecision,
  ToolPolicyType,
  ToolProfileBindingTargetType,
  ToolProfileDefaultAction,
  ToolProfileEntryEffect,
  ToolProfileEntrySelectorType,
  ToolProfileStatus,
  ToolRateLimitWindowKind,
  ToolRiskLevel,
  ToolRuntimeKind,
  ToolRuntimeSlotStatus,
};

export type ToolActorType = "agent" | "user" | "system" | "plugin";
export type ToolConnectionTransport = "remote_http" | "local_stdio";
export type ToolConnectionStatus = "draft" | "active" | "disabled" | "archived";

export interface McpConnectionCredentialRef {
  name: string;
  secretId: string;
  version?: number | "latest";
  placement: "header" | "env";
  key: string;
  prefix?: string | null;
}

export interface ToolCredentialSecretRef {
  secretId: string;
  versionSelector?: number | "latest";
  configPath: string;
  required?: boolean;
  label?: string | null;
}

export interface ToolRedactedValueSummary {
  summary: string;
  sizeBytes?: number | null;
  sha256?: string | null;
  redactedFields?: string[];
  artifactId?: string | null;
}

export interface ToolApplication {
  id: string;
  companyId: string;
  applicationKey?: string;
  name: string;
  description: string | null;
  type: ToolApplicationType;
  status: ToolApplicationStatus;
  pluginId: string | null;
  ownerAgentId: string | null;
  ownerUserId: string | null;
  metadata: Record<string, unknown> | null;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolConnection {
  id: string;
  companyId: string;
  applicationId: string;
  name: string;
  connectionKind: ToolConnectionKind;
  transport?: ToolConnectionTransport;
  status?: ToolConnectionStatus;
  transportConfig: Record<string, unknown>;
  config?: Record<string, unknown>;
  credentialSecretRefs: ToolCredentialSecretRef[];
  credentialRefs?: McpConnectionCredentialRef[];
  healthStatus: ToolConnectionHealthStatus;
  healthMessage?: string | null;
  healthCheckedAt: Date | null;
  lastHealthAt?: Date | string | null;
  lastCatalogRefreshAt?: Date | string | null;
  lastError: string | null;
  enabled: boolean;
  createdByAgentId: string | null;
  createdByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolCatalogEntry {
  id: string;
  companyId: string;
  applicationId: string | null;
  connectionId: string;
  entryKind: ToolCatalogEntryKind;
  name?: string;
  toolName: string;
  title: string | null;
  description: string | null;
  inputSchema: Record<string, unknown> | null;
  outputSchema: Record<string, unknown> | null;
  annotations: Record<string, unknown> | null;
  riskLevel: ToolRiskLevel;
  isReadOnly: boolean;
  isWrite: boolean;
  isDestructive: boolean;
  status: ToolCatalogEntryStatus;
  version: string | null;
  versionHash?: string | null;
  schemaHash: string | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
  reviewedAt: Date | null;
  reviewedByAgentId: string | null;
  reviewedByUserId: string | null;
  quarantinedAt?: Date | string | null;
  quarantineReason?: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolProfile {
  id: string;
  companyId: string;
  profileKey: string;
  name: string;
  description: string | null;
  status: ToolProfileStatus;
  defaultAction: ToolProfileDefaultAction;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolProfileEntry {
  id: string;
  companyId: string;
  profileId: string;
  selectorType: ToolProfileEntrySelectorType;
  effect: ToolProfileEntryEffect;
  applicationId: string | null;
  connectionId: string | null;
  catalogEntryId: string | null;
  toolName: string | null;
  riskLevel: ToolRiskLevel | null;
  conditions: Record<string, unknown> | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolProfileBinding {
  id: string;
  companyId: string;
  profileId: string;
  targetType: ToolProfileBindingTargetType;
  targetId: string;
  priority: number;
  metadata: Record<string, unknown> | null;
  createdByAgentId: string | null;
  createdByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolPolicy {
  id: string;
  companyId: string;
  name: string;
  description: string | null;
  policyType: ToolPolicyType;
  priority: number;
  enabled: boolean;
  selectors: Record<string, unknown>;
  conditions: Record<string, unknown> | null;
  config: Record<string, unknown> | null;
  createdByAgentId: string | null;
  createdByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolRuntimeSlot {
  id: string;
  companyId: string;
  applicationId: string | null;
  connectionId: string | null;
  projectWorkspaceId: string | null;
  executionWorkspaceId: string | null;
  issueId: string | null;
  ownerScopeType: string;
  ownerScopeId: string | null;
  runtimeKind: ToolRuntimeKind;
  slotKey?: string;
  status: ToolRuntimeSlotStatus;
  reuseKey: string | null;
  workspaceScope: string | null;
  credentialScopeHash: string | null;
  provider: string | null;
  providerRef: string | null;
  processId: number | null;
  commandTemplateKey: string | null;
  healthStatus: string | null;
  healthMessage?: string | null;
  lastHealthCheckAt: Date | null;
  lastStartedAt?: Date | string | null;
  idleExpiresAt: Date | null;
  idleDeadlineAt?: Date | string | null;
  startedAt: Date | null;
  stoppedAt: Date | null;
  lastUsedAt: Date | null;
  lastError: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolConnectionHealthCheckResult {
  connection: ToolConnection;
  runtimeSlot: ToolRuntimeSlot | null;
}

export interface ToolCatalogRefreshResult {
  connection: ToolConnection;
  catalog: ToolCatalogEntry[];
  discoveredCount: number;
  quarantinedCount: number;
}

export interface McpJsonImportDraft {
  name: string;
  transport: ToolConnectionTransport;
  status: ToolConnectionStatus;
  config: Record<string, unknown>;
  credentialRefs: McpConnectionCredentialRef[];
  warnings: string[];
}

export interface McpJsonImportPreview {
  drafts: McpJsonImportDraft[];
}

export interface ToolInvocation {
  id: string;
  companyId: string;
  idempotencyKey: string | null;
  actorType: ToolActorType;
  actorId: string | null;
  agentId: string | null;
  issueId: string | null;
  runId: string | null;
  applicationId: string | null;
  connectionId: string | null;
  catalogEntryId: string | null;
  toolName: string;
  argumentsHash: string | null;
  argumentsSummary: ToolRedactedValueSummary | null;
  policyDecision: ToolPolicyDecision | null;
  matchedPolicyIds: string[];
  approvalState: ToolInvocationApprovalState;
  status: ToolInvocationStatus;
  upstreamRequestId: string | null;
  resultHash: string | null;
  resultSummary: ToolRedactedValueSummary | null;
  resultSizeBytes: number | null;
  resultArtifactId: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolActionRequest {
  id: string;
  companyId: string;
  invocationId: string;
  issueId: string | null;
  interactionId: string | null;
  approvalId: string | null;
  status: ToolActionRequestStatus;
  canonicalArgumentsHash: string;
  canonicalArgumentsSummary: ToolRedactedValueSummary;
  signedArguments: string | null;
  previewMarkdown: string | null;
  requestedByAgentId: string | null;
  requestedByUserId: string | null;
  resolvedByAgentId: string | null;
  resolvedByUserId: string | null;
  decidedByAgentId?: string | null;
  decidedByUserId?: string | null;
  decidedAt?: Date | null;
  expiresAt: Date | null;
  resolvedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ToolCallEvent {
  id: string;
  companyId: string;
  eventType: ToolAuditEventType;
  actorType: ToolActorType;
  actorId: string | null;
  agentId: string | null;
  runId: string | null;
  issueId: string | null;
  applicationId: string | null;
  connectionId: string | null;
  catalogEntryId: string | null;
  invocationId: string | null;
  actionRequestId: string | null;
  runtimeSlotId: string | null;
  toolName: string | null;
  decision: ToolPolicyDecision | null;
  matchedPolicyIds: string[];
  reasonCode: string | null;
  outcome: ToolAuditOutcome;
  latencyMs: number | null;
  argumentsSummary?: ToolRedactedValueSummary | null;
  requestHash: string | null;
  requestSummary: ToolRedactedValueSummary | null;
  resultHash: string | null;
  resultSummary: ToolRedactedValueSummary | null;
  resultSizeBytes: number | null;
  redactionPlan: Record<string, unknown> | null;
  rateLimitState: Record<string, unknown> | null;
  metadata: Record<string, unknown> | null;
  errorCode: string | null;
  errorMessage: string | null;
  createdAt: Date;
}

export interface ToolRateLimitCounter {
  id: string;
  companyId: string;
  policyId: string | null;
  counterKey: string;
  scopeType: string;
  scopeId: string;
  windowKind: ToolRateLimitWindowKind;
  windowStartAt: Date;
  limit: number;
  remaining: number;
  resetAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export type ToolAccessReasonCode =
  | "allow_profile"
  | "allow_explicit_grant"
  | "allow_policy"
  | "requires_approval_policy"
  | "deny_default"
  | "deny_company_boundary"
  | "deny_disabled_connection"
  | "deny_archived_application"
  | "deny_missing_tool"
  | "deny_policy_block"
  | "deny_run_context_mismatch"
  | "deny_missing_agent"
  | "rate_limited";

export interface ToolAccessSelector {
  actorType?: ToolActorType;
  actorTypes?: ToolActorType[];
  agentId?: string;
  agentIds?: string[];
  projectId?: string;
  projectIds?: string[];
  routineId?: string;
  routineIds?: string[];
  issueId?: string;
  issueIds?: string[];
  applicationId?: string;
  applicationIds?: string[];
  connectionId?: string;
  connectionIds?: string[];
  catalogEntryId?: string;
  catalogEntryIds?: string[];
  toolName?: string;
  toolNames?: string[];
  riskLevel?: ToolRiskLevel;
  riskLevels?: ToolRiskLevel[];
}

export interface ToolRateLimitRule {
  limit: number;
  windowSeconds: number;
  keyBy?: Array<"company" | "agent" | "application" | "connection" | "tool">;
}

export interface ToolAccessDecisionInput {
  companyId: string;
  actor: {
    actorType: ToolActorType;
    actorId: string;
    agentId?: string | null;
    userId?: string | null;
  };
  runContext?: {
    heartbeatRunId?: string | null;
    issueId?: string | null;
    projectId?: string | null;
    routineId?: string | null;
  } | null;
  request: {
    applicationId?: string | null;
    connectionId?: string | null;
    catalogEntryId?: string | null;
    toolName: string;
    arguments?: unknown;
    idempotencyKey?: string | null;
    sideEffecting?: boolean;
  };
  consumeRateLimit?: boolean;
  writeAuditEvent?: boolean;
}

export interface ToolAccessDecision {
  decision: ToolPolicyDecision;
  allowed: boolean;
  reasonCode: ToolAccessReasonCode;
  explanation: string;
  effectiveProfileIds: string[];
  matchedPolicyIds: string[];
  redactionPlan?: Record<string, unknown> | null;
  argumentsSummary?: ToolRedactedValueSummary | null;
  rateLimitState?: Record<string, unknown> | null;
  invocationId?: string | null;
  actionRequestId?: string | null;
}
