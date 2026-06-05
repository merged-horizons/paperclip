import { Router } from "express";
import type { Db } from "@paperclipai/db";
import {
  createToolApplicationSchema,
  createToolConnectionSchema,
  importMcpJsonSchema,
  toolPolicyTestRequestSchema,
  updateToolApplicationSchema,
  updateToolConnectionSchema,
} from "@paperclipai/shared";
import { validate } from "../middleware/validate.js";
import { getActorInfo, assertBoard, assertCompanyAccess } from "./authz.js";
import { logActivity, toolAccessPolicyService, toolAccessService } from "../services/index.js";

export function toolAccessRoutes(db: Db) {
  const router = Router();
  const svc = toolAccessService(db);
  const policySvc = toolAccessPolicyService(db);

  router.get("/companies/:companyId/tools/applications", async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    res.json({ applications: await svc.listApplications(companyId) });
  });

  router.post("/companies/:companyId/tools/applications", validate(createToolApplicationSchema), async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    try {
      const application = await svc.createApplication(companyId, req.body);
      await logActivity(db, {
        companyId,
        actorType: "user",
        actorId: req.actor.userId ?? "board",
        action: "tool_application.created",
        entityType: "tool_application",
        entityId: application.id,
        details: { type: application.type, name: application.name },
      });
      res.status(201).json(application);
    } catch (error) {
      svc.ensureNoDuplicateNameError(error);
    }
  });

  router.patch("/tool-applications/:applicationId", validate(updateToolApplicationSchema), async (req, res) => {
    assertBoard(req);
    const existing = await svc.getApplication(req.params.applicationId as string);
    assertCompanyAccess(req, existing.companyId);
    const application = await svc.updateApplication(existing.id, req.body);
    await logActivity(db, {
      companyId: application.companyId,
      actorType: "user",
      actorId: req.actor.userId ?? "board",
      action: "tool_application.updated",
      entityType: "tool_application",
      entityId: application.id,
      details: { status: application.status, name: application.name },
    });
    res.json(application);
  });

  router.get("/companies/:companyId/tools/connections", async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    res.json({ connections: await svc.listConnections(companyId) });
  });

  router.post("/companies/:companyId/tools/connections", validate(createToolConnectionSchema), async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    try {
      const connection = await svc.createConnection(companyId, req.body);
      await logActivity(db, {
        companyId,
        actorType: "user",
        actorId: req.actor.userId ?? "board",
        action: "tool_connection.created",
        entityType: "tool_connection",
        entityId: connection.id,
        details: {
          transport: connection.transport,
          status: connection.status,
          enabled: connection.enabled,
          credentialRefCount: (connection.credentialRefs ?? []).length + connection.credentialSecretRefs.length,
        },
      });
      res.status(201).json(connection);
    } catch (error) {
      svc.ensureNoDuplicateNameError(error);
    }
  });

  router.get("/tool-connections/:connectionId", async (req, res) => {
    assertBoard(req);
    const connection = await svc.getConnection(req.params.connectionId as string);
    assertCompanyAccess(req, connection.companyId);
    res.json(connection);
  });

  router.patch("/tool-connections/:connectionId", validate(updateToolConnectionSchema), async (req, res) => {
    assertBoard(req);
    const existing = await svc.getConnection(req.params.connectionId as string);
    assertCompanyAccess(req, existing.companyId);
    const connection = await svc.updateConnection(existing.id, req.body);
    await logActivity(db, {
      companyId: connection.companyId,
      actorType: "user",
      actorId: req.actor.userId ?? "board",
      action: "tool_connection.updated",
      entityType: "tool_connection",
      entityId: connection.id,
      details: {
        status: connection.status,
        enabled: connection.enabled,
        credentialRefCount: (connection.credentialRefs ?? []).length + connection.credentialSecretRefs.length,
      },
    });
    res.json(connection);
  });

  router.delete("/tool-connections/:connectionId", async (req, res) => {
    assertBoard(req);
    const existing = await svc.getConnection(req.params.connectionId as string);
    assertCompanyAccess(req, existing.companyId);
    const connection = await svc.archiveConnection(existing.id);
    await logActivity(db, {
      companyId: connection.companyId,
      actorType: "user",
      actorId: req.actor.userId ?? "board",
      action: "tool_connection.archived",
      entityType: "tool_connection",
      entityId: connection.id,
      details: { transport: connection.transport },
    });
    res.json(connection);
  });

  router.post("/tool-connections/:connectionId/health-check", async (req, res) => {
    assertBoard(req);
    const existing = await svc.getConnection(req.params.connectionId as string);
    assertCompanyAccess(req, existing.companyId);
    res.json(await svc.checkHealth(existing.id, getActorInfo(req)));
  });

  router.post("/tool-connections/:connectionId/catalog/refresh", async (req, res) => {
    assertBoard(req);
    const existing = await svc.getConnection(req.params.connectionId as string);
    assertCompanyAccess(req, existing.companyId);
    res.json(await svc.refreshCatalog(existing.id, getActorInfo(req)));
  });

  router.get("/tool-connections/:connectionId/catalog", async (req, res) => {
    assertBoard(req);
    const existing = await svc.getConnection(req.params.connectionId as string);
    assertCompanyAccess(req, existing.companyId);
    res.json({ catalog: await svc.listCatalog(existing.id, existing.companyId) });
  });

  router.get("/companies/:companyId/tools/runtime-slots", async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    res.json({ runtimeSlots: await svc.listRuntimeSlots(companyId) });
  });

  router.get("/companies/:companyId/tools/stdio-templates", async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    res.json({ templates: svc.approvedStdioTemplates() });
  });

  router.post("/companies/:companyId/tools/mcp/import-json", validate(importMcpJsonSchema), async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    const preview = await svc.previewMcpJsonImport(req.body);
    await logActivity(db, {
      companyId,
      actorType: "user",
      actorId: req.actor.userId ?? "board",
      action: "tool_connection.import_mcp_json_previewed",
      entityType: "tool_connection_import",
      entityId: companyId,
      details: { draftCount: preview.drafts.length },
    });
    res.json(preview);
  });

  router.post("/companies/:companyId/tools/policy/test", validate(toolPolicyTestRequestSchema), async (req, res) => {
    assertBoard(req);
    const companyId = req.params.companyId as string;
    assertCompanyAccess(req, companyId);
    const input = { ...req.body, companyId };
    const decision = await policySvc.decide(input);
    let auditEvent = null;
    if (input.writeAuditEvent === true) {
      auditEvent = await policySvc.writeAudit(input, decision);
    }
    res.json({ decision, auditEvent });
  });

  return router;
}
