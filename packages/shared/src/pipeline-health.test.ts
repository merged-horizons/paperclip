import { describe, expect, it } from "vitest";
import { computePipelineHealth } from "./pipeline-health.js";

describe("computePipelineHealth", () => {
  it("dedupes repeated failed automation warnings for the same item and stage", () => {
    const report = computePipelineHealth({
      pipelineId: "pipeline-1",
      stages: [],
      agentsById: {},
      pipelinesById: {},
      failedAutomations: [
        {
          stageId: "stage-1",
          stageKey: "assembly",
          stageName: "Assembly",
          caseId: "case-1",
          caseTitle: "Watchdog blog",
          error: "automation_not_configured",
        },
        {
          stageId: "stage-1",
          stageKey: "assembly",
          stageName: "Assembly",
          caseId: "case-1",
          caseTitle: "Watchdog blog",
          error: "automation_not_configured",
        },
      ],
    });

    expect(report.warnings).toEqual([
      expect.objectContaining({
        code: "automation_failed",
        stageId: "stage-1",
        stageName: "Assembly",
        href: "/pipelines/pipeline-1/items/case-1",
      }),
    ]);
  });
});
