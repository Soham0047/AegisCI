import { expect, test } from "@playwright/test";

test("reports page renders table rows", async ({ page }) => {
  await page.route("**/api/v1/dashboard/reports**", async (route) => {
    await route.fulfill({
      json: [
        {
          report_id: "job-1",
          job_id: "job-1",
          repo: "org/repo",
          commit: "abc123",
          created_at: new Date().toISOString(),
          findings_count: 4,
          high_critical: 2,
        },
      ],
    });
  });

  await page.goto("/reports");
  await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible();
  await expect(page.getByText("org/repo")).toBeVisible();
});

test("patches page renders patch rows", async ({ page }) => {
  await page.route("**/api/v1/dashboard/patches**", async (route) => {
    await route.fulfill({
      json: [
        {
          job_id: "job-2",
          repo: "org/repo",
          commit: "def456",
          status: "completed",
          validated_count: 1,
          rejected_count: 0,
          avg_validation_time: 2.1,
          success_rate: 1,
          created_at: new Date().toISOString(),
        },
      ],
    });
  });

  await page.goto("/patches");
  await expect(page.getByRole("heading", { name: "Patches" })).toBeVisible();
  await expect(page.getByText("job-2")).toBeVisible();
});

test("gateway page renders events and summary", async ({ page }) => {
  await page.route("**/api/v1/dashboard/gateway/events**", async (route) => {
    await route.fulfill({
      json: [
        {
          id: "evt-1",
          timestamp: new Date().toISOString(),
          tool: "fs.read",
          decision: "allow",
          reason: "allowed",
          correlation_id: "cid-1",
        },
      ],
    });
  });
  await page.route("**/api/v1/dashboard/gateway/summary**", async (route) => {
    await route.fulfill({
      json: {
        total: 1,
        blocked: 0,
        top_reasons: [["allowed", 1]],
        top_tools: [["fs.read", 1]],
      },
    });
  });

  await page.goto("/gateway");
  await expect(page.getByRole("heading", { name: "Gateway events" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "fs.read" })).toBeVisible();
  await expect(page.getByText("fs.read (1)")).toBeVisible();
});

test("patch detail can submit outcome", async ({ page }) => {
  await page.route("**/api/v1/dashboard/patches/job-1**", async (route) => {
    await route.fulfill({
      json: {
        job_id: "job-1",
        repo: "org/repo",
        commit: "abc123",
        status: "completed",
        summary: {
          total: 1,
          validated: 1,
          rejected: 0,
          patched: 1,
          avg_validation_time: 1.2,
        },
        findings: [
          {
            finding_id: "f-1",
            rule_id: "B602",
            filepath: "app.py",
            start_line: 1,
            end_line: 1,
            status: "validated",
            reason: null,
            source: "deterministic",
            candidate_id: "det-0",
          },
        ],
        diff: "--- a/app.py\\n+++ b/app.py\\n",
        run_id: "run-1",
        outcomes: [],
      },
    });
  });
  await page.route("**/api/v1/outcomes", async (route) => {
    await route.fulfill({
      json: {
        id: "out-1",
        job_id: "job-1",
        finding_id: "f-1",
        candidate_id: "det-0",
        action: "accepted",
        notes: null,
        diff_hash: "abc",
        timestamp: new Date().toISOString(),
      },
    });
  });

  await page.goto("/patches/job-1");
  await page.getByRole("button", { name: "accepted" }).first().click();
  await expect(page.getByText("Saved accepted for f-1")).toBeVisible();
});
