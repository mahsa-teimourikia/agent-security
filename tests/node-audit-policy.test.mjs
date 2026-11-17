import assert from "node:assert/strict";
import test from "node:test";

import { evaluateAuditReport, temporaryException } from "../scripts/audit-node-dependencies.mjs";

const currentDate = new Date("2026-11-17T20:00:00.000Z");
const installedVersions = { picomatch: temporaryException.version };

function affectedReport() {
  return {
    vulnerabilities: {
      fdir: { severity: "high", via: ["picomatch"] },
      picomatch: {
        severity: "high",
        via: [
          {
            name: "picomatch",
            severity: "high",
            url: temporaryException.advisoryUrl,
          },
        ],
      },
      tinyglobby: { severity: "high", via: ["fdir", "picomatch"] },
      vite: { severity: "high", via: ["picomatch", "tinyglobby"] },
    },
  };
}

test("passes a clean audit report", () => {
  assert.deepEqual(evaluateAuditReport({ vulnerabilities: {} }, {}, currentDate), {
    allowed: [],
    unexpected: [],
  });
});

test("fails closed when npm audit reports an operational error", () => {
  assert.deepEqual(
    evaluateAuditReport({ error: { code: "EAUDITENDPOINT" } }, {}, currentDate).unexpected,
    ["npm-audit-error"],
  );
});

test("allows only the transitive chain rooted in the exact temporary exception", () => {
  assert.deepEqual(evaluateAuditReport(affectedReport(), installedVersions, currentDate), {
    allowed: ["fdir", "picomatch", "tinyglobby", "vite"],
    unexpected: [],
  });
});

test("fails closed for an unrelated high-severity advisory", () => {
  const report = affectedReport();
  report.vulnerabilities.other = {
    severity: "high",
    via: [{ name: "other", severity: "high", url: "https://example.invalid/advisory" }],
  };

  assert.deepEqual(evaluateAuditReport(report, installedVersions, currentDate).unexpected, ["other"]);
});

test("fails closed when the exception expires", () => {
  const result = evaluateAuditReport(
    affectedReport(),
    installedVersions,
    new Date(temporaryException.expiresAt),
  );
  assert.deepEqual(result.allowed, []);
  assert.deepEqual(result.unexpected, ["fdir", "picomatch", "tinyglobby", "vite"]);
});

test("fails closed when the installed vulnerable version changes", () => {
  const result = evaluateAuditReport(affectedReport(), { picomatch: "4.0.6" }, currentDate);
  assert.deepEqual(result.allowed, []);
  assert.deepEqual(result.unexpected, ["fdir", "picomatch", "tinyglobby", "vite"]);
});
