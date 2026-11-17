import { spawnSync } from "node:child_process";
import fs from "node:fs";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const temporaryException = Object.freeze({
  advisoryUrl: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
  expiresAt: "2026-12-01T00:00:00.000Z",
  packageName: "picomatch",
  version: "4.0.7",
});

const blockingSeverities = new Set(["high", "critical"]);

export function evaluateAuditReport(report, installedVersions, now = new Date()) {
  if (report?.error) {
    return { allowed: [], unexpected: ["npm-audit-error"] };
  }

  const vulnerabilities = report?.vulnerabilities ?? {};
  const blocking = Object.entries(vulnerabilities).filter(([, vulnerability]) =>
    blockingSeverities.has(vulnerability.severity),
  );

  if (blocking.length === 0) {
    return { allowed: [], unexpected: [] };
  }

  const allowed = new Set();
  const exception = vulnerabilities[temporaryException.packageName];
  const exceptionIsCurrent = now < new Date(temporaryException.expiresAt);
  const installedVersionMatches = installedVersions[temporaryException.packageName] === temporaryException.version;
  const directAdvisories = exception?.via?.filter((item) => typeof item === "object") ?? [];
  const directAdvisoriesMatch =
    directAdvisories.length > 0 &&
    directAdvisories.every(
      (item) =>
        item.name === temporaryException.packageName &&
        item.url === temporaryException.advisoryUrl &&
        blockingSeverities.has(item.severity),
    ) &&
    exception.via.every((item) => typeof item === "object");

  if (exceptionIsCurrent && installedVersionMatches && directAdvisoriesMatch) {
    allowed.add(temporaryException.packageName);
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, vulnerability] of blocking) {
      if (allowed.has(name) || !Array.isArray(vulnerability.via) || vulnerability.via.length === 0) continue;
      if (vulnerability.via.every((item) => typeof item === "string" && allowed.has(item))) {
        allowed.add(name);
        changed = true;
      }
    }
  }

  return {
    allowed: blocking.map(([name]) => name).filter((name) => allowed.has(name)),
    unexpected: blocking.map(([name]) => name).filter((name) => !allowed.has(name)),
  };
}

function runNpmAudit() {
  const npmExecPath = process.env.npm_execpath;
  const command = npmExecPath ? process.execPath : "npm";
  const args = npmExecPath
    ? [npmExecPath, "audit", "--json", "--audit-level=high"]
    : ["audit", "--json", "--audit-level=high"];
  return spawnSync(command, args, {
    encoding: "utf8",
    shell: process.platform === "win32" && !npmExecPath,
  });
}

function main() {
  const lockfile = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
  const installedVersions = Object.fromEntries(
    Object.entries(lockfile.packages ?? {})
      .filter(([path]) => path.startsWith("node_modules/"))
      .map(([path, metadata]) => [path.slice("node_modules/".length), metadata.version]),
  );
  const audit = runNpmAudit();

  let report;
  try {
    report = JSON.parse(audit.stdout);
  } catch {
    process.stderr.write(audit.stderr || audit.stdout || "npm audit did not return valid JSON.\n");
    process.exitCode = 1;
    return;
  }

  if (audit.error || audit.status === null || audit.status > 1) {
    process.stderr.write(audit.stderr || "npm audit could not complete.\n");
    process.exitCode = 1;
    return;
  }

  const result = evaluateAuditReport(report, installedVersions);
  if (result.unexpected.length > 0) {
    process.stderr.write(`Blocking Node vulnerabilities: ${result.unexpected.join(", ")}\n`);
    process.exitCode = 1;
    return;
  }

  if (result.allowed.length > 0) {
    process.stdout.write(
      [
        `Temporary exception: ${temporaryException.advisoryUrl}`,
        `Affected build-time chain: ${result.allowed.join(", ")}`,
        `Pinned package: ${temporaryException.packageName}@${temporaryException.version}`,
        `Exception expires: ${temporaryException.expiresAt}`,
        "Rationale: Vite is used only to build trusted repository inputs for a static site; no untrusted glob pattern reaches picomatch.",
      ].join("\n") + "\n",
    );
    return;
  }

  process.stdout.write("No high or critical Node dependency vulnerabilities found.\n");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  main();
}
