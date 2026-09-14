import fs from "fs";
import path from "path";

const failures = [];

function isExternal(target) {
  return /^(?:[a-z]+:|#)/i.test(target);
}

function resolveTarget(sourceFile, rawTarget) {
  const withoutFragment = rawTarget.split("#", 1)[0].split("?", 1)[0];
  if (!withoutFragment || isExternal(withoutFragment)) return null;

  const decoded = decodeURIComponent(withoutFragment.replace(/^<|>$/g, ""));
  if (decoded.startsWith("/")) return path.resolve(decoded.slice(1));
  return path.resolve(path.dirname(sourceFile), decoded);
}

function checkTarget(sourceFile, rawTarget) {
  const resolved = resolveTarget(sourceFile, rawTarget);
  if (resolved && !fs.existsSync(resolved)) {
    failures.push(`${sourceFile}: missing ${rawTarget}`);
  }
}

function markdownFilesUnder(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) return markdownFilesUnder(candidate);
    return entry.isFile() && entry.name.endsWith(".md") ? [candidate] : [];
  });
}

const markdownFiles = [
  "README.md",
  "COURSE_MAP.md",
  "LEARNING.md",
  "CURRICULUM_EVOLUTION_PLAN.md",
  "COURSE_REVIEW_AND_IMPROVEMENT_PLAN.md",
  "CONTRIBUTING.md",
  ...markdownFilesUnder("curriculum"),
];
for (const sourceFile of markdownFiles) {
  const content = fs.readFileSync(sourceFile, "utf8");
  for (const match of content.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    checkTarget(sourceFile, match[1]);
  }
}

const htmlFiles = ["index.html", "quiz/index.html"];
for (const sourceFile of htmlFiles) {
  const content = fs.readFileSync(sourceFile, "utf8");
  for (const match of content.matchAll(/(?:href|src)=["']([^"']+)["']/g)) {
    checkTarget(sourceFile, match[1]);
  }
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log(`Validated local links in ${markdownFiles.length + htmlFiles.length} learning entry points.`);
