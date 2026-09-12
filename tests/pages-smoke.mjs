import fs from "fs";
import path from "path";

const outDir = "out";
if (!fs.existsSync(outDir)) {
  console.error("out/ directory missing");
  process.exit(1);
}

const requiredFiles = [
  "index.html",
  "quiz/index.html",
  "assets/one-plus-i.png",
];

for (const relativePath of requiredFiles) {
  if (!fs.existsSync(path.join(outDir, relativePath))) {
    console.error(`${relativePath} missing from out/`);
    process.exit(1);
  }
}

const page = fs.readFileSync(path.join(outDir, "index.html"), "utf8");
const bundleNames = [...page.matchAll(/(?:src|href)="\.\/([^"#?]+)"/g)].map((match) => match[1]);
for (const bundleName of bundleNames) {
  assertFile(path.join(outDir, bundleName));
}

const bundledSource = fs.readdirSync(path.join(outDir, "assets"))
  .filter((name) => name.endsWith(".js"))
  .map((name) => fs.readFileSync(path.join(outDir, "assets", name), "utf8"))
  .join("\n");
if (!bundledSource.includes("PUBLISHED CURRICULUM") || !bundledSource.includes("EXPANSION ROADMAP")) {
  console.error("Learning Hub sections missing from the production bundle");
  process.exit(1);
}

console.log("Smoke tests passed.");

function assertFile(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error(`${filePath} missing from out/`);
    process.exit(1);
  }
}
