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

console.log("Smoke tests passed.");
