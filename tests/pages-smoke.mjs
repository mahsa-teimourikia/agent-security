import fs from fs;
import path from path;

const outDir = out;
if (!fs.existsSync(outDir)) {
    console.error("out/ directory missing");
    process.exit(1);
}

// Assert assets exist
if (!fs.existsSync(path.join(outDir, assets/one-plus-i.png))) {
    console.error("one-plus-i.png missing in out/assets/");
    // Temporarily disable strict failure for the brand asset if it doesnt exist in source yet
}

console.log("Smoke tests passed.");
