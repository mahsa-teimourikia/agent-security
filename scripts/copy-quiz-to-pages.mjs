import fs from "fs";
import path from "path";

const quizDir = "quiz";
const outQuizDir = "out/quiz";
const assetsDir = "assets";
const outAssetsDir = "out/assets";

if (!fs.existsSync(outQuizDir)) fs.mkdirSync(outQuizDir, { recursive: true });
if (!fs.existsSync(outAssetsDir)) fs.mkdirSync(outAssetsDir, { recursive: true });

// Copy quiz files
if (fs.existsSync(quizDir)) {
    fs.readdirSync(quizDir).forEach(file => {
        fs.copyFileSync(path.join(quizDir, file), path.join(outQuizDir, file));
    });
}

// Copy one-plus-i.png
if (fs.existsSync(path.join(assetsDir, "one-plus-i.png"))) {
    fs.copyFileSync(path.join(assetsDir, "one-plus-i.png"), path.join(outAssetsDir, "one-plus-i.png"));
}
