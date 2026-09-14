import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { publishedLessons, roadmapCourses, roadmapTracks } from "../app/course-data.js";


test("published lessons have runnable, course-specific artifacts", () => {
  assert.equal(new Set(publishedLessons.map(({ id }) => id)).size, publishedLessons.length);
  assert.equal(new Set(publishedLessons.map(({ checkpoint }) => checkpoint.prompt)).size, publishedLessons.length);

  for (const lesson of publishedLessons) {
    for (const field of ["material", "lab", "notebook"]) {
      assert.ok(fs.existsSync(lesson[field]), `${lesson.id}: missing ${field} ${lesson[field]}`);
    }
    assert.ok(lesson.checkpoint.options.length >= 3, `${lesson.id}: checkpoint needs at least three options`);
    assert.ok(lesson.checkpoint.correct >= 0 && lesson.checkpoint.correct < lesson.checkpoint.options.length);
    assert.ok(lesson.checkpoint.explanation.length > 30, `${lesson.id}: checkpoint explanation is too short`);

    const material = fs.readFileSync(lesson.material, "utf8");
    const lab = fs.readFileSync(lesson.lab, "utf8");
    const notebook = JSON.parse(fs.readFileSync(lesson.notebook, "utf8"));
    const codeCells = notebook.cells.filter(({ cell_type }) => cell_type === "code");
    const markdownCells = notebook.cells.filter(({ cell_type }) => cell_type === "markdown");

    assert.ok(material.length >= 1_000, `${lesson.id}: README is too shallow for publication`);
    assert.ok(!material.includes("\\n"), `${lesson.id}: README contains escaped placeholder newlines`);
    assert.ok((material.match(/^## /gm) ?? []).length >= 4, `${lesson.id}: README needs a usable learning structure`);
    assert.ok(lab.length >= 3_000, `${lesson.id}: lab is too shallow for the stated outcome`);
    assert.ok(codeCells.length >= 2, `${lesson.id}: notebook needs executable progression`);
    assert.ok(markdownCells.length >= 2, `${lesson.id}: notebook needs explanatory progression`);
    assert.ok(
      codeCells.length >= 5 || codeCells.some(({ source }) => source.join("").includes("assert")),
      `${lesson.id}: notebook needs executable checks`,
    );
  }
});

test("roadmap is clearly separate from published lessons", () => {
  assert.deepEqual(roadmapTracks.map(({ range }) => range), ["01–07", "08–17", "18–27", "28–36"]);
  assert.ok(roadmapTracks.every(({ status }) => status !== "Published"));
  assert.equal(roadmapCourses.length, 36);
  assert.deepEqual(roadmapCourses.map(({ number }) => number), Array.from({ length: 36 }, (_, index) => String(index + 1).padStart(2, "0")));
  assert.equal(new Set(roadmapCourses.map(({ folder }) => folder)).size, 36);
  for (const course of roadmapCourses) {
    assert.notEqual(course.status, "Published", `${course.number}: roadmap course was promoted without its gate`);
    assert.ok(fs.existsSync(`curriculum/${course.folder}/README.md`), `${course.number}: missing roadmap page`);
    assert.ok(course.evidence.includes("needs"), `${course.number}: remaining evidence must be explicit`);
    const roadmapPage = fs.readFileSync(`curriculum/${course.folder}/README.md`, "utf8");
    assert.ok(roadmapPage.includes(`Roadmap status: ${course.status}`), `${course.number}: page and registry status disagree`);
  }
});
