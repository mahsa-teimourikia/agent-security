import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { publishedLessons, roadmapTracks } from "../app/course-data.js";


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
  }
});

test("roadmap is clearly separate from published lessons", () => {
  assert.deepEqual(roadmapTracks.map(({ range }) => range), ["01–07", "08–17", "18–27", "28–36"]);
  assert.ok(roadmapTracks.every(({ status }) => status !== "Published"));
});
