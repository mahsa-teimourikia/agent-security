import { lessons, checks } from "./lessons.js";

const base = "https://github.com/mahsa-teimourikia/agent-security/blob/main/";
const filters = document.querySelector("#filters");
const cards = document.querySelector("#cards");
const workspace = document.querySelector("#workspace");
let level = "All";
let selected = lessons[0];
let tab = "learn";
let completed = JSON.parse(localStorage.getItem("course-hub-progress") || "[]");
const link = (path) => path.startsWith("http") ? path : base + path;

function renderFilters() {
  filters.innerHTML = ["All", "Beginner", "Intermediate", "Advanced"].map((value) => `<button class="${level === value ? "active" : ""}" data-level="${value}">${value}</button>`).join("");
  filters.querySelectorAll("button").forEach((button) => button.onclick = () => { level = button.dataset.level; renderFilters(); renderCards(); });
}

function renderCards() {
  const visible = level === "All" ? lessons : lessons.filter((lesson) => lesson.level === level);
  cards.innerHTML = `<p class="progress">${completed.length}/${lessons.length} lessons complete</p>` + visible.map((lesson) => `<button class="card ${selected.id === lesson.id ? "selected" : ""}" data-id="${lesson.id}"><span class="pill">${lesson.level} · ${lesson.step}</span><h3>${lesson.title} ${completed.includes(lesson.id) ? "✓" : ""}</h3><p>${lesson.summary}</p></button>`).join("");
  cards.querySelectorAll(".card").forEach((card) => card.onclick = () => { selected = lessons.find((lesson) => lesson.id === card.dataset.id); tab = "learn"; renderCards(); renderWorkspace(); workspace.scrollIntoView({ behavior: "smooth" }); });
}

function renderWorkspace() {
  const check = checks[selected.id];
  const notebook = selected.notebook ? `<a class="button secondary" href="${link(selected.notebook)}" target="_blank">Open notebook ↗</a>` : "";
  const body = tab === "learn" ? `<p class="eyebrow">CONCEPT SUMMARY</p><p class="description">${selected.description}</p><p class="outcome">${selected.outcome}</p><a class="button" href="${link(selected.material)}" target="_blank">Read full GitHub lesson ↗</a>` : tab === "lab" ? `<p class="outcome">Run the lab, change one assumption, and record the observed failure or result.</p><a class="button" href="${link(selected.lab)}" target="_blank">Open practical lab ↗</a>${notebook}` : `<ol><li>${check[0]}</li><li>What could fail?</li><li>What evidence proves success?</li></ol><details><summary>Reveal answer guide</summary><p>${check[1]}</p></details><a href="../quiz/">Take the full quiz ↗</a>`;
  workspace.innerHTML = `<div class="workspace-head"><div><p class="eyebrow">LESSON ${selected.step} · ${selected.level.toUpperCase()}</p><h2>${selected.title}</h2></div><span class="pill">${selected.level}</span></div><div class="lesson-tabs"><button data-tab="learn" class="${tab === "learn" ? "active" : ""}">01 / Learn</button><button data-tab="lab" class="${tab === "lab" ? "active" : ""}">02 / Lab</button><button data-tab="checkpoint" class="${tab === "checkpoint" ? "active" : ""}">03 / Checkpoint</button></div><div class="lesson-grid"><article>${body}<button class="complete" id="complete">${completed.includes(selected.id) ? "Completed ✓" : "Mark lesson complete"}</button></article><aside><p class="eyebrow">SOURCES</p>${selected.refs.map((ref) => `<a class="source" href="${link(ref)}" target="_blank">${ref} ↗</a>`).join("")}</aside></div>`;
  workspace.querySelectorAll("[data-tab]").forEach((button) => button.onclick = () => { tab = button.dataset.tab; renderWorkspace(); });
  workspace.querySelector("#complete").onclick = () => { completed = completed.includes(selected.id) ? completed.filter((id) => id !== selected.id) : [...completed, selected.id]; localStorage.setItem("course-hub-progress", JSON.stringify(completed)); renderCards(); renderWorkspace(); };
}

renderFilters(); renderCards(); renderWorkspace();
