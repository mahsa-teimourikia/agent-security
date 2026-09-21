import React, { useEffect, useMemo, useState } from "react";
import "./globals.css";
import { publishedLessons, roadmapCourses, roadmapTracks } from "./course-data";

const repository = "https://github.com/mahsa-teimourikia/agent-security/blob/main/";
const sourceLink = (path: string) => `${repository}${path}`;

export default function App() {
  const [level, setLevel] = useState("All");
  const [selectedId, setSelectedId] = useState(publishedLessons[0].id);
  const [tab, setTab] = useState("learn");
  const [answer, setAnswer] = useState<number | null>(null);
  const [graded, setGraded] = useState(false);
  const [completed, setCompleted] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem("agent-security-progress") || "[]");
    } catch {
      return [];
    }
  });

  useEffect(() => {
    localStorage.setItem("agent-security-progress", JSON.stringify(completed));
  }, [completed]);

  const selected = publishedLessons.find((item) => item.id === selectedId) || publishedLessons[0];
  const visible = useMemo(
    () => level === "All" ? publishedLessons : publishedLessons.filter((item) => item.level === level),
    [level],
  );

  const chooseLesson = (id: string) => {
    setSelectedId(id);
    setTab("learn");
    setAnswer(null);
    setGraded(false);
  };

  const toggleComplete = () => {
    setCompleted((current) => current.includes(selected.id)
      ? current.filter((id) => id !== selected.id)
      : [...current, selected.id]);
  };

  return (
    <>
      <header className="hero">
        <nav>
          <a className="brand" href="https://oneplusi.io"><span>✦</span> One+i Learning</a>
          <div><a href="#curriculum">Curriculum</a><a href="#roadmap">Roadmap</a><a href="./quiz/">Knowledge check ↗</a></div>
        </nav>
        <div className="hero-grid">
          <div>
            <p className="eyebrow">AI AGENT SECURITY ENGINEERING</p>
            <h1>Build authority<br /><i>with boundaries.</i></h1>
            <p className="lede">A credential-free path from trust boundaries to production evidence. Trace the attack, enforce the control, and prove the bypass stays closed.</p>
            <a className="primary" href="#curriculum">Start the published path ↓</a>
          </div>
          <aside className="signal-card">
            <p className="eyebrow">THE SECURITY LOOP</p>
            <ol><li>Model the boundary</li><li>Inject a realistic failure</li><li>Enforce outside the model</li><li>Measure and preserve evidence</li></ol>
          </aside>
        </div>
      </header>

      <main>
        <section id="curriculum" className="section">
          <div className="section-head">
            <div><p className="eyebrow">PUBLISHED CURRICULUM</p><h2>Learn → Lab → Checkpoint</h2></div>
            <p className="progress">{completed.length} / {publishedLessons.length} completed</p>
          </div>
          <div className="filters" aria-label="Filter lessons by level">
            {["All", "Foundation", "Beginner", "Intermediate", "Advanced"].map((item) => (
              <button className={level === item ? "active" : ""} key={item} onClick={() => setLevel(item)}>{item}</button>
            ))}
          </div>
          <div className="curriculum-grid">
            <div className="lesson-list">
              {visible.map((item) => (
                <button className={`lesson-card ${selected.id === item.id ? "selected" : ""}`} key={item.id} onClick={() => chooseLesson(item.id)}>
                  <span className="lesson-meta">{item.level} · {item.step}</span>
                  <strong>{item.title} {completed.includes(item.id) ? "✓" : ""}</strong>
                  <span>{item.summary}</span>
                </button>
              ))}
            </div>

            <article className="workspace" aria-live="polite">
              <div className="workspace-head"><div><p className="eyebrow">{selected.level} · {selected.step}</p><h2>{selected.title}</h2></div><span className="published">Published</span></div>
              <div className="tabs" role="tablist">
                {["learn", "lab", "checkpoint"].map((item, index) => <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{String(index + 1).padStart(2, "0")} / {item}</button>)}
              </div>
              {tab === "learn" && <div className="panel"><p>{selected.summary}</p><h3>Outcome</h3><p>{selected.outcome}</p><a className="primary" href={sourceLink(selected.material)} target="_blank" rel="noreferrer">Read the lesson ↗</a></div>}
              {tab === "lab" && <div className="panel"><p>Run the deterministic implementation, change one assumption, and record the resulting policy decision and trace.</p><div className="actions"><a className="primary" href={sourceLink(selected.notebook)} target="_blank" rel="noreferrer">Open guided notebook ↗</a><a className="secondary" href={sourceLink(selected.lab)} target="_blank" rel="noreferrer">Open reusable lab ↗</a></div></div>}
              {tab === "checkpoint" && <div className="panel"><h3>{selected.checkpoint.prompt}</h3><div className="answers">{selected.checkpoint.options.map((option, index) => <label key={option}><input type="radio" name="answer" checked={answer === index} onChange={() => { setAnswer(index); setGraded(false); }} />{option}</label>)}</div><button className="primary button" disabled={answer === null} onClick={() => setGraded(true)}>Check answer</button>{graded && <p className={answer === selected.checkpoint.correct ? "feedback correct" : "feedback review"}>{answer === selected.checkpoint.correct ? "Correct — " : "Review — "}{selected.checkpoint.explanation}</p>}</div>}
              <button className="complete" onClick={toggleComplete}>{completed.includes(selected.id) ? "Completed ✓" : "Mark lesson complete"}</button>
            </article>
          </div>
        </section>

        <section id="roadmap" className="section roadmap-section">
          <div className="section-head"><div><p className="eyebrow">EXPANSION ROADMAP</p><h2>36 courses, released by evidence</h2></div><p>Roadmap entries are not counted as complete until their chapter, notebook, lab, evaluation, and focused checkpoint all run together.</p></div>
          <div className="roadmap-grid">{roadmapTracks.map((track) => <article key={track.level}><span>{track.range}</span><h3>{track.level}</h3><p>{track.summary}</p><strong>{track.status}</strong></article>)}</div>
          <div className="roadmap-list" aria-label="Course-by-course roadmap status">
            {roadmapCourses.map((course) => <a key={course.code} href={sourceLink(`curriculum/${course.folder}/README.md`)} target="_blank" rel="noreferrer">
              <span>{course.code}</span>
              <span><strong>{course.title}</strong><small>{course.level} · {course.evidence}</small></span>
              <em className={`status-${course.status.toLowerCase()}`}>{course.status}</em>
            </a>)}
          </div>
          <div className="roadmap-actions"><a className="primary" href={sourceLink("curriculum/README.md")} target="_blank" rel="noreferrer">Explore the curriculum map ↗</a><a className="secondary" href={sourceLink("ROADMAP.md")} target="_blank" rel="noreferrer">Read the publication rules ↗</a></div>
        </section>
      </main>

      <footer><a className="brand" href="https://oneplusi.io"><img src="./assets/one-plus-i.png" alt="One+i" /> One+i</a><p>Responsible AI, proven through observable controls.</p><a href="https://github.com/mahsa-teimourikia/agent-security">GitHub ↗</a></footer>
    </>
  );
}
