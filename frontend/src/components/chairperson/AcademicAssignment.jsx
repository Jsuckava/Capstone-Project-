import React, { useEffect, useState } from "react";
import FacultyLoading from "./FacultyLoading";
import { programOptions } from "../../data/registrarData";
import { fetchApprovedFaculties, fetchCurriculums, assignFacultyLoadToBackend } from "../../services/api";
import { STUDENT_BATCHES_KEY, getDefaultSectionName } from "../../utils/studentSectioningHelpers";
import { pushAssignmentsSharedState } from "../../utils/sharedClientState";
import "./SubjectAssignment.css";

const read = (key) => { try { const value = JSON.parse(localStorage.getItem(key)); return Array.isArray(value) ? value : []; } catch { return []; } };
const nameOf = (person) => person?.fullname || person?.fullName || person?.name || person?.email || "";
const idOf = (person) => String(person?.id || person?.email || "");
const years = ["1st Year", "2nd Year", "3rd Year", "4th Year"];
const terms = { FIRST: "1st Semester", SECOND: "2nd Semester", MIDYEAR: "Summer" };
const identity = (item) => [item.program, item.sectionName, item.schoolYear, item.semester, item.subjectCode].join("|");
function Icon({ type }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{type === "search" ? <><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/></> : type === "book" ? <><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 7h6M9 11h6M9 15h4"/></> : type === "save" ? <><path d="M4 3h13l3 3v15H4zM8 3v6h8V3M8 21v-8h8v8"/></> : type === "cap" ? <><path d="m2 9 10-5 10 5-10 5zM6 12v5l6 3 6-3v-5M22 9v7"/></> : type === "upload" ? <><path d="M12 16V3m-5 5 5-5 5 5M4 15v6h16v-6"/></> : type === "trash" ? <><path d="M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/></> : <><circle cx="12" cy="7" r="4"/><path d="M4 21v-3a8 8 0 0 1 16 0v3z"/></>}</svg>;
}
function Heading({ icon, title }) { return <div className="sa-heading"><span className="sa-icon"><Icon type={icon}/></span><div><h3>{title}</h3></div></div>; }

export default function AcademicAssignment({ chairpersonDepartment = "" }) {
  const [faculty, setFaculty] = useState([]);
  const [curricula, setCurricula] = useState([]);
  const [loading, setLoading] = useState(true);
  const [professor, setProfessor] = useState("");
  const [lookup, setLookup] = useState("");
  const [professorListOpen, setProfessorListOpen] = useState(false);
  const availablePrograms = programOptions.filter((item) => item.name === chairpersonDepartment || item.code === chairpersonDepartment);
  const [program, setProgram] = useState(availablePrograms[0]?.code || "");
  const [year, setYear] = useState("3rd Year");
  const [term, setTerm] = useState("SECOND");
  const [query, setQuery] = useState("");
  const [subjectCode, setSubjectCode] = useState("");
  const [mode, setMode] = useState("manual");
  const [draft, setDraft] = useState([]);
  const [saved, setSaved] = useState(() => read("registrarAssignments"));
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);

  const [schedules, setSchedules] = useState({});
  useEffect(() => {
    let active = true;
    Promise.allSettled([fetchApprovedFaculties(), fetchCurriculums()]).then(([people, courses]) => {
      if (!active) return;
      if (people.status === "fulfilled") setFaculty(people.value.faculties || []);
      if (courses.status === "fulfilled") setCurricula(courses.value.data || []);
      if (people.status === "rejected" || courses.status === "rejected") setNotice("Some data could not be loaded. Refresh the page to retry.");
      setLoading(false);
    });
    return () => { active = false; };
  }, []);
  const departmentFaculty = faculty.filter((person) => (person.department || person.program) === chairpersonDepartment || (person.department || person.program) === program);
  const selectedProfessor = departmentFaculty.find((person) => idOf(person) === professor);
  const programName = programOptions.find((item) => item.code === program)?.name || program;
  const curriculum = curricula.find((item) => item.programCode === program && item.status === "PUBLISHED");
  const subjects = (curriculum?.subjects || []).filter((item) => Number(item.yearLevel) === years.indexOf(year) + 1 && item.semester === term);
  const visibleSubjects = subjects.filter((item) => `${item.subjectCode} ${item.subjectTitle}`.toLowerCase().includes(query.toLowerCase()));
  const subject = subjects.find((item) => item.subjectCode === subjectCode);
  const allSections = [...read("studentSections"), ...read(STUDENT_BATCHES_KEY).filter((batch) => batch.status !== "Promoted").flatMap((batch) => (batch.sectionPlans || []).map((section) => ({
    program: batch.program, yearLevel: section.yearLevel, section: section.sectionName || getDefaultSectionName(batch.program, section.sectionCode), schoolYear: batch.batchYear, semester: batch.semester,
    students: (batch.students || []).filter((student) => student.sectionCode === section.sectionCode && (!student.yearLevel || student.yearLevel === section.yearLevel)),
  })))];
  const sections = allSections.filter((item, index, items) => item.program === programName && item.yearLevel === year && (!item.semester || item.semester === terms[term]) && items.findIndex((other) => other.section === item.section && other.program === item.program && other.schoolYear === item.schoolYear && other.semester === item.semester) === index);
  const rows = [...saved, ...draft].filter((item) => String(item.facultyId) === professor);
  const professorDraft = draft.filter((item) => String(item.facultyId) === professor);
  const totalUnits = rows.reduce((sum, item) => sum + (Number(item.units) || 0), 0);
  const selectProfessor = (person) => { setProfessor(idOf(person)); setLookup(""); setProfessorListOpen(false); };
  const add = (section, index) => {
    if (!subject || !selectedProfessor) return;
    const item = { id: `subject-${Date.now()}-${index}`, facultyId: professor, facultyName: nameOf(selectedProfessor), program: programName, sectionName: section.section, yearLevel: year, schoolYear: section.schoolYear, semester: terms[term], subjectCode: subject.subjectCode, subjectTitle: subject.subjectTitle, units: String(subject.units || 0), schedule: schedules[`${program}|${section.section}|${section.schoolYear}`] || "", day: "", date: "", rosterStudents: section.students || [], rosterFileName: "Created section roster", loadMode: "Manual Section Distribution", uploadedAt: new Date().toISOString() };
    if ([...saved, ...draft].some((other) => identity(other) === identity(item))) { setNotice("This subject and section already have an assignment for this term."); return; }
    setDraft((current) => [...current, item]); setNotice("");
  };
  const save = async () => {
    if (!professorDraft.length || saving) return;
    setSaving(true); setNotice("");
    try {
      const latest = read("registrarAssignments");
      if (professorDraft.some((item) => latest.some((other) => identity(other) === identity(item)))) throw new Error("An assignment was added elsewhere. Reload before saving to avoid duplicates.");
      const next = [...latest, ...professorDraft];
      localStorage.setItem("registrarAssignments", JSON.stringify(next));
      setSaved(next);
      const pending = [...professorDraft]; setDraft((current) => current.filter((item) => String(item.facultyId) !== professor));
      const results = await Promise.allSettled(pending.map((item) => assignFacultyLoadToBackend(item)));
      await pushAssignmentsSharedState();
      setNotice(results.some((result) => result.status === "rejected") ? "Assignments saved locally. Some faculty loads could not sync to the server." : "Assignments saved successfully.");
    } catch (error) { setNotice(error.message || "Unable to save assignments."); }
    finally { setSaving(false); }
  };

  return <div className="subject-assignment">
    <header className="sa-header"><div><div className="sa-breadcrumb">Academic Management <span>›</span> <strong>Academic Assignment</strong></div><h2>Assign Subjects and Sections to Professors</h2></div></header>
    
    {notice && <div className="sa-info" role="status">{notice}</div>}
    <section className="sa-card sa-lookup"><div><Heading title="Professor Lookup" /><div className="sa-search"><Icon type="search"/><input aria-label="Search professors" onFocus={() => setProfessorListOpen(true)} onClick={() => setProfessorListOpen(true)} placeholder="Search professor by name or faculty ID..." value={lookup} onChange={(event) => setLookup(event.target.value)}/><button aria-label="Clear professor search" onClick={() => setLookup("")}>×</button></div><div className="sa-professors">{(professorListOpen || lookup || !selectedProfessor) && (departmentFaculty.filter((person) => `${nameOf(person)} ${idOf(person)}`.toLowerCase().includes(lookup.toLowerCase())).map((person) => <button key={idOf(person)} onClick={() => selectProfessor(person)}>{nameOf(person)} <small>{idOf(person)}</small></button>))}{loading && <p>Loading professors…</p>}{!loading && !departmentFaculty.length && <p>No approved professors available.</p>}</div></div><div className="sa-professor"><span className="sa-avatar">{nameOf(selectedProfessor).split(/\s+/).filter(Boolean).slice(0, 2).map((word) => word[0]).join("") || <Icon/>}</span><div><h3>{nameOf(selectedProfessor) || "Select a professor"}</h3><p>Faculty ID: &nbsp; {professor || "—"}</p><p>Department: &nbsp; {selectedProfessor?.department || selectedProfessor?.program || "—"}</p></div><div className="sa-badge"><Icon type="cap"/><div><strong>{totalUnits} units</strong><small>{rows.length} assignments</small></div></div></div></section>
    <div className="sa-tabs" role="group" aria-label="Assignment method"><button className={mode === "manual" ? "active" : ""} aria-pressed={mode === "manual"} onClick={() => { setMode("manual"); setSaved(read("registrarAssignments")); }}><Icon type="cap"/>Manual Assignment</button><button className={mode === "bulk" ? "active" : ""} aria-pressed={mode === "bulk"} disabled={draft.length > 0} onClick={() => setMode("bulk")}><Icon type="upload"/>Bulk Assignment</button><span>{draft.length ? "Save or clear pending assignments before switching modes." : ""}</span></div>
    {mode === "bulk" ? <><label className="sa-program">Academic Program<select value={program} onChange={(event) => setProgram(event.target.value)}>{availablePrograms.map((item) => <option key={item.code} value={item.code}>{item.name}</option>)}</select></label><FacultyLoading key={program} chairpersonDepartment={programName} assignmentMode="bulk"/></> : <>
    {selectedProfessor && (<section className="sa-card sa-assigned"><div className="sa-assigned-header"><Heading icon="cap" title={`Assigned to ${nameOf(selectedProfessor) || "Selected Professor"}`} /><div className="sa-totals"><div><Icon type="book"/><span>Total Assignments<strong>{rows.length}</strong></span></div><div><Icon type="cap"/><span>Total Units<strong>{totalUnits}</strong></span></div></div></div><div className="sa-table-scroll"><table><thead><tr><th>Subject Code</th><th>Subject Title</th><th>Section</th><th>Units</th><th>Schedule</th><th>Action</th></tr></thead><tbody>{rows.map((item) => <tr key={item.id}><td>{item.subjectCode}</td><td>{item.subjectTitle}</td><td>{item.sectionName}</td><td>{item.units}</td><td>{[item.day, item.schedule].filter(Boolean).join(" ") || "Not set"}</td><td>{draft.some((row) => row.id === item.id) ? <button className="sa-remove" aria-label={`Remove ${item.subjectCode} ${item.sectionName}`} onClick={() => setDraft(draft.filter((row) => row.id !== item.id))}><Icon type="trash"/></button> : <span className="sa-saved">Saved</span>}</td></tr>)}{!rows.length && <tr><td colSpan="6" className="sa-empty">{selectedProfessor ? "No assignments yet." : "Choose a professor to see their assignments."}</td></tr>}</tbody></table></div><footer><button className="sa-clear" disabled={saving} onClick={() => { setDraft((current) => current.filter((item) => String(item.facultyId) !== professor)); setSubjectCode(""); setNotice(""); }}>♧ &nbsp; Clear Selection</button><span>{professorDraft.length > 0 && `${professorDraft.length} pending assignment${professorDraft.length > 1 ? "s" : ""}`}</span><button className="sa-save" disabled={!professorDraft.length || saving} onClick={save}><Icon type="save"/>{saving ? "Saving…" : "Save Assignments"}</button></footer></section>)}
    <div className="sa-columns"><section className="sa-card"><Heading icon="book" title="Available Subjects" /><div className="sa-filters"><label>Academic Program<select value={program} onChange={(event) => { setProgram(event.target.value); setSubjectCode(""); }}>{availablePrograms.map((item) => <option key={item.code} value={item.code}>{item.name}</option>)}</select></label><label>Year Level<select value={year} onChange={(event) => { setYear(event.target.value); setSubjectCode(""); }}>{years.map((item) => <option key={item}>{item}</option>)}</select></label><label>Semester<select value={term} onChange={(event) => { setTerm(event.target.value); setSubjectCode(""); }}>{Object.entries(terms).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label></div><div className="sa-search"><Icon type="search"/><input aria-label="Search subjects" placeholder="Search subjects by code or title..." value={query} onChange={(event) => setQuery(event.target.value)}/></div><div className="sa-table-scroll"><table><thead><tr><th></th><th>Subject Code</th><th>Subject Title</th><th>Units</th></tr></thead><tbody>{visibleSubjects.map((item) => <tr key={item.subjectCode} className={subjectCode === item.subjectCode ? "selected" : ""}><td><input type="radio" name="subject" aria-label={`Select ${item.subjectCode}`} checked={subjectCode === item.subjectCode} onChange={() => setSubjectCode(item.subjectCode)}/></td><td><button className="sa-text-button" onClick={() => setSubjectCode(item.subjectCode)}>{item.subjectCode}</button></td><td>{item.subjectTitle}</td><td>{item.units}</td></tr>)}{!visibleSubjects.length && <tr><td colSpan="4" className="sa-empty">{loading ? "Loading subjects…" : !curriculum ? "No published curriculum for this program." : "No subjects match these filters."}</td></tr>}</tbody></table></div><p className="sa-footnote">Showing {visibleSubjects.length} of {subjects.length} subjects</p></section>
    <section className="sa-card"><Heading title={`Available Sections${subject ? ` for ${subject.subjectCode}` : ""}`} /><div className="sa-table-scroll"><table><thead><tr><th>Section</th><th>Year Level</th><th>Schedule</th><th>Action</th></tr></thead><tbody>{subject && sections.map((section, index) => <tr key={`${section.section}-${section.schoolYear}`}><td className="sa-section-name">{section.section}<small>{section.schoolYear}</small></td><td>{section.yearLevel}</td><td><input className="sa-schedule" aria-label={`Schedule for ${section.section}`} placeholder="Set schedule" value={schedules[`${program}|${section.section}|${section.schoolYear}`] || ""} onChange={(event) => setSchedules({ ...schedules, [`${program}|${section.section}|${section.schoolYear}`]: event.target.value })}/></td><td><button className="sa-assign" disabled={!selectedProfessor || saving} onClick={() => add(section, index)}>＋ Assign</button></td></tr>)}{(!subject || !sections.length) && <tr><td colSpan="4" className="sa-empty">{!subject ? "No subject selected." : "No sections created for this program and year level."}</td></tr>}</tbody></table></div><div className="sa-info sa-selected"><span>ⓘ</span><div><strong>Selected Subject: {subject ? `${subject.subjectCode} – ${subject.subjectTitle}` : "None"}</strong></div></div></section></div>
</>}
  </div>;
}

