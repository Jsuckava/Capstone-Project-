export const CHAIRPERSON_REVIEW_KEY = "chairpersonSectionReviews";

export const normalizeText = (value = "") =>
  String(value).trim().toLowerCase();

const buildStableFacultyKey = (faculty = {}) =>
  normalizeText(
    faculty.facultyId ||
      faculty.id ||
      faculty.email ||
      faculty.facultyName ||
      faculty.name ||
      ""
  );

export const buildAssignmentStorageKey = (assignment = {}) =>
  assignment.assignmentKey ||
  assignment.id ||
  [
    String(
      assignment.facultyId ||
        assignment.id ||
        assignment.facultyName ||
        ""
    ).trim(),
    assignment.sectionName,
    assignment.schoolYear,
    assignment.semester,
    assignment.subjectCode,
  ].join("__");

export const buildFacultyDirectory = ({ facultyList = [], assignments = [] }) => {
  const map = new Map();

  facultyList.forEach((faculty) => {
    const facultyKey = buildStableFacultyKey(faculty);
    if (!facultyKey) return;

    map.set(facultyKey, {
      facultyId: faculty.facultyId || faculty.id || faculty.email || facultyKey,
      facultyKey,
      facultyName: faculty.facultyName || faculty.name || faculty.email || "Unnamed Faculty",
      department: faculty.program,
      sections: [],
    });
  });

  assignments.forEach((assignment) => {
    const facultyKey = buildStableFacultyKey(assignment);
    if (!facultyKey) return;

    if (!map.has(facultyKey)) {
      map.set(facultyKey, {
        facultyId: assignment.facultyId || facultyKey,
        facultyKey,
        facultyName: assignment.facultyName || `Faculty ${assignment.facultyId || facultyKey}`,
        department: assignment.program,
        sections: [],
      });
    }

    const facultyEntry = map.get(facultyKey);
    facultyEntry.facultyId = assignment.facultyId || facultyEntry.facultyId;
    facultyEntry.facultyName =
      assignment.facultyName || facultyEntry.facultyName;
    facultyEntry.department = assignment.program || facultyEntry.department;
    facultyEntry.sections.push(assignment);
  });

  return Array.from(map.values());
};

export const getSectionStudents = ({ students = [], assignment }) => {
  if (!assignment) return [];

  if (Array.isArray(assignment.rosterStudents) && assignment.rosterStudents.length) {
    return assignment.rosterStudents;
  }

  return students.filter((student) => {
    const sameProgram = normalizeText(student.program) === normalizeText(assignment.program);
    const sameSchoolYear = normalizeText(student.schoolYear) === normalizeText(assignment.schoolYear);
    const sameSemester =
      !normalizeText(student.semester) ||
      !normalizeText(assignment.semester) ||
      normalizeText(student.semester) === normalizeText(assignment.semester);

    const sectionOptions = [
      assignment.sectionName,
      `${assignment.program} ${assignment.sectionName}`,
    ].map(normalizeText);

    const sameSection = sectionOptions.includes(normalizeText(student.section));

    return sameProgram && sameSchoolYear && sameSemester && sameSection;
  });
};

export const getSectionReviewRecord = ({ reviewData = {}, reviewKey }) =>
  reviewData[reviewKey] || {
    status: "pending",
    note: "",
    lastUpdated: null,
  };

export const getReviewStatusLabel = (status = "pending") => {
  if (status === "returned") return "Returned to Faculty";
  if (status === "approved") return "Approved by Chairperson";
  if (status === "forwarded") return "Forwarded to Registrar";
  if (status === "submitted") return "Submitted to Chairperson";
  return "Not Yet Submitted";
};

export const getReviewStatusClasses = (status = "pending") => {
  if (status === "returned") {
    return "bg-red-100 text-red-700 border border-red-200";
  }

  if (status === "approved") {
    return "bg-emerald-100 text-emerald-700 border border-emerald-200";
  }

  if (status === "forwarded") {
    return "bg-violet-100 text-violet-700 border border-violet-200";
  }

  if (status === "submitted") {
    return "bg-blue-100 text-blue-700 border border-blue-200";
  }

  return "bg-amber-100 text-amber-700 border border-amber-200";
};

export const getEncodedCount = ({ grades = {}, students = [], activeTerm = "finals" }) =>
  students.filter((student) => {
    const studentGradesForSubject =
      grades[student.id] || grades[student.studentId] || {};

    return activeTerm === "midterm"
      ? studentGradesForSubject.midterm !== undefined &&
          studentGradesForSubject.midterm !== null &&
          studentGradesForSubject.midterm !== ""
      : studentGradesForSubject.finals !== undefined &&
          studentGradesForSubject.finals !== null &&
          studentGradesForSubject.finals !== "";
  }).length;

export const getFacultyStatus = ({ encodedSections = 0, totalSections = 0 }) => {
  if (totalSections === 0) return "No Assigned Sections";
  if (encodedSections === 0) return "Not Started";
  if (encodedSections >= totalSections) return "Completed";
  return "In Progress";
};

export const getFacultyStatusClasses = (status) => {
  if (status === "Completed") return "bg-emerald-100 text-emerald-700";
  if (status === "In Progress") return "bg-yellow-100 text-yellow-700";
  if (status === "No Assigned Sections") return "bg-slate-100 text-slate-600";
  return "bg-red-100 text-red-700";
};

export const getChairActionLabel = (status = "pending") => {
  if (status === "returned") return "Returned for Correction";
  if (status === "approved") return "Approved";
  if (status === "forwarded") return "Sent to Registrar";
  if (status === "submitted") return "Needs Review";
  return "Waiting for Faculty";
};

export const buildReviewKey = (assignment) =>
  [buildAssignmentStorageKey(assignment), assignment.term || "finals"].join("__");

export const computeGradeStatus = (record = {}, activeTerm = "finals") => {
  if (["dropped", "unofficially_dropped", "withdrawn", "incomplete"].includes(record.standing)) {
    return record.standing;
  }

  const midterm = Number(record.midterm);
  const finals = Number(record.finals);

  if (activeTerm === "midterm") {
    if (!midterm) return "pending";
    return midterm >= 75 ? "passed" : "failed";
  }

  if (!midterm || !finals) return "pending";

  return (midterm + finals) / 2 >= 75 ? "passed" : "failed";
};
