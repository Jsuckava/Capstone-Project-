import { saveSharedClientState } from "../services/api";

export const STUDENT_PUBLISHED_GRADES_KEY = "studentPublishedGrades";

export const normalizeStudentId = (studentId = "") =>
  String(studentId).trim().toLowerCase();

export const getPublishedGradesForStudent = (studentId) => {
  const saved = localStorage.getItem(STUDENT_PUBLISHED_GRADES_KEY);
  const publishedGrades = saved ? JSON.parse(saved) : {};

  return publishedGrades[normalizeStudentId(studentId)] || [];
};

export const upsertPublishedStudentGrades = (records = []) => {
  const saved = localStorage.getItem(STUDENT_PUBLISHED_GRADES_KEY);
  const publishedGrades = saved ? JSON.parse(saved) : {};

  records.forEach((record) => {
    const studentKey = normalizeStudentId(record.studentId);
    const currentRecords = publishedGrades[studentKey] || [];
    const recordKey = [
      record.schoolYear,
      record.semester,
      record.subjectCode,
      record.sectionName,
    ].join("|");

    publishedGrades[studentKey] = [
      ...currentRecords.filter(
        (currentRecord) =>
          [
            currentRecord.schoolYear,
            currentRecord.semester,
            currentRecord.subjectCode,
            currentRecord.sectionName,
          ].join("|") !== recordKey
      ),
      record,
    ];
  });

  localStorage.setItem(
    STUDENT_PUBLISHED_GRADES_KEY,
    JSON.stringify(publishedGrades)
  );
  saveSharedClientState(STUDENT_PUBLISHED_GRADES_KEY, publishedGrades).catch(
    (error) => console.warn("Shared published grades sync failed:", error)
  );

  return publishedGrades;
};
