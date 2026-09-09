import React, { useState, useCallback, useEffect, useRef } from 'react';
import { fetchFacultySections, fetchFacultyStudents, fetchAllGrades, batchUploadGrades, getSystemSetting, issueGrade, submitSectionGrades } from '../../services/api';
import Modal from '../../services/Modal';
import FacultyHeader from './FacultyHeader';
import YearTabs from './YearTabs';
import ProgramCard from './ProgramCard';
import FacultyCurriculumPanel from './FacultyCurriculumPanel';
import { getGradeEquivalent } from '../../utils/gradingHelpers';

const normalizeYearLabel = (value) => {
  const raw = String(value || '').trim();
  if (!raw) return "N/A";

  const normalized = raw.toLowerCase();
  if (normalized === "1" || normalized === "1st" || normalized === "1st year") {
    return "1st Year";
  }
  if (normalized === "2" || normalized === "2nd" || normalized === "2nd year") {
    return "2nd Year";
  }
  if (normalized === "3" || normalized === "3rd" || normalized === "3rd year") {
    return "3rd Year";
  }
  if (normalized === "4" || normalized === "4th" || normalized === "4th year") {
    return "4th Year";
  }

  return raw;
};

const normalizeText = (value = "") => String(value || "").trim().toLowerCase();
const getOptionalAssignmentValue = (value) => {
  const normalizedValue = String(value || "").trim();
  return normalizedValue || "Not Available";
};
const parseTimestamp = (value) => {
  if (!value) return 0;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
};
const buildFacultyAssignmentLookupKey = ({
  program = "",
  sectionName = "",
  subjectCode = "",
  yearLevel = "",
} = {}) =>
  [
    normalizeText(program),
    normalizeText(sectionName),
    normalizeText(subjectCode),
    normalizeText(yearLevel),
  ].join("|");

const STUDENT_STATUS_ACTIVE = "active";
const RETURNED_SECTION_STATUSES = ["returned", "rejected"];
const LOCKED_SECTION_STATUSES = ["submitted", "approved", "forwarded", "finalized"];
const KNOWN_SECTION_STATUSES = [
  "draft",
  "submitted",
  "approved",
  "forwarded",
  "finalized",
  "returned",
];
const SECTION_STATUS_PRIORITY = {
  draft: 0,
  returned: 1,
  submitted: 2,
  approved: 3,
  forwarded: 4,
  finalized: 4,
};
const createDefaultSectionTermStatuses = () => ({
  midterm: "draft",
  finals: "draft",
});
const normalizeEncodingTerm = (term) => (term === "finals" ? "finals" : "midterm");
const normalizeSectionStatusValue = (status) => {
  const normalized = normalizeText(status);
  if (normalized.includes("issued") || normalized.includes("submitted")) return "submitted";
  if (normalized.includes("departmentapproved") || normalized.includes("approved")) return "approved";
  if (normalized.includes("finalized") || normalized.includes("forwarded")) return "forwarded";
  if (RETURNED_SECTION_STATUSES.includes(normalized)) return "returned";
  return KNOWN_SECTION_STATUSES.includes(normalized) ? normalized : "draft";
};
const normalizeSectionStatusEntry = (entry) => {
  if (typeof entry === "string") {
    return {
      ...createDefaultSectionTermStatuses(),
      midterm: normalizeSectionStatusValue(entry),
    };
  }

  return {
    midterm: normalizeSectionStatusValue(entry?.midterm),
    finals: normalizeSectionStatusValue(entry?.finals),
  };
};
const isLockedSectionStatus = (status) =>
  LOCKED_SECTION_STATUSES.includes(normalizeSectionStatusValue(status));
const mergeSectionTermStatuses = (previousEntry, nextEntry) => {
  const previous = normalizeSectionStatusEntry(previousEntry);
  const next = normalizeSectionStatusEntry(nextEntry);
  const shouldOverrideLockedStatus = (nextStatus) =>
    nextStatus === "returned" || nextStatus === "draft";

  return {
    midterm:
      isLockedSectionStatus(previous.midterm) && !shouldOverrideLockedStatus(next.midterm)
        ? previous.midterm
        : next.midterm,
    finals:
      isLockedSectionStatus(previous.finals) && !shouldOverrideLockedStatus(next.finals)
        ? previous.finals
        : next.finals,
  };
};
const buildFacultyGradeSnapshotKey = (facultyEmail = "") =>
  `facultySectionGrades:${normalizeText(facultyEmail || "faculty")}`;
const buildFacultyBulkUploadKey = (facultyEmail = "") =>
  `facultyBulkUploads:${normalizeText(facultyEmail || "faculty")}`;
const getFacultyResetToken = () => localStorage.getItem("facultyLoadResetAt") || "";
const loadResetAwareLocalData = (storageKey) => {
  try {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return null;

    const parsed = JSON.parse(raw);
    const currentResetToken = getFacultyResetToken();

    if (
      parsed &&
      typeof parsed === "object" &&
      Object.prototype.hasOwnProperty.call(parsed, "resetToken") &&
      Object.prototype.hasOwnProperty.call(parsed, "data")
    ) {
      return parsed.resetToken === currentResetToken ? parsed.data : null;
    }

    return currentResetToken ? null : parsed;
  } catch (error) {
    return null;
  }
};
const saveResetAwareLocalData = (storageKey, data) => {
  const payload = {
    resetToken: getFacultyResetToken(),
    data,
  };
  localStorage.setItem(storageKey, JSON.stringify(payload));
};

const parseGradeValue = (value) => {
  if (value === null || value === undefined) return "";

  const normalized = String(value).trim();
  if (!normalized) return "";

  const numeric = Number(normalized);
  return Number.isNaN(numeric) ? "" : numeric;
};

const hasEncodedGrade = (value) => {
  if (value === null || value === undefined || value === "") return false;
  const numeric = Number(value);
  return !Number.isNaN(numeric) && numeric > 0;
};

const hasEncodedGradeForTerm = (student = {}, term = "midterm") =>
  term === "finals"
    ? hasEncodedGrade(student.finals)
    : hasEncodedGrade(student.midterm);

const computeFinalAverage = (student = {}) => {
  if (!hasEncodedGrade(student.midterm) || !hasEncodedGrade(student.finals)) {
    return null;
  }

  const mid = Number(student.midterm);
  const fin = Number(student.finals);

  if (Number.isNaN(mid) || Number.isNaN(fin)) return null;

  return (mid + fin) / 2;
};

const getAcademicStatus = (student = {}) => {
  const finalAverage = computeFinalAverage(student);
  if (finalAverage === null) return "-";
  return finalAverage >= 75 ? "Passed" : "Failed";
};

const getTemporarySheetHeader = () => [
  "Student ID",
  "Student Name",
  "Quizzes (20%)",
  "Assignments (10%)",
  "Attendance (10%)",
  "Midterm Exam (60%)",
  "Midterm Grade",
  "Final Quizzes (20%)",
  "Final Assignments (10%)",
  "Final Attendance (10%)",
  "Final Exam (60%)",
  "Final Grade",
  "Final Rating",
];

const FacultyPortal = ({ facultyData, onLogout }) => {
  const [portalView, setPortalView] = useState('grades');
  const [activeSection, setActiveSection] = useState(null);
  const [activeTab, setActiveTab] = useState("All Sections");
  const [searchQuery, setSearchQuery] = useState("");
  const [rowSaveState, setRowSaveState] = useState({});
  const [sectionStatus, setSectionStatus] = useState({});
  const [validationErrors, setValidationErrors] = useState({});
  
  const [uploadingSection, setUploadingSection] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [isLoadingData, setIsLoadingData] = useState(true);
  const [bulkUploadedSections, setBulkUploadedSections] = useState({});
  const [submitConfirmSection, setSubmitConfirmSection] = useState(null);
  const hasHydratedFacultyDataRef = useRef(false);

  const [sections, setSections] = useState({});
  const sectionStatusStorageKey = `facultySectionStatuses:${normalizeText(facultyData?.email || "faculty")}`;
  const facultyGradeSnapshotStorageKey = buildFacultyGradeSnapshotKey(facultyData?.email || "");
  const facultyBulkUploadStorageKey = buildFacultyBulkUploadKey(facultyData?.email || "");

  const [encodingStart, setEncodingStart] = useState(null);
  const [encodingEnd, setEncodingEnd] = useState(null);
  const [encodingTerm, setEncodingTerm] = useState("midterm");
  const [encodingSemester, setEncodingSemester] = useState("2nd Semester");

  useEffect(() => {
    const parseLocalDate = (value, endOfDay = false) => {
      if (!value) return null;
      const [year, month, day] = String(value).split("-").map(Number);
      if (!year || !month || !day) return null;
      const date = new Date(year, month - 1, day);
      if (endOfDay) date.setHours(23, 59, 59, 999);
      else date.setHours(0, 0, 0, 0);
      return date;
    };

    const applyEncodingPeriod = (value) => {
      if (!value) return;
      const parsed = typeof value === 'string' ? JSON.parse(value) : value;
      setEncodingSemester(parsed.semester || "2nd Semester");
      setEncodingTerm(parsed.term === "finals" ? "finals" : "midterm");
      setEncodingStart(parseLocalDate(parsed.startDate));
      setEncodingEnd(parseLocalDate(parsed.endDate, true));
    };

    const loadEncodingPeriod = async () => {
        try {
            const res = await getSystemSetting("encoding_period");
            if (res.status === "Success" && res.value) {
                applyEncodingPeriod(res.value);
            }
        } catch (e) { console.error(e); }
    };

    const handleSystemSettingChanged = (event) => {
      const key = event.detail?.key || event.detail?.Key;
      const value = event.detail?.value || event.detail?.Value;
      if (key === 'encoding_period') applyEncodingPeriod(value);
    };

    loadEncodingPeriod();
    const refreshTimer = window.setInterval(loadEncodingPeriod, 10000);
    window.addEventListener('blockgo:system-setting-changed', handleSystemSettingChanged);
    window.addEventListener('focus', loadEncodingPeriod);

    return () => {
      window.clearInterval(refreshTimer);
      window.removeEventListener('blockgo:system-setting-changed', handleSystemSettingChanged);
      window.removeEventListener('focus', loadEncodingPeriod);
    };
  }, []);

  useEffect(() => {
    try {
      const parsedStatuses = loadResetAwareLocalData(sectionStatusStorageKey);
      if (!parsedStatuses || typeof parsedStatuses !== "object") return;

      setSectionStatus((prev) => {
        const next = { ...prev };
        Object.entries(parsedStatuses).forEach(([sectionKey, entry]) => {
          next[sectionKey] = normalizeSectionStatusEntry(entry);
        });
        return next;
      });
    } catch (error) {
      console.warn("Failed to parse saved faculty section statuses.", error);
    }
  }, [sectionStatusStorageKey]);

  useEffect(() => {
    if (!hasHydratedFacultyDataRef.current) return;

    try {
      saveResetAwareLocalData(sectionStatusStorageKey, sectionStatus);
    } catch (error) {
      console.warn("Failed to persist faculty section statuses.", error);
    }
  }, [sectionStatus, sectionStatusStorageKey]);

  useEffect(() => {
    if (!hasHydratedFacultyDataRef.current) return;

    try {
      const snapshot = Object.entries(sections).reduce((acc, [sectionKey, sectionValue]) => {
        acc[sectionKey] = {
          metadata: {
            subjectCode: sectionValue.subjectCode || "",
            sectionCourse: sectionValue.sectionCourse || "",
            canonicalSection: sectionValue.canonicalSection || "",
            schoolYear: sectionValue.schoolYear || "",
            semester: sectionValue.semester || "",
          },
          students: (sectionValue.students || []).reduce((studentAcc, student) => {
            const studentKey = normalizeText(student.email || student.id);
            if (!studentKey) return studentAcc;

            studentAcc[studentKey] = {
              id: student.id,
              email: student.email || "",
              midterm: student.midterm ?? "",
              finals: student.finals ?? "",
              standing: student.standing || STUDENT_STATUS_ACTIVE,
              flagged: !!student.flagged,
            };
            return studentAcc;
          }, {}),
        };
        return acc;
      }, {});

      saveResetAwareLocalData(facultyGradeSnapshotStorageKey, snapshot);
    } catch (error) {
      console.warn("Failed to persist faculty grade snapshots.", error);
    }
  }, [facultyGradeSnapshotStorageKey, sections]);

  useEffect(() => {
    if (!hasHydratedFacultyDataRef.current) return;

    try {
      saveResetAwareLocalData(facultyBulkUploadStorageKey, bulkUploadedSections);
    } catch (error) {
      console.warn("Failed to persist faculty bulk upload flags.", error);
    }
  }, [bulkUploadedSections, facultyBulkUploadStorageKey]);

  const loadFacultyData = useCallback(async (isBackground = false) => {
    if (!isBackground) setIsLoadingData(true);

    try {
      const sectionsData = await fetchFacultySections(facultyData.email).catch(() => null);
      const studentsData = await fetchFacultyStudents(facultyData.email).catch(() => null);
      const gradesData = await fetchAllGrades(facultyData.email).catch(() => null);

      const actualSections = Array.isArray(sectionsData?.sections) ? sectionsData.sections : [];
      const actualStudents = Array.isArray(studentsData?.students) ? studentsData.students : [];
      const actualGrades = Array.isArray(gradesData) ? gradesData : (gradesData?.data || []);
      const studentsByStudentNo = new Map(
        actualStudents
          .filter((student) => String(student.studentno || '').trim())
          .map((student) => [String(student.studentno || '').trim(), student])
      );
      const savedAssignments = (() => {
        try {
          const saved = localStorage.getItem("registrarAssignments");
          return saved ? JSON.parse(saved) : [];
        } catch (error) {
          console.warn("Failed to parse saved registrar assignments.", error);
          return [];
        }
      })();
      const savedGradeSnapshots = (() => {
        try {
          return loadResetAwareLocalData(facultyGradeSnapshotStorageKey) || {};
        } catch (error) {
          console.warn("Failed to parse saved faculty grade snapshots.", error);
          return {};
        }
      })();
      const savedBulkUploadedSections = (() => {
        try {
          return loadResetAwareLocalData(facultyBulkUploadStorageKey) || {};
        } catch (error) {
          console.warn("Failed to parse saved faculty bulk upload flags.", error);
          return {};
        }
      })();
      const facultyLoadResetAt = parseTimestamp(
        localStorage.getItem("facultyLoadResetAt")
      );

      const savedAssignmentsBySection = new Map(
        savedAssignments.map((assignment) => [
          buildFacultyAssignmentLookupKey({
            program: assignment.program,
            sectionName: assignment.sectionName,
            subjectCode: assignment.subjectCode,
            yearLevel: assignment.yearLevel,
          }),
          assignment,
        ])
      );

      const newSections = {};
      const nextSectionStatuses = {};
      const nextBulkUploadedSections = {};

      const parseSavedGrade = (rawGrade) => {
        if (!rawGrade) {
          return {
            midterm: "",
            finals: "",
            finalAverage: "",
            standing: STUDENT_STATUS_ACTIVE,
            flagged: false,
          };
        }
        if (typeof rawGrade === 'number') {
          return {
            midterm: rawGrade,
            finals: rawGrade,
            finalAverage: rawGrade,
            standing: STUDENT_STATUS_ACTIVE,
            flagged: false,
          };
        }
        if (typeof rawGrade === 'string' && rawGrade.trim().startsWith('{')) {
          try {
            const parsed = JSON.parse(rawGrade);
            
            let computedRaw = parsed.finalAverage || parsed.final || parsed.grade || '';
            const mid = parseFloat(parsed.midterm);
            const fin = parseFloat(parsed.finals);
            if (!isNaN(mid) && !isNaN(fin)) {
                computedRaw = ((mid + fin) / 2).toFixed(2);
            } else if (!isNaN(mid)) {
                computedRaw = mid.toFixed(2);
            } else if (!isNaN(fin)) {
                computedRaw = fin.toFixed(2);
            }

            return {
              midterm: parseGradeValue(parsed.midterm),
              finals: parseGradeValue(parsed.finals),
              finalAverage: parseGradeValue(computedRaw),
              standing: parsed.standing || STUDENT_STATUS_ACTIVE,
              flagged: !!parsed.flagged,
            };
          } catch (e) {
            return {
              midterm: "",
              finals: "",
              finalAverage: "",
              standing: STUDENT_STATUS_ACTIVE,
              flagged: false,
            };
          }
        }
        const numericGrade = parseGradeValue(rawGrade);
        return {
          midterm: numericGrade,
          finals: numericGrade,
          finalAverage: numericGrade,
          standing: STUDENT_STATUS_ACTIVE,
          flagged: false,
        };
      };

      const recordHasEncodedValueForTerm = (record, term) => {
        const parsedGrade = parseSavedGrade(record?.grade || record?.Grade);
        return term === "finals"
          ? hasEncodedGrade(parsedGrade.finals)
          : hasEncodedGrade(parsedGrade.midterm);
      };

      const deriveSectionReviewState = (records = [], term = encodingTerm) => {
        const termRelevantRecords = records.filter((record) =>
          recordHasEncodedValueForTerm(record, term)
        );
        const meaningfulStatusRecords = termRelevantRecords
          .map((record, index) => ({
            record,
            index,
            timestamp: parseTimestamp(record.date || record.Date),
            normalizedStatus: normalizeSectionStatusValue(
              record.status || record.Status
            ),
          }))
          .filter(({ normalizedStatus }) => normalizedStatus !== "draft");

        const latestRecordEntry = meaningfulStatusRecords.reduce((current, next) => {
          if (!current) return next;
          if (next.timestamp !== current.timestamp) {
            return next.timestamp > current.timestamp ? next : current;
          }

          const nextPriority = SECTION_STATUS_PRIORITY[next.normalizedStatus] ?? 0;
          const currentPriority = SECTION_STATUS_PRIORITY[current.normalizedStatus] ?? 0;
          if (nextPriority !== currentPriority) {
            return nextPriority > currentPriority ? next : current;
          }

          return next.index > current.index ? next : current;
        }, null);

        const latestStatus = latestRecordEntry?.normalizedStatus || "draft";
        const reviewNote =
          latestStatus === "returned"
            ? latestRecordEntry?.record?.note ||
              latestRecordEntry?.record?.Note ||
              ""
            : "";

        return {
          status: latestStatus,
          note: reviewNote,
        };
      };

      const getGradeStudentKey = (grade) => (
        grade.student_no ||
        grade.studentNo ||
        grade.StudentNo ||
        grade.student_hash ||
        grade.studentHash ||
        grade.StudentHash ||
        grade.studentId ||
        grade.StudentId ||
        ''
      );

      const getGradeSubjectKey = (grade) => (
        grade.subject_code ||
        grade.subjectCode ||
        grade.SubjectCode ||
        grade.course ||
        grade.Course ||
        ''
      );
      const getGradeRecordSectionKey = (grade) => (
        grade.record_section ||
        grade.recordSection ||
        grade.section ||
        grade.Section ||
        ''
      );

      actualSections.forEach(sec => {
        const matchedAssignment =
          savedAssignmentsBySection.get(
            buildFacultyAssignmentLookupKey({
              program: sec.department,
              sectionName: sec.section,
              subjectCode: sec.subject,
              yearLevel: sec.yearLevel,
            })
          ) ||
          savedAssignments.find((assignment) =>
            normalizeText(assignment.program) === normalizeText(sec.department) &&
            normalizeText(assignment.sectionName) === normalizeText(sec.section) &&
            normalizeText(assignment.subjectCode) === normalizeText(sec.subject)
          ) ||
          null;
        const assignmentUploadedAt = parseTimestamp(matchedAssignment?.uploadedAt);

        if (
          facultyLoadResetAt > 0 &&
          (!matchedAssignment || assignmentUploadedAt < facultyLoadResetAt)
        ) {
          return;
        }
        const sectionKey = `${sec.department} ${sec.section}${sec.subject ? ` (${sec.subject})` : ''}`; 
        const savedSectionSnapshot = savedGradeSnapshots[sectionKey] || {};
        const sectionGrades = actualGrades.filter((grade) => {
          const gradeSubjectKey = normalizeText(getGradeSubjectKey(grade));
          const gradeRecordSectionKey = normalizeText(getGradeRecordSectionKey(grade));
          const gradeDisplaySectionKey = normalizeText(grade.section || grade.Section || "");
          const expectedSubjectCode = normalizeText(
            matchedAssignment?.subjectCode || sec.subject
          );
          const expectedSectionKeys = [
            sectionKey,
            matchedAssignment?.sectionName,
            sec.section,
          ]
            .map((value) => normalizeText(value))
            .filter(Boolean);

          const sectionMatches =
            expectedSectionKeys.includes(gradeRecordSectionKey) ||
            expectedSectionKeys.includes(gradeDisplaySectionKey);
          const subjectMatches =
            !expectedSubjectCode || gradeSubjectKey === expectedSubjectCode;

          return sectionMatches && subjectMatches;
        });
        const sectionReviewState = deriveSectionReviewState(
          sectionGrades,
          encodingTerm
        );
        nextBulkUploadedSections[sectionKey] = !!savedBulkUploadedSections[sectionKey];
        nextSectionStatuses[sectionKey] = {
          ...createDefaultSectionTermStatuses(),
          [normalizeEncodingTerm(encodingTerm)]: sectionReviewState.status,
        };
        const backendStudents = actualStudents.filter(s => 
          s.department === sec.department && 
          (String(s.section) === String(sec.section) || String(s.sectionNum) === String(sec.section)) && 
          (s.assignmentStatus === 'Enrolled' || s.enrollmentStatus === 'Enrolled')
        );
        const rosterSource =
          Array.isArray(matchedAssignment?.rosterStudents) &&
          matchedAssignment.rosterStudents.length
            ? matchedAssignment.rosterStudents
            : backendStudents;
        const enrolledStudents = rosterSource.map(studentRecord => {
          const preferredStudentNo =
            studentRecord.studentno ||
            studentRecord.studentNo ||
            "";
          const rosterStudentId =
            preferredStudentNo ||
            studentRecord.studentId ||
            studentRecord.id ||

            (studentRecord.email ? studentRecord.email.split('@')[0] : 'N/A');
          const firstName = studentRecord.firstName || "";
          const lastName = studentRecord.lastName || "";
            let fullName =
            studentRecord.fullname ||
            studentRecord.name ||
            [lastName, firstName].filter(Boolean).join(", ") ||
              (rosterStudentId !== 'N/A' ? `Student ${rosterStudentId}` : "Unnamed Student");
              
            if (fullName.includes('@')) {
                fullName = fullName.split('@')[0];
            }

          const backendMatch = backendStudents.find(
            (student) =>
              String(student.studentno || "").trim() === String(rosterStudentId).trim() ||
              normalizeText(student.email) === normalizeText(studentRecord.email)
          );
          const globalStudentMatch =
            backendMatch ||
            studentsByStudentNo.get(String(rosterStudentId).trim()) ||
            actualStudents.find(
              (student) =>
                normalizeText(student.email) === normalizeText(studentRecord.email)
            ) ||
            null;
          const resolvedStudentNo =
            preferredStudentNo ||
            backendMatch?.studentno ||
            globalStudentMatch?.studentno ||
            "";
          const savedGrade = [...sectionGrades].reverse().find(g => {
            const gradeStudentKey = normalizeText(getGradeStudentKey(g));
            const studentCandidates = [
              studentRecord.email,
              backendMatch?.email,
              globalStudentMatch?.email,
              backendMatch?.studentno,
              globalStudentMatch?.studentno,
              rosterStudentId,
            ]
              .map((value) => normalizeText(value))
              .filter(Boolean);
            const sameStudent = studentCandidates.includes(gradeStudentKey);
            return sameStudent;
          });
          const snapshotStudent =
            savedSectionSnapshot?.students?.[normalizeText(globalStudentMatch?.email || studentRecord.email || resolvedStudentNo || rosterStudentId)] ||
            savedSectionSnapshot?.students?.[normalizeText(resolvedStudentNo || rosterStudentId)] ||
            null;
          const savedValues = savedGrade
            ? parseSavedGrade(savedGrade?.grade || savedGrade?.Grade)
            : {
                midterm: snapshotStudent?.midterm ?? "",
                finals: snapshotStudent?.finals ?? "",
                finalAverage: "",
                standing: snapshotStudent?.standing || STUDENT_STATUS_ACTIVE,
                flagged: !!snapshotStudent?.flagged,
              };

          return {
            id: resolvedStudentNo || rosterStudentId,
            studentNo: resolvedStudentNo || rosterStudentId,
            userId: backendMatch?.id || globalStudentMatch?.id || studentRecord.id || "",
            name: fullName,
            email: globalStudentMatch?.email || studentRecord.email || "",
            firstName: firstName || globalStudentMatch?.fullname?.split(", ").slice(1).join(", ") || "",
            lastName: lastName || globalStudentMatch?.fullname?.split(", ")[0] || fullName,
            midterm: savedValues.midterm,
            finals: savedValues.finals,
            standing: savedValues.standing || STUDENT_STATUS_ACTIVE,
            flagged: !!savedValues.flagged,
            customGrades: {}
          };
        });

        newSections[sectionKey] = {
          year: normalizeYearLabel(matchedAssignment?.yearLevel || sec.yearLevel),
          subjectCode: matchedAssignment?.subjectCode || sec.subject || `${sec.department}-${sec.section}`, 
          subjectTitle: matchedAssignment?.subjectTitle || sec.subject || `Assigned Subject (${sec.department})`, 
          sectionCourse: sec.department,
          canonicalSection: matchedAssignment?.sectionName || sec.section || sectionKey,
          units: matchedAssignment?.units || "Not Available",
          schedule: getOptionalAssignmentValue(matchedAssignment?.schedule),
          day: getOptionalAssignmentValue(matchedAssignment?.day),
          date: getOptionalAssignmentValue(matchedAssignment?.date),
          schoolYear: matchedAssignment?.schoolYear || "Not Available",
          semester: matchedAssignment?.semester || encodingSemester || "Not Available",
          reviewNote: sectionReviewState.note,
          students: enrolledStudents
        };
      });

      setSections((previousSections) => {
        const mergedSections = {};

        Object.entries(newSections).forEach(([sectionKey, sectionValue]) => {
          const previousStudents = previousSections[sectionKey]?.students || [];
          const previousStudentsById = new Map(
            previousStudents.map((student) => [
              normalizeText(student.email || student.id),
              student,
            ])
          );

          mergedSections[sectionKey] = {
            ...sectionValue,
            students: sectionValue.students.map((student) => {
              const previousStudent =
                previousStudentsById.get(normalizeText(student.email || student.id)) ||
                previousStudents.find(
                  (item) =>
                    normalizeText(item.id) === normalizeText(student.id) ||
                    normalizeText(item.email) === normalizeText(student.email)
                ) ||
                null;

              if (!previousStudent) {
                return student;
              }

              const nextMidterm = hasEncodedGrade(student.midterm)
                ? student.midterm
                : previousStudent.midterm;
              const nextFinals = hasEncodedGrade(student.finals)
                ? student.finals
                : previousStudent.finals;
              const nextStanding =
                student.standing && student.standing !== STUDENT_STATUS_ACTIVE
                  ? student.standing
                  : previousStudent.standing || student.standing || STUDENT_STATUS_ACTIVE;

              return {
                ...student,
                midterm: nextMidterm ?? "",
                finals: nextFinals ?? "",
                standing: nextStanding,
                flagged: student.flagged || previousStudent.flagged || false,
                customGrades: previousStudent.customGrades || student.customGrades || {},
              };
            }),
            reviewNote: sectionValue.reviewNote,
          };
        });

        return mergedSections;
      });
      setSectionStatus((previousStatuses) => {
        const mergedStatuses = {};

        Object.keys(newSections).forEach((sectionKey) => {
          mergedStatuses[sectionKey] = mergeSectionTermStatuses(
            previousStatuses[sectionKey],
            nextSectionStatuses[sectionKey]
          );
        });

        return mergedStatuses;
      });
      setBulkUploadedSections(nextBulkUploadedSections);
    } catch (error) {
      console.error("Failed to load faculty sections:", error);
    } finally {
      hasHydratedFacultyDataRef.current = true;
      if (!isBackground) setIsLoadingData(false);
    }
  }, [
    encodingSemester,
    encodingTerm,
    facultyBulkUploadStorageKey,
    facultyData.email,
    facultyGradeSnapshotStorageKey,
  ]);

  useEffect(() => {
    loadFacultyData();
    const handleAcademicDataChanged = () => loadFacultyData(true);
    const handleFacultyLoadReset = () => {
      setSections({});
      setActiveSection(null);
      setSectionStatus({});
      localStorage.removeItem(sectionStatusStorageKey);
      localStorage.removeItem(facultyGradeSnapshotStorageKey);
      localStorage.removeItem(facultyBulkUploadStorageKey);
      loadFacultyData();
    };
    const handleStorageChanged = (event) => {
      if (event.key === 'facultyLoadResetAt') {
        handleFacultyLoadReset();
      }
    };
    const handleWindowFocus = () => loadFacultyData(true);
    window.addEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
    window.addEventListener('blockgo:faculty-load-reset', handleFacultyLoadReset);
    window.addEventListener('storage', handleStorageChanged);
    window.addEventListener('focus', handleWindowFocus);

    return () => {
      window.removeEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
      window.removeEventListener('blockgo:faculty-load-reset', handleFacultyLoadReset);
      window.removeEventListener('storage', handleStorageChanged);
      window.removeEventListener('focus', handleWindowFocus);
    };
  }, [facultyBulkUploadStorageKey, facultyGradeSnapshotStorageKey, loadFacultyData, sectionStatusStorageKey]);

  const getSectionTermStatus = useCallback(
    (sectionName, term = encodingTerm) =>
      normalizeSectionStatusEntry(sectionStatus[sectionName])[normalizeEncodingTerm(term)],
    [encodingTerm, sectionStatus]
  );

  const updateSectionTermStatus = useCallback((sectionName, term, status) => {
    const normalizedTerm = normalizeEncodingTerm(term);
    const normalizedStatus = normalizeSectionStatusValue(status);

    setSectionStatus((previousStatuses) => ({
      ...previousStatuses,
      [sectionName]: {
        ...createDefaultSectionTermStatuses(),
        ...normalizeSectionStatusEntry(previousStatuses[sectionName]),
        [normalizedTerm]: normalizedStatus,
      },
    }));
  }, []);

  const totalSections = Object.keys(sections).length;

  const now            = new Date();
  const msLeft         = encodingEnd ? encodingEnd - now : 0;
  const daysLeft       = Math.ceil(msLeft / (1000 * 60 * 60 * 24));
  const isClosed       = !encodingStart || !encodingEnd || now < encodingStart || now > encodingEnd;
  const isUrgent       = !isClosed && daysLeft <= 3;

  const getBannerState = () => {
    if (!encodingStart || !encodingEnd) return 'not_set';
    if (now > encodingEnd)   return 'closed_after';
    if (now < encodingStart) return 'closed_before';
    if (isUrgent)             return 'urgent';
    return 'open';
  };
  const bannerState = getBannerState();

  const formatDate = (date) =>
    date ? date.toLocaleDateString('en-US', { month: 'long', day: '2-digit', year: 'numeric' }) : 'not set';

  const calculateFinalAverage = (stu) => {
    if (!hasEncodedGrade(stu.midterm) || !hasEncodedGrade(stu.finals)) {
      return null;
    }

    const mid = Number(stu.midterm);
    const fin = Number(stu.finals);

    if (Number.isNaN(mid) || Number.isNaN(fin)) return null;
    return (mid + fin) / 2;
  };

  const validateGrade = (value) => {
    const num = parseFloat(value);
    if (value === '') return '';
    if (isNaN(num)) return 'Must be a number';
    if (num < 60 || num > 100) return 'Must be 60–100';
    return '';
  };

  const handleGradeChange = useCallback((sectionName, index, field, value) => {
    if (bulkUploadedSections[sectionName]) return;
    if (isLockedSectionStatus(getSectionTermStatus(sectionName))) return;
    if (field === 'midterm' && encodingTerm !== 'midterm') return;
    if (field === 'finals' && encodingTerm !== 'finals') return;
    const error = validateGrade(value);
    setValidationErrors(prev => ({
      ...prev,
      [sectionName]: { ...prev[sectionName], [index]: { ...(prev[sectionName]?.[index] || {}), [field]: error } }
    }));
    
    const updated = JSON.parse(JSON.stringify(sections));
    const student = updated[sectionName].students[index];
    if (student.standing && student.standing !== STUDENT_STATUS_ACTIVE) return;
    updated[sectionName].students[index][field] = value === '' ? '' : parseFloat(value) || 0;
    
    setSections(updated);
    setRowSaveState(prev => ({ ...prev, [sectionName]: { ...(prev[sectionName] || {}), [index]: 'idle' } }));
  }, [sections, encodingTerm, getSectionTermStatus, bulkUploadedSections]);

  const handleStudentStatusChange = useCallback((sectionName, index, value) => {
    if (isLockedSectionStatus(getSectionTermStatus(sectionName))) return;

    const updated = JSON.parse(JSON.stringify(sections));
    const student = updated[sectionName].students[index];
    student.standing = value;

    if (value !== STUDENT_STATUS_ACTIVE) {
      student.midterm = 0;
      student.finals = 0;
    }

    setSections(updated);
    setRowSaveState(prev => ({ ...prev, [sectionName]: { ...(prev[sectionName] || {}), [index]: 'idle' } }));
  }, [sections, getSectionTermStatus]);

  const toggleStudentFlag = useCallback((sectionName, index) => {
    if (isLockedSectionStatus(getSectionTermStatus(sectionName))) return;

    const updated = JSON.parse(JSON.stringify(sections));
    updated[sectionName].students[index].flagged = !updated[sectionName].students[index].flagged;
    setSections(updated);
  }, [sections, getSectionTermStatus]);

  const handleExportPDFClassGrades = (sectionName) => {
    const sectionData = sections[sectionName];
    if (!sectionData || !sectionData.students) return;
    if (!isLockedSectionStatus(getSectionTermStatus(sectionName))) {
      alert("Export PDF is available only after the grades for this section have been submitted to the Chairperson.");
      return;
    }
    
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        const summary = sectionData.students.reduce((acc, student) => {
            const studentStatus = student.standing || STUDENT_STATUS_ACTIVE;
            const academicStatus = getAcademicStatus(student);

            acc.totalStudents += 1;

            if (academicStatus === "Passed") acc.passed += 1;
            if (academicStatus === "Failed") acc.failed += 1;
            if (studentStatus === "withdrawn") acc.withdrawn += 1;
            if (studentStatus === "dropped") acc.dropped += 1;
            if (studentStatus === "unofficially_dropped") acc.unofficiallyDropped += 1;
            if (studentStatus === "incomplete") acc.incomplete += 1;

            return acc;
        }, {
            totalStudents: 0,
            passed: 0,
            failed: 0,
            withdrawn: 0,
            dropped: 0,
            unofficiallyDropped: 0,
            incomplete: 0,
        });
        
        doc.setTextColor(0, 51, 102);
        doc.setFontSize(16);
        doc.text("GRADE ENCODING SHEET", 14, 20);
        doc.setFontSize(11);
        doc.text("FACULTY COPY", 14, 26);
        
        doc.setFontSize(10);
        doc.setTextColor(100);
        doc.text(`Department: ${sectionData.sectionCourse}`, 14, 34);
        doc.text(`Section: ${sectionName}`, 14, 39);
        doc.text(`Faculty: ${facultyData.name}`, 14, 44);
        doc.text(`Total Students: ${summary.totalStudents}`, 14, 52);
        doc.text(`Passed: ${summary.passed}`, 14, 57);
        doc.text(`Failed: ${summary.failed}`, 14, 62);
        doc.text(`Withdrawn (W): ${summary.withdrawn}`, 110, 52);
        doc.text(`Dropped (D): ${summary.dropped}`, 110, 57);
        doc.text(`Unofficial Dropped (UD): ${summary.unofficiallyDropped}`, 110, 62);
        doc.text(`Incomplete (INC): ${summary.incomplete}`, 110, 67);
        
        const tableColumn = ["Student ID", "Student Name", "Midterm", "Finals", "Final Grade", "Grade Equivalent", "Status", "Student Status"];
        const tableRows = sectionData.students.map(student => {
            const finalGrade = calculateFinalAverage(student);
            const status = getAcademicStatus(student);
            return [
              student.studentNo || student.id,
              student.name,
              student.midterm ?? "",
              student.finals ?? "",
              finalGrade === null ? "" : finalGrade.toFixed(2),
              finalGrade === null ? "-" : getGradeEquivalent(finalGrade),
              status,
              student.standing || STUDENT_STATUS_ACTIVE,
            ];
        });
        
        doc.autoTable({
            head: [tableColumn], body: tableRows, startY: 74, theme: 'striped',
            headStyles: { fillColor: [0, 51, 102], fontSize: 9 }, bodyStyles: { fontSize: 8 }
        });
        
        doc.save(`${sectionName.replace(/[^a-zA-Z0-9-]/g, "_")}_GradingSheet.pdf`);
    } catch (err) {
        alert("Could not generate PDF. Make sure jsPDF is available.");
    }
  };

  const handleDownloadTemporaryGradingSheet = (sectionName) => {
    const sectionData = sections[sectionName];
    if (!sectionData || !sectionData.students) return;

    const header = `${getTemporarySheetHeader().join(",")}\n`;
    const rows = sectionData.students
      .map((student, index) => {
        const rowNumber = index + 2;
        const midtermFormula = `"=ROUND((C${rowNumber}*20%)+(D${rowNumber}*10%)+(E${rowNumber}*10%)+(F${rowNumber}*60%),2)"`;
        const finalFormula = `"=ROUND((H${rowNumber}*20%)+(I${rowNumber}*10%)+(J${rowNumber}*10%)+(K${rowNumber}*60%),2)"`;
        const finalRatingFormula = `"=ROUND(AVERAGE(G${rowNumber},L${rowNumber}),2)"`;
        const studentName =
          student.name ||
          [student.lastName, student.firstName].filter(Boolean).join(", ");

        return [
          student.studentNo || student.id || "",
          `"${studentName}"`,
          "",
          "",
          "",
          "",
          midtermFormula,
          "",
          "",
          "",
          "",
          finalFormula,
          finalRatingFormula,
        ].join(",");
      })
      .join("\n");

    const blob = new Blob([header + rows], { type: "text/csv;charset=utf-8;" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    const safeSectionName = String(sectionName || "section").replace(/[^a-zA-Z0-9-]/g, "_");

    link.href = url;
    link.setAttribute(
      "download",
      `${safeSectionName}_temporary_grading_sheet.csv`
    );
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleFileUpload = async (sectionName, e) => {
    const file = e.target.files[0];
    if (!file) return;

    const sectionData = sections[sectionName];
    const semester = encodingSemester; 
    const schoolYear = "2024";
    const course = sectionData.subjectCode || sectionData.sectionCourse || sectionName;
    const canonicalSection = sectionData.canonicalSection || sectionName;

    setUploadingSection(sectionName);

    try {
      const res = await batchUploadGrades(file, semester, schoolYear, course, facultyData.email, encodingTerm, canonicalSection);
      if (res.status === 'Success' || res.status === 'Partial Success') {
        setUploadResult({ 
          type: 'success', 
          title: 'Upload Successful', 
          message: `Processed: ${res.totalProcessed}, Success: ${res.successful}`, 
          details: Array.isArray(res.errors) && res.errors.length > 0
            ? res.errors
            : 'All records processed successfully.'
        });
        setBulkUploadedSections((prev) => ({ ...prev, [sectionName]: true }));
        updateSectionTermStatus(sectionName, encodingTerm, 'draft');
        loadFacultyData();
      } else {
        setUploadResult({ type: 'error', title: 'Upload Failed', message: res.message });
      }
    } catch (err) {
      console.error(err);
      setUploadResult({ type: 'error', title: 'Batch Upload Failed', message: err.message });
    } finally {
      setUploadingSection(null);
      e.target.value = null; 
    }
  };

  const handleSaveAll = async (sectionName) => {
    const students = sections[sectionName].students;
    const saving = {};
    students.forEach((_, i) => { saving[i] = 'saving'; });
    setRowSaveState(prev => ({ ...prev, [sectionName]: saving }));
    
    try {
      const sectionData = sections[sectionName];
      const canonicalSection = sectionData.canonicalSection || sectionName;
      const promises = students.map(student => {
          const finalAverage = calculateFinalAverage(student);
          const resolvedStudentId = student.studentNo || student.id || "";
          const gradePayload = {
              student_id: resolvedStudentId,
              student_name: student.name || [student.lastName, student.firstName].filter(Boolean).join(", "),
              student_hash: student.email || resolvedStudentId,
              section: canonicalSection,
              course: sectionData.sectionCourse || sectionData.subjectCode || sectionName,
              subject_code: sectionData.subjectCode,
              subject_name: sectionData.subjectTitle || sectionData.subjectCode,
              professor_name: facultyData.name || facultyData.email,
              program: sectionData.sectionCourse || '',
              term: encodingTerm,
              units: Number(sectionData.units) || 3,
              year_level: sectionData.year || "",
              grade: JSON.stringify({
                midterm: student.midterm,
                finals: student.finals,
                finalAverage: finalAverage === null ? "" : finalAverage.toFixed(2),
                standing: student.standing || STUDENT_STATUS_ACTIVE,
                flagged: !!student.flagged,
              }),
              semester: encodingSemester,
              school_year: "2024",
              faculty_id: facultyData.email,
              date: new Date().toISOString().split('T')[0],
              status: "Issued"
          };
          return issueGrade(gradePayload);
      });
      
      await Promise.all(promises);
      
      const saved = {};
      students.forEach((_, i) => { saved[i] = 'saved'; });
      setRowSaveState(prev => ({ ...prev, [sectionName]: saved }));
      updateSectionTermStatus(sectionName, encodingTerm, 'draft');
    } catch (error) {
      console.error(error);
      alert(`Failed to save all grades: ${error.message}`);
      const idle = {};
      students.forEach((_, i) => { idle[i] = 'idle'; });
      setRowSaveState(prev => ({ ...prev, [sectionName]: idle }));
    }
  };

  const requestSubmitToChairperson = (sectionName) => {
    const students = sections[sectionName].students;
    const hasIncomplete = students.some(s =>
      (s.standing || STUDENT_STATUS_ACTIVE) === STUDENT_STATUS_ACTIVE &&
      (
        encodingTerm === 'midterm'
          ? s.midterm === '' || Number.isNaN(Number(s.midterm))
          : s.finals === '' || Number.isNaN(Number(s.finals))
      )
    );
    
    if (hasIncomplete) {
      alert(`Submission Blocked: All students in the section must have ${encodingTerm === 'midterm' ? 'Midterm' : 'Finals'} grades encoded before submitting to the Chairperson.`);
      return;
    }

    setSubmitConfirmSection(sectionName);
  };

  const handleSubmit = async (sectionName) => {
    try {
      await handleSaveAll(sectionName);
      const sectionData = sections[sectionName];
      
      await submitSectionGrades(
        sectionData.sectionCourse,
        sectionData.canonicalSection || sectionName
      );
      updateSectionTermStatus(sectionName, encodingTerm, 'submitted');
      setSubmitConfirmSection(null);
    } catch (e) { alert("Error submitting section: " + e.message); }
  };

  const hasValidationErrors = (sectionName) => {
    const errs = validationErrors[sectionName] || {};
    return Object.values(errs).some(row => row.midterm || row.finals);
  };

  const currentStatus = activeSection ? getSectionTermStatus(activeSection) : null;
  const isSubmittedToChairperson = isLockedSectionStatus(currentStatus);
  const isBulkUploadedSection = activeSection ? !!bulkUploadedSections[activeSection] : false;
  const isGradeEncodingLocked = isSubmittedToChairperson || isBulkUploadedSection;
  const isMidtermLocked = encodingTerm !== 'midterm';
  const isFinalsLocked = encodingTerm !== 'finals';

  if (portalView === 'curriculum') {
    return (
      <div className="min-h-screen bg-slate-50 pb-10 font-sans">
        <FacultyHeader
          facultyData={{ ...facultyData, semester: encodingSemester }}
          totalSections={totalSections}
          onLogout={onLogout}
        />
        <main className="w-full px-4 py-5 md:px-6">
          <button
            type="button"
            onClick={() => setPortalView('grades')}
            className="mb-5 rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white"
          >
            Back to Grade Encoding
          </button>
          <FacultyCurriculumPanel />
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 pb-10 font-sans">
      <FacultyHeader
        facultyData={{ ...facultyData, semester: encodingSemester }}
        totalSections={totalSections}
        onLogout={onLogout}
      />

      <div className="w-full px-4 md:px-6">
        <div className="mt-5 flex justify-end">
          <button
            type="button"
            onClick={() => setPortalView('curriculum')}
            className="rounded-lg border border-[#003366] bg-white px-4 py-2 text-sm font-bold text-[#003366] hover:bg-blue-50"
          >
            View Program Curriculum
          </button>
        </div>
        {bannerState === 'not_set' && (
          <div className="mt-5 flex items-center gap-4 rounded-xl border-l-4 border-slate-400 bg-white p-4 text-slate-800 shadow-sm">
            <div>
              <strong className="block text-lg">Grade Encoding Period is not set</strong>
              <p className="mt-1 text-sm">The registrar has not opened an encoding schedule yet.</p>
            </div>
          </div>
        )}

        {bannerState === 'closed_after' && (
          <div className="mt-5 flex items-center gap-4 rounded-xl border-l-4 border-red-500 bg-red-50 p-4 text-red-900 shadow-sm">
            <div className="text-2xl">LOCKED</div>
            <div>
              <strong className="block text-lg">Grade Encoding Period is currently Closed</strong>
              <p className="mt-1 text-sm">The encoding deadline has passed as of <strong>{formatDate(encodingEnd)}</strong>. Contact or visit the Registrar's Office for any concerns.</p>
            </div>
          </div>
        )}

        {bannerState === 'closed_before' && (
          <div className="mt-5 flex items-center gap-4 rounded-xl border-l-4 border-slate-500 bg-slate-50 p-4 text-slate-800 shadow-sm">
            <div>
              <strong className="block text-lg">Grade Encoding Period has not started yet</strong>
              <p className="mt-1 text-sm">Encoding opens on <strong>{formatDate(encodingStart)}</strong>. Please check back then.</p>
            </div>
          </div>
        )}

        {bannerState === 'open' && (
          <div className="mt-5 flex items-center gap-4 rounded-xl border-l-4 border-green-500 bg-green-50 p-4 text-green-900 shadow-sm">
            <div>
              <strong className="block text-lg">Grade Encoding Period is Open!</strong>
              <p className="mt-1 text-sm">Finalize your section grades and upload to the Registrar by <strong>{formatDate(encodingEnd)}</strong></p>
            </div>
          </div>
        )}

        {bannerState === 'urgent' && (
          <div className="mt-5 flex items-center gap-4 rounded-xl border-l-4 border-yellow-500 bg-yellow-50 p-4 text-yellow-900 shadow-sm">
            <div>
              <strong className="block text-lg">Encoding Deadline in {daysLeft} {daysLeft === 1 ? 'Day' : 'Days'}!</strong>
              <p className="mt-1 text-sm">You have <strong>{daysLeft} {daysLeft === 1 ? 'day' : 'days'}</strong> left to submit grades before the deadline on <strong>{formatDate(encodingEnd)}</strong>. Please upload immediately.</p>
            </div>
          </div>
        )}

      {!activeSection ? (
        <div className="py-4">
          <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_440px] xl:items-center">
            <YearTabs
              activeTab={activeTab}
              setActiveTab={setActiveTab}
              sections={Object.values(sections)}
              className="mt-0 min-w-0 py-0"
            />

            <div className="relative w-full xl:justify-self-end">
              <input type="text" placeholder="Search for a section..." className="w-full rounded-xl border border-slate-300 py-3 pl-10 pr-4 outline-none focus:border-[#003366] focus:ring-2 focus:ring-[#003366]/20" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
            {isLoadingData ? (
              <div className="col-span-full py-10 text-center text-slate-500">Loading assigned sections and enrolled students...</div>
            ) : Object.keys(sections).length === 0 ? (
              <div className="col-span-full py-10 text-center text-slate-500">No sections are currently assigned to you.</div>
            ) : (
              Object.entries(sections)
              .filter(([name, data]) => {
                const matchesTab = activeTab === "All Sections" || data.year === activeTab;
                const matchesSearch = name.toLowerCase().includes(searchQuery.toLowerCase());
                return matchesTab && matchesSearch;
              })
              .map(([sectionName, sectionData]) => {
                const total = sectionData.students.length;
                const encoded = sectionData.students.filter((student) =>
                  hasEncodedGradeForTerm(student, encodingTerm)
                ).length;
                const progressPct = total > 0 ? Math.round((encoded / total) * 100) : 0;
                const secStatus = getSectionTermStatus(sectionName);

                return (
                  <ProgramCard 
                    key={sectionName}
                    sectionName={sectionName}
                    sectionData={sectionData}
                    onClick={() => setActiveSection(sectionName)}
                    progress={progressPct}
                    reviewStatus={
                      secStatus === 'returned'
                        ? 'returned'
                        : secStatus === 'approved'
                        ? 'approved'
                        : secStatus === 'finalized' || secStatus === 'forwarded'
                        ? 'forwarded'
                        : secStatus === 'submitted'
                        ? 'submitted'
                        : 'pending'
                    }
                    reviewNote={sectionData.reviewNote || ""}
                    onSubmit={() => requestSubmitToChairperson(sectionName)}
                    onUpload={(e) => handleFileUpload(sectionName, e)}
                    isUploading={uploadingSection === sectionName}
                    isClosed={isClosed}
                  />
                );
              })
            )}
          </div>
        </div>
      ) : (
        <div className="animate-in fade-in duration-300 py-6">
          <button
            className="mb-6 inline-flex items-center rounded-xl bg-yellow-400 px-5 py-3 text-sm font-bold text-[#003366] shadow-sm transition duration-200 hover:-translate-y-0.5 hover:bg-yellow-500 hover:shadow-md"
            onClick={() => setActiveSection(null)}
            aria-label="Back to section"
            title="Back to section"
          >
            Back to Sections
          </button>

          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="flex flex-col items-start justify-between gap-4 border-b border-slate-200 bg-slate-50 p-6 md:flex-row md:items-center">
              <div>
                <h3 className="inline text-xl font-bold text-[#003366]">Section: {activeSection}</h3>
                {currentStatus && (
                  <span className={`ml-3 rounded-full px-3 py-1 text-xs font-bold ${
                    currentStatus === 'draft' ? 'bg-yellow-100 text-yellow-800' :
                    currentStatus === 'returned' ? 'bg-red-100 text-red-700' :
                    currentStatus === 'submitted' ? 'bg-blue-100 text-blue-800' :
                    currentStatus === 'approved' ? 'bg-emerald-100 text-emerald-800' :
                    'bg-green-100 text-green-800'
                  }`}>
                    {currentStatus === 'draft'
                      ? 'Draft Saved'
                      : currentStatus === 'returned'
                      ? 'Returned'
                      : currentStatus === 'submitted'
                      ? 'Submitted'
                      : currentStatus === 'approved'
                      ? 'Approved'
                      : 'Finalized'}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-3">
                {!isSubmittedToChairperson && (
                  <>
                    <div className="relative overflow-hidden">
                      <input
                        type="file"
                        accept=".csv, .xlsx"
                        className="absolute inset-0 z-10 h-full w-full cursor-pointer opacity-0"
                        onChange={(e) => handleFileUpload(activeSection, e)}
                        disabled={uploadingSection === activeSection || isClosed}
                      />
                      <button className="rounded-lg bg-yellow-400 px-4 py-2.5 text-sm font-bold text-[#003366] transition hover:bg-yellow-500 disabled:opacity-50" disabled={uploadingSection === activeSection || isClosed}>
                        {uploadingSection === activeSection ? 'Upload' : 'Bulk Upload'}
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleDownloadTemporaryGradingSheet(activeSection)}
                      className="rounded-lg border border-[#003366] bg-white px-4 py-2.5 text-sm font-bold text-[#003366] transition hover:bg-slate-50"
                    >
                      Grading Sheet Template
                    </button>
                  </>
                )}
                {isSubmittedToChairperson && (
                  <button onClick={() => handleExportPDFClassGrades(activeSection)} className="rounded-lg border border-emerald-600 bg-white px-4 py-2.5 text-sm font-bold text-emerald-700 transition hover:bg-emerald-50">
                    Export PDF
                  </button>
                )}
              </div>
            </div>

            {isSubmittedToChairperson && (
              <div className="border-b border-red-200 bg-red-50 p-4 text-center text-sm font-semibold text-red-700">
                 These grades have already been uploaded to chairperson and are now locked from further encoding.
              </div>
            )}

            {currentStatus === 'returned' && sections[activeSection]?.reviewNote ? (
              <div className="border-b border-red-200 bg-red-50 p-4 text-sm text-red-700">
                <p className="font-semibold">Returned by chairperson</p>
                <p className="mt-1">{sections[activeSection].reviewNote}</p>
              </div>
            ) : null}

            {!isSubmittedToChairperson && isBulkUploadedSection && (
              <div className="border-b border-amber-200 bg-amber-50 p-4 text-center text-sm font-semibold text-amber-800">
                 Manual encoding is locked because this section was bulk uploaded. To edit grades, upload an updated grading sheet.
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full min-w-[800px] text-left text-sm">
                <thead className="bg-[#003366] text-white">
                  <tr>
                    <th className="p-4">Student ID</th>
                    <th className="p-4">Student Name</th>
                    <th className="p-4 text-center">Midterm <span className="font-normal opacity-70">(60-100)</span></th>
                    <th className="p-4 text-center">Finals <span className="font-normal opacity-70">(60-100)</span></th>
                    <th className="p-4 text-center">Final Grade</th>
                    <th className="p-4 text-center">Grade Equivalent</th>
                    <th className="p-4 text-center">Status</th>
                    <th className="p-4 text-center">Student Status</th>
                    <th className="p-4 text-center">Remarks</th>
                  </tr>
                </thead>
                <tbody>
                  {sections[activeSection].students.map((stu, i) => {
                    const finalAverage = calculateFinalAverage(stu);
                    const finalGradeText = finalAverage === null ? '-' : finalAverage.toFixed(2);
                    const gradeEquivalent = finalAverage === null ? '-' : getGradeEquivalent(finalAverage);
                    const academicStatus = getAcademicStatus(stu);
                    const studentStatus = stu.standing || STUDENT_STATUS_ACTIVE;
                    const isStudentLocked = studentStatus !== STUDENT_STATUS_ACTIVE;
                    const isFlagged = !!stu.flagged;
                    const rowState = rowSaveState[activeSection]?.[i] || 'idle';
                    const errors = validationErrors[activeSection]?.[i] || {};
                    const hasError = errors.midterm || errors.finals;

                    return (
                      <tr key={`${stu.id}-${i}`} className={`border-b border-slate-100 hover:bg-slate-50 ${hasError ? 'bg-red-50' : rowState === 'saved' ? 'bg-green-50' : ''} ${isFlagged ? 'bg-amber-50' : ''}`}>
                        <td className="p-4 font-semibold text-slate-700">{stu.studentNo || stu.id}</td>
                        <td className="p-4 font-medium text-slate-800">{stu.name}</td>
                        
                        <td className="p-4 text-center">
                          <div className="relative inline-block">
                            <input
                              type="number"
                              min="60"
                              max="100"
                              value={stu.midterm}
                              onChange={(e) => handleGradeChange(activeSection, i, 'midterm', e.target.value)}
                              disabled={isGradeEncodingLocked || isMidtermLocked || isStudentLocked}
                              className={`h-10 w-20 rounded-xl border px-2 text-center outline-none focus:ring-2 focus:ring-[#003366]/20 ${
                                errors.midterm ? 'border-red-500 bg-red-50' : 'border-slate-300 bg-white'
                              } disabled:bg-slate-100 disabled:text-slate-400`}
                              placeholder="60-100"
                            />
                            {errors.midterm && <div className="absolute left-1/2 -translate-x-1/2 -bottom-5 whitespace-nowrap text-[10px] font-bold text-red-600">{errors.midterm}</div>}
                          </div>
                        </td>

                        <td className="p-4 text-center">
                          <div className="relative inline-block">
                            <input
                              type="number"
                              min="60"
                              max="100"
                              value={stu.finals}
                              onChange={(e) => handleGradeChange(activeSection, i, 'finals', e.target.value)}
                              disabled={isGradeEncodingLocked || isFinalsLocked || isStudentLocked}
                              className={`h-10 w-20 rounded-xl border px-2 text-center outline-none focus:ring-2 focus:ring-[#003366]/20 ${
                                errors.finals ? 'border-red-500 bg-red-50' : 'border-slate-300 bg-white'
                              } disabled:bg-slate-100 disabled:text-slate-400`}
                              placeholder="60-100"
                            />
                            {errors.finals && <div className="absolute left-1/2 -translate-x-1/2 -bottom-5 whitespace-nowrap text-[10px] font-bold text-red-600">{errors.finals}</div>}
                          </div>
                        </td>

                        <td className="p-4 text-center text-lg font-bold text-[#003366]">{finalGradeText}</td>
                        <td className="p-4 text-center font-bold text-slate-700">{gradeEquivalent}</td>
                        <td className="p-4 text-center">
                          <span className={`inline-flex rounded-full px-3 py-1 text-[10px] font-bold uppercase ${
                            academicStatus === 'Passed' ? 'bg-green-100 text-green-700' :
                            academicStatus === 'Failed' ? 'bg-red-100 text-red-700' :
                            'bg-slate-100 text-slate-700'
                          }`}>
                            {academicStatus}
                          </span>
                        </td>
                        
                        <td className="p-4 text-center">
                          <select
                            value={studentStatus}
                            onChange={(e) => handleStudentStatusChange(activeSection, i, e.target.value)}
                            disabled={isGradeEncodingLocked}
                            className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium outline-none text-slate-700 disabled:bg-slate-100 disabled:text-slate-400"
                          >
                            <option value="active">Active</option>
                            <option value="dropped">Dropped (D)</option>
                            <option value="unofficially_dropped">Unofficial Dropped (UD)</option>
                            <option value="withdrawn">Withdrawn (W)</option>
                            <option value="incomplete">Incomplete (INC)</option>
                          </select>
                        </td>

                        <td className="p-4 text-center">
                          <button
                            type="button"
                            onClick={() => toggleStudentFlag(activeSection, i)}
                            disabled={isGradeEncodingLocked}
                            className={`rounded-lg px-3 py-2 text-sm font-bold transition ${
                              isFlagged ? 'bg-amber-100 text-amber-700 hover:bg-amber-200' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                            } disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400`}
                          >
                            {isFlagged ? 'Flagged' : 'Flag'}
                          </button>
                        </td>

                      </tr>
                    );
                  })}
                  {sections[activeSection].students.length === 0 && (
                    <tr>
                      <td colSpan="9" className="p-8 text-center text-slate-500 bg-slate-50 rounded-b-xl text-base">
                        No students are assigned to this section yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            
            <div className="flex flex-wrap items-center justify-between gap-4 border-t border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center gap-3">
                <div className="h-3 w-3 rounded-full bg-red-50 border border-red-200" title="Has Error" /> <span className="text-xs text-slate-500">Error</span>
                <div className="h-3 w-3 rounded-full bg-amber-50 border border-amber-200" title="Flagged" /> <span className="text-xs text-slate-500">Flagged</span>
                <div className="h-3 w-3 rounded-full bg-green-50 border border-green-200" title="Saved" /> <span className="text-xs text-slate-500">Saved</span>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={() => handleSaveAll(activeSection)}
                  disabled={isGradeEncodingLocked || hasValidationErrors(activeSection) || isClosed}
                  className="rounded-xl border border-[#003366] bg-white px-5 py-2.5 text-sm font-bold text-[#003366] transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:border-slate-300 disabled:text-slate-400"
                >
                  Save Draft
                </button>
                <button
                  onClick={() => requestSubmitToChairperson(activeSection)}
                  disabled={isSubmittedToChairperson || hasValidationErrors(activeSection) || isClosed}
                  className="rounded-xl bg-emerald-600 px-5 py-2.5 text-sm font-bold text-white transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:bg-slate-300"
                >
                  Submit to Chairperson
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      </div>
      <Modal isOpen={!!submitConfirmSection} onClose={() => setSubmitConfirmSection(null)} title="Submit Grades to Chairperson">
        <div className="flex flex-col gap-4">
          <p className="text-sm text-slate-600">
            Are you sure the encoded grades for <span className="font-semibold text-slate-800">{submitConfirmSection || 'this section'}</span> are final?
          </p>
          <p className="text-sm text-red-600">
            Once submitted to the Chairperson, these grades cannot be changed or edited anymore.
          </p>
          <div className="mt-2 flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setSubmitConfirmSection(null)}
              className="rounded-xl border border-slate-300 bg-white px-5 py-2.5 text-sm font-bold text-slate-700 transition hover:bg-slate-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => handleSubmit(submitConfirmSection)}
              className="rounded-xl bg-[#003366] px-5 py-2.5 text-sm font-bold text-white transition hover:bg-[#00264d]"
            >
              Yes, Submit Final Grades
            </button>
          </div>
        </div>
      </Modal>

      {uploadResult && (
        <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div className="flex max-h-[85vh] w-full max-w-2xl flex-col rounded-2xl bg-white p-6 shadow-2xl">
            <h2 className={`mb-2 text-2xl font-bold ${uploadResult.type === 'error' ? 'text-red-600' : 'text-green-600'}`}>
              {uploadResult.title}
            </h2>
            <p className="mb-4 font-semibold text-slate-700">{uploadResult.message}</p>
            {Array.isArray(uploadResult.details) ? (
              <div className="mb-5 flex-grow overflow-x-auto rounded-xl border border-slate-200">
                <table className="w-full border-collapse text-left text-sm">
                  <thead className="bg-slate-100 text-slate-700">
                    <tr>
                      <th className="px-4 py-3 font-bold">Student ID</th>
                      <th className="px-4 py-3 font-bold">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {uploadResult.details.map((error, index) => (
                      <tr key={`${error.studentId || 'row'}-${index}`} className="border-t border-slate-200">
                        <td className="px-4 py-3 font-semibold text-slate-700">{error.studentId || 'Unknown'}</td>
                        <td className="px-4 py-3 text-slate-600">{error.reason || 'No reason provided'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : uploadResult.details ? (
              <div className="mb-5 rounded-xl bg-green-50 p-4 text-sm font-medium text-green-800">
                {uploadResult.details}
              </div>
            ) : null}
            <div className="text-right">
              <button
                className="rounded-xl bg-slate-200 px-5 py-2 font-bold text-slate-800 transition hover:bg-slate-300"
                onClick={() => setUploadResult(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FacultyPortal;
