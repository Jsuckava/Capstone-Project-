import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AVAILABLE_YEAR_LEVELS,
  STUDENT_BATCHES_KEY,
  YEAR_LEVEL_PREFIXES,
  downloadStudentCsvFile,
  getDefaultSectionName,
  getStudentMiddleName,
  parseStudentIdSpreadsheet,
  syncSectionedStudentsToStorage,
} from "../../utils/studentSectioningHelpers";
import {
  fetchApprovedStudents,
  fetchDepartmentSections,
} from "../../services/api";
import { pushSectioningSharedState } from "../../utils/sharedClientState";

const buildStudentName = (student) => {
  const firstAndMiddle = [
    student.firstName,
    getStudentMiddleName(student),
  ]
    .filter(Boolean)
    .join(" ");

  return [student.lastName, firstAndMiddle].filter(Boolean).join(", ");
};

const compareStudentsByName = (left, right) => {
  const leftName = [
    left.lastName,
    left.firstName,
    getStudentMiddleName(left),
    left.studentId,
  ]
    .join(" ")
    .toLowerCase();
  const rightName = [
    right.lastName,
    right.firstName,
    getStudentMiddleName(right),
    right.studentId,
  ]
    .join(" ")
    .toLowerCase();

  return leftName.localeCompare(rightName);
};

const buildGeneratedSections = ({
  program,
  yearLevel,
  sectionCount,
}) => {
  const resolvedSectionCount = Math.max(sectionCount, 1);
  const yearPrefix = YEAR_LEVEL_PREFIXES[yearLevel] || "1";

  return Array.from({ length: resolvedSectionCount }, (_, index) => {
    const sectionCode = `${yearPrefix}-${index + 1}`;

    return {
      id: `${sectionCode}-${Date.now()}-${index}`,
      sectionCode,
      sectionName: getDefaultSectionName(program, sectionCode),
      yearLevel,
    };
  });
};

const sectionMatchesYearLevel = (section = {}, yearLevel = "1st Year") => {
  const yearPrefix = YEAR_LEVEL_PREFIXES[yearLevel] || "";

  if (section.yearLevel) {
    return section.yearLevel === yearLevel;
  }

  return !!yearPrefix && section.sectionCode?.startsWith(`${yearPrefix}-`);
};

const REMOVAL_REASONS = [
  "Duplicate student record",
  "Wrong program",
  "Not in final enrolled list",
  "Encoding error",
  "Other",
];
const GRADUATING_STUDENTS_KEY = "graduatingStudents";
const GRADUATING_STATUSES = [
  "Graduated",
  "Incomplete",
  "Returning Student",
  "Irregular Completion",
];
const IRREGULAR_SUBJECTS_KEY = "irregularSubjectAssignments";

const getStoredArray = (key) => {
  const saved = localStorage.getItem(key);
  return saved ? JSON.parse(saved) : [];
};

const getNextYearLevel = (yearLevel = "") => {
  const nextYearLevels = {
    "1st Year": "2nd Year",
    "2nd Year": "3rd Year",
    "3rd Year": "4th Year",
  };

  return nextYearLevels[yearLevel] || "";
};

const getNextSectionCode = (sectionCode = "", nextYearLevel = "") => {
  const nextPrefix = YEAR_LEVEL_PREFIXES[nextYearLevel];
  const sectionNumber = String(sectionCode).split("-")[1];

  return nextPrefix && sectionNumber ? `${nextPrefix}-${sectionNumber}` : "";
};

const needsGraduatingReview = (student = {}) =>
  (student.status || "Incomplete") !== "Graduated";

const getGraduatingBatchKey = (student = {}) =>
  [
    student.program || "",
    student.originBatchYear || student.batchYear || student.sourceSchoolYear || "",
    student.targetSchoolYear || student.sourceSchoolYear || "",
  ].join("|");

const getBatchUpdatedTime = (batch = {}) =>
  new Date(batch.lastSectionedAt || batch.submittedAt || 0).getTime();

const getCurrentRolloverBatches = (workspaces = []) => {
  const latestByBatchYear = {};

  workspaces
    .filter(
      (batch) =>
        (batch.students || []).length > 0 && (batch.sectionPlans || []).length > 0
    )
    .forEach((batch) => {
      const batchYear = batch.batchYear || "Unassigned";
      const current = latestByBatchYear[batchYear];

      if (!current || getBatchUpdatedTime(batch) > getBatchUpdatedTime(current)) {
        latestByBatchYear[batchYear] = batch;
      }
    });

  return Object.values(latestByBatchYear).sort((left, right) =>
    String(left.batchYear || "").localeCompare(String(right.batchYear || ""))
  );
};

const buildIrregularSubjectKey = () =>
  `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
const BACKEND_BATCH_KEY_PREFIX = "backend-approved-students";
const BACKEND_SYNCED_AT = "1970-01-01T00:00:00.000Z";

const normalizeYearLevelLabel = (value = "") => {
  const text = String(value || "").trim();
  if (AVAILABLE_YEAR_LEVELS.includes(text)) return text;

  const matchedYear = text.match(/[1-4]/)?.[0];
  const yearLabels = {
    1: "1st Year",
    2: "2nd Year",
    3: "3rd Year",
    4: "4th Year",
  };

  return yearLabels[matchedYear] || "1st Year";
};

const normalizeSectionCode = (section = "", yearLevel = "1st Year") => {
  const text = String(section || "").trim();
  const matchedCode = text.match(/([1-4])\s*-\s*(\d+)/);
  if (matchedCode) return `${matchedCode[1]}-${matchedCode[2]}`;

  const matchedCompact = text.match(/([1-4])\s+(\d+)/);
  if (matchedCompact) return `${matchedCompact[1]}-${matchedCompact[2]}`;

  const matchedNumber = text.match(/\d+/);
  if (!matchedNumber) return "";

  return `${YEAR_LEVEL_PREFIXES[yearLevel] || "1"}-${matchedNumber[0]}`;
};

const splitBackendFullName = (fullName = "") => {
  const cleanName = String(fullName || "").trim();
  if (!cleanName) return { firstName: "", lastName: "", middleName: "" };

  if (cleanName.includes(",")) {
    const [lastName, rest = ""] = cleanName.split(",");
    const nameParts = rest.trim().split(/\s+/).filter(Boolean);
    return {
      firstName: nameParts[0] || "",
      middleName: nameParts.slice(1).join(" "),
      lastName: lastName.trim(),
    };
  }

  const parts = cleanName.split(/\s+/).filter(Boolean);
  return {
    firstName: parts[0] || "",
    middleName: parts.length > 2 ? parts.slice(1, -1).join(" ") : "",
    lastName: parts.length > 1 ? parts[parts.length - 1] : "",
  };
};

const buildBackendBatch = (department, approvedStudents = [], academicSections = []) => {
  if (!department) return null;

  const students = approvedStudents
    .filter((student) => student.department === department)
    .map((student) => {
      const inferredYearLevel = normalizeYearLevelLabel(student.yearLevel || student.section);
      const sectionCode = normalizeSectionCode(student.section, inferredYearLevel);
      const names = splitBackendFullName(student.fullname || student.fullName);

      return {
        studentId: student.studentno || student.email || String(student.id || ""),
        sex: student.sex || "",
        firstName: names.firstName,
        lastName: names.lastName,
        middleName: names.middleName,
        middleInitial: names.middleName,
        yearLevel: inferredYearLevel,
        sectionCode,
        sectionName: sectionCode ? getDefaultSectionName(department, sectionCode) : "",
        studentType: "Regular",
        remarks: student.assignmentStatus || "",
      };
    })
    .sort(compareStudentsByName);

  const sectionPlansByCode = new Map();

  academicSections
    .filter((section) => section.department === department)
    .forEach((section) => {
      const yearLevel = normalizeYearLevelLabel(section.yearLevel);
      const sectionCode = normalizeSectionCode(
        `${section.yearLevel}-${section.sectionNum}`,
        yearLevel
      );
      if (!sectionCode) return;
      sectionPlansByCode.set(sectionCode, {
        id: section.id || sectionCode,
        sectionCode,
        sectionName: getDefaultSectionName(department, sectionCode),
        yearLevel,
      });
    });

  students.forEach((student) => {
    if (!student.sectionCode || sectionPlansByCode.has(student.sectionCode)) return;
    sectionPlansByCode.set(student.sectionCode, {
      id: `student-${student.sectionCode}`,
      sectionCode: student.sectionCode,
      sectionName: student.sectionName || getDefaultSectionName(department, student.sectionCode),
      yearLevel: student.yearLevel,
    });
  });

  const sectionPlans = [...sectionPlansByCode.values()].sort((left, right) =>
    String(left.sectionCode || "").localeCompare(String(right.sectionCode || ""))
  );

  if (!students.length && !sectionPlans.length) return null;

  return {
    id: `${BACKEND_BATCH_KEY_PREFIX}-${department}`,
    key: `${BACKEND_BATCH_KEY_PREFIX}|${department}`,
    program: department,
    batchYear: String(new Date().getFullYear()),
    submittedTo: `${department} Chairperson`,
    fileName: "System student records",
    submittedAt: BACKEND_SYNCED_AT,
    status: sectionPlans.length ? "Sectioning" : "Imported",
    students,
    sectionPlans,
    removedStudents: [],
    importedCount: students.length,
    source: "backend",
  };
};

const mergeBackendBatch = (previousBatches = [], backendBatch) => {
  if (!backendBatch) return previousBatches;
  return [
    ...previousBatches.filter((batch) => batch.key !== backendBatch.key),
    backendBatch,
  ];
};

function StudentSectioning({
  chairpersonDepartment,
  onSectioningSaved,
}) {
  const isRegistrarMode = false;
  const canEditRoster = false;
  const isChairpersonMode = true;
  const rosterRef = useRef(null);
  const [batches, setBatches] = useState(() => {
    const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
    return saved ? JSON.parse(saved) : [];
  });
  const [activeWorkspace, setActiveWorkspace] = useState("sectioning");
  const [selectedBatchKey, setSelectedBatchKey] = useState("");
  const [sectioningBatchYear, setSectioningBatchYear] = useState(() =>
    String(new Date().getFullYear())
  );
  const [targetSemester] = useState("1st Semester");
  const [promotionSummary, setPromotionSummary] = useState(null);
  const [graduatingStudents, setGraduatingStudents] = useState(() =>
    getStoredArray(GRADUATING_STUDENTS_KEY)
  );
  const [irregularSubjectAssignments, setIrregularSubjectAssignments] =
    useState(() => getStoredArray(IRREGULAR_SUBJECTS_KEY));
  const [graduatingStatusFilter, setGraduatingStatusFilter] =
    useState("Needs Checking");
  const [expandedGraduatingSections, setExpandedGraduatingSections] = useState(
    {}
  );
  const [irregularSubjectForm, setIrregularSubjectForm] = useState({
    studentKey: "",
    subjectAssignmentId: "",
    assignedSection: "",
    faculty: "",
    remarks: "",
  });
  const [transferSubjectForm, setTransferSubjectForm] = useState({
    studentKey: "",
    irregularSubjectId: "",
    newSection: "",
    reason: "",
  });
  const [selectedYearLevel, setSelectedYearLevel] = useState("1st Year");
  const [manualSectionCount, setManualSectionCount] = useState("1");
  const [selectedSectionCode, setSelectedSectionCode] = useState("");
  const [studentSearch, setStudentSearch] = useState("");
  const [pendingRemoval, setPendingRemoval] = useState(null);
  const [lateStudent, setLateStudent] = useState({
    studentId: "",
    sex: "",
    lastName: "",
    firstName: "",
    middleName: "",
  });

  useEffect(() => {
    let cancelled = false;

    const refreshBackendSectioningData = async () => {
      if (!chairpersonDepartment) return;

      try {
        const [studentsResponse, sectionsResponse] = await Promise.all([
          fetchApprovedStudents(),
          fetchDepartmentSections(chairpersonDepartment),
        ]);

        if (cancelled) return;

        const backendBatch = buildBackendBatch(
          chairpersonDepartment,
          studentsResponse.students || studentsResponse.data || [],
          sectionsResponse.data || sectionsResponse.sections || []
        );

        if (!backendBatch) return;

        setBatches((previousBatches) => {
          const nextBatches = mergeBackendBatch(previousBatches, backendBatch);
          if (JSON.stringify(previousBatches) === JSON.stringify(nextBatches)) {
            return previousBatches;
          }

          localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(nextBatches));
          syncSectionedStudentsToStorage(nextBatches);
          pushSectioningSharedState();
          onSectioningSaved?.();
          return nextBatches;
        });
      } catch (error) {
        console.error("Failed to refresh backend sectioning data:", error);
      }
    };

    refreshBackendSectioningData();

    const handleAcademicDataChanged = () => refreshBackendSectioningData();
    window.addEventListener("blockgo:academic-data-changed", handleAcademicDataChanged);

    return () => {
      cancelled = true;
      window.removeEventListener("blockgo:academic-data-changed", handleAcademicDataChanged);
    };
  }, [chairpersonDepartment, onSectioningSaved]);

  const departmentBatches = useMemo(() => {
    return batches
      .filter(
        (batch) =>
          batch.program === chairpersonDepartment &&
          ["Forwarded", "Imported"].includes(batch.status || "Forwarded") &&
          !(batch.sectionPlans || []).length
      )
      .sort(
        (left, right) =>
          new Date(right.submittedAt || 0) - new Date(left.submittedAt || 0)
      );
  }, [batches, chairpersonDepartment]);

  const departmentWorkspaces = useMemo(
    () =>
      batches.filter(
        (batch) =>
          batch.program === chairpersonDepartment && batch.status !== "Promoted"
      ),
    [batches, chairpersonDepartment]
  );
  const rolloverWorkspaces = isRegistrarMode
    ? batches.filter((batch) => batch.status !== "Promoted")
    : departmentWorkspaces;
  const savedAssignments = useMemo(() => {
    const saved = localStorage.getItem("registrarAssignments");
    return saved ? JSON.parse(saved) : [];
  }, []);
  const departmentAssignments = useMemo(
    () =>
      savedAssignments.filter(
        (assignment) => assignment.program === chairpersonDepartment
      ),
    [chairpersonDepartment, savedAssignments]
  );

  const savedSectioningWorkspace = departmentWorkspaces.find((batch) =>
    (batch.sectionPlans || []).some((section) =>
      sectionMatchesYearLevel(section, selectedYearLevel)
    )
  );
  const fallbackSectioningWorkspace =
    savedSectioningWorkspace ||
    departmentWorkspaces.find((batch) => (batch.sectionPlans || []).length > 0) ||
    null;
  const selectedBatch =
    departmentWorkspaces.find((batch) => batch.key === selectedBatchKey) ||
    (!selectedBatchKey ? fallbackSectioningWorkspace : null) ||
    null;
  const activeBatchKey = selectedBatchKey || selectedBatch?.key || "";
  const displayedBatchYear = selectedBatch?.batchYear || sectioningBatchYear;

  const sectionPlans = selectedBatch?.sectionPlans || [];
  const yearSectionPlans = sectionPlans.filter(
    (section) => sectionMatchesYearLevel(section, selectedYearLevel)
  );
  const students = selectedBatch?.students || [];
  const removedStudents = selectedBatch?.removedStudents || [];
  const selectedSection =
    yearSectionPlans.find((section) => section.sectionCode === selectedSectionCode) ||
    yearSectionPlans[0] ||
    null;

  const viewSectionRoster = (sectionCode) => {
    setSelectedSectionCode(sectionCode);
    window.requestAnimationFrame(() => {
      rosterRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const sectionSummaries = yearSectionPlans.map((section) => {
    const sectionYearLevel = section.yearLevel || selectedYearLevel;
    const sectionStudents = students
      .filter(
        (student) =>
          student.sectionCode === section.sectionCode &&
          (student.yearLevel || sectionYearLevel) === sectionYearLevel
      )
      .sort(compareStudentsByName);
    return {
      ...section,
      sectionName:
        section.sectionName ||
        getDefaultSectionName(selectedBatch?.program, section.sectionCode),
      assigned: sectionStudents.length,
      students: sectionStudents,
    };
  });

  const searchValue = useMemo(
    () => studentSearch.trim().toLowerCase(),
    [studentSearch]
  );
  const visibleSectionStudents = selectedSection
    ? students
        .filter(
          (student) => {
            const sectionYearLevel = selectedSection.yearLevel || selectedYearLevel;

            return (
              student.sectionCode === selectedSection.sectionCode &&
              (student.yearLevel || sectionYearLevel) === sectionYearLevel
            );
          }
        )
        .sort(compareStudentsByName)
        .filter((student) => {
          if (!searchValue) return true;

          const fullName = buildStudentName(student).toLowerCase();

          return (
            student.studentId.toLowerCase().includes(searchValue) ||
            fullName.includes(searchValue)
          );
        })
    : [];
  const departmentGraduatingStudents = useMemo(
    () =>
      graduatingStudents
        .filter((student) => student.program === chairpersonDepartment)
        .filter((student) => {
          if (!searchValue) return true;

          return (
            student.studentId.toLowerCase().includes(searchValue) ||
            buildStudentName(student).toLowerCase().includes(searchValue) ||
            (student.sectionName || student.sectionCode || "")
              .toLowerCase()
              .includes(searchValue)
          );
        }),
    [chairpersonDepartment, graduatingStudents, searchValue]
  );
  const visibleGraduatingStudents = useMemo(
    () =>
      departmentGraduatingStudents.filter((student) => {
        if (graduatingStatusFilter === "All") return true;
        if (graduatingStatusFilter === "Needs Checking") {
          return needsGraduatingReview(student);
        }

        return (student.status || "Incomplete") === graduatingStatusFilter;
      }),
    [departmentGraduatingStudents, graduatingStatusFilter]
  );
  const graduatingBatchGroups = useMemo(() => {
    const groupedBatches = {};

    visibleGraduatingStudents.forEach((student) => {
      const batchKey = getGraduatingBatchKey(student);
      const batchYear =
        student.originBatchYear || student.batchYear || student.sourceSchoolYear;
      const reviewYear = student.targetSchoolYear || student.sourceSchoolYear;
      const sectionKey = student.sectionCode || student.sectionName || "Unassigned";

      if (!groupedBatches[batchKey]) {
        groupedBatches[batchKey] = {
          key: batchKey,
          batchYear: batchYear || "Unassigned Batch",
          reviewYear: reviewYear || "Graduation Review",
          students: [],
          sections: {},
        };
      }

      if (!groupedBatches[batchKey].sections[sectionKey]) {
        groupedBatches[batchKey].sections[sectionKey] = {
          key: `${batchKey}|${sectionKey}`,
          sectionName: student.sectionName || student.sectionCode || "Unassigned",
          origin: [
            student.sourceSchoolYear || student.batchYear,
            student.yearLevel || "4th Year",
          ]
            .filter(Boolean)
            .join(" - "),
          students: [],
        };
      }

      groupedBatches[batchKey].students.push(student);
      groupedBatches[batchKey].sections[sectionKey].students.push(student);
    });

    return Object.values(groupedBatches).map((batch) => ({
      ...batch,
      sections: Object.values(batch.sections),
    }));
  }, [visibleGraduatingStudents]);
  const graduatingReviewStats = useMemo(
    () => ({
      all: departmentGraduatingStudents.length,
      needsChecking: departmentGraduatingStudents.filter(needsGraduatingReview)
        .length,
      graduated: departmentGraduatingStudents.filter(
        (student) => student.status === "Graduated"
      ).length,
      incomplete: departmentGraduatingStudents.filter(
        (student) => (student.status || "Incomplete") === "Incomplete"
      ).length,
      returning: departmentGraduatingStudents.filter(
        (student) => student.status === "Returning Student"
      ).length,
      irregularCompletion: departmentGraduatingStudents.filter(
        (student) => student.status === "Irregular Completion"
      ).length,
    }),
    [departmentGraduatingStudents]
  );
  const departmentIrregularStudents = useMemo(
    () =>
      departmentWorkspaces
        .flatMap((batch) =>
          (batch.students || []).map((student) => ({
            ...student,
            batchKey: batch.key,
            batchYear: batch.batchYear,
            semester: batch.semester || "",
            program: batch.program,
          }))
        )
        .filter((student) => student.studentType === "Irregular")
        .filter((student) => {
          if (!searchValue) return true;

          return (
            student.studentId.toLowerCase().includes(searchValue) ||
            buildStudentName(student).toLowerCase().includes(searchValue) ||
            (student.sectionName || student.sectionCode || "")
              .toLowerCase()
              .includes(searchValue)
          );
        }),
    [departmentWorkspaces, searchValue]
  );
  const departmentActiveStudents = useMemo(
    () =>
      departmentWorkspaces.flatMap((batch) =>
        (batch.students || []).map((student) => ({
          ...student,
          batchKey: batch.key,
          batchYear: batch.batchYear,
          program: batch.program,
        }))
      ),
    [departmentWorkspaces]
  );
  const availableIrregularSections = useMemo(
    () =>
      departmentWorkspaces.flatMap((batch) =>
        (batch.sectionPlans || []).map((section) => ({
          ...section,
          batchKey: batch.key,
          batchYear: batch.batchYear,
          label:
            section.sectionName ||
            getDefaultSectionName(batch.program, section.sectionCode),
        }))
      ),
    [departmentWorkspaces]
  );
  const currentRolloverBatches = getCurrentRolloverBatches(rolloverWorkspaces);
  const promotionSourceSections = (() => {
    const grouped = {};

    currentRolloverBatches.forEach((batch) => {
      (batch.students || []).forEach((student) => {
        const sectionCode = student.sectionCode || "unassigned";
        const key = [
          batch.key,
          student.yearLevel || "Unassigned",
          sectionCode,
        ].join("|");

        if (!grouped[key]) {
          const nextYearLevel = getNextYearLevel(student.yearLevel);
          const nextSectionCode = getNextSectionCode(
            student.sectionCode,
            nextYearLevel
          );

          grouped[key] = {
            key,
            originBatchYear: batch.batchYear,
            sourceYearLevel: student.yearLevel || "Unassigned",
            sourceSection:
              student.sectionName || student.sectionCode || "Unassigned",
            targetYearLevel: nextYearLevel || "Graduating Review",
            targetSection: nextSectionCode
              ? getDefaultSectionName(batch.program, nextSectionCode)
              : "Graduating Review",
            students: [],
          };
        }

        grouped[key].students.push(student);
      });
    });

    return Object.values(grouped).sort((left, right) =>
      [left.originBatchYear, left.sourceYearLevel, left.sourceSection]
        .join(" ")
        .localeCompare(
          [right.originBatchYear, right.sourceYearLevel, right.sourceSection].join(
            " "
          )
        )
    );
  })();

  useEffect(() => {
    localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(batches));
  }, [batches]);

  useEffect(() => {
    const handleSharedStateChanged = (event) => {
      const keys = event.detail?.keys || [];
      if (!keys.includes(STUDENT_BATCHES_KEY)) return;

      try {
        const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
        setBatches(saved ? JSON.parse(saved) : []);
      } catch (error) {
        console.warn("Failed to refresh chairperson batches from shared state.", error);
      }
    };

    window.addEventListener(
      "blockgo:shared-client-state-changed",
      handleSharedStateChanged
    );

    return () =>
      window.removeEventListener(
        "blockgo:shared-client-state-changed",
        handleSharedStateChanged
      );
  }, []);

  const updateSelectedBatch = (updater) => {
    if (!activeBatchKey) return;

    setBatches((previousBatches) =>
      previousBatches.map((batch) =>
        batch.key === activeBatchKey ? updater(batch) : batch
      )
    );
  };

  const persistBatches = (nextBatches) => {
    setBatches(nextBatches);
    localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(nextBatches));
    syncSectionedStudentsToStorage(nextBatches);
    pushSectioningSharedState();
    onSectioningSaved?.();
  };

  const handleBatchYearChange = (value) => {
    const nextBatchYear = value.replace(/\D/g, "").slice(0, 4);

    setSectioningBatchYear(nextBatchYear);

    if (!isRegistrarMode || !activeBatchKey) return;

    const nextBatches = batches.map((batch) =>
      batch.key === activeBatchKey
        ? {
            ...batch,
            batchYear: nextBatchYear,
            lastSectionedAt: new Date().toISOString(),
          }
        : batch
    );

    persistBatches(nextBatches);
  };

  const handleDownloadRegistrarCsv = (batch) => {
    const csvContent = batch.receivedCsvContent;

    if (!csvContent) {
      alert("This imported list has no registrar CSV content saved.");
      return;
    }

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.setAttribute(
      "download",
      batch.fileName || `${batch.program}-${batch.batchYear}-registrar-list.csv`
    );
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleGenerateSections = () => {
    if (!chairpersonDepartment) {
      alert("Please choose a department first.");
      return;
    }

    if (!/^\d{4}$/.test(sectioningBatchYear)) {
      alert("Enter a valid 4-digit batch year.");
      return;
    }

    const requestedSectionCount = Number(manualSectionCount);

    if (!Number.isInteger(requestedSectionCount) || requestedSectionCount <= 0) {
      alert("Enter how many sections to create.");
      return;
    }

    const resolvedBatchYear = selectedBatch?.batchYear || sectioningBatchYear;
    const targetYearLevel = isRegistrarMode ? "1st Year" : selectedYearLevel;
    const matchingSourceBatch = batches.find(
      (batch) =>
        batch.program === chairpersonDepartment &&
        batch.batchYear === resolvedBatchYear &&
        (batch.students || []).length > 0 &&
        batch.status !== "Promoted"
    );
    const sourceImportedBatch =
      departmentBatches.find((batch) => batch.key === activeBatchKey) ||
      departmentBatches.find((batch) => batch.batchYear === resolvedBatchYear) ||
      matchingSourceBatch ||
      null;
    const workspaceKey = selectedBatch
      ? activeBatchKey
      : [chairpersonDepartment, resolvedBatchYear, "sectioning"].join("|");
    const createdAt = new Date().toISOString();
    const workspaceId = Number(createdAt.replace(/\D/g, "").slice(0, 13));
    const baseWorkspace =
      selectedBatch ||
      departmentWorkspaces.find((batch) => batch.key === workspaceKey) || {
        id: workspaceId,
        key: workspaceKey,
        program: chairpersonDepartment,
        batchYear: resolvedBatchYear,
        submittedTo: isRegistrarMode
          ? "Registrar Sectioning Office"
          : `${chairpersonDepartment} Chairperson`,
        fileName: isRegistrarMode
          ? "Registrar sectioning workspace"
          : "Chairperson sectioning workspace",
        submittedAt: createdAt,
        status: "Sectioning",
        students: [],
        sectionPlans: [],
        removedStudents: [],
      };
    const sourceStudents =
      (baseWorkspace.students || []).length > 0
        ? baseWorkspace.students || []
        : sourceImportedBatch?.students || [];
    const workspace = {
      ...baseWorkspace,
      students: sourceStudents,
    };

    if (!workspace.students.length && !isRegistrarMode) {
      alert(
        "No students were found for this batch year. Make sure the registrar has forwarded the student list first."
      );
      return;
    }
    const generatedSections = buildGeneratedSections({
      program: workspace.program,
      yearLevel: targetYearLevel,
      sectionCount: requestedSectionCount,
    });
    const existingYearSections = (workspace.sectionPlans || []).filter((section) =>
      sectionMatchesYearLevel(section, targetYearLevel)
    );
    const existingYearSectionsByCode = new Map(
      existingYearSections.map((section) => [section.sectionCode, section])
    );
    const missingSections = generatedSections.filter(
      (section) => !existingYearSectionsByCode.has(section.sectionCode)
    );
    const mergedYearSections = [...existingYearSections, ...missingSections].sort(
      (left, right) => String(left.sectionCode || "").localeCompare(String(right.sectionCode || ""))
    );
    const mergedYearSectionCodes = new Set(
      mergedYearSections.map((section) => section.sectionCode)
    );
    const studentsForYear = (workspace.students || []).filter(
      (student) => (student.yearLevel || targetYearLevel) === targetYearLevel
    );
    const studentsNeedingSection = studentsForYear.filter(
      (student) => !mergedYearSectionCodes.has(student.sectionCode)
    );
    const assignedStudentsById = new Map(
      studentsNeedingSection.map((student, index) => {
        const targetSection = mergedYearSections[index % mergedYearSections.length];

        return [
          student.studentId,
          {
            ...student,
            yearLevel: targetYearLevel,
            sectionCode: targetSection.sectionCode,
            sectionName: targetSection.sectionName,
          },
        ];
      })
    );

    const nextWorkspace = {
      ...workspace,
      importedCount: workspace.importedCount || workspace.students?.length || 0,
      sectionPlans: [
        ...(workspace.sectionPlans || []).filter(
          (section) => (section.yearLevel || "") !== targetYearLevel
        ),
        ...mergedYearSections,
      ],
      students: (workspace.students || []).map((student) =>
        assignedStudentsById.get(student.studentId) || student
      ),
      lastSectionedAt: new Date().toISOString(),
    };

    persistBatches([
      ...batches.filter((batch) => batch.key !== workspaceKey),
      nextWorkspace,
    ]);
    setSelectedBatchKey(workspaceKey);
    setSectioningBatchYear(workspace.batchYear || sectioningBatchYear);
    setSelectedYearLevel(targetYearLevel);
    setSelectedSectionCode(mergedYearSections[0]?.sectionCode || "");

    if (!studentsForYear.length) {
      alert(
        `${missingSections.length || mergedYearSections.length} empty 1st Year section${(missingSections.length || mergedYearSections.length) === 1 ? "" : "s"} created for ${workspace.program}.`
      );
    }
  };

  const handleSectionNameChange = (sectionCode, sectionName) => {
    updateSelectedBatch((batch) => {
      const nextSectionPlans = (batch.sectionPlans || []).map((section) =>
        section.sectionCode === sectionCode ? { ...section, sectionName } : section
      );

      return {
        ...batch,
        sectionPlans: nextSectionPlans,
        students: (batch.students || []).map((student) =>
          student.sectionCode === sectionCode
            ? { ...student, sectionName }
            : student
        ),
      };
    });
  };

  const handleDeleteSection = (sectionCode) => {
    const section = sectionPlans.find((plan) => plan.sectionCode === sectionCode);
    const sectionName =
      section?.sectionName ||
      getDefaultSectionName(selectedBatch?.program, sectionCode);

    const confirmed = window.confirm(
      `Delete ${sectionName}? Students in this section will become unassigned.`
    );

    if (!confirmed) return;

    updateSelectedBatch((batch) => ({
      ...batch,
      sectionPlans: (batch.sectionPlans || []).filter(
        (plan) => plan.sectionCode !== sectionCode
      ),
      students: (batch.students || []).map((student) =>
        student.sectionCode === sectionCode
          ? {
              ...student,
              sectionCode: "",
              sectionName: "",
            }
          : student
      ),
      lastSectionedAt: new Date().toISOString(),
    }));

    if (selectedSectionCode === sectionCode) {
      const nextSection = yearSectionPlans.find(
        (plan) => plan.sectionCode !== sectionCode
      );
      setSelectedSectionCode(nextSection?.sectionCode || "");
    }
  };

  const handleMoveStudent = (studentId, sectionCode) => {
    const targetSection = sectionPlans.find(
      (section) => section.sectionCode === sectionCode
    );

    updateSelectedBatch((batch) => ({
      ...batch,
      students: (batch.students || []).map((student) =>
        student.studentId === studentId
          ? {
              ...student,
              yearLevel: sectionCode ? targetSection?.yearLevel || selectedYearLevel : "",
              sectionCode,
              sectionName: targetSection
                ? targetSection.sectionName ||
                  getDefaultSectionName(batch.program, targetSection.sectionCode)
                : "",
            }
          : student
      ),
      lastSectionedAt: new Date().toISOString(),
    }));
  };

  const handleStartRemoveStudent = (student) => {
    setPendingRemoval({
      studentId: student.studentId,
      studentName: buildStudentName(student),
      reason: REMOVAL_REASONS[0],
      note: "",
    });
  };

  const handleCancelRemoveStudent = () => {
    setPendingRemoval(null);
  };

  const handleConfirmRemoveStudent = () => {
    if (!pendingRemoval?.reason) {
      alert("Please choose a removal reason before removing a student.");
      return;
    }

    updateSelectedBatch((batch) => {
      const studentToRemove = (batch.students || []).find(
        (student) => student.studentId === pendingRemoval.studentId
      );

      if (!studentToRemove) return batch;

      return {
        ...batch,
        students: (batch.students || []).filter(
          (student) => student.studentId !== pendingRemoval.studentId
        ),
        removedStudents: [
          {
            ...studentToRemove,
            removedAt: new Date().toISOString(),
            removalReason: pendingRemoval.reason,
            removalNote: pendingRemoval.note.trim(),
            removedFromSectionCode: studentToRemove.sectionCode || "",
            removedFromSectionName: studentToRemove.sectionName || "",
          },
          ...(batch.removedStudents || []),
        ],
        lastSectionedAt: new Date().toISOString(),
      };
    });

    setPendingRemoval(null);
  };

  const handleRestoreStudent = (studentId) => {
    updateSelectedBatch((batch) => {
      const removedStudent = (batch.removedStudents || []).find(
        (student) => student.studentId === studentId
      );

      if (!removedStudent) return batch;

      const alreadyActive = (batch.students || []).some(
        (student) =>
          student.studentId.toLowerCase() === removedStudent.studentId.toLowerCase()
      );

      if (alreadyActive) {
        alert("This student ID already exists in the active roster.");
        return batch;
      }

      const originalSectionExists = (batch.sectionPlans || []).some(
        (section) => section.sectionCode === removedStudent.removedFromSectionCode
      );

      const restoredStudent = {
        studentId: removedStudent.studentId,
        sex: removedStudent.sex || "",
        lastName: removedStudent.lastName || "",
        firstName: removedStudent.firstName || "",
        middleName: getStudentMiddleName(removedStudent),
        middleInitial: removedStudent.middleInitial || getStudentMiddleName(removedStudent),
        yearLevel: originalSectionExists
          ? removedStudent.yearLevel || selectedYearLevel
          : "",
        sectionCode: originalSectionExists
          ? removedStudent.removedFromSectionCode
          : "",
        sectionName: originalSectionExists
          ? removedStudent.removedFromSectionName
          : "",
        isLateEnrollee: removedStudent.isLateEnrollee || false,
      };

      return {
        ...batch,
        students: [...(batch.students || []), restoredStudent],
        removedStudents: (batch.removedStudents || []).filter(
          (student) => student.studentId !== studentId
        ),
        lastSectionedAt: new Date().toISOString(),
      };
    });
  };

  const handleLateStudentChange = (field, value) => {
    setLateStudent((current) => ({ ...current, [field]: value }));
  };

  const handleAddLateStudent = () => {
    if (!selectedBatch) return;

    const studentId = lateStudent.studentId.trim();

    if (
      !studentId ||
      !lateStudent.sex ||
      !lateStudent.lastName.trim() ||
      !lateStudent.firstName.trim() ||
      !lateStudent.middleName.trim()
    ) {
      alert("Complete all late enrollee fields before adding the student.");
      return;
    }

    const duplicateStudent = students.some(
      (student) => student.studentId.toLowerCase() === studentId.toLowerCase()
    );

    if (duplicateStudent) {
      alert("This student ID is already in the roster.");
      return;
    }

    const targetSection = selectedSection || yearSectionPlans[0] || null;
    const nextStudent = {
      studentId,
      sex: lateStudent.sex,
      lastName: lateStudent.lastName.trim(),
      firstName: lateStudent.firstName.trim(),
      middleName: lateStudent.middleName.trim(),
      middleInitial: lateStudent.middleName.trim(),
      yearLevel: targetSection ? targetSection.yearLevel || selectedYearLevel : "",
      sectionCode: targetSection?.sectionCode || "",
      sectionName: targetSection
        ? targetSection.sectionName ||
          getDefaultSectionName(selectedBatch.program, targetSection.sectionCode)
        : "",
      isLateEnrollee: true,
    };

    updateSelectedBatch((batch) => ({
      ...batch,
      students: [...(batch.students || []), nextStudent],
      lastSectionedAt: new Date().toISOString(),
    }));

    setLateStudent({
      studentId: "",
      sex: "",
      lastName: "",
      firstName: "",
      middleName: "",
    });
  };

  const handleDownloadSectionCsv = (sectionCode) => {
    if (!selectedBatch) return;

    const section = sectionPlans.find((plan) => plan.sectionCode === sectionCode);
    const sectionStudents = students
      .filter((student) => student.sectionCode === sectionCode)
      .sort(compareStudentsByName);

    if (!sectionStudents.length) {
      alert("No students are assigned to this section yet.");
      return;
    }

    downloadStudentCsvFile(
      sectionStudents,
      `${section?.sectionName || sectionCode}-${selectedBatch.batchYear}.csv`
    );
  };

  const handleImportSectionCsv = (sectionCode) => {
    if (!selectedBatch) {
      alert("Please create or choose a section first.");
      return;
    }

    const section = sectionPlans.find((plan) => plan.sectionCode === sectionCode);

    if (!section) {
      alert("Selected section was not found.");
      return;
    }

    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".csv";

    input.onchange = (event) => {
      const file = event.target.files?.[0];

      if (!file) return;

      if (!file.name.toLowerCase().endsWith(".csv")) {
        alert("Please upload a CSV file.");
        return;
      }

      const reader = new FileReader();

      reader.onload = (readerEvent) => {
        const text = readerEvent.target?.result;
        const parsedStudents = parseStudentIdSpreadsheet(text || "");

        if (!parsedStudents.length) {
          alert(
            "The section CSV must contain Student ID, Sex, Last Name, First Name, and Middle Name columns with valid rows."
          );
          return;
        }

        const sectionYearLevel = section.yearLevel || selectedYearLevel;
        const sectionName =
          section.sectionName ||
          getDefaultSectionName(selectedBatch.program, section.sectionCode);
        const importedStudentIds = new Set(
          parsedStudents.map((student) => student.studentId.toLowerCase())
        );
        const existingSectionCount = students.filter(
          (student) =>
            student.sectionCode === section.sectionCode &&
            (student.yearLevel || sectionYearLevel) === sectionYearLevel
        ).length;
        const confirmed =
          existingSectionCount === 0 ||
          window.confirm(
            `Replace ${existingSectionCount} existing student${existingSectionCount === 1 ? "" : "s"} in ${sectionName}?`
          );

        if (!confirmed) return;

        const importedStudents = parsedStudents.map((student) => ({
          ...student,
          yearLevel: sectionYearLevel,
          sectionCode: section.sectionCode,
          sectionName,
        }));
        const nextBatches = batches.map((batch) =>
          batch.key === selectedBatch.key
            ? {
                ...batch,
                students: [
                  ...(batch.students || []).filter((student) => {
                    const sameTargetSection =
                      student.sectionCode === section.sectionCode &&
                      (student.yearLevel || sectionYearLevel) === sectionYearLevel;
                    const duplicateImportedStudent = importedStudentIds.has(
                      String(student.studentId || "").toLowerCase()
                    );

                    return !sameTargetSection && !duplicateImportedStudent;
                  }),
                  ...importedStudents,
                ],
                importedCount: Math.max(
                  batch.importedCount || 0,
                  (batch.students || []).length + importedStudents.length
                ),
                lastSectionedAt: new Date().toISOString(),
              }
            : batch
        );

        persistBatches(nextBatches);
        setSelectedSectionCode(section.sectionCode);
        alert(
          `${importedStudents.length} student${importedStudents.length === 1 ? "" : "s"} imported into ${sectionName}.`
        );
      };

      reader.readAsText(file);
    };

    input.click();
  };

  const handleSaveSectioning = () => {
    localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(batches));
    syncSectionedStudentsToStorage(batches);
    onSectioningSaved?.();
    alert("Sections saved successfully.");
  };

  const persistSectioningData = (nextBatches, nextGraduatingStudents) => {
    setBatches(nextBatches);
    setGraduatingStudents(nextGraduatingStudents);
    localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(nextBatches));
    localStorage.setItem(
      GRADUATING_STUDENTS_KEY,
      JSON.stringify(nextGraduatingStudents)
    );
    syncSectionedStudentsToStorage(nextBatches);
    pushSectioningSharedState();
    onSectioningSaved?.();
  };

  const persistIrregularAssignments = (nextBatches, nextAssignments) => {
    setBatches(nextBatches);
    setIrregularSubjectAssignments(nextAssignments);
    localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(nextBatches));
    localStorage.setItem(
      IRREGULAR_SUBJECTS_KEY,
      JSON.stringify(nextAssignments)
    );
    syncSectionedStudentsToStorage(nextBatches);
    pushSectioningSharedState();
    onSectioningSaved?.();
  };

  const handlePromoteStudents = () => {
    if (!currentRolloverBatches.length) {
      alert("No saved section lists are ready for promotion.");
      return;
    }

    const studentsToPromote = currentRolloverBatches.reduce(
      (total, batch) => total + (batch.students || []).length,
      0
    );
    const confirmed = window.confirm(
      `Promote ${studentsToPromote} student${studentsToPromote === 1 ? "" : "s"} across all available departments to the next academic year?`
    );

    if (!confirmed) return;

    const allPromotedStudents = [];
    const allGraduatingReviewList = [];
    const targetBatches = [];

    currentRolloverBatches.forEach((sourceBatch) => {
      const promotedStudents = [];
      const promotedSectionsByCode = new Map();
      const graduatingReviewList = [];

      (sourceBatch.students || []).forEach((student) => {
        const nextYearLevel = getNextYearLevel(student.yearLevel);
        const currentSectionCode = student.sectionCode || "";

        if (!nextYearLevel) {
          graduatingReviewList.push({
            ...student,
            program: sourceBatch.program,
            sourceBatchKey: sourceBatch.key,
            sourceSchoolYear: sourceBatch.batchYear,
            originBatchYear: sourceBatch.batchYear,
            originYearLevel: student.yearLevel,
            originSectionCode: student.sectionCode || "",
            originSectionName: student.sectionName || "",
            targetSchoolYear: sourceBatch.batchYear,
            targetSemester,
            status: (student.irregularSubjects || []).some(
              (subject) => (subject.status || "Pending") !== "Completed"
            )
              ? "Returning Student"
              : student.status || "Incomplete",
            studentType: student.studentType || "Regular",
            remarks: student.remarks || "",
            repeatedSubjects: student.repeatedSubjects || "",
            irregularSubjects: student.irregularSubjects || [],
            reviewedAt: "",
          });
          return;
        }

        const nextSectionCode = getNextSectionCode(
          currentSectionCode,
          nextYearLevel
        );
        const nextSectionName = nextSectionCode
          ? getDefaultSectionName(sourceBatch.program, nextSectionCode)
          : "";

        if (nextSectionCode && !promotedSectionsByCode.has(nextSectionCode)) {
          promotedSectionsByCode.set(nextSectionCode, {
            id: `${sourceBatch.batchYear}-${targetSemester}-${nextSectionCode}`,
            sectionCode: nextSectionCode,
            sectionName: nextSectionName,
            yearLevel: nextYearLevel,
          });
        }

        promotedStudents.push({
          ...student,
          yearLevel: nextYearLevel,
          sectionCode: nextSectionCode,
          sectionName: nextSectionName,
          semester: targetSemester,
          studentType: student.studentType || "Regular",
          remarks: student.remarks || "",
          repeatedSubjects: student.repeatedSubjects || "",
          irregularSubjects: student.irregularSubjects || [],
          originBatchYear: sourceBatch.batchYear,
          originYearLevel: student.yearLevel,
          originSectionCode: student.sectionCode || "",
          originSectionName: student.sectionName || "",
          promotedFromYearLevel: student.yearLevel,
          promotedFromSectionCode: student.sectionCode || "",
          promotedFromSectionName: student.sectionName || "",
          promotedFromSchoolYear: sourceBatch.batchYear,
          promotedFromBatchKey: sourceBatch.key,
          promotedAt: new Date().toISOString(),
        });
      });

      allPromotedStudents.push(...promotedStudents);
      allGraduatingReviewList.push(...graduatingReviewList);

      if (!promotedStudents.length) return;

      const targetBatchKey = [
        sourceBatch.program,
        sourceBatch.batchYear,
        targetSemester,
        "promotion",
      ].join("|");
      const createdAt = new Date().toISOString();

      targetBatches.push({
        id: Number(`${createdAt.replace(/\D/g, "").slice(0, 13)}${targetBatches.length}`),
        key: targetBatchKey,
        program: sourceBatch.program,
        batchYear: sourceBatch.batchYear,
        semester: targetSemester,
        submittedTo: `${sourceBatch.program} Chairperson`,
        fileName: "Academic year promoted section list",
        submittedAt: createdAt,
        status: "Sectioning",
        students: promotedStudents,
        sectionPlans: Array.from(promotedSectionsByCode.values()),
        removedStudents: [],
        promotedFromBatchKey: sourceBatch.key,
        lastSectionedAt: createdAt,
      });
    });

    const reviewKeys = new Set(
      allGraduatingReviewList.map(
        (student) =>
          `${student.studentId}|${student.targetSchoolYear}|${student.targetSemester}`
      )
    );
    const nextGraduatingStudents = [
      ...graduatingStudents.filter(
        (student) =>
          !reviewKeys.has(
            `${student.studentId}|${student.targetSchoolYear}|${student.targetSemester}`
          )
      ),
      ...allGraduatingReviewList,
    ];
    const targetBatchKeys = new Set(targetBatches.map((batch) => batch.key));
    const promotedStudentLookup = new Map(
      targetBatches.flatMap((batch) =>
        (batch.students || []).map((student) => [
          student.studentId,
          { batch, student },
        ])
      )
    );
    const nextIrregularAssignments = irregularSubjectAssignments.map(
      (assignment) => {
        const promotedRecord = promotedStudentLookup.get(assignment.studentId);

        if (!promotedRecord) return assignment;

        return {
          ...assignment,
          batchKey: promotedRecord.batch.key,
          mainBatchYear: promotedRecord.batch.batchYear,
          mainYearLevel: promotedRecord.student.yearLevel,
          mainSection: promotedRecord.student.sectionName || "",
          mainSectionCode: promotedRecord.student.sectionCode || "",
        };
      }
    );
    const sourceBatchKeys = new Set(
      currentRolloverBatches.map((batch) => batch.key)
    );
    const promotedToBySourceKey = Object.fromEntries(
      targetBatches.map((batch) => [batch.promotedFromBatchKey, batch.key])
    );
    const archivedSourceBatches = batches
      .filter((batch) => sourceBatchKeys.has(batch.key))
      .map((batch) => ({
        ...batch,
        status: "Promoted",
        promotedAt: new Date().toISOString(),
        promotedToBatchKey: promotedToBySourceKey[batch.key] || "",
      }));
    const nextBatches = [
      ...batches.filter(
        (batch) => !targetBatchKeys.has(batch.key) && !sourceBatchKeys.has(batch.key)
      ),
      ...archivedSourceBatches,
      ...targetBatches,
    ];

    persistSectioningData(nextBatches, nextGraduatingStudents);
    setIrregularSubjectAssignments(nextIrregularAssignments);
    localStorage.setItem(
      IRREGULAR_SUBJECTS_KEY,
      JSON.stringify(nextIrregularAssignments)
    );
    const firstTargetBatch = targetBatches[0] || null;
    setSelectedBatchKey(firstTargetBatch?.key || "");
    setSectioningBatchYear(firstTargetBatch?.batchYear || sectioningBatchYear);
    setSelectedYearLevel(firstTargetBatch?.sectionPlans[0]?.yearLevel || "2nd Year");
    setSelectedSectionCode(firstTargetBatch?.sectionPlans[0]?.sectionCode || "");
    setPromotionSummary({
      promoted: allPromotedStudents.length,
      sections: targetBatches.reduce(
        (total, batch) => total + (batch.sectionPlans || []).length,
        0
      ),
      graduating: allGraduatingReviewList.length,
      irregular: allPromotedStudents.filter(
        (student) => student.studentType === "Irregular"
      ).length,
      batches: currentRolloverBatches.length,
    });
    alert(
      `${allPromotedStudents.length} student${allPromotedStudents.length === 1 ? "" : "s"} promoted successfully across all available departments.`
    );
  };

  const getStudentFromKey = (studentKey = "") => {
    const [batchKey, studentId] = studentKey.split("|");
    const batch = batches.find((item) => item.key === batchKey);
    const student = (batch?.students || []).find(
      (item) => item.studentId === studentId
    );

    return { batch, batchKey, student, studentId };
  };

  const handleAssignIrregularSubject = () => {
    const { batch, batchKey, student, studentId } = getStudentFromKey(
      irregularSubjectForm.studentKey
    );
    const subjectAssignment = departmentAssignments.find(
      (assignment) =>
        String(assignment.id) === irregularSubjectForm.subjectAssignmentId
    );
    const assignedSection = availableIrregularSections.find(
      (section) => section.label === irregularSubjectForm.assignedSection
    );
    const sectionSubjectAssignment =
      departmentAssignments.find(
        (assignment) =>
          assignment.subjectCode === subjectAssignment?.subjectCode &&
          assignment.sectionName === irregularSubjectForm.assignedSection
      ) || subjectAssignment;

    if (!batch || !student || !subjectAssignment || !assignedSection || !sectionSubjectAssignment) {
      alert("Please choose the student, repeated subject, and assigned section.");
      return;
    }

    const nextSubject = {
      id: buildIrregularSubjectKey(),
      subjectCode: subjectAssignment.subjectCode,
      subjectTitle: subjectAssignment.subjectTitle,
      assignedSection: assignedSection.label,
      assignedSectionCode: assignedSection.sectionCode,
      faculty: sectionSubjectAssignment.facultyName,
      facultyId: sectionSubjectAssignment.facultyId,
      semester: sectionSubjectAssignment.semester || "",
      schoolYear: sectionSubjectAssignment.schoolYear || batch.batchYear,
      remarks: irregularSubjectForm.remarks.trim(),
      status: "Pending",
      assignedAt: new Date().toISOString(),
    };

    const nextBatches = batches.map((item) =>
      item.key === batchKey
        ? {
            ...item,
            students: (item.students || []).map((batchStudent) =>
              batchStudent.studentId === studentId
                ? {
                    ...batchStudent,
                    studentType: "Irregular",
                    irregularSubjects: [
                      ...(batchStudent.irregularSubjects || []),
                      nextSubject,
                    ],
                  }
                : batchStudent
            ),
            lastSectionedAt: new Date().toISOString(),
          }
        : item
    );
    const nextAssignments = [
      ...irregularSubjectAssignments,
      {
        ...nextSubject,
        studentId,
        firstName: student.firstName,
        lastName: student.lastName,
        middleName: getStudentMiddleName(student),
        middleInitial: student.middleInitial || getStudentMiddleName(student),
        sex: student.sex || "",
        program: batch.program,
        mainBatchYear: batch.batchYear,
        mainYearLevel: student.yearLevel,
        mainSection: student.sectionName || "",
        mainSectionCode: student.sectionCode || "",
        batchKey,
      },
    ];

    persistIrregularAssignments(nextBatches, nextAssignments);
    setIrregularSubjectForm({
      studentKey: "",
      subjectAssignmentId: "",
      assignedSection: "",
      faculty: "",
      remarks: "",
    });
  };

  const handleTransferSubjectSection = () => {
    const { batch, batchKey, student, studentId } = getStudentFromKey(
      transferSubjectForm.studentKey
    );
    const targetSection = availableIrregularSections.find(
      (section) => section.label === transferSubjectForm.newSection
    );
    const currentSubject = (student?.irregularSubjects || []).find(
      (subject) => subject.id === transferSubjectForm.irregularSubjectId
    );
    const newSubjectAssignment = departmentAssignments.find(
      (assignment) =>
        assignment.subjectCode === currentSubject?.subjectCode &&
        assignment.sectionName === transferSubjectForm.newSection
    );

    if (!batch || !student || !transferSubjectForm.irregularSubjectId || !targetSection) {
      alert("Please choose the student, repeated subject, and new section.");
      return;
    }

    const nextBatches = batches.map((item) =>
      item.key === batchKey
        ? {
            ...item,
            students: (item.students || []).map((batchStudent) =>
              batchStudent.studentId === studentId
                ? {
                    ...batchStudent,
                    irregularSubjects: (batchStudent.irregularSubjects || []).map(
                      (subject) =>
                        subject.id === transferSubjectForm.irregularSubjectId
                          ? {
                              ...subject,
                              assignedSection: targetSection.label,
                              assignedSectionCode: targetSection.sectionCode,
                              faculty:
                                newSubjectAssignment?.facultyName ||
                                subject.faculty,
                              facultyId:
                                newSubjectAssignment?.facultyId ||
                                subject.facultyId,
                              transferReason: transferSubjectForm.reason.trim(),
                              transferredAt: new Date().toISOString(),
                            }
                          : subject
                    ),
                  }
                : batchStudent
            ),
            lastSectionedAt: new Date().toISOString(),
          }
        : item
    );
    const nextAssignments = irregularSubjectAssignments.map((assignment) =>
      assignment.id === transferSubjectForm.irregularSubjectId
        ? {
            ...assignment,
            assignedSection: targetSection.label,
            assignedSectionCode: targetSection.sectionCode,
            faculty: newSubjectAssignment?.facultyName || assignment.faculty,
            facultyId: newSubjectAssignment?.facultyId || assignment.facultyId,
            transferReason: transferSubjectForm.reason.trim(),
            transferredAt: new Date().toISOString(),
          }
        : assignment
    );

    persistIrregularAssignments(nextBatches, nextAssignments);
    setTransferSubjectForm({
      studentKey: "",
      irregularSubjectId: "",
      newSection: "",
      reason: "",
    });
  };

  const handleResolveCompletedSubject = (batchKey, studentId, subjectId) => {
    const nextBatches = batches.map((item) =>
      item.key === batchKey
        ? {
            ...item,
            students: (item.students || []).map((student) =>
              student.studentId === studentId
                ? {
                    ...student,
                    irregularSubjects: (student.irregularSubjects || []).map(
                      (subject) =>
                        subject.id === subjectId
                          ? {
                              ...subject,
                              status: "Completed",
                              completedAt: new Date().toISOString(),
                            }
                          : subject
                    ),
                  }
                : student
            ),
          }
        : item
    );
    const nextAssignments = irregularSubjectAssignments.map((assignment) =>
      assignment.id === subjectId
        ? {
            ...assignment,
            status: "Completed",
            completedAt: new Date().toISOString(),
          }
        : assignment
    );

    persistIrregularAssignments(nextBatches, nextAssignments);
  };

  const handleGraduatingStatusChange = (studentId, updates) => {
    const nextGraduatingStudents = graduatingStudents.map((student) =>
      student.studentId === studentId ? { ...student, ...updates } : student
    );

    persistSectioningData(batches, nextGraduatingStudents);
  };

  const handleBulkGraduatingStatusChange = (status) => {
    if (!visibleGraduatingStudents.length) {
      alert("No visible fourth-year students to update.");
      return;
    }

    const visibleStudentIds = new Set(
      visibleGraduatingStudents.map((student) => student.studentId)
    );
    const nextGraduatingStudents = graduatingStudents.map((student) =>
      visibleStudentIds.has(student.studentId)
        ? {
            ...student,
            status,
            reviewedAt: new Date().toISOString(),
          }
        : student
    );

    persistSectioningData(batches, nextGraduatingStudents);
  };

  const handleGraduatingSectionStatusChange = (sectionStudents, status) => {
    const sectionStudentIds = new Set(
      sectionStudents.map((student) => student.studentId)
    );
    const nextGraduatingStudents = graduatingStudents.map((student) =>
      sectionStudentIds.has(student.studentId)
        ? {
            ...student,
            status,
            reviewedAt: new Date().toISOString(),
          }
        : student
    );

    persistSectioningData(batches, nextGraduatingStudents);
  };

  const handleDeleteGraduatingBatch = (batchGroup) => {
    const confirmed = window.confirm(
      `Delete graduation review records for Batch ${batchGroup.batchYear}?`
    );

    if (!confirmed) return;

    const nextGraduatingStudents = graduatingStudents.filter(
      (student) =>
        !(
          student.program === chairpersonDepartment &&
          getGraduatingBatchKey(student) === batchGroup.key
        )
    );

    persistSectioningData(batches, nextGraduatingStudents);
  };

  const toggleGraduatingSection = (sectionKey) => {
    setExpandedGraduatingSections((current) => ({
      ...current,
      [sectionKey]: !current[sectionKey],
    }));
  };

  return (
    <div className="space-y-6">

      {isRegistrarMode ? (
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {[
            ["sectioning", "Section Lists"],
            ["promotion", "Promote to Next Year"],
          ].map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => {
                setActiveWorkspace(id);
                setStudentSearch("");
              }}
              className={`rounded-xl px-4 py-3 text-sm font-semibold transition ${
                activeWorkspace === id
                  ? "bg-[#003366] text-white shadow-sm"
                  : "border border-slate-200 text-slate-700 hover:bg-slate-50"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      ) : null}

      {isRegistrarMode && activeWorkspace === "promotion" ? (
        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <h3 className="text-xl font-bold text-[#003366]">
                Academic Year Promotion
              </h3>
              
            </div>
            <span className="rounded-full bg-blue-100 px-4 py-2 text-sm font-semibold text-blue-700">
              Chairperson Rollover
            </span>
          </div>

          <div className="mt-6 flex flex-col gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-5 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-sm font-semibold text-slate-700">
                {promotionSourceSections.reduce(
                  (total, section) => total + section.students.length,
                  0
                )}{" "}
                students across all available departments and{" "}
                {currentRolloverBatches.length} batch
                {currentRolloverBatches.length === 1 ? "" : "es"} ready for
                rollover
              </p>
              
            </div>
            <button
              type="button"
              onClick={handlePromoteStudents}
              className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d]"
            >
              Promote All to Next Academic Year
            </button>
          </div>

          {promotionSummary ? (
            <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-xl bg-slate-50 p-4">
                <p className="text-sm text-slate-500">Total Promoted Students</p>
                <p className="mt-1 text-2xl font-bold text-[#003366]">
                  {promotionSummary.promoted}
                </p>
              </div>
              <div className="rounded-xl bg-slate-50 p-4">
                <p className="text-sm text-slate-500">Total Promoted Sections</p>
                <p className="mt-1 text-2xl font-bold text-[#003366]">
                  {promotionSummary.sections}
                </p>
              </div>
              <div className="rounded-xl bg-slate-50 p-4">
                <p className="text-sm text-slate-500">
                  Irregular Students Carried Over
                </p>
                <p className="mt-1 text-2xl font-bold text-[#003366]">
                  {promotionSummary.irregular}
                </p>
              </div>
              <div className="rounded-xl bg-slate-50 p-4">
                <p className="text-sm text-slate-500">
                  4th Year to Graduation Review
                </p>
                <p className="mt-1 text-2xl font-bold text-[#003366]">
                  {promotionSummary.graduating}
                </p>
              </div>
            </div>
          ) : null}
        </section>
      ) : null}

      {isRegistrarMode && activeWorkspace === "graduating" ? (
        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h3 className="text-xl font-bold text-[#003366]">
                Graduating Review List
              </h3>
              
            </div>
            <input
              type="text"
              value={studentSearch}
              onChange={(event) => setStudentSearch(event.target.value)}
              placeholder="Search fourth-year students..."
              className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366] lg:max-w-xs"
            />
          </div>

          <div className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-3 xl:grid-cols-6">
            {[
              ["Needs Checking", graduatingReviewStats.needsChecking],
              ["All", graduatingReviewStats.all],
              ["Graduated", graduatingReviewStats.graduated],
              ["Incomplete", graduatingReviewStats.incomplete],
              ["Returning Student", graduatingReviewStats.returning],
              [
                "Irregular Completion",
                graduatingReviewStats.irregularCompletion,
              ],
            ].map(([status, count]) => (
              <button
                key={status}
                type="button"
                onClick={() => setGraduatingStatusFilter(status)}
                className={`rounded-xl border p-4 text-left transition ${
                  graduatingStatusFilter === status
                    ? "border-[#003366] bg-[#003366]/5"
                    : "border-slate-200 bg-slate-50 hover:bg-white"
                }`}
              >
                <p className="text-xs font-semibold uppercase text-slate-500">
                  {status}
                </p>
                <p className="mt-1 text-2xl font-bold text-[#003366]">
                  {count}
                </p>
              </button>
            ))}
          </div>

          <div className="mb-5 flex flex-wrap items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 p-4">
            <span className="mr-2 text-sm font-semibold text-slate-700">
              Update visible:
            </span>
            {GRADUATING_STATUSES.map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => handleBulkGraduatingStatusChange(status)}
                className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:border-[#003366] hover:text-[#003366]"
              >
                {status}
              </button>
            ))}
          </div>

          <div className="space-y-5">
            {graduatingBatchGroups.length ? (
              graduatingBatchGroups.map((batchGroup) => (
                <article
                  key={batchGroup.key}
                  className="rounded-2xl border border-slate-200 bg-white p-4"
                >
                  <div className="mb-4 flex flex-col gap-3 border-b border-slate-200 pb-4 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                      <p className="text-xs font-semibold uppercase text-slate-500">
                        Graduation Review Batch
                      </p>
                      <h4 className="mt-1 text-lg font-bold text-[#003366]">
                        Batch {batchGroup.batchYear}
                      </h4>
                      <p className="mt-1 text-sm text-slate-500">
                        {batchGroup.reviewYear} • {batchGroup.students.length} student
                        {batchGroup.students.length === 1 ? "" : "s"} across{" "}
                        {batchGroup.sections.length} section
                        {batchGroup.sections.length === 1 ? "" : "s"}
                      </p>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => handleDeleteGraduatingBatch(batchGroup)}
                        className="rounded-lg border border-red-300 px-3 py-2 text-sm font-semibold text-red-600 hover:bg-red-50"
                      >
                        Delete Batch
                      </button>
                    </div>
                  </div>

                  <div className="space-y-4">
                    {batchGroup.sections.map((section) => (
                      <div
                        key={section.key}
                        className="rounded-2xl border border-slate-200 bg-slate-50 p-4"
                      >
                        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                          <div>
                            <p className="text-xs font-semibold uppercase text-slate-500">
                              {section.origin}
                            </p>
                            <h4 className="mt-1 text-lg font-bold text-[#003366]">
                              {section.sectionName}
                            </h4>
                            <p className="mt-1 text-sm text-slate-500">
                              {section.students.length} student
                              {section.students.length === 1 ? "" : "s"} for review
                            </p>
                          </div>

                          <div className="flex flex-wrap gap-2">
                            {GRADUATING_STATUSES.map((status) => (
                              <button
                                key={status}
                                type="button"
                                onClick={() =>
                                  handleGraduatingSectionStatusChange(
                                    section.students,
                                    status
                                  )
                                }
                                className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:border-[#003366] hover:text-[#003366]"
                              >
                                {status}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-4">
                          <div className="rounded-xl bg-white p-4">
                            <p className="text-sm text-slate-500">
                              Needs Checking
                            </p>
                            <p className="mt-1 text-2xl font-bold text-[#003366]">
                              {
                                section.students.filter(needsGraduatingReview)
                                  .length
                              }
                            </p>
                          </div>
                          {GRADUATING_STATUSES.slice(0, 3).map((status) => (
                            <div key={status} className="rounded-xl bg-white p-4">
                              <p className="text-sm text-slate-500">{status}</p>
                              <p className="mt-1 text-2xl font-bold text-[#003366]">
                                {
                                  section.students.filter(
                                    (student) =>
                                      (student.status || "Incomplete") === status
                                  ).length
                                }
                              </p>
                            </div>
                          ))}
                        </div>

                        <div className="mt-4">
                          <button
                            type="button"
                            onClick={() => toggleGraduatingSection(section.key)}
                            className="rounded-lg border border-[#003366] bg-white px-3 py-2 text-sm font-semibold text-[#003366] hover:bg-[#003366] hover:text-white"
                          >
                            {expandedGraduatingSections[section.key]
                              ? "Hide Students"
                              : "View Students"}
                          </button>
                        </div>

                        {expandedGraduatingSections[section.key] ? (
                          <div className="mt-4 overflow-x-auto">
                          <table className="min-w-full">
                            <thead>
                              <tr className="bg-[#003366] text-white">
                                <th className="px-4 py-3 text-left text-sm">Student</th>
                                <th className="px-4 py-3 text-left text-sm">Origin</th>
                                <th className="px-4 py-3 text-left text-sm">Status</th>
                                <th className="px-4 py-3 text-left text-sm">Remarks</th>
                              </tr>
                            </thead>
                            <tbody>
                              {section.students.map((student) => (
                                <tr
                                  key={`${student.studentId}-${student.targetSchoolYear}`}
                                  className="border-b bg-white"
                                >
                                  <td className="px-4 py-3">
                                    <p className="font-semibold text-slate-800">
                                      {student.studentId}
                                    </p>
                                    <p className="text-sm text-slate-500">
                                      {buildStudentName(student)}
                                    </p>
                                  </td>
                                  <td className="px-4 py-3 text-slate-700">
                                    Batch {student.originBatchYear || student.sourceSchoolYear}
                                    <span className="block text-xs text-slate-500">
                                      {student.originYearLevel || student.yearLevel}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3">
                                    <select
                                      value={student.status || "Incomplete"}
                                      onChange={(event) =>
                                        handleGraduatingStatusChange(student.studentId, {
                                          status: event.target.value,
                                          reviewedAt: new Date().toISOString(),
                                        })
                                      }
                                      className="min-w-48 rounded-xl border border-slate-300 px-3 py-2 text-sm outline-none focus:border-[#003366]"
                                    >
                                      {GRADUATING_STATUSES.map((status) => (
                                        <option key={status} value={status}>
                                          {status}
                                        </option>
                                      ))}
                                    </select>
                                  </td>
                                  <td className="px-4 py-3">
                                    <input
                                      type="text"
                                      value={student.remarks || ""}
                                      onChange={(event) =>
                                        handleGraduatingStatusChange(student.studentId, {
                                          remarks: event.target.value,
                                        })
                                      }
                                      placeholder="Review note"
                                      className="min-w-64 rounded-xl border border-slate-300 px-3 py-2 text-sm outline-none focus:border-[#003366]"
                                    />
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </article>
              ))
            ) : (
              <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-8 text-center text-sm text-slate-500">
                No fourth-year students match this review filter.
              </div>
            )}
          </div>
        </section>
      ) : null}

      {isRegistrarMode && activeWorkspace === "irregular" ? (
        <section className="space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="mb-5">
              <h3 className="text-xl font-bold text-[#003366]">
                Irregular Subject Assignment
              </h3>
              
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
              <select
                value={irregularSubjectForm.studentKey}
                onChange={(event) =>
                  setIrregularSubjectForm((current) => ({
                    ...current,
                    studentKey: event.target.value,
                  }))
                }
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366] xl:col-span-2"
              >
                <option value="">Select student</option>
                {departmentActiveStudents.map((student) => (
                  <option
                    key={`${student.batchKey}-${student.studentId}`}
                    value={`${student.batchKey}|${student.studentId}`}
                  >
                    {student.studentId} - {buildStudentName(student)} (
                    {student.yearLevel}, {student.sectionName || "Unassigned"})
                  </option>
                ))}
              </select>
              <select
                value={irregularSubjectForm.subjectAssignmentId}
                onChange={(event) => {
                  const assignment = departmentAssignments.find(
                    (item) => String(item.id) === event.target.value
                  );
                  setIrregularSubjectForm((current) => ({
                    ...current,
                    subjectAssignmentId: event.target.value,
                    assignedSection: assignment?.sectionName || "",
                    faculty: assignment?.facultyName || "",
                  }));
                }}
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366] xl:col-span-2"
              >
                <option value="">Select repeated subject</option>
                {departmentAssignments.map((assignment) => (
                  <option key={assignment.id} value={assignment.id}>
                    {assignment.subjectCode} - {assignment.subjectTitle} /{" "}
                    {assignment.sectionName}
                  </option>
                ))}
              </select>
              <select
                value={irregularSubjectForm.assignedSection}
                onChange={(event) =>
                  setIrregularSubjectForm((current) => ({
                    ...current,
                    assignedSection: event.target.value,
                  }))
                }
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
              >
                <option value="">Assigned section</option>
                {availableIrregularSections.map((section) => (
                  <option
                    key={`${section.batchKey}-${section.sectionCode}`}
                    value={section.label}
                  >
                    {section.label}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={irregularSubjectForm.faculty}
                readOnly
                placeholder="Faculty"
                className="rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 text-sm outline-none xl:col-span-2"
              />
              <input
                type="text"
                value={irregularSubjectForm.remarks}
                onChange={(event) =>
                  setIrregularSubjectForm((current) => ({
                    ...current,
                    remarks: event.target.value,
                  }))
                }
                placeholder="Remarks"
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366] xl:col-span-2"
              />
              <button
                type="button"
                onClick={handleAssignIrregularSubject}
                className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d]"
              >
                Assign Repeated Subject
              </button>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <h3 className="text-xl font-bold text-[#003366]">
              Transfer Subject Section
            </h3>
            <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
              <select
                value={transferSubjectForm.studentKey}
                onChange={(event) =>
                  setTransferSubjectForm({
                    studentKey: event.target.value,
                    irregularSubjectId: "",
                    newSection: "",
                    reason: "",
                  })
                }
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366] xl:col-span-2"
              >
                <option value="">Student</option>
                {departmentIrregularStudents.map((student) => (
                  <option
                    key={`${student.batchKey}-${student.studentId}`}
                    value={`${student.batchKey}|${student.studentId}`}
                  >
                    {student.studentId} - {buildStudentName(student)}
                  </option>
                ))}
              </select>

              <select
                value={transferSubjectForm.irregularSubjectId}
                onChange={(event) =>
                  setTransferSubjectForm((current) => ({
                    ...current,
                    irregularSubjectId: event.target.value,
                  }))
                }
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
              >
                <option value="">Repeated subject</option>
                {(
                  getStudentFromKey(transferSubjectForm.studentKey).student
                    ?.irregularSubjects || []
                )
                  .filter((subject) => (subject.status || "Pending") !== "Completed")
                  .map((subject) => (
                    <option key={subject.id} value={subject.id}>
                      {subject.subjectCode} - {subject.assignedSection}
                    </option>
                  ))}
              </select>

              <input
                type="text"
                readOnly
                value={
                  (
                    getStudentFromKey(transferSubjectForm.studentKey).student
                      ?.irregularSubjects || []
                  ).find(
                    (subject) =>
                      subject.id === transferSubjectForm.irregularSubjectId
                  )?.assignedSection || ""
                }
                placeholder="Current section"
                className="rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 text-sm outline-none"
              />

              <select
                value={transferSubjectForm.newSection}
                onChange={(event) =>
                  setTransferSubjectForm((current) => ({
                    ...current,
                    newSection: event.target.value,
                  }))
                }
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
              >
                <option value="">New section</option>
                {availableIrregularSections.map((section) => (
                  <option
                    key={`${section.batchKey}-${section.sectionCode}`}
                    value={section.label}
                  >
                    {section.label}
                  </option>
                ))}
              </select>

              <input
                type="text"
                value={transferSubjectForm.reason}
                onChange={(event) =>
                  setTransferSubjectForm((current) => ({
                    ...current,
                    reason: event.target.value,
                  }))
                }
                placeholder="Reason"
                className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
              />

              <button
                type="button"
                onClick={handleTransferSubjectSection}
                className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d]"
              >
                Transfer Subject Section
              </button>
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h3 className="text-xl font-bold text-[#003366]">
                  Active Irregular Subject Records
                </h3>
                
              </div>
              <input
                type="text"
                value={studentSearch}
                onChange={(event) => setStudentSearch(event.target.value)}
                placeholder="Search irregular records..."
                className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366] lg:max-w-xs"
              />
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead>
                  <tr className="bg-[#003366] text-white">
                    <th className="px-4 py-3 text-left text-sm">Student</th>
                    <th className="px-4 py-3 text-left text-sm">Official Record</th>
                    <th className="px-4 py-3 text-left text-sm">Repeated Subject</th>
                    <th className="px-4 py-3 text-left text-sm">Subject Section</th>
                    <th className="px-4 py-3 text-left text-sm">Faculty</th>
                    <th className="px-4 py-3 text-left text-sm">Remarks</th>
                    <th className="px-4 py-3 text-left text-sm">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {irregularSubjectAssignments
                    .filter((assignment) => assignment.program === chairpersonDepartment)
                    .filter((assignment) => {
                      if (!searchValue) return true;

                      return (
                        assignment.studentId.toLowerCase().includes(searchValue) ||
                        [assignment.lastName, assignment.firstName]
                          .join(" ")
                          .toLowerCase()
                          .includes(searchValue) ||
                        assignment.subjectCode.toLowerCase().includes(searchValue)
                      );
                    })
                    .map((assignment) => (
                      <tr key={assignment.id} className="border-b bg-white">
                        <td className="px-4 py-3">
                          <p className="font-semibold text-slate-800">
                            {assignment.studentId}
                          </p>
                          <p className="text-sm text-slate-500">
                            {buildStudentName(assignment)}
                          </p>
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {assignment.mainYearLevel}
                          <span className="block text-xs text-slate-500">
                            {assignment.mainSection} / Batch{" "}
                            {assignment.mainBatchYear}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {assignment.subjectCode}
                          <span className="block text-xs text-slate-500">
                            {assignment.subjectTitle}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {assignment.assignedSection}
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {assignment.faculty}
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {assignment.remarks || "--"}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            onClick={() =>
                              handleResolveCompletedSubject(
                                assignment.batchKey,
                                assignment.studentId,
                                assignment.id
                              )
                            }
                            className="rounded-lg border border-emerald-200 px-3 py-2 text-sm font-semibold text-emerald-700 hover:bg-emerald-50"
                          >
                            Resolve Completed
                          </button>
                        </td>
                      </tr>
                    ))}
                  {!irregularSubjectAssignments.filter(
                    (assignment) => assignment.program === chairpersonDepartment
                  ).length ? (
                    <tr>
                      <td colSpan="7" className="py-8 text-center text-slate-500">
                        No irregular subject assignments yet.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      ) : null}

      <div className={`grid grid-cols-1 gap-6 ${isRegistrarMode ? "xl:grid-cols-[300px_1fr]" : ""}`}>
        {isRegistrarMode ? (
          <aside className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="text-lg font-bold text-[#003366]">Imported Lists</h3>
          

          <div className="mt-4 space-y-3">
            {departmentBatches.length > 0 ? (
              departmentBatches.map((batch) => (
                <article
                  key={batch.key}
                  className="rounded-xl border border-slate-200 bg-white p-4"
                >
                  <p className="font-bold text-[#003366]">{batch.program}</p>
                  <p className="mt-1 text-sm text-slate-600">
                    Batch {batch.batchYear}
                  </p>
                  <p className="mt-2 text-xs text-slate-500">
                    {new Date(batch.submittedAt).toLocaleString("en-US")}
                  </p>
                  <span className="mt-3 inline-flex rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700">
                    {(batch.students || []).length} imported
                  </span>
                  <button
                    type="button"
                    onClick={() => handleDownloadRegistrarCsv(batch)}
                    className="mt-3 w-full rounded-lg border border-[#003366] px-3 py-2 text-sm font-semibold text-[#003366] hover:bg-[#003366] hover:text-white"
                  >
                    Download CSV
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedBatchKey(batch.key);
                      setSectioningBatchYear(batch.batchYear);
                      alert(
                        `${batch.program} Batch ${batch.batchYear} list selected for sectioning.`
                      );
                    }}
                    className="mt-2 w-full rounded-lg bg-[#003366] px-3 py-2 text-sm font-semibold text-white hover:bg-[#00264d]"
                  >
                    Use This List
                  </button>
                </article>
              ))
            ) : (
              <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-5 text-center text-sm text-slate-500">
                No imported student list is available for this department.
              </div>
            )}
          </div>
          </aside>
        ) : null}

        <main className="space-y-6">
          {isRegistrarMode ? (
            <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_170px_170px_170px_auto_auto] lg:items-end">
                <div>
                  <h3 className="text-xl font-bold text-[#003366]">
                    Section Generator
                  </h3>
                </div>

                <label className="block">
                  <span className="mb-2 block text-sm font-medium text-slate-700">
                    Year level
                  </span>
                  <div className="w-full rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-700">
                    1st Year only
                  </div>
                </label>

                <label className="block">
                  <span className="mb-2 block text-sm font-medium text-slate-700">
                    Batch year
                  </span>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={displayedBatchYear}
                    onChange={(event) => handleBatchYearChange(event.target.value)}
                    className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                  />
                </label>

                <label className="block">
                  <span className="mb-2 block text-sm font-medium text-slate-700">
                    Number of sections
                  </span>
                  <input
                    type="number"
                    min="1"
                    value={manualSectionCount}
                    onChange={(event) => setManualSectionCount(event.target.value)}
                    className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                  />
                </label>

                <button
                  type="button"
                  onClick={handleGenerateSections}
                  className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d]"
                >
                  Generate Sections
                </button>
                <button
                  type="button"
                  onClick={handleSaveSectioning}
                  disabled={!selectedBatch || !sectionPlans.length}
                  className="rounded-xl border border-[#003366] px-5 py-3 text-sm font-semibold text-[#003366] transition hover:bg-[#003366] hover:text-white disabled:cursor-not-allowed disabled:border-slate-300 disabled:text-slate-400"
                >
                  Save Sections
                </button>
              </div>

            </section>
          ) : null}

            <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <h3 className="text-xl font-bold text-[#003366]">
                    Sections Preview
                  </h3>
                </div>
                {isChairpersonMode ? (
                  <label className="block w-full md:max-w-xs">
                    <span className="mb-2 block text-sm font-medium text-slate-700">
                      Year level
                    </span>
                    <select
                      value={selectedYearLevel}
                      onChange={(event) => {
                        const nextYearLevel = event.target.value;
                        const workspaceWithYear =
                          (selectedBatch?.sectionPlans || []).some((section) =>
                            sectionMatchesYearLevel(section, nextYearLevel)
                          )
                            ? selectedBatch
                            : departmentWorkspaces.find((batch) =>
                                (batch.sectionPlans || []).some((section) =>
                                  sectionMatchesYearLevel(section, nextYearLevel)
                                )
                              );
                        const nextYearSection = (
                          workspaceWithYear?.sectionPlans || []
                        ).find((section) =>
                          sectionMatchesYearLevel(section, nextYearLevel)
                        );

                        setSelectedYearLevel(nextYearLevel);
                        if (workspaceWithYear?.key) {
                          setSelectedBatchKey(workspaceWithYear.key);
                          setSectioningBatchYear(
                            workspaceWithYear.batchYear || sectioningBatchYear
                          );
                        }
                        setSelectedSectionCode(nextYearSection?.sectionCode || "");
                      }}
                      className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                    >
                      {AVAILABLE_YEAR_LEVELS.map((yearLevel) => (
                        <option key={yearLevel} value={yearLevel}>
                          {yearLevel}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
              </div>

              {sectionSummaries.length ? (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-3">
                  {sectionSummaries.map((section) => (
                    <article
                      key={section.sectionCode}
                      className={`rounded-xl border p-4 transition ${
                        selectedSection?.sectionCode === section.sectionCode
                          ? "border-[#003366] bg-[#003366]/5"
                          : "border-slate-200 bg-white"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <button
                          type="button"
                          onClick={() => viewSectionRoster(section.sectionCode)}
                          className="text-left"
                        >
                          <p className="text-sm font-semibold text-slate-500">
                            Section {section.sectionCode}
                          </p>
                          <p className="mt-1 text-xs font-semibold uppercase text-slate-400">
                            Batch {displayedBatchYear}
                          </p>
                          <p className="mt-1 text-xl font-bold text-[#003366]">
                            {section.sectionName}
                          </p>
                        </button>

                        <span className="rounded-full bg-emerald-100 px-3 py-1 text-xs font-semibold text-emerald-700">
                          {section.assigned} student
                          {section.assigned === 1 ? "" : "s"}
                        </span>
                      </div>

                      {isRegistrarMode ? (
                        <input
                          type="text"
                          value={section.sectionName}
                          onChange={(event) =>
                            handleSectionNameChange(
                              section.sectionCode,
                              event.target.value
                            )
                          }
                          className="mt-4 w-full rounded-xl border border-slate-300 px-3 py-2 text-sm outline-none focus:border-[#003366]"
                          aria-label={`Edit ${section.sectionCode} section name`}
                        />
                      ) : null}

                      <div className="mt-4 flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => viewSectionRoster(section.sectionCode)}
                          className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
                        >
                          View Roster
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDownloadSectionCsv(section.sectionCode)}
                          className="rounded-lg border border-[#003366] px-3 py-2 text-sm font-semibold text-[#003366] hover:bg-[#003366] hover:text-white"
                        >
                          Export CSV
                        </button>
                        {isRegistrarMode ? (
                          <button
                            type="button"
                            onClick={() => handleImportSectionCsv(section.sectionCode)}
                            className="rounded-lg border border-emerald-300 px-3 py-2 text-sm font-semibold text-emerald-700 hover:bg-emerald-50"
                          >
                            Import List
                          </button>
                        ) : null}
                        {isRegistrarMode ? (
                          <button
                            type="button"
                            onClick={() => handleDeleteSection(section.sectionCode)}
                            className="rounded-lg border border-red-200 px-3 py-2 text-sm font-semibold text-red-600 hover:bg-red-50"
                          >
                            Delete
                          </button>
                        ) : null}
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-8 text-center text-sm text-slate-500">
                  {isRegistrarMode
                    ? "Generate sections to preview students by section."
                    : "No registrar-created sections are available yet."}
                </div>
              )}
            </section>

            <section ref={rosterRef} className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <h3 className="text-xl font-bold text-[#003366]">
                    {selectedSection
                      ? selectedSection.sectionName ||
                        getDefaultSectionName(
                          selectedBatch.program,
                          selectedSection.sectionCode
                        )
                      : "Section Students"}
                  </h3>
                </div>

                <input
                  type="text"
                  value={studentSearch}
                  onChange={(event) => setStudentSearch(event.target.value)}
                  placeholder="Search this section..."
                  className="w-full rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366] lg:max-w-xs"
                />
              </div>

              {pendingRemoval ? (
                <div className="mb-5 rounded-xl border border-red-200 bg-red-50 p-4">
                  <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
                    <div>
                      <p className="text-sm font-semibold text-red-700">
                        Remove {pendingRemoval.studentName}
                      </p>
                      <p className="mt-1 text-sm text-red-600">
                        This student will move to the removed students audit list.
                      </p>
                    </div>

                    <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-[220px_1fr_auto_auto] xl:max-w-4xl">
                      <select
                        value={pendingRemoval.reason}
                        onChange={(event) =>
                          setPendingRemoval((current) => ({
                            ...current,
                            reason: event.target.value,
                          }))
                        }
                        className="rounded-xl border border-red-200 bg-white px-4 py-3 text-sm outline-none focus:border-red-500"
                        aria-label="Removal reason"
                      >
                        {REMOVAL_REASONS.map((reason) => (
                          <option key={reason} value={reason}>
                            {reason}
                          </option>
                        ))}
                      </select>
                      <input
                        type="text"
                        value={pendingRemoval.note}
                        onChange={(event) =>
                          setPendingRemoval((current) => ({
                            ...current,
                            note: event.target.value,
                          }))
                        }
                        placeholder="Optional note"
                        className="rounded-xl border border-red-200 bg-white px-4 py-3 text-sm outline-none focus:border-red-500"
                      />
                      <button
                        type="button"
                        onClick={handleCancelRemoveStudent}
                        className="rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm font-semibold text-slate-700 hover:bg-slate-50"
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        onClick={handleConfirmRemoveStudent}
                        className="rounded-xl bg-red-600 px-4 py-3 text-sm font-semibold text-white hover:bg-red-700"
                      >
                        Confirm Remove
                      </button>
                    </div>
                  </div>
                </div>
              ) : null}

              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead>
                    <tr className="bg-[#003366] text-white">
                      <th className="px-4 py-3 text-left text-sm">Student ID</th>
                      <th className="px-4 py-3 text-left text-sm">Name</th>
                      <th className="px-4 py-3 text-left text-sm">Sex</th>
                      <th className="px-4 py-3 text-left text-sm">Section</th>
                      {canEditRoster ? (
                        <th className="px-4 py-3 text-left text-sm">Action</th>
                      ) : null}
                    </tr>
                  </thead>
                  <tbody>
                    {visibleSectionStudents.length > 0 ? (
                      visibleSectionStudents.map((student) => (
                        <tr key={student.studentId} className="border-b bg-white">
                          <td className="px-4 py-3 font-semibold text-slate-800">
                            {student.studentId}
                            {student.isLateEnrollee ? (
                              <span className="ml-2 rounded-full bg-amber-100 px-2 py-1 text-xs font-semibold text-amber-700">
                                Late
                              </span>
                            ) : null}
                          </td>
                          <td className="px-4 py-3 text-slate-700">
                            {buildStudentName(student)}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            {student.sex || "--"}
                          </td>
                          <td className="px-4 py-3">
                            {canEditRoster ? (
                              <select
                                value={student.sectionCode || ""}
                                onChange={(event) =>
                                  handleMoveStudent(
                                    student.studentId,
                                    event.target.value
                                  )
                                }
                                className="w-full min-w-44 rounded-xl border border-slate-300 px-3 py-2 text-sm outline-none focus:border-[#003366]"
                              >
                                <option value="">Unassigned</option>
                                {sectionSummaries.map((section) => (
                                  <option
                                    key={section.sectionCode}
                                    value={section.sectionCode}
                                  >
                                    {section.sectionName}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              <span className="text-sm text-slate-700">
                                {student.sectionName || selectedSection?.sectionName || "--"}
                              </span>
                            )}
                          </td>
                          {canEditRoster ? (
                            <td className="px-4 py-3">
                              <button
                                type="button"
                                onClick={() => handleStartRemoveStudent(student)}
                                className="rounded-lg border border-red-200 px-3 py-2 text-sm font-semibold text-red-600 hover:bg-red-50"
                              >
                                Remove
                              </button>
                            </td>
                          ) : null}
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td
                          colSpan={canEditRoster ? 5 : 4}
                          className="py-8 text-center text-slate-500"
                        >
                          {selectedSection
                            ? "No students found in this section."
                            : "Generate sections to view section rosters."}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            {canEditRoster ? (
            <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <h3 className="text-xl font-bold text-[#003366]">
                Add Student
              </h3>
              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
                <input
                  type="text"
                  value={lateStudent.studentId}
                  onChange={(event) =>
                    handleLateStudentChange("studentId", event.target.value)
                  }
                  placeholder="Student ID"
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                />
                <select
                  value={lateStudent.sex}
                  onChange={(event) =>
                    handleLateStudentChange("sex", event.target.value)
                  }
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                >
                  <option value="">Sex</option>
                  <option value="Male">Male</option>
                  <option value="Female">Female</option>
                </select>
                <input
                  type="text"
                  value={lateStudent.lastName}
                  onChange={(event) =>
                    handleLateStudentChange("lastName", event.target.value)
                  }
                  placeholder="Last name"
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                />
                <input
                  type="text"
                  value={lateStudent.firstName}
                  onChange={(event) =>
                    handleLateStudentChange("firstName", event.target.value)
                  }
                  placeholder="First name"
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                />
                <input
                  type="text"
                  value={lateStudent.middleName}
                  onChange={(event) =>
                    handleLateStudentChange("middleName", event.target.value)
                  }
                  placeholder="Middle name"
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                />
                <button
                  type="button"
                  onClick={handleAddLateStudent}
                  disabled={!sectionPlans.length}
                  className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d] disabled:cursor-not-allowed disabled:bg-slate-300"
                >
                  Add Student
                </button>
              </div>
            </section>
            ) : null}

            {canEditRoster ? (
            <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="mb-5">
                <h3 className="text-xl font-bold text-[#003366]">
                  Removed Students
                </h3>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead>
                    <tr className="bg-slate-800 text-white">
                      <th className="px-4 py-3 text-left text-sm">Student ID</th>
                      <th className="px-4 py-3 text-left text-sm">Name</th>
                      <th className="px-4 py-3 text-left text-sm">Previous Section</th>
                      <th className="px-4 py-3 text-left text-sm">Reason</th>
                      <th className="px-4 py-3 text-left text-sm">Removed At</th>
                      <th className="px-4 py-3 text-left text-sm">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {removedStudents.length > 0 ? (
                      removedStudents.map((student) => (
                        <tr key={`${student.studentId}-${student.removedAt}`} className="border-b bg-white">
                          <td className="px-4 py-3 font-semibold text-slate-800">
                            {student.studentId}
                          </td>
                          <td className="px-4 py-3 text-slate-700">
                            {buildStudentName(student)}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            {student.removedFromSectionName || "Unassigned"}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            <p>{student.removalReason || "--"}</p>
                            {student.removalNote ? (
                              <p className="mt-1 text-xs text-slate-500">
                                {student.removalNote}
                              </p>
                            ) : null}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            {student.removedAt
                              ? new Date(student.removedAt).toLocaleString("en-US")
                              : "--"}
                          </td>
                          <td className="px-4 py-3">
                            <button
                              type="button"
                              onClick={() => handleRestoreStudent(student.studentId)}
                              className="rounded-lg border border-[#003366] px-3 py-2 text-sm font-semibold text-[#003366] hover:bg-[#003366] hover:text-white"
                            >
                              Restore
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="6" className="py-8 text-center text-slate-500">
                          No students have been removed from this batch.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
            ) : null}
          </main>
      </div>
    </div>
  );
}

export default StudentSectioning;
