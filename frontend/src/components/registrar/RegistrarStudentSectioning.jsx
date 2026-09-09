import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AVAILABLE_YEAR_LEVELS,
  STUDENT_BATCHES_KEY,
  YEAR_LEVEL_PREFIXES,
  buildStudentCsvContent,
  downloadCsvFile,
  downloadStudentCsvFile,
  getDefaultSectionName,
  getGregorianCalendarYear,
  getNextStudentId,
  getStudentMiddleName,
  parseStudentIdSpreadsheet,
  syncSectionedStudentsToStorage,
} from "../../utils/studentSectioningHelpers";
import { downloadTemplateButtonClass } from "../shared/downloadButtonStyles";
import { fetchNextStudentId, fetchUnassignedEnrolledStudents } from "../../services/api";
import { syncSectioningBatchToBackend } from "../../utils/registrarSectioningBackendSync";
import { pushSectioningSharedState } from "../../utils/sharedClientState";

const buildStudentName = (student) => {
  if (student.fullName) return student.fullName;
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
const CURRENT_YEAR = getGregorianCalendarYear();

function RegistrarStudentSectioning({
  chairpersonDepartment,
  onSectioningSaved,
}) {
  const isRegistrarMode = true;
  const isChairpersonMode = false;
  const [batches, setBatches] = useState(() => {
    const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
    return saved ? JSON.parse(saved) : [];
  });
  const [activeWorkspace] = useState("sectioning");
  const [selectedBatchKey, setSelectedBatchKey] = useState("");
  const [sectioningBatchYear, setSectioningBatchYear] = useState(() =>
    String(new Date().getMonth() >= 5 ? CURRENT_YEAR : CURRENT_YEAR - 1)
  );
  const [sectioningSemester, setSectioningSemester] = useState(() => new Date().getMonth() >= 5 ? "FIRST" : "SECOND");
  const schoolYear = `${sectioningBatchYear}-${Number(sectioningBatchYear) + 1}`;
  const [enrolledCount, setEnrolledCount] = useState(0);
  const [enrolledLoading, setEnrolledLoading] = useState(true);
  const [enrolledError, setEnrolledError] = useState("");
  const [enrollmentRefresh, setEnrollmentRefresh] = useState(0);
  const [savingSections, setSavingSections] = useState(false);
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
  const [isBatchYearPickerOpen, setIsBatchYearPickerOpen] = useState(false);
  const [batchYearPickerAnchor, setBatchYearPickerAnchor] =
    useState(CURRENT_YEAR);
  const batchYearPickerRef = useRef(null);
  const rosterRef = useRef(null);
  const addStudentRef = useRef(null);
  const [selectedSectionCode, setSelectedSectionCode] = useState("");
  const [isRosterView, setIsRosterView] = useState(false);
  const [studentSearch, setStudentSearch] = useState("");
  const [pendingRemoval, setPendingRemoval] = useState(null);
  const [studentForm, setStudentForm] = useState({
    sex: "",
    lastName: "",
    firstName: "",
    middleName: "",
  });
  const [persistedSequences, setPersistedSequences] = useState({});
  const [studentIdLoading, setStudentIdLoading] = useState(false);
  const [studentIdError, setStudentIdError] = useState("");

  const syncBatchToBackend = async (batch, successMessage = "") => {
    if (!batch || !isRegistrarMode) return false;

    try {
      await syncSectioningBatchToBackend(batch);
      if (successMessage) alert(successMessage);
      return true;
    } catch (error) {
      alert(
        `Saved locally, but backend sync failed: ${error.message || "Please try saving again."}`
      );
      return false;
    }
  };

  const departmentWorkspaces = useMemo(
    () =>
      batches.filter(
        (batch) =>
          batch.program === chairpersonDepartment &&
          batch.schoolYear === schoolYear && batch.semester === sectioningSemester &&
          batch.status !== "Promoted"
      ),
    [batches, chairpersonDepartment, schoolYear, sectioningSemester]
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
    departmentWorkspaces[0] || null;
  const selectedBatch =
    departmentWorkspaces.find((batch) => batch.key === selectedBatchKey) ||
    (!selectedBatchKey ? fallbackSectioningWorkspace : null) ||
    null;
  const activeBatchKey = selectedBatchKey || selectedBatch?.key || "";
  const displayedBatchYear = selectedBatch?.batchYear || sectioningBatchYear;
  const studentIdYear = String(displayedBatchYear || "").match(/^\d{4}/)?.[0] || "";
  const hasPersistedSequence = Object.prototype.hasOwnProperty.call(
    persistedSequences,
    studentIdYear
  );
  const automaticStudentId = useMemo(
    () => hasPersistedSequence
      ? getNextStudentId(
          displayedBatchYear,
          batches,
          persistedSequences[studentIdYear]
        )
      : "",
    [batches, displayedBatchYear, hasPersistedSequence, persistedSequences, studentIdYear]
  );
  const studentIdLimitReached = hasPersistedSequence && !automaticStudentId;

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
    setIsRosterView(true);
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
  const batchYearOptions = useMemo(
    () =>
      Array.from({ length: 12 }, (_, index) =>
        String(batchYearPickerAnchor + index)
      ),
    [batchYearPickerAnchor]
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
    let cancelled = false;
    setEnrolledLoading(true);
    setEnrolledError("");
    setEnrolledCount(0);
    setSelectedBatchKey("");
    if (!chairpersonDepartment || !/^\d{4}$/.test(sectioningBatchYear)) {
      setEnrolledLoading(false);
      return;
    }
    fetchUnassignedEnrolledStudents({ department: chairpersonDepartment, schoolYear,
      semester: sectioningSemester, yearLevel: YEAR_LEVEL_PREFIXES[selectedYearLevel] })
      .then((response) => {
        if (cancelled) return;
        const enrolled = response.data || [];
        setEnrolledCount(enrolled.length);
        const key = [chairpersonDepartment, schoolYear, sectioningSemester, "sectioning"].join("|");
        setBatches((current) => {
          const existing = current.find((batch) => batch.key === key);
          if (!existing && !enrolled.length) return current;
          const retained = (existing?.students || []).filter((student) =>
            student.sectionCode || student.yearLevel !== selectedYearLevel);
          const retainedIds = new Set(retained.map((student) => student.studentId));
          const nextStudents = enrolled.filter((student) => !retainedIds.has(student.studentNo)).map((student) => ({
            ...student, studentId: student.studentNo,
            // Preserve the official full name; do not guess its component parts.
            firstName: student.fullName, lastName: "", middleName: "",
            yearLevel: AVAILABLE_YEAR_LEVELS[Number(student.yearLevel) - 1], sectionCode: "",
          }));
          const workspace = { id: Date.now(), status: "Sectioning", sectionPlans: [], removedStudents: [],
            ...existing, key, program: chairpersonDepartment, batchYear: sectioningBatchYear,
            schoolYear, semester: sectioningSemester, students: [...retained, ...nextStudents] };
          return [...current.filter((batch) => batch.key !== key), workspace];
        });
        setSelectedBatchKey(key);
      })
      .catch((error) => { if (!cancelled) setEnrolledError(error.message || "Could not load enrolled students."); })
      .finally(() => { if (!cancelled) setEnrolledLoading(false); });
    return () => { cancelled = true; };
  }, [chairpersonDepartment, schoolYear, sectioningBatchYear, sectioningSemester, selectedYearLevel, enrollmentRefresh]);

  useEffect(() => {
    if (!studentIdYear || Object.prototype.hasOwnProperty.call(persistedSequences, studentIdYear)) {
      return;
    }

    let cancelled = false;
    setStudentIdError("");
    setStudentIdLoading(true);
    fetchNextStudentId(studentIdYear)
      .then((response) => {
        if (cancelled) return;
        setPersistedSequences((current) => ({
          ...current,
          [studentIdYear]: Number(response?.highestSequence) || 0,
        }));
      })
      .catch((error) => {
        if (cancelled) return;
        console.warn("Could not load the persisted student ID sequence.", error);
        setStudentIdError("Automatic Student ID is unavailable. Please retry after the server connection is restored.");
      })
      .finally(() => {
        if (!cancelled) setStudentIdLoading(false);
      });

    return () => { cancelled = true; };
  }, [persistedSequences, studentIdYear]);

  useEffect(() => {
    const handleSharedStateChanged = (event) => {
      const keys = event.detail?.keys || [];
      if (!keys.includes(STUDENT_BATCHES_KEY)) return;

      try {
        const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
        setBatches(saved ? JSON.parse(saved) : []);
      } catch (error) {
        console.warn("Failed to refresh sectioning batches from shared state.", error);
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

  useEffect(() => {
    if (!isBatchYearPickerOpen) return;

    const handleOutsideClick = (event) => {
      if (batchYearPickerRef.current?.contains(event.target)) return;
      setIsBatchYearPickerOpen(false);
    };

    document.addEventListener("mousedown", handleOutsideClick);

    return () => {
      document.removeEventListener("mousedown", handleOutsideClick);
    };
  }, [isBatchYearPickerOpen]);

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

    setSelectedBatchKey("");
  };

  const openBatchYearPicker = () => {
    const resolvedYear = Math.max(
      Number(displayedBatchYear) || CURRENT_YEAR,
      CURRENT_YEAR
    );

    setBatchYearPickerAnchor(resolvedYear);
    setIsBatchYearPickerOpen(true);
  };

  const handleBatchYearSelect = (year) => {
    handleBatchYearChange(year);
    setIsBatchYearPickerOpen(false);
  };

  const handleGenerateSections = async () => {
    if (enrolledLoading || enrolledError || savingSections) return;
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
    const targetYearLevel = selectedYearLevel;
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
        schoolYear,
        semester: sectioningSemester,
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
    const existingStudents = baseWorkspace.students || [];
    const workspace = {
      ...baseWorkspace,
      students: existingStudents,
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

    const nextBatches = [
      ...batches.filter((batch) => batch.key !== workspaceKey),
      nextWorkspace,
    ];

    setSavingSections(true);
    try {
      await syncSectioningBatchToBackend(nextWorkspace);
    } catch (error) {
      alert(`Section assignment failed: ${error.message}`);
      setSavingSections(false);
      return;
    }
    setSavingSections(false);
    persistBatches(nextBatches);
    setEnrolledCount((count) => Math.max(0, count - studentsNeedingSection.length));
    setSelectedBatchKey(workspaceKey);
    setSectioningBatchYear(workspace.batchYear || sectioningBatchYear);
    setSelectedYearLevel(targetYearLevel);
    setSelectedSectionCode(mergedYearSections[0]?.sectionCode || "");

    if (!studentsForYear.length) {
      alert(
        `${missingSections.length || mergedYearSections.length} empty ${targetYearLevel} section${(missingSections.length || mergedYearSections.length) === 1 ? "" : "s"} created for ${workspace.program}.`
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
      `Delete ${sectionName}? This will remove the section and all students assigned to it.`
    );

    if (!confirmed) return;

    updateSelectedBatch((batch) => ({
      ...batch,
      sectionPlans: (batch.sectionPlans || []).filter(
        (plan) => plan.sectionCode !== sectionCode
      ),
      students: (batch.students || []).filter(
        (student) => student.sectionCode !== sectionCode
      ),
      removedStudents: (batch.removedStudents || []).filter(
        (student) => student.removedFromSectionCode !== sectionCode
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

  const handleStudentFormChange = (field, value) => {
    setStudentForm((current) => ({ ...current, [field]: value }));
  };

  const handleAddStudent = () => {
    if (!selectedBatch) return;

    const studentId = automaticStudentId;

    if (
      !studentId ||
      !studentForm.sex ||
      !studentForm.lastName.trim() ||
      !studentForm.firstName.trim() ||
      !studentForm.middleName.trim()
    ) {
      alert("Complete all student fields before adding the student.");
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
      sex: studentForm.sex,
      lastName: studentForm.lastName.trim(),
      firstName: studentForm.firstName.trim(),
      middleName: studentForm.middleName.trim(),
      middleInitial: studentForm.middleName.trim(),
      yearLevel: targetSection ? targetSection.yearLevel || selectedYearLevel : "",
      sectionCode: targetSection?.sectionCode || "",
      sectionName: targetSection
        ? targetSection.sectionName ||
          getDefaultSectionName(selectedBatch.program, targetSection.sectionCode)
        : "",
    };

    updateSelectedBatch((batch) => ({
      ...batch,
      students: [...(batch.students || []), nextStudent],
      lastSectionedAt: new Date().toISOString(),
    }));

    setStudentForm({
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

  const handleDownloadSectionTemplate = () => {
    const templateRows = [
      {
        studentId: "2026-0001",
        sex: "Male",
        lastName: "Dela Cruz",
        firstName: "Juan",
        middleName: "Santos",
        middleInitial: "Santos",
        yearLevel: selectedYearLevel,
      },
    ];
    const fileName = `${chairpersonDepartment || "student"}-${selectedYearLevel.replace(/\s+/g, "-").toLowerCase()}-section-template.csv`;

    downloadCsvFile(buildStudentCsvContent(templateRows), fileName);
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
        const updatedBatch = nextBatches.find((batch) => batch.key === selectedBatch.key);
        syncBatchToBackend(updatedBatch);
        setSelectedSectionCode(section.sectionCode);
        alert(
          `${importedStudents.length} student${importedStudents.length === 1 ? "" : "s"} imported into ${sectionName}.`
        );
      };

      reader.readAsText(file);
    };

    input.click();
  };

  const handleSaveSectioning = async () => {
    if (savingSections) return;
    const nextBatches = batches.map((batch) =>
      batch.key === activeBatchKey && (batch.sectionPlans || []).length > 0
        ? {
            ...batch,
            lastSectionedAt: new Date().toISOString(),
          }
        : batch
    );

    const batchToSync = nextBatches.find((batch) => batch.key === activeBatchKey);
    setSavingSections(true);
    const synced = await syncBatchToBackend(batchToSync);
    setSavingSections(false);
    if (synced) {
      persistBatches(nextBatches);
      alert("Sections saved and synced successfully.");
    }
  };

  const handleShuffleSections = () => {
    if (!selectedBatch || yearSectionPlans.length < 2) {
      alert("At least two saved sections are needed before shuffling students.");
      return;
    }

    const studentsForYear = students.filter(
      (student) => (student.yearLevel || selectedYearLevel) === selectedYearLevel
    );

    if (studentsForYear.length < 2) {
      alert("At least two students are needed before shuffling.");
      return;
    }

    const shuffledStudents = [...studentsForYear].sort(() => Math.random() - 0.5);
    const assignedStudentsById = new Map(
      shuffledStudents.map((student, index) => {
        const targetSection = yearSectionPlans[index % yearSectionPlans.length];
        const sectionName =
          targetSection.sectionName ||
          getDefaultSectionName(selectedBatch.program, targetSection.sectionCode);

        return [
          student.studentId,
          {
            ...student,
            yearLevel: targetSection.yearLevel || selectedYearLevel,
            sectionCode: targetSection.sectionCode,
            sectionName,
          },
        ];
      })
    );

    updateSelectedBatch((batch) => ({
      ...batch,
      students: (batch.students || []).map(
        (student) => assignedStudentsById.get(student.studentId) || student
      ),
      lastSectionedAt: new Date().toISOString(),
    }));

    alert(`${selectedYearLevel} students shuffled successfully.`);
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

      <div className="space-y-3">
        <main className="space-y-3">
          {!isRosterView ? (
            <>
          {isRegistrarMode ? (
            <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
              <div>
                <h3 className="text-sm font-bold text-[#003366]">
                  Section Generator
                </h3>
              </div>

              <div className="mt-3 flex flex-wrap items-end gap-3">
                <label className="text-xs font-medium text-slate-700">Enrollment semester
                  <select aria-label="Enrollment semester" value={sectioningSemester}
                    onChange={(event) => { setSectioningSemester(event.target.value); setSelectedBatchKey(""); }}
                    className="ml-2 rounded-md border border-slate-300 px-2 py-2">
                    <option value="FIRST">First Semester</option>
                    <option value="SECOND">Second Semester</option>
                    <option value="MIDYEAR">Midyear</option>
                  </select>
                </label>
                <button type="button" disabled={enrolledLoading || savingSections}
                  onClick={() => setEnrollmentRefresh((value) => value + 1)}
                  className="rounded-md border border-blue-200 px-3 py-2 text-xs font-semibold text-blue-700 disabled:opacity-50">
                  {enrolledLoading ? "Loading enrolled students..." : `Auto-Populate Enrolled (${enrolledCount})`}
                </button>
                <span className="text-xs text-slate-600">School year {schoolYear}. Enrolled students load automatically; no upload is needed.</span>
              </div>
              {enrolledError ? <p role="alert" className="mt-2 text-sm text-red-700">{enrolledError}</p> : null}

              <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-3 xl:grid-cols-[135px_135px_135px_auto_auto_auto_auto] xl:items-end">
                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-slate-700">
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
                    className="h-8 w-full rounded-md border border-slate-300 bg-white px-2 text-[11px] outline-none focus:border-[#003366]"
                  >
                    {AVAILABLE_YEAR_LEVELS.map((yearLevel) => (
                      <option key={yearLevel} value={yearLevel}>
                        {yearLevel}
                      </option>
                    ))}
                  </select>
                </label>

                <div className="block">
                  <span className="mb-1 block text-xs font-medium text-slate-700">
                    School year starting
                  </span>
                  <div ref={batchYearPickerRef} className="relative">
                    <input
                      type="text"
                      inputMode="numeric"
                      value={displayedBatchYear}
                      onFocus={openBatchYearPicker}
                      onClick={openBatchYearPicker}
                      onChange={(event) => handleBatchYearChange(event.target.value)}
                      className="h-8 w-full rounded-md border border-slate-300 bg-white px-2 text-[11px] outline-none focus:border-[#003366]"
                      placeholder="Select Year"
                    />

                    {isBatchYearPickerOpen ? (
                      <div className="absolute left-0 top-[calc(100%+8px)] z-20 w-full min-w-[240px] rounded-2xl border border-slate-200 bg-white shadow-xl">
                        <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
                          <button
                            type="button"
                            onClick={() =>
                              setBatchYearPickerAnchor((current) =>
                                Math.max(current - 12, CURRENT_YEAR)
                              )
                            }
                            disabled={batchYearPickerAnchor <= CURRENT_YEAR}
                            className="text-xl font-light text-slate-500 transition hover:text-[#003366] disabled:cursor-not-allowed disabled:text-slate-300"
                          >
                            {"<"}
                          </button>

                          <p className="text-sm font-semibold text-slate-700">
                            {batchYearPickerAnchor}
                          </p>

                          <button
                            type="button"
                            onClick={() =>
                              setBatchYearPickerAnchor((current) => current + 12)
                            }
                            className="text-xl font-light text-slate-500 transition hover:text-[#003366]"
                          >
                            {">"}
                          </button>
                        </div>

                        <div className="grid grid-cols-3 gap-1.5 p-3">
                          {batchYearOptions.map((year) => {
                            const isSelected = displayedBatchYear === year;

                            return (
                              <button
                                key={year}
                                type="button"
                                onClick={() => handleBatchYearSelect(year)}
                                className={`rounded-xl px-2 py-2 text-sm transition ${
                                  isSelected
                                    ? "bg-rose-50 text-rose-500"
                                    : "text-slate-700 hover:bg-slate-100"
                                }`}
                              >
                                {year}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>

                <label className="block">
                  <span className="mb-1 block text-xs font-medium text-slate-700">
                    Number of sections
                  </span>
                  <input
                    type="number"
                    min="1"
                    value={manualSectionCount}
                    onChange={(event) => setManualSectionCount(event.target.value)}
                    className="h-8 w-full rounded-md border border-slate-300 px-2 text-[11px] outline-none focus:border-[#003366]"
                  />
                </label>

                <button
                  type="button"
                  onClick={handleGenerateSections}
                  disabled={enrolledLoading || !!enrolledError || savingSections}
                  className="h-8 whitespace-nowrap rounded-md bg-[#003366] px-3 text-[11px] font-semibold text-white transition hover:bg-[#00264d]"
                >
                  Generate Sections
                </button>
                <button
                  type="button"
                  onClick={handleShuffleSections}
                  disabled={!selectedBatch || yearSectionPlans.length < 2}
                  className="h-8 whitespace-nowrap rounded-md border border-blue-200 px-3 text-[11px] font-semibold text-blue-700 transition hover:bg-blue-50 disabled:cursor-not-allowed disabled:border-slate-300 disabled:text-slate-400"
                >
                  Shuffle Students
                </button>
                <button
                  type="button"
                  onClick={handleDownloadSectionTemplate}
                  className={downloadTemplateButtonClass}
                >
                  Download Template
                </button>
                <button
                  type="button"
                  onClick={handleSaveSectioning}
                  disabled={!selectedBatch || !sectionPlans.length || savingSections}
                  className="h-8 whitespace-nowrap rounded-md border border-[#003366] px-3 text-[11px] font-semibold text-[#003366] transition hover:bg-[#003366] hover:text-white disabled:cursor-not-allowed disabled:border-slate-300 disabled:text-slate-400"
                >
                  Save Sections
                </button>
              </div>

            </section>
          ) : null}

            <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm">
              <div className="mb-3 flex flex-col gap-2 border-b border-slate-200 md:flex-row md:items-center md:justify-between">
                <div>
                  <h3 className="border-b-2 border-blue-700 px-2 pb-3 text-xs font-semibold text-blue-700">
                    All Sections <span className="ml-1 rounded-full bg-blue-50 px-2 py-0.5">{sectionSummaries.length}</span>
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
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
                  {sectionSummaries.map((section) => (
                    <article
                      key={section.sectionCode}
                      className={`rounded-md border p-2.5 transition ${
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
                          <p className="text-sm font-bold text-[#003366]">
                            {section.sectionName}
                          </p>
                          <p className="mt-1 text-[10px] text-slate-500">
                            Section {section.sectionCode} &nbsp;•&nbsp; Batch {displayedBatchYear} &nbsp;•&nbsp; {selectedYearLevel}
                          </p>
                        </button>

                        <span className="whitespace-nowrap rounded-full bg-emerald-50 px-2 py-1 text-[10px] font-semibold text-emerald-600">
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
                          className="mt-2 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-[11px] outline-none focus:border-[#003366]"
                          aria-label={`Edit ${section.sectionCode} section name`}
                        />
                      ) : null}

                      <div className="mt-2 flex flex-wrap gap-1.5 border-t border-slate-100 pt-2">
                        <button
                          type="button"
                          onClick={() => viewSectionRoster(section.sectionCode)}
                          className="rounded-md border border-blue-100 px-3 py-1.5 text-[10px] font-semibold text-blue-700 hover:bg-blue-50"
                        >
                          View Roster
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDownloadSectionCsv(section.sectionCode)}
                          className="rounded-md border border-blue-100 px-3 py-1.5 text-[10px] font-semibold text-blue-700 hover:bg-blue-50"
                        >
                          Export CSV
                        </button>
                        <button
                          type="button"
                          onClick={() => handleImportSectionCsv(section.sectionCode)}
                          className="rounded-md border border-emerald-200 px-3 py-1.5 text-[10px] font-semibold text-emerald-700 hover:bg-emerald-50"
                        >
                          Upload CSV
                        </button>
                        {isRegistrarMode ? (
                          <button
                            type="button"
                            onClick={() => handleDeleteSection(section.sectionCode)}
                            className="rounded-md border border-red-200 px-3 py-1.5 text-[10px] font-semibold text-red-600 hover:bg-red-50"
                          >
                            Delete Section
                          </button>
                        ) : null}
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-5 text-center text-xs text-slate-500">
                  {isRegistrarMode
                    ? "Generate sections to preview students by section."
                    : "No registrar-created sections are available yet."}
                </div>
              )}
            </section>
            </>
          ) : null}

            {isRosterView ? (
            <section ref={rosterRef} className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="mb-5 flex flex-col gap-4 border-b border-slate-200 pb-5 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex items-center gap-4">
                  <span className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-blue-50 text-blue-700">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" className="h-7 w-7"><circle cx="9" cy="8" r="3"/><circle cx="17" cy="10" r="2"/><path d="M3 20v-2a6 6 0 0 1 12 0v2m0-5a4 4 0 0 1 6 3v2"/></svg>
                  </span>
                  <div>
                    <button type="button" onClick={() => setIsRosterView(false)} className="mb-2 text-xs font-medium text-blue-700 hover:underline">Department Sections &nbsp;›</button>
                    <h3 className="text-2xl font-bold text-[#003366]">
                    {selectedSection
                      ? selectedSection.sectionName ||
                        getDefaultSectionName(
                          selectedBatch.program,
                          selectedSection.sectionCode
                        )
                      : "Section Students"}
                    </h3>
                    <p className="mt-1 text-xs text-slate-500">{chairpersonDepartment} &nbsp;•&nbsp; Batch {displayedBatchYear} &nbsp;•&nbsp; {selectedYearLevel} &nbsp; <span className="rounded-full bg-emerald-50 px-2 py-1 font-semibold text-emerald-700">{visibleSectionStudents.length} Students</span></p>
                  </div>
                </div>

                <button type="button" onClick={() => setIsRosterView(false)} className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-300 px-4 py-2.5 text-sm font-semibold text-[#003366] hover:bg-slate-50">
                  <span aria-hidden="true">←</span> Back to Department Sections
                </button>
              </div>

              <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center">
                <input
                    type="text"
                    value={studentSearch}
                    onChange={(event) => setStudentSearch(event.target.value)}
                    placeholder="Search by ID or name..."
                    className="w-full rounded-lg border border-slate-300 px-4 py-2.5 text-sm outline-none focus:border-[#003366] lg:max-w-sm"
                  />
                {isRegistrarMode ? (
                  <button
                    type="button"
                    onClick={() => addStudentRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })}
                    className="inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg bg-[#003366] px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#00264d]"
                  >
                    <span className="text-lg leading-none">+</span> Add Student
                  </button>
                ) : null}
                <button type="button" onClick={() => handleDownloadSectionCsv(selectedSection?.sectionCode)} className="rounded-lg border border-blue-200 px-4 py-2.5 text-sm font-semibold text-blue-700 hover:bg-blue-50">Export CSV</button>
                {isRegistrarMode ? <button type="button" onClick={() => handleImportSectionCsv(selectedSection?.sectionCode)} className="rounded-lg border border-blue-200 px-4 py-2.5 text-sm font-semibold text-blue-700 hover:bg-blue-50">Upload CSV</button> : null}
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
                      <th className="px-4 py-3 text-left text-sm">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleSectionStudents.length > 0 ? (
                      visibleSectionStudents.map((student) => (
                        <tr key={student.studentId} className="border-b bg-white">
                          <td className="px-4 py-3 font-semibold text-slate-800">
                            {student.studentId}
                          </td>
                          <td className="px-4 py-3 text-slate-700">
                            {buildStudentName(student)}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            {student.sex || "--"}
                          </td>
                          <td className="px-4 py-3">
                            <select
                              value={student.sectionCode || ""}
                              onChange={(event) =>
                                isRegistrarMode
                                  ? handleMoveStudent(
                                      student.studentId,
                                      event.target.value
                                    )
                                  : undefined
                              }
                              disabled={!isRegistrarMode}
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
                          </td>
                          <td className="px-4 py-3">
                            {isRegistrarMode ? (
                              <button
                                type="button"
                                onClick={() => handleStartRemoveStudent(student)}
                                className="rounded-lg border border-red-200 px-3 py-2 text-sm font-semibold text-red-600 hover:bg-red-50"
                              >
                                Remove
                              </button>
                            ) : (
                              <span className="text-sm text-slate-400">Preview</span>
                            )}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="5" className="py-8 text-center text-slate-500">
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
            ) : null}

            {isRegistrarMode ? (
            <section ref={addStudentRef} className="scroll-mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
              <h3 className="text-xl font-bold text-[#003366]">
                Add Student
              </h3>
              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
                <input
                  type="text"
                  value={automaticStudentId}
                  readOnly
                  aria-label="Student ID (automatic)"
                  title="Student ID is assigned automatically from the batch year"
                  placeholder={studentIdLoading
                    ? "Loading Student ID…"
                    : studentIdError || (studentIdLimitReached
                        ? `${studentIdYear}-year ID limit (9999) reached`
                        : "Select a valid batch year")}
                  className="cursor-not-allowed rounded-xl border border-slate-300 bg-slate-100 px-4 py-3 text-sm text-slate-700 outline-none"
                />
                <select
                  value={studentForm.sex}
                  onChange={(event) =>
                    handleStudentFormChange("sex", event.target.value)
                  }
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                >
                  <option value="">Sex</option>
                  <option value="Male">Male</option>
                  <option value="Female">Female</option>
                </select>
                <input
                  type="text"
                  value={studentForm.lastName}
                  onChange={(event) =>
                    handleStudentFormChange("lastName", event.target.value)
                  }
                  placeholder="Last name"
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                />
                <input
                  type="text"
                  value={studentForm.firstName}
                  onChange={(event) =>
                    handleStudentFormChange("firstName", event.target.value)
                  }
                  placeholder="First name"
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                />
                <input
                  type="text"
                  value={studentForm.middleName}
                  onChange={(event) =>
                    handleStudentFormChange("middleName", event.target.value)
                  }
                  placeholder="Middle name"
                  className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                />
                <button
                  type="button"
                  onClick={handleAddStudent}
                  disabled={!sectionPlans.length || studentIdLoading || !automaticStudentId}
                  className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d] disabled:cursor-not-allowed disabled:bg-slate-300"
                >
                  Add Student
                </button>
              </div>
            </section>
            ) : null}

            {isRegistrarMode ? (
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

export default RegistrarStudentSectioning;
