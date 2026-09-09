import React, { useEffect, useMemo, useState } from "react";
import {
  AVAILABLE_YEAR_LEVELS,
  STUDENT_BATCHES_KEY,
  YEAR_LEVEL_PREFIXES,
  downloadStudentCsvFile,
  getDefaultSectionName,
  getNextStudentId,
  getStudentMiddleName,
  parseStudentIdSpreadsheet,
  syncSectionedStudentsToStorage,
} from "../../utils/studentSectioningHelpers";
import { syncSectioningBatchesToBackend } from "../../utils/registrarSectioningBackendSync";
import { pushSectioningSharedState } from "../../utils/sharedClientState";
import { fetchNextStudentId } from "../../services/api";

const GRADUATING_STUDENTS_KEY = "graduatingStudents";
const IRREGULAR_SUBJECTS_KEY = "irregularSubjectAssignments";
const TARGET_SEMESTER = "1st Semester";
const REMOVAL_REASONS = [
  "Duplicate student record",
  "Wrong program",
  "Not in final enrolled list",
  "Encoding error",
  "Other",
];

const getStoredArray = (key) => {
  const saved = localStorage.getItem(key);
  return saved ? JSON.parse(saved) : [];
};

const buildStudentName = (student) => {
  const firstAndMiddle = [
    student.firstName,
    getStudentMiddleName(student),
  ]
    .filter(Boolean)
    .join(" ");

  return [student.lastName, firstAndMiddle].filter(Boolean).join(", ");
};

const sectionMatchesYearLevel = (section = {}, yearLevel = "1st Year") => {
  const yearPrefix = YEAR_LEVEL_PREFIXES[yearLevel] || "";

  if (section.yearLevel) return section.yearLevel === yearLevel;
  return !!yearPrefix && section.sectionCode?.startsWith(`${yearPrefix}-`);
};

const getSectionYearLevel = (section = {}) => {
  if (section.yearLevel) return section.yearLevel;
  return (
    Object.entries(YEAR_LEVEL_PREFIXES).find(([, prefix]) =>
      section.sectionCode?.startsWith(`${prefix}-`)
    )?.[0] || "1st Year"
  );
};

const getNextYearLevel = (yearLevel = "") =>
  ({
    "1st Year": "2nd Year",
    "2nd Year": "3rd Year",
    "3rd Year": "4th Year",
  })[yearLevel] || "";

const getNextSectionCode = (sectionCode = "", nextYearLevel = "") => {
  const nextPrefix = YEAR_LEVEL_PREFIXES[nextYearLevel];
  const sectionNumber = String(sectionCode).split("-")[1];
  return nextPrefix && sectionNumber ? `${nextPrefix}-${sectionNumber}` : "";
};

const getCurrentRolloverBatches = (batches = []) => {
  const latestByProgramYear = {};

  batches
    .filter(
      (batch) =>
        batch.status !== "Promoted" &&
        (batch.students || []).length > 0 &&
        (batch.sectionPlans || []).length > 0
    )
    .forEach((batch) => {
      const key = [batch.program, batch.batchYear].join("|");
      const current = latestByProgramYear[key];
      const batchTime = new Date(batch.lastSectionedAt || batch.submittedAt || 0).getTime();
      const currentTime = new Date(
        current?.lastSectionedAt || current?.submittedAt || 0
      ).getTime();

      if (!current || batchTime > currentTime) {
        latestByProgramYear[key] = batch;
      }
    });

  return Object.values(latestByProgramYear);
};

function RegistrarSectionsCreated() {
  const [batches, setBatches] = useState(() => getStoredArray(STUDENT_BATCHES_KEY));
  const [graduatingStudents, setGraduatingStudents] = useState(() =>
    getStoredArray(GRADUATING_STUDENTS_KEY)
  );
  const [irregularAssignments, setIrregularAssignments] = useState(() =>
    getStoredArray(IRREGULAR_SUBJECTS_KEY)
  );
  const [activeDepartment, setActiveDepartment] = useState("");
  const [activeYearLevel, setActiveYearLevel] = useState("1st Year");
  const [selectedBatchKey, setSelectedBatchKey] = useState("");
  const [selectedSectionCode, setSelectedSectionCode] = useState("");
  const [showRoster, setShowRoster] = useState(false);
  const [sectionSearch, setSectionSearch] = useState("");
  const [overviewYear, setOverviewYear] = useState("All");
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
  const [changedDepartments, setChangedDepartments] = useState(() => new Set());

  const persistBatches = (nextBatches) => {
    setBatches(nextBatches);
    localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(nextBatches));
    syncSectionedStudentsToStorage(nextBatches);
    pushSectioningSharedState();
  };

  useEffect(() => {
    const handleSharedStateChanged = (event) => {
      const keys = event.detail?.keys || [];
      if (!keys.includes(STUDENT_BATCHES_KEY)) return;

      try {
        const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
        setBatches(saved ? JSON.parse(saved) : []);
      } catch (error) {
        console.warn("Failed to refresh created sections from shared state.", error);
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

  const markDepartmentChanged = (department) => {
    if (!department) return;
    setChangedDepartments((current) => {
      const nextDepartments = new Set(current);
      nextDepartments.add(department);
      return nextDepartments;
    });
  };

  const handleApplyDepartmentChanges = async () => {
    if (!selectedDepartment) return;

    localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(batches));
    syncSectionedStudentsToStorage(batches);
    pushSectioningSharedState();
    try {
      await syncSectioningBatchesToBackend(
        batches.filter((batch) => batch.program === selectedDepartment)
      );
      setChangedDepartments((current) => {
        const nextDepartments = new Set(current);
        nextDepartments.delete(selectedDepartment);
        return nextDepartments;
      });
      alert(`${selectedDepartment} section changes applied and synced.`);
    } catch (error) {
      alert(
        `Changes were saved locally, but backend sync failed: ${error.message || "Please try applying again."}`
      );
    }
  };

  const sectionedBatches = useMemo(
    () =>
      batches.filter(
        (batch) =>
          (batch.sectionPlans || []).length > 0 &&
          batch.status !== "Promoted"
      ),
    [batches]
  );

  const departments = useMemo(
    () => [...new Set(sectionedBatches.map((batch) => batch.program))].sort(),
    [sectionedBatches]
  );

  const selectedDepartment = activeDepartment || departments[0] || "";
  const departmentBatches = sectionedBatches.filter(
    (batch) => batch.program === selectedDepartment
  );
  const selectedBatch =
    departmentBatches.find((batch) => batch.key === selectedBatchKey) ||
    departmentBatches.find((batch) =>
      (batch.sectionPlans || []).some((section) =>
        sectionMatchesYearLevel(section, activeYearLevel)
      )
    ) ||
    departmentBatches[0] ||
    null;
  const studentIdYear = String(selectedBatch?.batchYear || "").match(/^\d{4}/)?.[0] || "";
  const hasPersistedSequence = Object.prototype.hasOwnProperty.call(
    persistedSequences,
    studentIdYear
  );
  const automaticStudentId = useMemo(
    () => hasPersistedSequence
      ? getNextStudentId(
          selectedBatch?.batchYear,
          batches,
          persistedSequences[studentIdYear]
        )
      : "",
    [batches, hasPersistedSequence, persistedSequences, selectedBatch?.batchYear, studentIdYear]
  );
  const studentIdLimitReached = hasPersistedSequence && !automaticStudentId;

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
  const yearSections = (selectedBatch?.sectionPlans || []).filter((section) =>
    sectionMatchesYearLevel(section, activeYearLevel)
  );
  const selectedSection =
    yearSections.find((section) => section.sectionCode === selectedSectionCode) ||
    yearSections[0] ||
    null;
  const sectionStudents = selectedSection
    ? (selectedBatch?.students || [])
        .filter(
          (student) =>
            student.sectionCode === selectedSection.sectionCode &&
            (student.yearLevel || activeYearLevel) === activeYearLevel
        )
        .sort((left, right) => buildStudentName(left).localeCompare(buildStudentName(right)))
    : [];
  const removedStudents = (selectedBatch?.removedStudents || []).filter(
    (student) =>
      !activeYearLevel ||
      student.yearLevel === activeYearLevel ||
      student.removedFromSectionCode?.startsWith(
        `${YEAR_LEVEL_PREFIXES[activeYearLevel]}-`
      )
  );
  const activeYearSectionCount = departmentBatches.reduce(
    (total, batch) =>
      total +
      (batch.sectionPlans || []).filter((section) =>
        sectionMatchesYearLevel(section, activeYearLevel)
      ).length,
    0
  );
  const hasActiveDepartmentChanges = changedDepartments.has(selectedDepartment);
  const overviewSections = departmentBatches.flatMap((batch) =>
    (batch.sectionPlans || [])
      .filter(
        (section) =>
          overviewYear === "All" || sectionMatchesYearLevel(section, overviewYear)
      )
      .map((section) => {
        const yearLevel = getSectionYearLevel(section);
        const sectionName =
          section.sectionName || getDefaultSectionName(batch.program, section.sectionCode);
        const studentCount = (batch.students || []).filter(
          (student) =>
            student.sectionCode === section.sectionCode &&
            (student.yearLevel || yearLevel) === yearLevel
        ).length;
        return { batch, section, yearLevel, sectionName, studentCount };
      })
  ).filter(({ section, sectionName }) => {
    const query = sectionSearch.trim().toLowerCase();
    return !query || sectionName.toLowerCase().includes(query) || String(section.sectionCode).toLowerCase().includes(query);
  });

  const updateSelectedBatch = (updater) => {
    if (!selectedBatch) return;
    persistBatches(
      batches.map((batch) => (batch.key === selectedBatch.key ? updater(batch) : batch))
    );
    markDepartmentChanged(selectedBatch.program);
  };

  const handleMoveStudent = (studentId, sectionCode) => {
    const targetSection = (selectedBatch?.sectionPlans || []).find(
      (section) => section.sectionCode === sectionCode
    );

    updateSelectedBatch((batch) => ({
      ...batch,
      students: (batch.students || []).map((student) =>
        student.studentId === studentId
          ? {
              ...student,
              yearLevel: targetSection?.yearLevel || activeYearLevel,
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

  const handleDeleteSection = () => {
    if (!selectedBatch || !selectedSection) return;

    const sectionName =
      selectedSection.sectionName ||
      getDefaultSectionName(selectedBatch.program, selectedSection.sectionCode);
    const confirmed = window.confirm(
      `Delete ${sectionName}? This will remove the section and all students assigned to it.`
    );

    if (!confirmed) return;

    updateSelectedBatch((batch) => ({
      ...batch,
      sectionPlans: (batch.sectionPlans || []).filter(
        (section) => section.sectionCode !== selectedSection.sectionCode
      ),
      students: (batch.students || []).filter(
        (student) => student.sectionCode !== selectedSection.sectionCode
      ),
      removedStudents: (batch.removedStudents || []).filter(
        (student) =>
          student.removedFromSectionCode !== selectedSection.sectionCode
      ),
      lastSectionedAt: new Date().toISOString(),
    }));
    setSelectedSectionCode("");
    setPendingRemoval(null);
  };

  const handleExportSectionCsv = () => {
    if (!selectedBatch || !selectedSection) return;

    const sectionName =
      selectedSection.sectionName ||
      getDefaultSectionName(selectedBatch.program, selectedSection.sectionCode);

    if (!sectionStudents.length) {
      alert("No students are assigned to this section yet.");
      return;
    }

    downloadStudentCsvFile(
      sectionStudents,
      `${sectionName}-${selectedBatch.batchYear}.csv`
    );
  };

  const handleImportSectionCsv = () => {
    if (!selectedBatch || !selectedSection) return;

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

        const sectionYearLevel = selectedSection.yearLevel || activeYearLevel;
        const sectionName =
          selectedSection.sectionName ||
          getDefaultSectionName(selectedBatch.program, selectedSection.sectionCode);
        const existingSectionCount = (selectedBatch.students || []).filter(
          (student) =>
            student.sectionCode === selectedSection.sectionCode &&
            (student.yearLevel || sectionYearLevel) === sectionYearLevel
        ).length;
        const confirmed =
          existingSectionCount === 0 ||
          window.confirm(
            `Replace ${existingSectionCount} existing student${existingSectionCount === 1 ? "" : "s"} in ${sectionName}?`
          );

        if (!confirmed) return;

        const importedStudentIds = new Set(
          parsedStudents.map((student) => student.studentId.toLowerCase())
        );
        const importedStudents = parsedStudents.map((student) => ({
          ...student,
          yearLevel: sectionYearLevel,
          sectionCode: selectedSection.sectionCode,
          sectionName,
        }));

        updateSelectedBatch((batch) => ({
          ...batch,
          students: [
            ...(batch.students || []).filter((student) => {
              const sameTargetSection =
                student.sectionCode === selectedSection.sectionCode &&
                (student.yearLevel || sectionYearLevel) === sectionYearLevel;
              const duplicateImportedStudent = importedStudentIds.has(
                String(student.studentId || "").toLowerCase()
              );

              return !sameTargetSection && !duplicateImportedStudent;
            }),
            ...importedStudents,
          ],
          lastSectionedAt: new Date().toISOString(),
        }));
        alert(
          `${importedStudents.length} student${importedStudents.length === 1 ? "" : "s"} imported into ${sectionName}.`
        );
      };

      reader.readAsText(file);
    };

    input.click();
  };

  const handleConfirmRemoveStudent = () => {
    if (!pendingRemoval?.reason) {
      alert("Please choose a removal reason.");
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

      const restoredSectionExists = (batch.sectionPlans || []).some(
        (section) => section.sectionCode === removedStudent.removedFromSectionCode
      );

      return {
        ...batch,
        students: [
          ...(batch.students || []),
          {
            studentId: removedStudent.studentId,
            sex: removedStudent.sex || "",
            lastName: removedStudent.lastName || "",
            firstName: removedStudent.firstName || "",
            middleName: getStudentMiddleName(removedStudent),
            middleInitial: removedStudent.middleInitial || getStudentMiddleName(removedStudent),
            yearLevel: restoredSectionExists
              ? removedStudent.yearLevel || activeYearLevel
              : activeYearLevel,
            sectionCode: restoredSectionExists
              ? removedStudent.removedFromSectionCode
              : selectedSection?.sectionCode || "",
            sectionName: restoredSectionExists
              ? removedStudent.removedFromSectionName
              : selectedSection?.sectionName || "",
          },
        ],
        removedStudents: (batch.removedStudents || []).filter(
          (student) => student.studentId !== studentId
        ),
        lastSectionedAt: new Date().toISOString(),
      };
    });
  };

  const handleAddStudent = () => {
    if (!selectedBatch || !selectedSection) return;
    const studentId = automaticStudentId;

    if (
      !studentId ||
      !studentForm.sex ||
      !studentForm.lastName.trim() ||
      !studentForm.firstName.trim() ||
      !studentForm.middleName.trim()
    ) {
      alert("Complete all student fields before adding.");
      return;
    }

    const duplicate = (selectedBatch.students || []).some(
      (student) => student.studentId.toLowerCase() === studentId.toLowerCase()
    );
    if (duplicate) {
      alert("This student ID already exists in the roster.");
      return;
    }

    updateSelectedBatch((batch) => ({
      ...batch,
      students: [
        ...(batch.students || []),
        {
          studentId,
          sex: studentForm.sex,
          lastName: studentForm.lastName.trim(),
          firstName: studentForm.firstName.trim(),
          middleName: studentForm.middleName.trim(),
          middleInitial: studentForm.middleName.trim(),
          yearLevel: selectedSection.yearLevel || activeYearLevel,
          sectionCode: selectedSection.sectionCode,
          sectionName:
            selectedSection.sectionName ||
            getDefaultSectionName(batch.program, selectedSection.sectionCode),
        },
      ],
      lastSectionedAt: new Date().toISOString(),
    }));
    setStudentForm({
      sex: "",
      lastName: "",
      firstName: "",
      middleName: "",
    });
  };

  const handlePromoteStudents = () => {
    const rolloverBatches = getCurrentRolloverBatches(batches);
    if (!rolloverBatches.length) {
      alert("No saved section lists are ready for promotion.");
      return;
    }

    const confirmed = window.confirm(
      "Advance all sections across departments to the next academic year?"
    );
    if (!confirmed) return;

    const allPromotedStudents = [];
    const allGraduatingReviewList = [];
    const targetBatches = [];

    rolloverBatches.forEach((sourceBatch) => {
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
            targetSemester: TARGET_SEMESTER,
            status: "Incomplete",
            studentType: student.studentType || "Regular",
            irregularSubjects: student.irregularSubjects || [],
            reviewedAt: "",
          });
          return;
        }

        const nextSectionCode = getNextSectionCode(currentSectionCode, nextYearLevel);
        const nextSectionName = nextSectionCode
          ? getDefaultSectionName(sourceBatch.program, nextSectionCode)
          : "";

        if (nextSectionCode && !promotedSectionsByCode.has(nextSectionCode)) {
          promotedSectionsByCode.set(nextSectionCode, {
            id: `${sourceBatch.batchYear}-${TARGET_SEMESTER}-${nextSectionCode}`,
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
          semester: TARGET_SEMESTER,
          originBatchYear: sourceBatch.batchYear,
          promotedFromBatchKey: sourceBatch.key,
          promotedAt: new Date().toISOString(),
        });
      });

      allPromotedStudents.push(...promotedStudents);
      allGraduatingReviewList.push(...graduatingReviewList);
      if (!promotedStudents.length) return;

      const createdAt = new Date().toISOString();
      targetBatches.push({
        id: Number(`${createdAt.replace(/\D/g, "").slice(0, 13)}${targetBatches.length}`),
        key: [sourceBatch.program, sourceBatch.batchYear, TARGET_SEMESTER, "promotion"].join("|"),
        program: sourceBatch.program,
        batchYear: sourceBatch.batchYear,
        semester: TARGET_SEMESTER,
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

    const targetBatchKeys = new Set(targetBatches.map((batch) => batch.key));
    const sourceBatchKeys = new Set(rolloverBatches.map((batch) => batch.key));
    const promotedToBySourceKey = Object.fromEntries(
      targetBatches.map((batch) => [batch.promotedFromBatchKey, batch.key])
    );
    const nextBatches = [
      ...batches.filter(
        (batch) => !targetBatchKeys.has(batch.key) && !sourceBatchKeys.has(batch.key)
      ),
      ...batches
        .filter((batch) => sourceBatchKeys.has(batch.key))
        .map((batch) => ({
          ...batch,
          status: "Promoted",
          promotedAt: new Date().toISOString(),
          promotedToBatchKey: promotedToBySourceKey[batch.key] || "",
        })),
      ...targetBatches,
    ];
    const nextGraduatingStudents = [...graduatingStudents, ...allGraduatingReviewList];
    const promotedStudentLookup = new Map(
      targetBatches.flatMap((batch) =>
        (batch.students || []).map((student) => [student.studentId, { batch, student }])
      )
    );
    const nextIrregularAssignments = irregularAssignments.map((assignment) => {
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
    });

    persistBatches(nextBatches);
    setGraduatingStudents(nextGraduatingStudents);
    setIrregularAssignments(nextIrregularAssignments);
    localStorage.setItem(GRADUATING_STUDENTS_KEY, JSON.stringify(nextGraduatingStudents));
    localStorage.setItem(IRREGULAR_SUBJECTS_KEY, JSON.stringify(nextIrregularAssignments));
    alert(`${allPromotedStudents.length} students promoted successfully.`);
  };

  return (
    <div className="space-y-6">
      <section className={`${showRoster ? "hidden" : ""} rounded-2xl border border-slate-200 bg-white p-6 shadow-sm`}>
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h3 className="text-xl font-bold text-[#003366]">
              Year Level Progression
            </h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {hasActiveDepartmentChanges ? (
              <button
                type="button"
                onClick={handleApplyDepartmentChanges}
                className="rounded-xl border border-emerald-400 px-5 py-3 text-sm font-semibold text-emerald-700 hover:bg-emerald-100"
              >
                Apply Changes
              </button>
            ) : null}
            <button
              type="button"
              onClick={handlePromoteStudents}
              className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white hover:bg-[#00264d]"
            >
              Promote Academic Year
            </button>
          </div>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <h3 className="text-xl font-bold text-[#003366]">Sections Created</h3>
          </div>
        </div>

        {departments.length ? (
          <>
          <div className={showRoster ? "hidden" : "mt-6 space-y-4"}>
            <div className="grid gap-4 rounded-xl border border-slate-200 bg-white p-4 md:grid-cols-[1fr_2fr] md:items-end">
              <label>
                <span className="mb-2 block text-xs font-semibold text-slate-600">Department</span>
                <select value={selectedDepartment} onChange={(event) => { setActiveDepartment(event.target.value); setSelectedBatchKey(""); setSelectedSectionCode(""); }} className="h-11 w-full rounded-lg border border-slate-300 bg-white px-3 text-sm outline-none focus:border-[#003366]">
                  {departments.map((department) => <option key={department} value={department}>{department}</option>)}
                </select>
              </label>
              <div>
                <span className="mb-2 block text-xs font-semibold text-slate-600">Year Level</span>
                <div className="flex flex-wrap gap-2">
                  {["All", ...AVAILABLE_YEAR_LEVELS].map((yearLevel) => (
                    <button key={yearLevel} type="button" onClick={() => setOverviewYear(yearLevel)} className={`rounded-lg border px-4 py-2 text-xs font-semibold ${overviewYear === yearLevel ? "border-[#003366] bg-[#003366] text-white" : "border-slate-300 bg-white text-slate-600 hover:bg-slate-50"}`}>{yearLevel}</button>
                  ))}
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
              <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <input value={sectionSearch} onChange={(event) => setSectionSearch(event.target.value)} placeholder="Search section by name or code..." className="h-10 w-full rounded-lg border border-slate-300 px-3 text-xs outline-none focus:border-[#003366] sm:max-w-sm" />
                <div className="flex flex-wrap gap-2">
                  <button type="button" onClick={handleExportSectionCsv} disabled={!selectedSection} className="rounded-lg border border-blue-300 px-4 py-2 text-xs font-semibold text-blue-700 hover:bg-blue-50 disabled:opacity-40">Export CSV</button>
                  <button type="button" onClick={handleImportSectionCsv} disabled={!selectedSection} className="rounded-lg border border-emerald-300 px-4 py-2 text-xs font-semibold text-emerald-700 hover:bg-emerald-50 disabled:opacity-40">Import CSV</button>
                </div>
              </div>

              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="min-w-full">
                  <thead className="bg-slate-50 text-[11px] text-slate-600"><tr><th className="px-4 py-3 text-left">Section</th><th className="px-4 py-3 text-left">Section Code</th><th className="px-4 py-3 text-left">Year Level</th><th className="px-4 py-3 text-left">Students</th><th className="px-4 py-3 text-left">Actions</th></tr></thead>
                  <tbody>
                    {overviewSections.map(({ batch, section, yearLevel, sectionName, studentCount }) => (
                      <tr key={`${batch.key}-${section.sectionCode}`} className="border-t border-slate-100 text-xs text-slate-700">
                        <td className="px-4 py-3"><p className="font-bold text-[#003366]">{sectionName}</p><p className="mt-1 text-[10px] text-slate-500">Section {section.sectionCode}</p></td>
                        <td className="px-4 py-3">{section.sectionCode}</td>
                        <td className="px-4 py-3"><span className="rounded-md bg-blue-50 px-2 py-1 text-[10px] font-semibold text-blue-700">{yearLevel}</span></td>
                        <td className="px-4 py-3 font-semibold">{studentCount}</td>
                        <td className="px-4 py-3"><button type="button" onClick={() => { setActiveDepartment(batch.program); setActiveYearLevel(yearLevel); setSelectedBatchKey(batch.key); setSelectedSectionCode(section.sectionCode); setShowRoster(true); }} className="rounded-md border border-blue-200 px-3 py-1.5 text-[10px] font-semibold text-blue-700 hover:bg-blue-50">View Roster</button></td>
                      </tr>
                    ))}
                    {!overviewSections.length ? <tr><td colSpan="5" className="py-8 text-center text-sm text-slate-500">No sections match your filters.</td></tr> : null}
                  </tbody>
                </table>
              </div>
              <p className="mt-4 text-[11px] text-slate-500">Showing {overviewSections.length} section{overviewSections.length === 1 ? "" : "s"}</p>
            </div>
          </div>

          <div className={showRoster ? "mt-6" : "hidden"}>
            <aside className="hidden">
              <p className="text-sm font-bold text-[#003366]">Departments</p>
              <div className="mt-3 space-y-2">
                {departments.map((department) => {
                  const isActive = selectedDepartment === department;
                  const departmentSectionCount = sectionedBatches
                    .filter((batch) => batch.program === department)
                    .reduce(
                      (total, batch) => total + (batch.sectionPlans || []).length,
                      0
                    );

                  return (
                    <button
                      key={department}
                      type="button"
                      onClick={() => {
                        setActiveDepartment(department);
                        setSelectedBatchKey("");
                        setSelectedSectionCode("");
                      }}
                      className={`w-full rounded-xl px-3 py-2.5 text-left transition ${
                        isActive
                          ? "bg-[#003366] text-white shadow-sm"
                          : "bg-white text-slate-700 hover:bg-slate-100"
                      }`}
                      title={department}
                    >
                      <span className="block truncate text-sm font-bold">
                        {department}
                      </span>
                      <span
                        className={`mt-1 block text-xs ${
                          isActive ? "text-white/80" : "text-slate-500"
                        }`}
                      >
                        {departmentSectionCount} section
                        {departmentSectionCount === 1 ? "" : "s"}
                      </span>
                      {changedDepartments.has(department) ? (
                        <span
                          className={`mt-2 inline-flex rounded-full px-2 py-1 text-xs font-semibold ${
                            isActive
                              ? "bg-white/15 text-white"
                              : "bg-emerald-100 text-emerald-700"
                          }`}
                        >
                          Changes pending
                        </span>
                      ) : null}
                    </button>
                  );
                })}
              </div>
            </aside>

            <div className="space-y-5">
              <button type="button" onClick={() => setShowRoster(false)} className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-[#003366] hover:bg-slate-50">← Back to Sections Created</button>
              <div className="hidden">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <p className="text-sm font-bold text-[#003366]">
                      {selectedDepartment}
                    </p>
                    <p className="text-sm text-slate-500">
                      {activeYearSectionCount} section
                      {activeYearSectionCount === 1 ? "" : "s"} in{" "}
                      {activeYearLevel}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {AVAILABLE_YEAR_LEVELS.map((yearLevel) => {
                      const yearCount = departmentBatches.reduce(
                        (total, batch) =>
                          total +
                          (batch.sectionPlans || []).filter((section) =>
                            sectionMatchesYearLevel(section, yearLevel)
                          ).length,
                        0
                      );

                      return (
                        <button
                          key={yearLevel}
                          type="button"
                          onClick={() => {
                            setActiveYearLevel(yearLevel);
                            setSelectedBatchKey("");
                            setSelectedSectionCode("");
                          }}
                          className={`rounded-lg px-3 py-2 text-sm font-semibold ${
                            activeYearLevel === yearLevel
                              ? "bg-[#003366] text-white"
                              : "border border-slate-300 text-slate-700 hover:bg-slate-50"
                          }`}
                        >
                          {yearLevel} ({yearCount})
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              <div>
                <aside className="hidden">
                  <p className="text-sm font-bold text-[#003366]">Sections</p>
                  <div className="mt-3 space-y-3">
                    {departmentBatches.map((batch) => {
                      const batchSections = (batch.sectionPlans || []).filter(
                        (section) =>
                          sectionMatchesYearLevel(section, activeYearLevel)
                      );
                      if (!batchSections.length) return null;

                      return (
                        <div key={batch.key} className="rounded-xl bg-slate-50 p-3">
                          <p className="text-xs font-bold uppercase text-slate-500">
                            Batch {batch.batchYear}
                          </p>
                          <div className="mt-2 space-y-2">
                            {batchSections.map((section) => {
                              const sectionStudentCount = (batch.students || []).filter(
                                (student) =>
                                  student.sectionCode === section.sectionCode &&
                                  (student.yearLevel || activeYearLevel) ===
                                    activeYearLevel
                              ).length;
                              const isSelected =
                                selectedBatch?.key === batch.key &&
                                selectedSection?.sectionCode === section.sectionCode;

                              return (
                                <button
                                  key={section.sectionCode}
                                  type="button"
                                  onClick={() => {
                                    setSelectedBatchKey(batch.key);
                                    setSelectedSectionCode(section.sectionCode);
                                  }}
                                  className={`w-full rounded-lg border px-3 py-2 text-left text-sm transition ${
                                    isSelected
                                      ? "border-[#003366] bg-[#003366] text-white"
                                      : "border-slate-200 bg-white text-slate-700 hover:bg-slate-100"
                                  }`}
                                  title={
                                    section.sectionName ||
                                    getDefaultSectionName(
                                      batch.program,
                                      section.sectionCode
                                    )
                                  }
                                >
                                  <span className="block truncate font-semibold">
                                    {section.sectionName ||
                                      getDefaultSectionName(
                                        batch.program,
                                        section.sectionCode
                                      )}
                                  </span>
                                  <span
                                    className={`mt-1 block text-xs ${
                                      isSelected ? "text-white/80" : "text-slate-500"
                                    }`}
                                  >
                                    {section.sectionCode} | {sectionStudentCount} student
                                    {sectionStudentCount === 1 ? "" : "s"}
                                  </span>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })}

                    {!activeYearSectionCount ? (
                      <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-5 text-center text-sm text-slate-500">
                        No sections for this year level.
                      </div>
                    ) : null}
                  </div>
                </aside>

                <main className="space-y-5">
                  <section className="rounded-xl border border-slate-200 bg-white p-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div>
                        <h4 className="text-lg font-bold text-[#003366]">
                          {selectedSection
                            ? selectedSection.sectionName ||
                              getDefaultSectionName(
                                selectedBatch.program,
                                selectedSection.sectionCode
                              )
                            : "Select a section"}
                        </h4>
                        <p className="mt-1 text-sm text-slate-500">
                          {selectedSection
                            ? `${sectionStudents.length} student${
                                sectionStudents.length === 1 ? "" : "s"
                              } enrolled`
                            : "Choose a section from the left panel."}
                        </p>
                      </div>
                      {selectedSection ? (
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={handleExportSectionCsv}
                            className="rounded-lg border border-[#003366] px-3 py-2 text-sm font-semibold text-[#003366] hover:bg-[#003366] hover:text-white"
                          >
                            Export CSV
                          </button>
                          <button
                            type="button"
                            onClick={handleImportSectionCsv}
                            className="rounded-lg border border-emerald-300 px-3 py-2 text-sm font-semibold text-emerald-700 hover:bg-emerald-50"
                          >
                            Import CSV
                          </button>
                          <button
                            type="button"
                            onClick={handleDeleteSection}
                            className="rounded-lg border border-red-200 px-3 py-2 text-sm font-semibold text-red-600 hover:bg-red-50"
                          >
                            Delete Section
                          </button>
                        </div>
                      ) : null}
                    </div>

                    {pendingRemoval ? (
                      <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-4">
                        <p className="text-sm font-semibold text-red-700">
                          Remove {pendingRemoval.studentName}
                        </p>
                        <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-[220px_1fr_auto_auto]">
                          <select
                            value={pendingRemoval.reason}
                            onChange={(event) =>
                              setPendingRemoval((current) => ({
                                ...current,
                                reason: event.target.value,
                              }))
                            }
                            className="rounded-xl border border-red-200 bg-white px-4 py-3 text-sm outline-none focus:border-red-500"
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
                            onClick={() => setPendingRemoval(null)}
                            className="rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm font-semibold text-slate-700"
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            onClick={handleConfirmRemoveStudent}
                            className="rounded-xl bg-red-600 px-4 py-3 text-sm font-semibold text-white"
                          >
                            Confirm Remove
                          </button>
                        </div>
                      </div>
                    ) : null}

                    <div className="mt-4 overflow-x-auto">
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
                          {sectionStudents.length ? (
                            sectionStudents.map((student) => (
                              <tr key={student.studentId} className="border-b">
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
                                      handleMoveStudent(
                                        student.studentId,
                                        event.target.value
                                      )
                                    }
                                    className="w-full min-w-44 rounded-xl border border-slate-300 px-3 py-2 text-sm outline-none focus:border-[#003366]"
                                  >
                                    {yearSections.map((section) => (
                                      <option
                                        key={section.sectionCode}
                                        value={section.sectionCode}
                                      >
                                        {section.sectionName ||
                                          getDefaultSectionName(
                                            selectedBatch.program,
                                            section.sectionCode
                                          )}
                                      </option>
                                    ))}
                                  </select>
                                </td>
                                <td className="px-4 py-3">
                                  <button
                                    type="button"
                                    onClick={() =>
                                      setPendingRemoval({
                                        studentId: student.studentId,
                                        studentName: buildStudentName(student),
                                        reason: REMOVAL_REASONS[0],
                                        note: "",
                                      })
                                    }
                                    className="rounded-lg border border-red-200 px-3 py-2 text-sm font-semibold text-red-600 hover:bg-red-50"
                                  >
                                    Remove
                                  </button>
                                </td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td colSpan="5" className="py-8 text-center text-slate-500">
                                {selectedSection
                                  ? "No students found in this section."
                                  : "Select a section to view students."}
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </section>

                  {selectedSection ? (
                    <section className="rounded-xl border border-slate-200 bg-white p-4">
                      <h4 className="text-lg font-bold text-[#003366]">Add Student</h4>
                      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-6">
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
                            setStudentForm((current) => ({
                              ...current,
                              sex: event.target.value,
                            }))
                          }
                          className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                        >
                          <option value="">Sex</option>
                          <option value="Male">Male</option>
                          <option value="Female">Female</option>
                        </select>
                        {[
                          ["lastName", "Last name"],
                          ["firstName", "First name"],
                          ["middleName", "Middle name"],
                        ].map(([field, placeholder]) => (
                          <input
                            key={field}
                            type="text"
                            value={studentForm[field]}
                            onChange={(event) =>
                              setStudentForm((current) => ({
                                ...current,
                                [field]: event.target.value,
                              }))
                            }
                            placeholder={placeholder}
                            className="rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                          />
                        ))}
                        <button
                          type="button"
                          onClick={handleAddStudent}
                          disabled={studentIdLoading || !automaticStudentId}
                          className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white hover:bg-[#00264d] disabled:cursor-not-allowed disabled:bg-slate-300"
                        >
                          Add Student
                        </button>
                      </div>
                    </section>
                  ) : null}

                  <section className="rounded-xl border border-slate-200 bg-white p-4">
                    <h4 className="text-lg font-bold text-[#003366]">
                      Removed Students
                    </h4>
                    <div className="mt-4 overflow-x-auto">
                      <table className="min-w-full">
                        <thead>
                          <tr className="bg-slate-800 text-white">
                            <th className="px-4 py-3 text-left text-sm">Student</th>
                            <th className="px-4 py-3 text-left text-sm">
                              Removed From
                            </th>
                            <th className="px-4 py-3 text-left text-sm">Reason</th>
                            <th className="px-4 py-3 text-left text-sm">Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {removedStudents.length ? (
                            removedStudents.map((student) => (
                              <tr
                                key={`${student.studentId}-${student.removedAt}`}
                                className="border-b"
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
                                  {student.removedFromSectionName || "--"}
                                </td>
                                <td className="px-4 py-3 text-slate-700">
                                  {student.removalReason}
                                  {student.removalNote ? (
                                    <p className="mt-1 text-xs text-slate-500">
                                      {student.removalNote}
                                    </p>
                                  ) : null}
                                </td>
                                <td className="px-4 py-3">
                                  <button
                                    type="button"
                                    onClick={() =>
                                      handleRestoreStudent(student.studentId)
                                    }
                                    className="rounded-lg border border-emerald-200 px-3 py-2 text-sm font-semibold text-emerald-700 hover:bg-emerald-50"
                                  >
                                    Restore
                                  </button>
                                </td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td colSpan="4" className="py-8 text-center text-slate-500">
                                No removed students for this year.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </section>
                </main>
              </div>
            </div>
          </div>
          </>
        ) : (
          <div className="mt-5 rounded-xl border border-dashed border-slate-300 bg-slate-50 p-8 text-center text-sm text-slate-500">
            No registrar-created sections yet.
          </div>
        )}
      </section>
    </div>
  );
}

export default RegistrarSectionsCreated;
