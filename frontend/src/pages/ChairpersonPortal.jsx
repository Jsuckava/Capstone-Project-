import React, { useEffect, useMemo, useState } from "react";
import ChairpersonHeader from "../components/chairperson/ChairpersonHeader";
import ChairpersonSidebar from "../components/chairperson/ChairpersonSidebar";
import ChairpersonOverview from "../components/chairperson/ChairpersonOverview";
import FacultyStatusTable from "../components/chairperson/FacultyStatusTable";
import SectionReviewPanel from "../components/chairperson/SectionReviewPanel";
import AcademicAssignment from "../components/chairperson/AcademicAssignment";
import StudentSectioning from "../components/chairperson/StudentSectioning";
import { facultyList } from "../data/registrarData";
import { STUDENT_BATCHES_KEY } from "../utils/studentSectioningHelpers";
import {
  buildAssignmentStorageKey,
  buildFacultyDirectory,
  buildReviewKey,
  CHAIRPERSON_REVIEW_KEY,
  getEncodedCount,
  getFacultyStatus,
  getSectionReviewRecord,
  getSectionStudents,
} from "../utils/chairpersonHelpers";
import { getSystemSetting } from "../services/api";

const DEFAULT_CHAIRPERSON_DEPARTMENT =
  "Bachelor of Science in Information Technology";

const loadSavedReviewData = () => {
  try {
    const saved = localStorage.getItem(CHAIRPERSON_REVIEW_KEY);
    return saved ? JSON.parse(saved) : {};
  } catch (error) {
    console.error("Failed to load chairperson review data:", error);
    return {};
  }
};

function ChairpersonPortal({ onLogout, allGrades = {} }) {
  const [activeTab, setActiveTab] = useState("sectioning");
  const [reviewData, setReviewData] = useState(loadSavedReviewData);
  const [selectedReviewKey, setSelectedReviewKey] = useState("");
  const [studentDataVersion, setStudentDataVersion] = useState(0);
  const [encodingPeriod, setEncodingPeriod] = useState({
    semester: "2nd Semester",
    term: "midterm",
  });

  useEffect(() => {
    localStorage.setItem(CHAIRPERSON_REVIEW_KEY, JSON.stringify(reviewData));
  }, [reviewData]);

  useEffect(() => {
    const refreshReviewData = (event) => {
      if (event?.detail?.reviewData) {
        setReviewData(event.detail.reviewData);
        return;
      }

      setReviewData(loadSavedReviewData());
    };

    const handleStorage = (event) => {
      if (event.key === CHAIRPERSON_REVIEW_KEY) {
        refreshReviewData();
      }
    };

    window.addEventListener("blockgo:chairperson-review-changed", refreshReviewData);
    window.addEventListener("storage", handleStorage);

    return () => {
      window.removeEventListener("blockgo:chairperson-review-changed", refreshReviewData);
      window.removeEventListener("storage", handleStorage);
    };
  }, []);

  useEffect(() => {
    const refreshPortalData = (event) => {
      const keys = event.detail?.keys || [];
      if (
        keys.includes(STUDENT_BATCHES_KEY) ||
        keys.includes("registrarAssignments") ||
        keys.includes("studentMasterlist") ||
        keys.includes(CHAIRPERSON_REVIEW_KEY)
      ) {
        setStudentDataVersion((current) => current + 1);
      }
    };

    window.addEventListener("blockgo:shared-client-state-changed", refreshPortalData);

    return () =>
      window.removeEventListener(
        "blockgo:shared-client-state-changed",
        refreshPortalData
      );
  }, []);

  useEffect(() => {
    const applyEncodingPeriod = (value) => {
      if (!value) return;
      const parsed = typeof value === "string" ? JSON.parse(value) : value;
      setEncodingPeriod({
        semester: parsed?.semester || "2nd Semester",
        term:
          parsed?.term === "finals" || parsed?.term === "midterm"
            ? parsed.term
            : "midterm",
      });
    };

    const loadEncodingPeriod = async () => {
      try {
        const res = await getSystemSetting("encoding_period");
        if (res.status === "Success" && res.value) {
          applyEncodingPeriod(res.value);
        }
      } catch (error) {
        console.error(error);
      }
    };

    const handleSystemSettingChanged = (event) => {
      const key = event.detail?.key || event.detail?.Key;
      const value = event.detail?.value || event.detail?.Value;
      if (key === "encoding_period") applyEncodingPeriod(value);
    };

    loadEncodingPeriod();
    window.addEventListener("blockgo:system-setting-changed", handleSystemSettingChanged);

    return () =>
      window.removeEventListener("blockgo:system-setting-changed", handleSystemSettingChanged);
  }, []);

  const assignments = useMemo(() => {
    const saved = localStorage.getItem("registrarAssignments");
    return saved ? JSON.parse(saved) : [];
  }, [studentDataVersion]);

  const importedStudents = useMemo(() => {
    const saved = localStorage.getItem("studentMasterlist");
    return saved ? JSON.parse(saved) : [];
  }, [studentDataVersion]);

  const forwardedBatches = useMemo(() => {
    const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
    return saved ? JSON.parse(saved) : [];
  }, [studentDataVersion]);

  const availableDepartments = useMemo(() => {
    const departments = new Set();

    forwardedBatches.forEach((batch) => {
      if ((batch.status || "Forwarded") === "Forwarded" && batch.program) {
        departments.add(batch.program);
      }
    });

    assignments.forEach((assignment) => {
      if (assignment.program) {
        departments.add(assignment.program);
      }
    });

    return Array.from(departments);
  }, [assignments, forwardedBatches]);

  const [selectedDepartment, setSelectedDepartment] = useState("");
  const resolvedSelectedDepartment =
    selectedDepartment && availableDepartments.includes(selectedDepartment)
      ? selectedDepartment
      : availableDepartments[0] || DEFAULT_CHAIRPERSON_DEPARTMENT;

  const chairpersonData = {
    name: "Elena Marquez",
    department: resolvedSelectedDepartment,
    schoolYear: "2025",
    semester: encodingPeriod.semester,
  };
  const chairpersonDepartment = resolvedSelectedDepartment;

  const activeGradeKey = chairpersonData.semester;
  const activeTerm = encodingPeriod.term;

  const departmentFaculty = useMemo(() => {
    const facultyDirectory = buildFacultyDirectory({
      facultyList,
      assignments,
    });

    return facultyDirectory.filter(
      (faculty) => faculty.department === chairpersonDepartment
    );
  }, [assignments, chairpersonDepartment]);

  const monitoredRows = useMemo(() => {
    return departmentFaculty.flatMap((faculty) => {
      return faculty.sections.map((assignment) => {
        const assignmentKey = buildAssignmentStorageKey(assignment);
        const reviewKey = buildReviewKey({
          ...assignment,
          assignmentKey,
          term: activeTerm,
        });
        const students = getSectionStudents({
          students: importedStudents,
          assignment,
        });
        const gradeKey = assignment.semester || activeGradeKey;
        const sectionGrades =
          allGrades?.[gradeKey]?.[assignmentKey] ||
          allGrades?.[activeGradeKey]?.[assignmentKey] ||
          {};
        const encodedCount = getEncodedCount({
          grades: sectionGrades,
          students,
          activeTerm,
        });
        const totalStudents = students.length;
        const progress = totalStudents > 0 ? Math.round((encodedCount / totalStudents) * 100) : 0;
        const reviewRecord = getSectionReviewRecord({ reviewData, reviewKey });

        return {
          reviewKey,
          assignmentKey,
          facultyId: assignment.facultyId,
          facultyName: assignment.facultyName,
          department: assignment.program,
          sectionName: assignment.sectionName,
          subjectCode: assignment.subjectCode,
          subjectTitle: assignment.subjectTitle,
          units: assignment.units,
          schedule: assignment.schedule,
          day: assignment.day,
          schoolYear: assignment.schoolYear,
          semester: assignment.semester,
          students,
          totalStudents,
          encodedCount,
          progress,
          grades: sectionGrades,
          facultyEncodingStatus:
            totalStudents === 0
              ? "No Assigned Sections"
              : encodedCount === 0
              ? "Not Started"
              : progress >= 100
              ? "Completed"
              : "In Progress",
          reviewStatus: reviewRecord.status,
          reviewNote: reviewRecord.note,
          reviewLogs: reviewRecord.logs || [],
          lastUpdated: reviewRecord.lastUpdated,
        };
      });
    });
  }, [activeGradeKey, activeTerm, allGrades, departmentFaculty, importedStudents, reviewData]);

  const selectedSection =
    monitoredRows.find((row) => row.reviewKey === selectedReviewKey) || null;

  const metrics = useMemo(() => {
    const facultySummaries = departmentFaculty.map((faculty) => {
      const encodedSections = faculty.sections.filter((section) => {
        const row = monitoredRows.find(
          (monitoredRow) =>
            monitoredRow.reviewKey ===
              buildReviewKey({
                ...section,
                assignmentKey: buildAssignmentStorageKey(section),
                term: activeTerm,
              })
        );
        return row && row.encodedCount > 0;
      }).length;

      return getFacultyStatus({
        encodedSections,
        totalSections: faculty.sections.length,
      });
    });

    return {
      totalFaculty: departmentFaculty.length,
      totalSections: monitoredRows.length,
      submittedSections: monitoredRows.filter((row) => row.reviewStatus === "submitted").length,
      approvedSections: monitoredRows.filter((row) => row.reviewStatus === "approved").length,
      returnedSections: monitoredRows.filter((row) => row.reviewStatus === "returned").length,
      forwardedSections: monitoredRows.filter((row) => row.reviewStatus === "forwarded").length,
      completedFaculty: facultySummaries.filter((status) => status === "Completed").length,
    };
  }, [activeTerm, departmentFaculty, monitoredRows]);

  const updateReviewStatus = (status, note = "") => {
    if (!selectedSection) return;

    setReviewData((prev) => {
      const currentRecord = prev[selectedSection.reviewKey] || {};
      const timestamp = new Date().toISOString();
      const nextLog = {
        status,
        note,
        timestamp,
        actor: chairpersonData.name,
        role: "Chairperson",
      };

      return {
        ...prev,
        [selectedSection.reviewKey]: {
          ...currentRecord,
          status,
          note,
          lastUpdated: timestamp,
          assignmentKey: selectedSection.assignmentKey,
          facultyId: selectedSection.facultyId,
          facultyName: selectedSection.facultyName,
          sectionName: selectedSection.sectionName,
          department: selectedSection.department,
          schoolYear: selectedSection.schoolYear,
          semester: selectedSection.semester,
          subjectCode: selectedSection.subjectCode,
          subjectTitle: selectedSection.subjectTitle,
          units: selectedSection.units,
          schedule: selectedSection.schedule,
          day: selectedSection.day,
          term: activeTerm,
          students: selectedSection.students || [],
          grades: selectedSection.grades || {},
          logs: [...(currentRecord.logs || []), nextLog],
        },
      };
    });
  };

  const filteredRows = useMemo(() => {
    if (activeTab === "assignment") {
      return monitoredRows;
    }

    if (activeTab === "forReview") {
      return monitoredRows.filter((row) => row.reviewStatus === "submitted");
    }

    if (activeTab === "returned") {
      return monitoredRows.filter((row) => row.reviewStatus === "returned");
    }

    if (activeTab === "approved") {
      return monitoredRows.filter((row) => row.reviewStatus === "approved");
    }

    if (activeTab === "forwarded") {
      return monitoredRows.filter((row) => row.reviewStatus === "forwarded");
    }

    return monitoredRows;
  }, [activeTab, monitoredRows]);

  useEffect(() => {
    const reviewQueueTabs = ["forReview", "returned", "approved", "forwarded"];

    if (!reviewQueueTabs.includes(activeTab)) return;

    if (!filteredRows.length) {
      if (selectedReviewKey) setSelectedReviewKey("");
      return;
    }

    const selectedRowStillVisible = filteredRows.some(
      (row) => row.reviewKey === selectedReviewKey
    );

    if (!selectedRowStillVisible) {
      setSelectedReviewKey(filteredRows[0].reviewKey);
    }
  }, [activeTab, filteredRows, selectedReviewKey]);

  return (
    <div className="min-h-screen bg-[#f3f4f6]">
      <ChairpersonHeader
        chairpersonData={chairpersonData}
        departmentCount={departmentFaculty.length}
        availableDepartments={availableDepartments}
        selectedDepartment={resolvedSelectedDepartment}
        onDepartmentChange={setSelectedDepartment}
        onLogout={onLogout}
      />

      <div className="px-6 py-6">
        <div className="flex flex-col gap-6 lg:flex-row">
          <ChairpersonSidebar activeTab={activeTab} setActiveTab={setActiveTab} />

          <main className="flex-1 space-y-6">
            {activeTab === "sectioning" ? (
              <StudentSectioning
                chairpersonDepartment={chairpersonDepartment}
                onSectioningSaved={() =>
                  setStudentDataVersion((current) => current + 1)
                }
              />
            ) : activeTab === "assignment" ? (
              <>
                <AcademicAssignment chairpersonDepartment={chairpersonDepartment} />
              </>
            ) : activeTab === "dashboard" ? (
              <>
                <div>
                  <h2 className="text-2xl font-bold text-[#003366]">
                    Chairperson Review Dashboard
                  </h2>
                  
                </div>

                <ChairpersonOverview metrics={metrics} />

                <FacultyStatusTable
                  rows={monitoredRows}
                  selectedReviewKey={selectedReviewKey}
                  onSelectSection={(row) => setSelectedReviewKey(row.reviewKey)}
                />

                <SectionReviewPanel
                  selectedSection={selectedSection}
                  activeTerm={activeTerm}
                  onSendBack={(note) => updateReviewStatus("returned", note)}
                  onApprove={(note) => updateReviewStatus("approved", note)}
                  onSubmitToRegistrar={(note) =>
                    updateReviewStatus("forwarded", note)
                  }
                />
              </>
            ) : (
              <>
                <FacultyStatusTable
                  rows={filteredRows}
                  selectedReviewKey={selectedReviewKey}
                  onSelectSection={(row) => setSelectedReviewKey(row.reviewKey)}
                />

                <SectionReviewPanel
                  selectedSection={selectedSection}
                  activeTerm={activeTerm}
                  onSendBack={(note) => updateReviewStatus("returned", note)}
                  onApprove={(note) => updateReviewStatus("approved", note)}
                  onSubmitToRegistrar={(note) =>
                    updateReviewStatus("forwarded", note)
                  }
                />
              </>
            )}
          </main>
        </div>
      </div>
    </div>
  );
}

export default ChairpersonPortal;
