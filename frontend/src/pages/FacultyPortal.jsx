import { useCallback, useEffect, useMemo, useState } from "react";
import FacultyHeader from "../components/faculty/FacultyHeader";
import EncodingBanner from "../components/faculty/EncodingBanner";
import YearTabs from "../components/faculty/YearTabs";
import SearchWithDropdown from "../components/faculty/SearchWithDropdown";
import ProgramCard from "../components/faculty/ProgramCard";
import GradingTable from "../components/faculty/GradingTable";
import {
  CHAIRPERSON_REVIEW_KEY,
  buildAssignmentStorageKey,
  buildReviewKey,
} from "../utils/chairpersonHelpers";
import {
  getSystemSetting,
  submitFacultySectionToChairperson,
} from "../services/api";

const notifyChairpersonReviewChanged = (reviewData) => {
  window.dispatchEvent(
    new CustomEvent("blockgo:chairperson-review-changed", {
      detail: { reviewData },
    })
  );
};

const buildStudentRosterSignature = (students = []) =>
  students
    .map((student) => `${student.id}:${student.lastName}:${student.firstName}`)
    .sort()
    .join("|");

const compareStudentsByName = (left, right) => {
  const leftName = [
    left.lastName,
    left.firstName,
    left.middleInitial,
    left.id,
  ]
    .join(" ")
    .toLowerCase();
  const rightName = [
    right.lastName,
    right.firstName,
    right.middleInitial,
    right.id,
  ]
    .join(" ")
    .toLowerCase();

  return leftName.localeCompare(rightName);
};

const getOptionalAssignmentValue = (value) => {
  const normalizedValue = String(value || "").trim();
  return normalizedValue || "Not Available";
};

const FacultyPortal = ({ onLogout, allGrades, setAllGrades }) => {
  const [activeTab, setActiveTab] = useState("All Sections");
  const [selectedProgram, setSelectedProgram] = useState("");
  const [selectedSection, setSelectedSection] = useState(null);
  const [sharedDataVersion, setSharedDataVersion] = useState(0);

  const [systemSettings, setSystemSettings] = useState({
    semester: "2nd Semester",
  });

  const facultyData = {
    firstName: "Juan",
    lastName: "Dela Cruz",
    sex: "Male",
    facultyId: "FAC-001",
    department: "IT Department",
    Classification: "Full-Time",
  };

  const facultyFullName = `${facultyData.firstName} ${facultyData.lastName}`;

  const [reviewData, setReviewData] = useState(() => {
    const saved = localStorage.getItem(CHAIRPERSON_REVIEW_KEY);
    return saved ? JSON.parse(saved) : {};
  });

  const [encodingData, setEncodingData] = useState(() => {
    const saved = localStorage.getItem("encodingPeriod");
    return saved ? JSON.parse(saved) : null;
  });

  useEffect(() => {
    const applyEncodingPeriod = (value) => {
      if (!value) return;
      const parsed = typeof value === "string" ? JSON.parse(value) : value;
      localStorage.setItem("encodingPeriod", JSON.stringify(parsed));
      setEncodingData(parsed);
      setSystemSettings((current) => ({
        ...current,
        semester: parsed?.semester || "2nd Semester",
      }));
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
    const refreshTimer = window.setInterval(loadEncodingPeriod, 10000);
    window.addEventListener("blockgo:system-setting-changed", handleSystemSettingChanged);
    window.addEventListener("focus", loadEncodingPeriod);

    return () => {
      window.clearInterval(refreshTimer);
      window.removeEventListener("blockgo:system-setting-changed", handleSystemSettingChanged);
      window.removeEventListener("focus", loadEncodingPeriod);
    };
  }, []);

  useEffect(() => {
    const refreshSharedData = (event) => {
      const keys = event.detail?.keys || [];
      if (
        keys.includes("registrarAssignments") ||
        keys.includes("studentSections") ||
        keys.includes("irregularSubjectAssignments")
      ) {
        setSharedDataVersion((current) => current + 1);
      }
    };

    window.addEventListener("blockgo:shared-client-state-changed", refreshSharedData);

    return () =>
      window.removeEventListener(
        "blockgo:shared-client-state-changed",
        refreshSharedData
      );
  }, []);

  const systemTerm =
    encodingData?.term === "finals" || encodingData?.term === "midterm"
      ? encodingData.term
      : "midterm";

  const assignments = useMemo(() => {
    const saved = localStorage.getItem("registrarAssignments");
    return saved ? JSON.parse(saved) : [];
  }, [sharedDataVersion]);

  const studentSections = useMemo(() => {
    const saved = localStorage.getItem("studentSections");
    return saved ? JSON.parse(saved) : [];
  }, [sharedDataVersion]);

  const irregularSubjectAssignments = useMemo(() => {
    const saved = localStorage.getItem("irregularSubjectAssignments");
    return saved ? JSON.parse(saved) : [];
  }, [sharedDataVersion]);

  const myAssignments = useMemo(() => {
    return assignments.filter(
      (assignment) => assignment.facultyName === facultyFullName
    );
  }, [assignments, facultyFullName]);

  const sections = useMemo(() => {
    return myAssignments.reduce((acc, assign) => {
      const assignmentKey = buildAssignmentStorageKey(assign);
      const matchedSection = studentSections.find(
        (section) =>
          section.section === assign.sectionName &&
          section.program === assign.program &&
          section.schoolYear === assign.schoolYear &&
          (!section.semester || !assign.semester || section.semester === assign.semester)
      );

      const irregularStudentsForSubject = irregularSubjectAssignments.filter(
        (item) =>
          (item.status || "Pending") !== "Completed" &&
          item.faculty === assign.facultyName &&
          item.subjectCode === assign.subjectCode &&
          item.assignedSection === assign.sectionName
      );
      const regularStudents = assign.rosterStudents || matchedSection?.students || [];
      const rosterById = new Map(
        regularStudents.map((student) => [
          student.studentId,
          {
            id: student.studentId,
            firstName: student.firstName,
            lastName: student.lastName,
          },
        ])
      );

      irregularStudentsForSubject.forEach((student) => {
        rosterById.set(student.studentId, {
          id: student.studentId,
          firstName: student.firstName,
          lastName: student.lastName,
          isIrregularSubject: true,
        });
      });

      acc[assignmentKey] = {
        assignmentKey,
        year: assign.yearLevel,
        sectionName: assign.sectionName,
        subjectCode: assign.subjectCode,
        subjectTitle: assign.subjectTitle,
        sectionCourse: assign.program,
        units: assign.units || 3,
        schedule: getOptionalAssignmentValue(assign.schedule),
        day: getOptionalAssignmentValue(assign.day),
        date: getOptionalAssignmentValue(assign.date),
        semester: assign.semester,
        schoolYear: assign.schoolYear,
        students: Array.from(rosterById.values()).sort(compareStudentsByName),
      };

      return acc;
    }, {});
  }, [irregularSubjectAssignments, myAssignments, studentSections]);

  const activeGradeKey = systemSettings.semester;
  const getGradeBucketKey = (sectionData = {}) =>
    sectionData.semester || activeGradeKey;
  const getSectionGrades = (assignmentKey, sectionData = {}) =>
    allGrades?.[getGradeBucketKey(sectionData)]?.[assignmentKey] ||
    allGrades?.[activeGradeKey]?.[assignmentKey] ||
    {};

  const getReviewKey = useCallback((assignmentKey, sectionData) =>
    buildReviewKey({
      assignmentKey,
      facultyId: 1,
      sectionName: sectionData.sectionName,
      schoolYear: sectionData.schoolYear,
      semester: sectionData.semester,
      subjectCode: sectionData.subjectCode,
      term: systemTerm,
    }), [systemTerm]);

  const normalizedReviewData = useMemo(() => {
    const next = { ...reviewData };

    Object.entries(sections).forEach(([assignmentKey, sectionData]) => {
      const reviewKey = getReviewKey(assignmentKey, sectionData);
      const record = next[reviewKey];

      if (!record) return;

      const currentRosterSignature = buildStudentRosterSignature(sectionData.students);
      const savedRosterSignature = record.studentRosterSignature || "";
      const isLockedStatus = ["submitted", "approved", "forwarded"].includes(
        record.status
      );

      if (isLockedStatus && savedRosterSignature !== currentRosterSignature) {
        next[reviewKey] = {
          ...record,
          status: "pending",
          note:
            "Roster updated by registrar. Faculty may encode and submit this section again.",
          lastUpdated: new Date().toISOString(),
          studentRosterSignature: currentRosterSignature,
        };
      }
    });

    return next;
  }, [getReviewKey, reviewData, sections]);

  useEffect(() => {
    localStorage.setItem(
      CHAIRPERSON_REVIEW_KEY,
      JSON.stringify(normalizedReviewData)
    );
    notifyChairpersonReviewChanged(normalizedReviewData);
  }, [normalizedReviewData]);

  const getSectionProgress = (assignmentKey, sectionData) => {
    const currentSectionGrades = getSectionGrades(assignmentKey, sectionData);

    if (!sectionData.students.length) return 0;

    const encodedCount = sectionData.students.filter((student) => {
      const record = currentSectionGrades[student.id];
      if (!record) return false;

      if (systemTerm === "midterm") return !!record.midterm;
      if (systemTerm === "finals") return !!record.finals;

      return false;
    }).length;

    return Math.round((encodedCount / sectionData.students.length) * 100);
  };

  const submitSectionToChairperson = async (assignmentKey, sectionData) => {
    const reviewKey = getReviewKey(assignmentKey, sectionData);
    const submittedAt = new Date().toISOString();

    try {
      await submitFacultySectionToChairperson({
        department: sectionData.sectionCourse,
        section: sectionData.sectionName,
      });
    } catch (error) {
      console.warn("Backend section submission failed; keeping local review queue in sync.", error);
    }

    setReviewData((prev) => {
      const previousRecord = prev[reviewKey] || {};
      const nextReviewData = {
        ...prev,
        [reviewKey]: {
          ...previousRecord,
          status: "submitted",
          lastUpdated: submittedAt,
          facultyId: 1,
          facultyName: facultyFullName,
          assignmentKey,
          sectionName: sectionData.sectionName,
          department: sectionData.sectionCourse,
          schoolYear: sectionData.schoolYear,
          semester: sectionData.semester,
          subjectCode: sectionData.subjectCode,
          term: systemTerm,
          studentRosterSignature: buildStudentRosterSignature(sectionData.students),
        },
      };

      localStorage.setItem(CHAIRPERSON_REVIEW_KEY, JSON.stringify(nextReviewData));
      notifyChairpersonReviewChanged(nextReviewData);

      return nextReviewData;
    });
  };

  const filteredSections = Object.entries(sections).filter(
    ([, sectionData]) => {
      const matchesYear =
        activeTab === "All Sections" || sectionData.year === activeTab;

      const searchValue = selectedProgram.toLowerCase();

      const matchesSearch =
        selectedProgram === "" ||
        sectionData.sectionName.toLowerCase().includes(searchValue) ||
        sectionData.subjectTitle.toLowerCase().includes(searchValue) ||
        sectionData.sectionCourse.toLowerCase().includes(searchValue) ||
        sectionData.subjectCode.toLowerCase().includes(searchValue);

      return matchesYear && matchesSearch;
    }
  );

  const parseLocalDate = (value, endOfDay = false) => {
    if (!value) return null;
    const [year, month, day] = String(value).split("-").map(Number);
    if (!year || !month || !day) return null;
    const date = new Date(year, month - 1, day);
    if (endOfDay) date.setHours(23, 59, 59, 999);
    else date.setHours(0, 0, 0, 0);
    return date;
  };

  const ENCODING_START = parseLocalDate(encodingData?.startDate);
  const ENCODING_END = parseLocalDate(encodingData?.endDate, true);

  const now = new Date();

  const getBannerState = () => {
    if (!ENCODING_START || !ENCODING_END) return "closed_before";
    if (now > ENCODING_END) return "closed_after";
    if (now < ENCODING_START) return "closed_before";

    const msLeft = ENCODING_END - now;
    const computedDaysLeft = Math.ceil(msLeft / (1000 * 60 * 60 * 24));

    if (computedDaysLeft <= 3) return "urgent";
    return "open";
  };

  const daysLeft =
    ENCODING_END && now <= ENCODING_END
      ? Math.ceil((ENCODING_END - now) / (1000 * 60 * 60 * 24))
      : 0;

  const isEncodingOpen =
    !!ENCODING_START &&
    !!ENCODING_END &&
    now >= ENCODING_START &&
    now <= ENCODING_END;

  const formatDate = (date) => {
    if (!date) return "No schedule set";

    return new Date(date).toLocaleDateString("en-US", {
      month: "long",
      day: "2-digit",
      year: "numeric",
    });
  };

  return (
    <div className="min-h-screen bg-slate-100">
      <FacultyHeader
        facultyData={{ ...facultyData, semester: systemSettings.semester }}
        totalSections={Object.keys(sections).length}
        onLogout={onLogout}
      />

      <EncodingBanner
        bannerState={getBannerState()}
        daysLeft={daysLeft}
        formatDate={formatDate}
        startDate={ENCODING_START}
        endDate={ENCODING_END}
      />

      {!selectedSection ? (
        <>
          <div className="mt-6 flex flex-col gap-4 px-4 md:flex-row md:items-center">
            <YearTabs
              activeTab={activeTab}
              setActiveTab={setActiveTab}
              sections={sections}
            />

            <div className="flex max-w-xl flex-1 items-center">
              <SearchWithDropdown
                selectedProgram={selectedProgram}
                setSelectedProgram={setSelectedProgram}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 px-4 pb-8 pt-6 sm:grid-cols-2 lg:grid-cols-3">
            {filteredSections.length > 0 ? (
              filteredSections.map(([assignmentKey, sectionData]) => {
                const reviewRecord =
                  normalizedReviewData[getReviewKey(assignmentKey, sectionData)] || {
                    status: "pending",
                    note: "",
                  };

                return (
                  <ProgramCard
                    key={assignmentKey}
                    sectionName={sectionData.sectionName}
                    sectionData={sectionData}
                    progress={getSectionProgress(assignmentKey, sectionData)}
                    reviewStatus={reviewRecord.status}
                    reviewNote={reviewRecord.note}
                    onSubmit={() =>
                      submitSectionToChairperson(assignmentKey, sectionData)
                    }
                    onClick={() =>
                      setSelectedSection({ ...sectionData, assignmentKey })
                    }
                  />
                );
              })
            ) : (
              <div className="col-span-full rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-slate-500">
                No assigned sections yet.
              </div>
            )}
          </div>
        </>
      ) : (
        <GradingTable
          selectedSection={selectedSection}
          onBack={() => setSelectedSection(null)}
          systemTerm={systemTerm}
          activeGradeKey={getGradeBucketKey(selectedSection)}
          isEncodingOpen={isEncodingOpen}
          grades={getSectionGrades(selectedSection.assignmentKey, selectedSection)}
          setAllGrades={setAllGrades}
          reviewStatus={
            normalizedReviewData[
              getReviewKey(selectedSection.assignmentKey, selectedSection)
            ]
              ?.status || "pending"
          }
          reviewNote={
            normalizedReviewData[
              getReviewKey(selectedSection.assignmentKey, selectedSection)
            ]
              ?.note || ""
          }
        />
      )}
    </div>
  );
};

export default FacultyPortal;
