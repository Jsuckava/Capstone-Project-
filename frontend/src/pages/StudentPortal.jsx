import { useEffect, useState } from "react";
import StudentNavbar from "../components/student/StudentNavbar";
import StudentInfoCard from "../components/student/StudentInfoCard";
import StudentSummary from "../components/student/StudentSummary";
import StudentGradesTable from "../components/student/StudentGradesTable";
import { getSystemSetting } from "../services/api";
import {
  getCalculatedGWA,
  getTotalUnits,
  isDeanLister,
} from "../utils/studentHelpers";

const StudentPortal = ({ studentData, onLogout, failedSubjectsCount }) => {
  const [activeSemester, setActiveSemester] = useState("Semester Grades");
  const totalUnits = getTotalUnits(studentData.subjects);
  const gwa = getCalculatedGWA(studentData.subjects);
  const isDeansLister = isDeanLister(studentData.subjects, gwa);

  useEffect(() => {
    const applyEncodingPeriod = (value) => {
      if (!value) return;
      try {
        const parsed = typeof value === "string" ? JSON.parse(value) : value;
        setActiveSemester(parsed?.semester ? `${parsed.semester} Grades` : "Semester Grades");
      } catch (error) {
        console.error("Failed to parse encoding period for student page:", error);
      }
    };

    const loadEncodingPeriod = async () => {
      try {
        const res = await getSystemSetting("encoding_period");
        if (res.status === "Success" && res.value) applyEncodingPeriod(res.value);
      } catch (error) {
        console.error("Failed to load encoding period for student page:", error);
      }
    };

    const handleSystemSettingChanged = (event) => {
      const key = event.detail?.key || event.detail?.Key;
      const value = event.detail?.value || event.detail?.Value;
      if (key === "encoding_period") applyEncodingPeriod(value);
    };

    loadEncodingPeriod();
    window.addEventListener("blockgo:system-setting-changed", handleSystemSettingChanged);
    return () => window.removeEventListener("blockgo:system-setting-changed", handleSystemSettingChanged);
  }, []);

  return (
    <div className="min-h-screen bg-slate-100">
      <StudentNavbar onLogout={onLogout} />
      <StudentInfoCard
        studentData={{
          ...studentData,
          email: studentData.studentEmail || studentData.email,
        }}
      />
      <StudentSummary
        totalUnits={totalUnits}
        gwa={gwa}
        isDeansLister={isDeansLister}
        failedSubjectsCount={failedSubjectsCount}
        semesterLabel={activeSemester}
      />
      <StudentGradesTable subjects={studentData.subjects} />
    </div>
  );
};

export default StudentPortal;
