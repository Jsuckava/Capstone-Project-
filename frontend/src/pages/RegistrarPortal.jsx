import React, { useEffect, useState } from "react";
import RegistrarHeader from "../components/registrar/RegistrarHeader";
import RegistrarSidebar from "../components/registrar/RegistrarSidebar";
import RegistrarDashboard from "../components/registrar/RegistrarDashboard";
import FacultyMonitoring from "../components/registrar/FacultyMonitoring";
import EncodingPeriod from "../components/registrar/EncodingPeriod";
import StudentListImport, {
  StudentSubmissionLogs,
} from "../components/registrar/StudentListImport";
import GradeFinalization from "../components/registrar/GradeFinalization";
import RegistrarStudentSectioning from "../components/registrar/RegistrarStudentSectioning";
import RegistrarSectionsCreated from "../components/registrar/RegistrarSectionsCreated";
import { programs } from "../data/registrarData";
import { getSystemSetting } from "../services/api";

function RegistrarPortal({ onLogout, onResetEncodingSeason, allGrades = {} }) {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [sectioningDepartment, setSectioningDepartment] = useState(
    programs[0] || ""
  );
  const [sectioningVersion, setSectioningVersion] = useState(0);
  const [activeSemester, setActiveSemester] = useState("2nd Semester");

  useEffect(() => {
    const applyEncodingPeriod = (value) => {
      if (!value) return;
      const parsed = typeof value === "string" ? JSON.parse(value) : value;
      setActiveSemester(parsed?.semester || "2nd Semester");
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

  const registrarData = {
    name: "PLV Registrar",
    schoolYear: "2025-2026",
    semester: activeSemester,
  };

  const getSectionTitle = () => {
    switch (activeTab) {
      case "dashboard":
        return "Dashboard";
      case "encoding":
        return "Encoding Period";
      case "sectioning":
        return "Student Sectioning";
      case "sectionsCreated":
        return "Sections Created";
      case "monitoring":
        return "Monitoring";
      case "finalization":
        return "Grade Finalization";
      case "reports":
        return "Reports & PDF";
      default:
        return "Dashboard";
    }
  };



  const renderContent = () => {
  if (activeTab === "dashboard") {
    return <RegistrarDashboard />;
  }

  if (activeTab === "encoding") {
    return <EncodingPeriod onResetEncodingSeason={onResetEncodingSeason} />;
  }

  if (activeTab === "sectioning") {
    return (
      <div className="space-y-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <label className="block max-w-xl">
            <span className="mb-2 block text-sm font-medium text-slate-700">
              Department
            </span>
            <select
              value={sectioningDepartment}
              onChange={(event) => setSectioningDepartment(event.target.value)}
              className="w-full rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm outline-none focus:border-[#003366]"
            >
              {programs.map((program) => (
                <option key={program} value={program}>
                  {program}
                </option>
              ))}
            </select>
          </label>
        </div>

        <StudentListImport
          selectedProgram={sectioningDepartment}
          onImportComplete={() =>
            setSectioningVersion((currentVersion) => currentVersion + 1)
          }
        />

        <RegistrarStudentSectioning
          key={sectioningVersion}
          chairpersonDepartment={sectioningDepartment}
        />

        <StudentSubmissionLogs />
      </div>
    );
  }

  if (activeTab === "monitoring") {
    return <FacultyMonitoring />;
  }

  if (activeTab === "sectionsCreated") {
    return <RegistrarSectionsCreated />;
  }

  if (activeTab === "finalization") {
    return <GradeFinalization allGrades={allGrades} />;
  }

  return (
    <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-10 text-center shadow-sm">
      <h3 className="text-xl font-semibold text-[#003366]">
        {getSectionTitle()}
      </h3>
      
      <p className="mt-4 text-sm text-slate-400">
        This section will be added next.
      </p>
    </div>
  );
};

  return (
    <div className="min-h-screen bg-[#f3f4f6]">
      <RegistrarHeader registrarData={registrarData} onLogout={onLogout} />

      <div className="px-6 py-6">
        <div className="flex flex-col gap-6 lg:flex-row">
          <RegistrarSidebar
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            managementDefaultTab="monitoring"
          />

          <main className="flex-1 space-y-4">
            <div>
              <h2 className="text-2xl font-bold text-[#003366]">
                {getSectionTitle()}
              </h2>
              
            </div>

            {renderContent()}
          </main>
        </div>
      </div>
    </div>
  );
}

export default RegistrarPortal;
