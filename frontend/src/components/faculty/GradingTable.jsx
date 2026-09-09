import React, { useState } from "react";
import BulkUploadModal from "./BulkUploadModal";
import { exportGradingSheet } from "../../utils/exportGradingSheet";
import StudentRow from "./StudentRow";
import {
  computeFinal,
  formatName,
  getGradeEquivalent,
  getStatus,
} from "../../utils/gradingHelpers";

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

const GradingTable = ({
  selectedSection,
  onBack,
  systemTerm,
  activeGradeKey,
  isEncodingOpen = false,
  grades,
  setAllGrades,
  reviewStatus = "pending",
  reviewNote = "",
}) => {
  const [showBulkUpload, setShowBulkUpload] = useState(false);
  const [studentSearch, setStudentSearch] = useState("");
  const displaySchedule = selectedSection?.schedule || "Not Available";
  const displayDay = selectedSection?.day || "Not Available";
  const activeTerm = systemTerm;
  const gradeStorageKey = selectedSection.assignmentKey || selectedSection.sectionName;
  const sortedStudents = [...(selectedSection.students || [])].sort(
    compareStudentsByName
  );
  const searchValue = studentSearch.trim().toLowerCase();
  const visibleStudents = searchValue
    ? sortedStudents.filter((student) => {
        const studentName = formatName(student).toLowerCase();
        const studentId = String(student.id || "").toLowerCase();

        return studentName.includes(searchValue) || studentId.includes(searchValue);
      })
    : sortedStudents;

  const handleChange = (studentId, field, value) => {
    const formattedValue = ["INC", "UD", "D", "W"].includes(value.toUpperCase())
      ? value.toUpperCase()
      : value;

    setAllGrades((prev) => ({
      ...prev,
      [activeGradeKey]: {
        ...(prev[activeGradeKey] || {}),
        [gradeStorageKey]: {
          ...(prev[activeGradeKey]?.[gradeStorageKey] || {}),
          [studentId]: {
            ...(prev[activeGradeKey]?.[gradeStorageKey]?.[studentId] || {}),
            [field]: formattedValue,
          },
        },
      },
    }));
  };

  const toggleFlagStudent = (studentId) => {
    setAllGrades((prev) => ({
      ...prev,
      [activeGradeKey]: {
        ...(prev[activeGradeKey] || {}),
        [gradeStorageKey]: {
          ...(prev[activeGradeKey]?.[gradeStorageKey] || {}),
          [studentId]: {
            ...(prev[activeGradeKey]?.[gradeStorageKey]?.[studentId] || {}),
            flagged:
              !prev[activeGradeKey]?.[gradeStorageKey]?.[studentId]?.flagged,
          },
        },
      },
    }));
  };

  const handleStandingChange = (studentId, value) => {
    setAllGrades((prev) => ({
      ...prev,
      [activeGradeKey]: {
        ...(prev[activeGradeKey] || {}),
        [gradeStorageKey]: {
          ...(prev[activeGradeKey]?.[gradeStorageKey] || {}),
          [studentId]: {
            ...(prev[activeGradeKey]?.[gradeStorageKey]?.[studentId] || {}),
            standing: value,
            midterm: value === "active"
              ? prev[activeGradeKey]?.[gradeStorageKey]?.[studentId]?.midterm || ""
              : 0,
            finals: value === "active"
              ? prev[activeGradeKey]?.[gradeStorageKey]?.[studentId]?.finals || ""
              : 0,
          },
        },
      },
    }));
  };

  const handleBulkUpload = (data) => {
    setAllGrades((prev) => ({
      ...prev,
      [activeGradeKey]: {
        ...(prev[activeGradeKey] || {}),
        [gradeStorageKey]: {
          ...(prev[activeGradeKey]?.[gradeStorageKey] || {}),
          ...Object.keys(data).reduce((acc, studentId) => {
            acc[studentId] = {
              ...(prev[activeGradeKey]?.[gradeStorageKey]?.[studentId] || {}),
              ...data[studentId],
            };
            return acc;
          }, {}),
        },
      },
    }));
  };

  return (
    <div className="px-4 pb-10 pt-6 md:px-6">
      <button
        onClick={onBack}
        className="mb-4 flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white text-2xl font-bold leading-none text-[#003366] shadow-sm transition hover:bg-slate-50"
        aria-label="Back to sections"
        title="Back to sections"
      >
        {"<"}
      </button>

      <div className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-md">
        <div className="flex flex-col gap-4 px-4 py-4 md:flex-row md:items-center md:justify-between">
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-3">
              <span className="shrink-0 rounded-lg bg-blue-50 px-3 py-1 text-sm font-bold text-blue-500">
                {selectedSection.subjectCode}
              </span>

              <h2 className="text-xl font-bold text-[#003366]">
                Section: {selectedSection.sectionName}
              </h2>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-sm text-slate-600">
              <span>{selectedSection.units} Units</span>
              <span className="text-slate-300">•</span>
              <span>{displaySchedule}</span>
              <span className="text-slate-300">•</span>
              <span>{displayDay}</span>
            </div>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              type="text"
              value={studentSearch}
              onChange={(event) => setStudentSearch(event.target.value)}
              placeholder="Search student..."
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm outline-none focus:border-[#003366]"
            />
            <button
              onClick={() => setShowBulkUpload(true)}
              disabled={!isEncodingOpen}
              className="rounded-lg bg-yellow-400 px-4 py-2 text-sm font-bold text-[#003366] hover:bg-yellow-500 disabled:cursor-not-allowed disabled:bg-slate-200 disabled:text-slate-500"
            >
              Bulk Upload
            </button>

            <button
              onClick={() => exportGradingSheet(selectedSection, grades, systemTerm)}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100"
            >
              Export Grades
            </button>
          </div>
        </div>

        {reviewStatus === "returned" && reviewNote ? (
          <div className="border-t border-red-100 bg-red-50 px-4 py-4 text-sm text-red-700">
            <p className="font-semibold">Returned by chairperson</p>
            <p className="mt-1">{reviewNote}</p>
          </div>
        ) : null}

        {!isEncodingOpen ? (
          <div className="border-t border-amber-100 bg-amber-50 px-4 py-4 text-sm text-amber-700">
            <p className="font-semibold">Encoding is closed</p>
            <p className="mt-1">
              Faculty can view this grading table, but grade entry is locked
              until the registrar reopens the encoding period.
            </p>
          </div>
        ) : null}

        <div className="space-y-3 p-4 md:hidden">
          {visibleStudents.map((student) => {
            const studentData = grades[student.id] || {};
            const final = computeFinal(grades, student.id, activeTerm);
            const status = getStatus(final, activeTerm);
            const isFlagged = studentData.flagged;
            const standing = studentData.standing || "active";

            return (
              <div
                key={student.id}
                className={`rounded-2xl border border-slate-200 p-4 shadow-sm ${
                  isFlagged ? "bg-red-50" : "bg-white"
                }`}
              >
                <div className="mb-3 flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm text-slate-500">Student ID</p>
                    <p className="font-semibold text-slate-800">{student.id}</p>
                  </div>

                  <button
                    type="button"
                    onClick={() => toggleFlagStudent(student.id)}
                    disabled={!isEncodingOpen}
                    className={`rounded-lg px-3 py-1 text-xs font-bold ${
                      isFlagged
                        ? "bg-red-100 text-red-600"
                        : "bg-slate-100 text-slate-600"
                    } disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400`}
                  >
                    {isFlagged ? "Unflag" : "Flag"}
                  </button>
                </div>

                <div className="mb-3">
                  <p className="text-sm text-slate-500">Student Name</p>
                  <p className="font-semibold text-slate-800">
                    {formatName(student)}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="mb-1 text-sm text-slate-500">Midterm</p>
                    <input
                      type="text"
                      value={studentData.midterm || ""}
                      onChange={(e) =>
                        handleChange(student.id, "midterm", e.target.value)
                      }
                      disabled={
                        !isEncodingOpen ||
                        activeTerm !== "midterm" ||
                        standing !== "active"
                      }
                      className="h-10 w-full rounded-xl border border-slate-300 bg-white px-2 text-center focus:outline-none focus:ring-2 focus:ring-[#003366] disabled:bg-slate-100 disabled:text-slate-400"
                    />
                  </div>

                  <div>
                    <p className="mb-1 text-sm text-slate-500">Finals</p>
                    <input
                      type="text"
                      value={studentData.finals || ""}
                      onChange={(e) =>
                        handleChange(student.id, "finals", e.target.value)
                      }
                      disabled={
                        !isEncodingOpen ||
                        activeTerm !== "finals" ||
                        standing !== "active"
                      }
                      className="h-10 w-full rounded-xl border border-slate-300 bg-white px-2 text-center focus:outline-none focus:ring-2 focus:ring-[#003366] disabled:bg-slate-100 disabled:text-slate-400"
                    />
                  </div>

                  <div>
                    <p className="text-sm text-slate-500">Final Grade</p>
                    <p className="font-bold text-[#003366]">{final}</p>
                  </div>

                  <div>
                    <p className="text-sm text-slate-500">Grade Equivalent</p>
                    <p className="font-bold text-[#003366]">
                      {final !== "-" && !isNaN(final)
                        ? getGradeEquivalent(final)
                        : final}
                    </p>
                  </div>

                  <div>
                    <p className="text-sm text-slate-500">Status</p>
                    <p
                      className={`font-semibold ${
                        status === "Passed"
                          ? "text-green-600"
                          : status === "Failed"
                          ? "text-red-600"
                          : "text-slate-500"
                      }`}
                    >
                      {status}
                    </p>
                  </div>

                  <div>
                    <p className="mb-1 text-sm text-slate-500">Student Status</p>
                    <select
                      value={standing}
                      onChange={(e) =>
                        handleStandingChange(student.id, e.target.value)
                      }
                      disabled={!isEncodingOpen}
                      className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm disabled:bg-slate-100 disabled:text-slate-400"
                    >
                      <option value="active">Active</option>
                      <option value="dropped">Dropped (D)</option>
                      <option value="unofficially_dropped">Unofficial Dropped (UD)</option>
                      <option value="withdrawn">Withdrawn (W)</option>
                      <option value="incomplete">Incomplete (INC)</option>
                    </select>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="hidden overflow-x-auto md:block">
          <table className="w-full min-w-[900px] table-fixed">
            <colgroup>
              <col className="w-[9%]" />
              <col className="w-[18%]" />
              <col className="w-[12%]" />
              <col className="w-[12%]" />
              <col className="w-[12%]" />
              <col className="w-[14%]" />
              <col className="w-[10%]" />
              <col className="w-[13%]" />
              <col className="w-[10%]" />
            </colgroup>
            <thead>
              <tr className="border-b-4 border-yellow-400 bg-[#003b78] text-white">
                <th className="px-6 py-4 text-left text-[15px] font-bold uppercase tracking-wide">
                  Student ID
                </th>
                <th className="px-6 py-4 text-left text-[15px] font-bold uppercase tracking-wide">
                  Student Name
                </th>
                <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">
                  Midterm <span className="font-normal text-slate-300">(60-100)</span>
                </th>
                <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">
                  Finals <span className="font-normal text-slate-300">(60-100)</span>
                </th>
                <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">
                  Final Grade
                </th>
                <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">
                  Grade Equivalent
                </th>
                <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">
                  Status
                </th>
                <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">
                  Student Status
                </th>
                <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">
                  Remarks
                </th>
              </tr>
            </thead>

            <tbody>
              {visibleStudents.map((student) => (
                <StudentRow
                  key={student.id}
                  student={student}
                  grades={grades}
                  activeTerm={activeTerm}
                  isEncodingOpen={isEncodingOpen}
                  handleChange={handleChange}
                  toggleFlagStudent={toggleFlagStudent}
                  handleStandingChange={handleStandingChange}
                />
              ))}
            </tbody>
          </table>
        </div>
        {!visibleStudents.length ? (
          <div className="border-t border-slate-200 bg-slate-50 px-4 py-8 text-center text-sm text-slate-500">
            No students match your search.
          </div>
        ) : null}
      </div>

      <BulkUploadModal
        isOpen={showBulkUpload}
        onClose={() => setShowBulkUpload(false)}
        sectionData={selectedSection}
        systemTerm={systemTerm}
        isEncodingOpen={isEncodingOpen}
        onUpload={handleBulkUpload}
      />
    </div>
  );
};

export default GradingTable;
