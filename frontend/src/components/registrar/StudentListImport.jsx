import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  STUDENT_BATCHES_KEY,
  STUDENT_SUBMISSION_LOGS_KEY,
  buildStudentCsvContent,
  downloadCsvFile,
  parseStudentIdSpreadsheet,
  syncSectionedStudentsToStorage,
} from "../../utils/studentSectioningHelpers";
import { downloadTemplateButtonClass } from "../shared/downloadButtonStyles";
import { pushSectioningSharedState } from "../../utils/sharedClientState";

const buildRegistrarSectioningName = () => "Registrar Sectioning Office";
const CURRENT_YEAR = new Date().getFullYear();

const getStoredSubmissionLogs = () => {
  const saved = localStorage.getItem(STUDENT_SUBMISSION_LOGS_KEY);
  return saved ? JSON.parse(saved) : [];
};

export function StudentSubmissionLogs() {
  const [isViewingLogs, setIsViewingLogs] = useState(false);
  const submissionLogs = isViewingLogs ? getStoredSubmissionLogs() : [];

  return (
    <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h3 className="text-xl font-bold text-[#003366]">
            Submission Logs
          </h3>
          
        </div>

        <button
          type="button"
          onClick={() => setIsViewingLogs((current) => !current)}
          className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d]"
        >
          {isViewingLogs ? "Hide Submission Logs" : "View Submission Logs"}
        </button>
      </div>

      {isViewingLogs ? (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="bg-[#003366] text-white">
                <th className="px-4 py-3 text-left text-sm">Department</th>
                <th className="px-4 py-3 text-left text-sm">Batch Year</th>
                <th className="px-4 py-3 text-left text-sm">File</th>
                <th className="px-4 py-3 text-left text-sm">Students</th>
                <th className="px-4 py-3 text-left text-sm">Workspace</th>
                <th className="px-4 py-3 text-left text-sm">Imported At</th>
                <th className="px-4 py-3 text-left text-sm">Status</th>
              </tr>
            </thead>

            <tbody>
              {submissionLogs.length > 0 ? (
                submissionLogs.map((log) => (
                  <tr key={log.id} className="border-b bg-white">
                    <td className="px-4 py-3">{log.program}</td>
                    <td className="px-4 py-3">{log.batchYear}</td>
                    <td className="px-4 py-3">{log.fileName}</td>
                    <td className="px-4 py-3">{log.totalStudents}</td>
                    <td className="px-4 py-3">{log.submittedTo}</td>
                    <td className="px-4 py-3">
                      {new Date(log.submittedAt).toLocaleString("en-US")}
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded-full bg-emerald-100 px-3 py-1 text-xs font-semibold text-emerald-700">
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-slate-500">
                    No submission logs yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

function StudentListImport({ selectedProgram = "", onImportComplete }) {
  const [selectedBatchYear, setSelectedBatchYear] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [isYearPickerOpen, setIsYearPickerOpen] = useState(false);
  const [yearPickerAnchor, setYearPickerAnchor] = useState(CURRENT_YEAR);
  const yearPickerRef = useRef(null);

  const [submissionBatches, setSubmissionBatches] = useState(() => {
    const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
    return saved ? JSON.parse(saved) : [];
  });

  const [submissionLogs, setSubmissionLogs] = useState(() => {
    const saved = localStorage.getItem(STUDENT_SUBMISSION_LOGS_KEY);
    return saved ? JSON.parse(saved) : [];
  });

  useEffect(() => {
    if (!isYearPickerOpen) return;

    const handleOutsideClick = (event) => {
      if (yearPickerRef.current?.contains(event.target)) return;
      setIsYearPickerOpen(false);
    };

    document.addEventListener("mousedown", handleOutsideClick);

    return () => {
      document.removeEventListener("mousedown", handleOutsideClick);
    };
  }, [isYearPickerOpen]);

  useEffect(() => {
    const handleSharedStateChanged = (event) => {
      const keys = event.detail?.keys || [];

      try {
        if (keys.includes(STUDENT_BATCHES_KEY)) {
          const saved = localStorage.getItem(STUDENT_BATCHES_KEY);
          setSubmissionBatches(saved ? JSON.parse(saved) : []);
        }

        if (keys.includes(STUDENT_SUBMISSION_LOGS_KEY)) {
          const saved = localStorage.getItem(STUDENT_SUBMISSION_LOGS_KEY);
          setSubmissionLogs(saved ? JSON.parse(saved) : []);
        }
      } catch (error) {
        console.warn("Failed to refresh imported students from shared state.", error);
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

  const yearOptions = useMemo(
    () => Array.from({ length: 12 }, (_, index) => String(yearPickerAnchor + index)),
    [yearPickerAnchor]
  );

  const openYearPicker = () => {
    const resolvedYear = Math.max(Number(selectedBatchYear) || CURRENT_YEAR, CURRENT_YEAR);
    setYearPickerAnchor(resolvedYear);
    setIsYearPickerOpen(true);
  };

  const handleYearInputChange = (event) => {
    const numericValue = event.target.value.replace(/\D/g, "").slice(0, 4);

    if (numericValue.length === 4) {
      const resolvedYear = Math.max(Number(numericValue), CURRENT_YEAR);
      setSelectedBatchYear(String(resolvedYear));
      setYearPickerAnchor(resolvedYear);
      return;
    }

    setSelectedBatchYear(numericValue);
  };

  const handleYearSelect = (year) => {
    setSelectedBatchYear(year);
    setIsYearPickerOpen(false);
  };

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
  };

  const handleDownloadTemplate = () => {
    if (!selectedProgram || !selectedBatchYear) {
      alert("Please complete the department and batch year first.");
      return;
    }

    if (Number(selectedBatchYear) < CURRENT_YEAR) {
      alert(`Batch year cannot be earlier than ${CURRENT_YEAR}.`);
      return;
    }

    const templateRows = [
      {
        studentId: "26-0001",
        sex: "Male",
        lastName: "Dela Cruz",
        firstName: "Juan",
        middleInitial: "A",
      },
      {
        studentId: "26-0002",
        sex: "Female",
        lastName: "Santos",
        firstName: "Maria",
        middleInitial: "L",
      },
    ];

    downloadCsvFile(
      buildStudentCsvContent(templateRows, { includeYearLevel: false }),
      `${selectedProgram}-${selectedBatchYear}-student-list.csv`
    );
  };

  const handleImport = () => {
    if (!selectedProgram || !selectedBatchYear) {
      alert("Please complete the department and batch year first.");
      return;
    }

    if (!/^\d{4}$/.test(selectedBatchYear)) {
      alert("Batch year must be a 4-digit year.");
      return;
    }

    if (Number(selectedBatchYear) < CURRENT_YEAR) {
      alert(`Batch year cannot be earlier than ${CURRENT_YEAR}.`);
      return;
    }

    if (!selectedFile) {
      alert("Please choose the Excel CSV file first.");
      return;
    }

    if (!selectedFile.name.toLowerCase().endsWith(".csv")) {
      alert("Please upload the Excel CSV template in .csv format.");
      return;
    }

    const reader = new FileReader();

    reader.onload = (event) => {
      const text = event.target?.result;

      if (!text) {
        alert("Unable to read file.");
        return;
      }

      const parsedStudents = parseStudentIdSpreadsheet(text);

      if (parsedStudents.length === 0) {
        alert(
          "The file must contain Student ID, Sex, Last Name, First Name, and Middle Initial columns with valid rows."
        );
        return;
      }

      const submissionKey = [selectedProgram, selectedBatchYear].join("|");
      const submittedAt = new Date().toISOString();

      const nextBatch = {
        id: Date.now(),
        key: submissionKey,
        program: selectedProgram,
        batchYear: selectedBatchYear,
        submittedTo: buildRegistrarSectioningName(),
        fileName: selectedFile.name,
        submittedAt,
        status: "Imported",
        receivedCsvContent: buildStudentCsvContent(parsedStudents, {
          includeYearLevel: false,
        }),
        students: parsedStudents,
      };

      const updatedBatches = [
        ...submissionBatches.filter((batch) => batch.key !== submissionKey),
        nextBatch,
      ];

      const updatedLogs = [
        {
          id: Date.now(),
          program: selectedProgram,
          batchYear: selectedBatchYear,
          submittedTo: buildRegistrarSectioningName(),
          fileName: selectedFile.name,
          totalStudents: parsedStudents.length,
          submittedAt,
        status: "Imported",
        },
        ...submissionLogs,
      ];

      setSubmissionBatches(updatedBatches);
      setSubmissionLogs(updatedLogs);
      localStorage.setItem(STUDENT_BATCHES_KEY, JSON.stringify(updatedBatches));
      localStorage.setItem(
        STUDENT_SUBMISSION_LOGS_KEY,
        JSON.stringify(updatedLogs)
      );
      syncSectionedStudentsToStorage(updatedBatches);
      pushSectioningSharedState();
      onImportComplete?.(updatedBatches);

      setSelectedFile(null);
      alert("Student list imported for registrar sectioning successfully.");
    };

    reader.readAsText(selectedFile);
  };

  return (
      <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="mb-5">
          <h3 className="text-lg font-bold text-[#003366]">
            Import Student List
          </h3>
          <p className="mt-1 text-sm text-slate-500">
            Please upload one Excel CSV file per department containing student IDs, 
            sex, last names, first names, and middle initials. 
            This prepares the sectioning roster only. Create or re-enroll official
            student accounts from Student Enrollment before syncing a section.
          </p>
        </div>

        <div className="max-w-xs">
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-700">
              Batch Year
            </label>
            <div ref={yearPickerRef} className="relative">
              <input
                type="text"
                inputMode="numeric"
                value={selectedBatchYear}
                onFocus={openYearPicker}
                onClick={openYearPicker}
                onChange={handleYearInputChange}
                className="w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-sm outline-none focus:border-[#003366]"
                placeholder="Select Year"
              />

              {isYearPickerOpen ? (
                <div className="absolute left-0 top-[calc(100%+8px)] z-20 w-full min-w-[240px] rounded-2xl border border-slate-200 bg-white shadow-xl">
                  <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
                    <button
                      type="button"
                      onClick={() =>
                        setYearPickerAnchor((current) =>
                          Math.max(current - 12, CURRENT_YEAR)
                        )
                      }
                      disabled={yearPickerAnchor <= CURRENT_YEAR}
                      className="text-xl font-light text-slate-500 transition hover:text-[#003366] disabled:cursor-not-allowed disabled:text-slate-300"
                    >
                      ‹
                    </button>

                    <p className="text-sm font-semibold text-slate-700">
                      {yearPickerAnchor}
                    </p>

                    <button
                      type="button"
                      onClick={() => setYearPickerAnchor((current) => current + 12)}
                      className="text-xl font-light text-slate-500 transition hover:text-[#003366]"
                    >
                      ›
                    </button>
                  </div>

                  <div className="grid grid-cols-3 gap-1.5 p-3">
                    {yearOptions.map((year) => {
                      const isSelected = selectedBatchYear === year;

                      return (
                        <button
                          key={year}
                          type="button"
                          onClick={() => handleYearSelect(year)}
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
        </div>

        <div className="mt-6 rounded-3xl border-2 border-dashed border-slate-300 bg-slate-50 p-6">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_auto_auto] lg:items-end">
            <div>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <label className="shrink-0 text-sm font-medium text-slate-700">
                  Upload Excel CSV File
                </label>
                <input
                  type="file"
                  accept=".csv"
                  onChange={handleFileChange}
                  className="block w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-sm text-slate-500 file:mr-10 file:border-0 file:border-r file:border-solid file:border-slate-300 file:bg-transparent file:pr-4 file:text-sm file:font-semibold file:text-slate-500"
                />
              </div>
              <p className="mt-2 text-sm text-slate-500">
                {selectedFile
                  ? `Selected file: ${selectedFile.name}`
                  : "Template Format: Student ID, Sex, Last Name, First Name, Middle Initial saved from Excel as CSV"}
              </p>
            </div>

            <button
              onClick={handleDownloadTemplate}
              className={downloadTemplateButtonClass}
            >
              Download Template
            </button>

            <button
              onClick={handleImport}
              className="rounded-2xl bg-[#003366] px-6 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d]"
            >
              Import Roster for Sectioning
            </button>
          </div>
        </div>
      </div>
  );
}

export default StudentListImport;
