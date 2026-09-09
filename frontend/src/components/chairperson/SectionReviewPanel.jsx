import React, { useMemo, useState } from "react";
import {
  computeGradeStatus,
  getReviewStatusClasses,
  getReviewStatusLabel,
} from "../../utils/chairpersonHelpers";
import { getGradeEquivalent } from "../../utils/gradingHelpers";

const formatLogDate = (value) => {
  if (!value) return "--";

  return new Date(value).toLocaleString();
};

const getEncodingTermLabel = (term = "") =>
  String(term || "").toLowerCase() === "finals" ? "Finals" : "Midterm";

function SectionReviewPanel({
  selectedSection,
  activeTerm,
  onSendBack,
  onApprove,
  onSubmitToRegistrar,
  onViewIpfs,
}) {
  const [draftNotes, setDraftNotes] = useState({});
  const note = selectedSection
    ? draftNotes[selectedSection.reviewKey] ?? selectedSection.reviewNote ?? ""
    : "";

  const rows = useMemo(() => {
    if (!selectedSection) return [];

    return selectedSection.students.map((student) => {
      const record =
        selectedSection.grades[student.studentId] ||
        selectedSection.grades[student.id] ||
        {};

      const numericMidterm = Number(record.midterm);
      const numericFinals = Number(record.finals);
      const finalAverage =
        Number.isFinite(numericMidterm) &&
        Number.isFinite(numericFinals) &&
        numericMidterm > 0 &&
        numericFinals > 0
          ? ((numericMidterm + numericFinals) / 2).toFixed(2)
          : "-";

      const gradeEquivalent =
        finalAverage !== "-" && !Number.isNaN(Number(finalAverage))
          ? getGradeEquivalent(Number(finalAverage))
          : finalAverage;

      return {
        id: student.studentNo || student.studentId || student.id,
        name:
          student.fullName ||
          `${student.lastName || ""}, ${student.firstName || ""}`.replace(
            /^,\s*/,
            ""
          ) ||
          student.studentId ||
          "-",
        midterm: record.midterm || "-",
        finals: record.finals || "-",
        finalAverage,
        gradeEquivalent,
        standing: record.standing || "active",
        flagged: !!record.flagged,
        status: computeGradeStatus(record, activeTerm),
      };
    });
  }, [selectedSection, activeTerm]);

  const summary = useMemo(() => {
    return rows.reduce(
      (acc, row) => {
        const normalizedStanding = String(row.standing || "").toLowerCase();
        const numericFinalAverage = Number(row.finalAverage);

        if (Number.isFinite(numericFinalAverage)) {
          if (numericFinalAverage >= 75) acc.passed += 1;
          else acc.failed += 1;
        }

        if (normalizedStanding === "dropped") acc.d += 1;
        if (normalizedStanding === "unofficially_dropped") acc.ud += 1;
        if (normalizedStanding === "withdrawn") acc.w += 1;
        if (normalizedStanding === "incomplete") acc.inc += 1;
        if (row.flagged) acc.flagged += 1;

        return acc;
      },
      {
        passed: 0,
        failed: 0,
        d: 0,
        ud: 0,
        w: 0,
        inc: 0,
        flagged: 0,
      }
    );
  }, [rows]);

  if (!selectedSection) {
    return (
      <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-10 text-center shadow-sm">
        <h3 className="text-xl font-semibold text-[#003366]">Section Review Panel</h3>
        
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-blue-200 bg-blue-50 p-6 shadow-sm">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h3 className="text-lg font-bold text-blue-900">
              Attached Grading Sheet (IPFS Vault)
            </h3>
            <p className="mt-1 text-sm text-blue-700">
              {selectedSection.ipfsCid
                ? `Open the encrypted grading sheet attached for ${selectedSection.sectionName}.`
                : `No IPFS attachment was found for ${selectedSection.sectionName} yet.`}
            </p>
          </div>

          <button
            type="button"
            onClick={() => selectedSection.ipfsCid && onViewIpfs?.(selectedSection.ipfsCid)}
            disabled={!selectedSection.ipfsCid}
            className={`rounded-xl px-5 py-2.5 text-sm font-bold shadow-sm transition ${
              selectedSection.ipfsCid
                ? "bg-blue-600 text-white hover:bg-blue-700"
                : "bg-slate-300 text-slate-600"
            }`}
          >
            {selectedSection.ipfsCid ? "Decrypt & View" : "Unavailable"}
          </button>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h3 className="text-xl font-bold text-[#003366]">Section Review Details</h3>
            <p className="mt-1 text-sm text-slate-500">
              {selectedSection.facultyName} • {selectedSection.sectionName} •{" "}
              {selectedSection.semester} • {getEncodingTermLabel(activeTerm)}
            </p>
          </div>

          <span
            className={`inline-flex w-fit rounded-full px-4 py-2 text-sm font-semibold ${getReviewStatusClasses(
              selectedSection.reviewStatus
            )}`}
          >
            {getReviewStatusLabel(selectedSection.reviewStatus)}
          </span>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-4">
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">Department</p>
            <p className="mt-1 font-semibold text-slate-800">{selectedSection.department}</p>
          </div>
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">Students</p>
            <p className="mt-1 font-semibold text-slate-800">{selectedSection.totalStudents}</p>
          </div>
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">Encoded</p>
            <p className="mt-1 font-semibold text-slate-800">
              {selectedSection.encodedCount} / {selectedSection.totalStudents}
            </p>
          </div>
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">Progress</p>
            <p className="mt-1 font-semibold text-slate-800">{selectedSection.progress}%</p>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-7">
          <div className="rounded-xl bg-emerald-50 p-4">
            <p className="text-sm text-emerald-700">Passed</p>
            <p className="mt-1 font-semibold text-emerald-900">{summary.passed}</p>
          </div>
          <div className="rounded-xl bg-rose-50 p-4">
            <p className="text-sm text-rose-700">Failed</p>
            <p className="mt-1 font-semibold text-rose-900">{summary.failed}</p>
          </div>
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">D</p>
            <p className="mt-1 font-semibold text-slate-800">{summary.d}</p>
          </div>
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">UD</p>
            <p className="mt-1 font-semibold text-slate-800">{summary.ud}</p>
          </div>
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">W</p>
            <p className="mt-1 font-semibold text-slate-800">{summary.w}</p>
          </div>
          <div className="rounded-xl bg-amber-50 p-4">
            <p className="text-sm text-amber-700">INC</p>
            <p className="mt-1 font-semibold text-amber-900">{summary.inc}</p>
          </div>
          <div className="rounded-xl bg-red-50 p-4">
            <p className="text-sm text-red-700">Flagged</p>
            <p className="mt-1 font-semibold text-red-900">{summary.flagged}</p>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h3 className="text-lg font-bold text-[#003366]">Submitted Grades</h3>
            
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="bg-[#003366] text-white">
                <th className="px-4 py-3 text-left text-sm">Student ID</th>
                <th className="px-4 py-3 text-left text-sm">Student Name</th>
                <th className="px-4 py-3 text-left text-sm">Midterm</th>
                <th className="px-4 py-3 text-left text-sm">Finals</th>
                <th className="px-4 py-3 text-left text-sm">Final Grade</th>
                <th className="px-4 py-3 text-left text-sm">Equivalent</th>
                <th className="px-4 py-3 text-left text-sm">Standing</th>
                <th className="px-4 py-3 text-left text-sm">Status</th>
                <th className="px-4 py-3 text-left text-sm">Remarks</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className={`border-b ${row.flagged ? "bg-red-50" : "bg-white"}`}>
                  <td className="px-4 py-3">{row.id}</td>
                  <td className="px-4 py-3 font-medium text-slate-800">{row.name}</td>
                  <td className="px-4 py-3">{row.midterm}</td>
                  <td className="px-4 py-3">{row.finals}</td>
                  <td className="px-4 py-3 font-semibold text-slate-800">{row.finalAverage}</td>
                  <td className="px-4 py-3">{row.gradeEquivalent}</td>
                  <td className="px-4 py-3 capitalize">
                    {String(row.standing).replaceAll("_", " ")}
                  </td>
                  <td className="px-4 py-3 capitalize">
                    {String(row.status).replaceAll("_", " ")}
                  </td>
                  <td className="px-4 py-3">{row.flagged ? "Flagged by faculty" : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <h3 className="text-lg font-bold text-[#003366]">Chairperson Decision</h3>
        

        <div className="mt-4">
          <label className="mb-2 block text-sm font-medium text-slate-700">Review Note</label>
          <textarea
            value={note}
            onChange={(event) => {
              if (!selectedSection) return;

              setDraftNotes((prev) => ({
                ...prev,
                [selectedSection.reviewKey]: event.target.value,
              }));
            }}
            placeholder="Enter the discrepancy, correction request, or approval remark here..."
            className="min-h-[120px] w-full rounded-xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-[#003366]"
          />
        </div>

        <div className="mt-6 flex flex-col gap-3 md:flex-row">
          <button
            onClick={() => onSendBack(note)}
            disabled={!note.trim() || selectedSection.reviewStatus === "forwarded"}
            className="rounded-xl bg-red-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-red-600 disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            Send Back to Faculty
          </button>
          <button
            onClick={() => onApprove(note)}
            disabled={selectedSection.reviewStatus === "forwarded"}
            className="rounded-xl bg-emerald-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            Approve Section
          </button>
          <button
            onClick={() => onSubmitToRegistrar(note)}
            disabled={selectedSection.reviewStatus !== "approved"}
            className="rounded-xl bg-[#003366] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#00264d] disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            Forward to Registrar
          </button>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <h3 className="text-lg font-bold text-[#003366]">Decision Log</h3>
        

        <div className="mt-4 space-y-3">
          {(selectedSection.reviewLogs || []).length ? (
            [...selectedSection.reviewLogs].reverse().map((log, index) => (
              <div
                key={`${log.timestamp}-${index}`}
                className="rounded-xl border border-slate-200 bg-slate-50 p-4"
              >
                <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <span
                    className={`inline-flex w-fit rounded-full px-3 py-1 text-xs font-semibold ${getReviewStatusClasses(
                      log.status
                    )}`}
                  >
                    {getReviewStatusLabel(log.status)}
                  </span>
                  <p className="text-xs text-slate-500">
                    {formatLogDate(log.timestamp)}
                  </p>
                </div>
                <p className="mt-2 text-sm font-semibold text-slate-700">
                  {log.actor || "Chairperson"}
                </p>
                {log.note ? (
                  <p className="mt-1 text-sm text-slate-600">{log.note}</p>
                ) : (
                  <p className="mt-1 text-sm text-slate-400">No note added.</p>
                )}
              </div>
            ))
          ) : (
            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-5 text-center text-sm text-slate-500">
              No chairperson decision has been recorded yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default SectionReviewPanel;
