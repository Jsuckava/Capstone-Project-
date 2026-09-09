import React from "react";

import {
  formatName,
  getGradeEquivalent,
  computeFinal,
  getStatus,
} from "../../utils/gradingHelpers";

const StudentRow = ({
  student,
  grades,
  activeTerm,
  isEncodingOpen,
  handleChange,
  toggleFlagStudent,
  handleStandingChange,
}) => {
  const studentData = grades[student.id] || {};
  const standing = studentData.standing || "active";
  const final = computeFinal(grades, student.id, activeTerm);
  const status = getStatus(final, activeTerm);
  const isFlagged = studentData.flagged;

  return (
    <tr
      className={`border-b border-slate-200 last:border-b-0 ${
        isFlagged ? "bg-red-50" : ""
      }`}
    >
      <td className="px-6 py-4">{student.id}</td>

      <td className="px-6 py-4">
        <div className="flex items-center gap-2">
          {isFlagged && <span className="text-red-500"></span>}
          <span>{formatName(student)}</span>
        </div>
      </td>

      <td className="px-6 py-4 text-center">
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
          className="h-10 w-24 rounded-xl border border-slate-300 bg-white px-2 text-center focus:outline-none focus:ring-2 focus:ring-[#003366] disabled:bg-slate-100 disabled:text-slate-400"
        />
      </td>

      <td className="px-6 py-4 text-center">
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
          className="h-10 w-24 rounded-xl border border-slate-300 bg-white px-2 text-center focus:outline-none focus:ring-2 focus:ring-[#003366] disabled:bg-slate-100 disabled:text-slate-400"
        />
      </td>

      <td className="px-6 py-4 text-center font-bold">{final}</td>

      <td className="px-6 py-4 text-center font-bold">
        {final !== "-" && !isNaN(final) ? getGradeEquivalent(final) : final}
      </td>

      <td
        className={`px-6 py-4 text-center font-semibold ${
          status === "Passed"
            ? "text-green-600"
            : status === "Failed"
            ? "text-red-600"
            : "text-slate-500"
        }`}
      >
        {status}
      </td>

      <td className="px-6 py-4 text-center">
        <select
          value={standing}
          onChange={(e) => handleStandingChange(student.id, e.target.value)}
          disabled={!isEncodingOpen}
          className="rounded-lg border border-slate-300 px-3 py-2 text-sm disabled:bg-slate-100 disabled:text-slate-400"
        >
          <option value="active">Active</option>
          <option value="dropped">Dropped (D)</option>
          <option value="unofficially_dropped">Unofficial Dropped (UD)</option>
          <option value="withdrawn">Withdrawn (W)</option>
          <option value="incomplete">Incomplete (INC)</option>
        </select>
      </td>

      <td className="px-6 py-4 text-center">
        <button
          type="button"
          onClick={() => toggleFlagStudent(student.id)}
          disabled={!isEncodingOpen}
          className={`rounded-lg px-3 py-2 text-sm font-bold transition ${
            isFlagged
              ? "bg-red-100 text-red-600 hover:bg-red-200"
              : "bg-slate-100 text-slate-600 hover:bg-slate-200"
          } disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400`}
        >
          {isFlagged ? "Unflag" : "Flag"}
        </button>
      </td>
    </tr>
  );
};

export default StudentRow;
