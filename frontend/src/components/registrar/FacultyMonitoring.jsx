import React, { useMemo } from "react";
import {
  buildAssignmentStorageKey,
  CHAIRPERSON_REVIEW_KEY,
  getReviewStatusClasses,
  getReviewStatusLabel,
} from "../../utils/chairpersonHelpers";

const formatDateTime = (value) => {
  if (!value) return "--";

  return new Date(value).toLocaleString();
};

function FacultyMonitoring() {
  const reviewRows = useMemo(() => {
    const savedReviews = localStorage.getItem(CHAIRPERSON_REVIEW_KEY);
    const reviewData = savedReviews ? JSON.parse(savedReviews) : {};
    const savedAssignments = localStorage.getItem("registrarAssignments");
    const assignments = savedAssignments ? JSON.parse(savedAssignments) : [];

    return Object.entries(reviewData)
      .map(([reviewKey, review]) => {
        const assignment =
          assignments.find(
            (item) =>
              buildAssignmentStorageKey(item) === review.assignmentKey ||
              item.assignmentKey === review.assignmentKey
          ) || {};

        return {
          reviewKey,
          facultyName: review.facultyName || assignment.facultyName || "--",
          department: review.department || assignment.program || "--",
          sectionName: review.sectionName || assignment.sectionName || "--",
          subjectCode: review.subjectCode || assignment.subjectCode || "--",
          schoolYear: review.schoolYear || assignment.schoolYear || "--",
          semester: review.semester || assignment.semester || "--",
          status: review.status || "pending",
          note: review.note || "",
          lastUpdated: review.lastUpdated,
          logs: review.logs || [],
        };
      })
      .sort(
        (left, right) =>
          new Date(right.lastUpdated || 0) - new Date(left.lastUpdated || 0)
      );
  }, []);

  const stats = useMemo(
    () => ({
      approved: reviewRows.filter((row) => row.status === "approved").length,
      returned: reviewRows.filter((row) => row.status === "returned").length,
      forwarded: reviewRows.filter((row) => row.status === "forwarded").length,
      submitted: reviewRows.filter((row) => row.status === "submitted").length,
    }),
    [reviewRows]
  );

  return (
    <section className="space-y-6">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        {[
          ["Submitted", stats.submitted],
          ["Approved", stats.approved],
          ["Returned", stats.returned],
          ["Forwarded", stats.forwarded],
        ].map(([label, count]) => (
          <div
            key={label}
            className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
          >
            <p className="text-sm font-semibold text-slate-500">{label}</p>
            <p className="mt-2 text-3xl font-bold text-[#003366]">{count}</p>
          </div>
        ))}
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div>
          <h3 className="text-xl font-bold text-[#003366]">
            Chairperson Review Log
          </h3>
          
        </div>

        <div className="mt-6 overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr className="bg-[#003366] text-white">
                <th className="px-4 py-3 text-left text-sm">Section</th>
                <th className="px-4 py-3 text-left text-sm">Faculty</th>
                <th className="px-4 py-3 text-left text-sm">Subject</th>
                <th className="px-4 py-3 text-left text-sm">Status</th>
                <th className="px-4 py-3 text-left text-sm">Latest Note</th>
                <th className="px-4 py-3 text-left text-sm">Updated</th>
              </tr>
            </thead>
            <tbody>
              {reviewRows.length ? (
                reviewRows.map((row) => (
                  <tr key={row.reviewKey} className="border-b bg-white">
                    <td className="px-4 py-3">
                      <p className="font-semibold text-slate-800">
                        {row.sectionName}
                      </p>
                      <p className="text-xs text-slate-500">
                        {row.department} | {row.schoolYear} | {row.semester}
                      </p>
                    </td>
                    <td className="px-4 py-3 text-slate-700">
                      {row.facultyName}
                    </td>
                    <td className="px-4 py-3 text-slate-700">
                      {row.subjectCode}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${getReviewStatusClasses(
                          row.status
                        )}`}
                      >
                        {getReviewStatusLabel(row.status)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-600">
                      {row.note || "No note added."}
                      {row.logs.length > 1 ? (
                        <span className="mt-1 block text-xs text-slate-400">
                          {row.logs.length} total decision logs
                        </span>
                      ) : null}
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-600">
                      {formatDateTime(row.lastUpdated)}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="py-8 text-center text-slate-500">
                    No chairperson review activity has reached the registrar yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

export default FacultyMonitoring;
