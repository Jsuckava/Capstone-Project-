import { getPLVPoint } from "../../utils/studentHelpers";

const getSubjectDisplay = (subject) => {
  const midterm = subject.midterm || "-";
  const finals = subject.finals || "-";
  const finalGrade =
    subject.finalGrade ||
    (Number(subject.midterm) && Number(subject.finals)
      ? ((Number(subject.midterm) + Number(subject.finals)) / 2).toFixed(2)
      : "-");
  const equivalent =
    subject.equivalent ||
    (finalGrade !== "-" && !Number.isNaN(Number(finalGrade))
      ? getPLVPoint(Number(finalGrade), Number(finalGrade)).toFixed(2)
      : finalGrade);
  const remarks =
    subject.remarks ||
    (finalGrade !== "-" && !Number.isNaN(Number(finalGrade))
      ? Number(finalGrade) >= 75
        ? "Passed"
        : "Failed"
      : "Incomplete");

  return {
    code: subject.code || subject.subjectCode || "--",
    name: subject.name || subject.subjectTitle || "--",
    units: subject.units || 0,
    midterm,
    finals,
    finalGrade,
    equivalent,
    remarks,
    passed: String(remarks).toLowerCase() === "passed",
  };
};

const StudentGradesTable = ({ subjects }) => {
  return (
    <div className="mx-4 mt-5 md:mx-6">
      <div className="space-y-3 md:hidden">
        {subjects.map((sub, index) => {
          const display = getSubjectDisplay(sub);

          return (
            <div
              key={index}
              className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
            >
              <div className="mb-3">
                <p className="text-sm text-slate-500">Code</p>
                <p className="font-semibold text-[#003366]">{display.code}</p>
              </div>

              <div className="mb-3">
                <p className="text-sm text-slate-500">Subject Title</p>
                <p className="font-semibold">{display.name}</p>
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p className="text-slate-500">Units</p>
                  <p className="font-semibold">{display.units}</p>
                </div>

                <div>
                  <p className="text-slate-500">Grade Equivalent</p>
                  <p className="font-semibold text-[#003366]">
                    {display.equivalent}
                  </p>
                </div>

                <div>
                  <p className="text-slate-500">Remarks</p>
                  <span
                    className={`inline-block rounded-full px-3 py-1 text-xs font-bold ${
                      display.passed
                        ? "bg-green-100 text-green-600"
                        : "bg-red-100 text-red-600"
                    }`}
                  >
                    {String(display.remarks).toUpperCase()}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="hidden overflow-x-auto rounded-xl bg-white shadow md:block">
        <table className="w-full min-w-[800px] text-sm">
          <thead className="bg-[#003366] text-white">
            <tr>
              <th className="p-4 text-left">Code</th>
              <th className="p-4 text-left">Subject Title</th>
              <th className="p-4 text-center">Units</th>
              <th className="p-4 text-center">Grade Equivalent</th>
              <th className="p-4 text-center">Remarks</th>
            </tr>
          </thead>

          <tbody>
            {subjects.map((sub, index) => {
              const display = getSubjectDisplay(sub);

              return (
                <tr
                  key={index}
                  className="border-b border-slate-200 hover:bg-slate-50"
                >
                  <td className="p-4 font-semibold text-[#003366]">{display.code}</td>
                  <td className="p-4">{display.name}</td>
                  <td className="p-4 text-center">{display.units}</td>
                  <td className="p-4 text-center font-bold text-[#003366]">
                    {display.equivalent}
                  </td>
                  <td className="p-4 text-center">
                    <span
                      className={`rounded-full px-3 py-1 text-xs font-bold ${
                        display.passed
                          ? "bg-green-100 text-green-600"
                          : "bg-red-100 text-red-600"
                      }`}
                    >
                      {String(display.remarks).toUpperCase()}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default StudentGradesTable;
