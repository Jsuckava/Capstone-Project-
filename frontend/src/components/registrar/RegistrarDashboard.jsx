import React, { useMemo } from "react";
import { CHAIRPERSON_REVIEW_KEY } from "../../utils/chairpersonHelpers";

function RegistrarDashboard() {
  const reviewRecords = useMemo(() => {
    const saved = localStorage.getItem(CHAIRPERSON_REVIEW_KEY);
    return Object.values(saved ? JSON.parse(saved) : {});
  }, []);

  const overviewCards = [
    {
      title: "Forwarded by Chairperson",
      value: reviewRecords.filter((item) => item.status === "forwarded").length,
      subtitle: "Sections already endorsed to the registrar",
    },
    {
      title: "Approved by Chairperson",
      value: reviewRecords.filter((item) => item.status === "approved").length,
      subtitle: "Sections approved but not yet forwarded",
    },
    {
      title: "Returned to Faculty",
      value: reviewRecords.filter((item) => item.status === "returned").length,
      subtitle: "Sections sent back for correction",
    },
    {
      title: "Submitted to Chairperson",
      value: reviewRecords.filter((item) => item.status === "submitted").length,
      subtitle: "Sections still under chairperson review",
    },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {overviewCards.map((card) => (
          <div
            key={card.title}
            className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
          >
            <p className="text-sm font-medium text-slate-500">{card.title}</p>
            <h3 className="mt-2 text-3xl font-bold text-[#003366]">
              {card.value}
            </h3>
            <p className="mt-2 text-sm text-slate-400">{card.subtitle}</p>
          </div>
        ))}
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h3 className="text-xl font-bold text-[#003366]">
              Chairperson to Registrar Flow
            </h3>
            
          </div>

          <div className="inline-flex w-fit rounded-full bg-blue-100 px-4 py-2 text-sm font-semibold text-blue-700">
            Workflow Tracking
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">Forwarded Sections</p>
            <p className="mt-1 font-semibold text-slate-800">
              {reviewRecords.filter((item) => item.status === "forwarded").length}
            </p>
          </div>

          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">Awaiting Registrar</p>
            <p className="mt-1 font-semibold text-slate-800">
              {reviewRecords.filter((item) => item.status === "approved").length}
            </p>
          </div>

          <div className="rounded-xl bg-slate-50 p-4">
            <p className="text-sm text-slate-500">Needs Faculty Revision</p>
            <p className="mt-1 font-semibold text-slate-800">
              {reviewRecords.filter((item) => item.status === "returned").length}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default RegistrarDashboard;
