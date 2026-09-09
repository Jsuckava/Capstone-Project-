import React from "react";

function ChairpersonOverview({ metrics }) {
  const cards = [
    {
      title: "Faculty in Department",
      value: metrics.totalFaculty,
      subtitle: "Faculty members under chairperson monitoring",
    },
    {
      title: "Sections for Review",
      value: metrics.totalSections,
      subtitle: "Assigned sections awaiting monitoring or review",
    },
    {
      title: "Submitted Sections",
      value: metrics.submittedSections,
      subtitle: "Faculty submissions waiting for chairperson review",
    },
    {
      title: "Returned Sections",
      value: metrics.returnedSections,
      subtitle: "Sections sent back to faculty for correction",
    },
    {
      title: "Approved Sections",
      value: metrics.approvedSections,
      subtitle: "Sections approved and ready to forward to registrar",
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <div
          key={card.title}
          className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
        >
          <p className="text-sm font-medium text-slate-500">{card.title}</p>
          <h3 className="mt-2 text-3xl font-bold text-[#003366]">{card.value}</h3>
          <p className="mt-2 text-sm text-slate-400">{card.subtitle}</p>
        </div>
      ))}
    </div>
  );
}

export default ChairpersonOverview;
