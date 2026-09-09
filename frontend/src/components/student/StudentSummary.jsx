const StudentSummary = ({ totalUnits, gwa, isDeansLister, failedSubjectsCount, semesterLabel = "Semester Grades" }) => {
  return (
    <div className="mx-4 mt-5 md:mx-6">
      {failedSubjectsCount === 2 && (
        <div className="mb-4 rounded-xl border border-yellow-200 bg-yellow-50 p-4 text-yellow-800 shadow-sm">
          <p className="font-semibold">Warning: Academic Standing Alert</p>
          <p className="mt-1 text-sm">
            You currently have 2 failed subjects. Please be advised that accumulating 3 or more failed subjects may lead to academic probation or dismissal. We encourage you to seek academic counseling and support.
          </p>
        </div>
      )}

      {failedSubjectsCount >= 3 && (
        <div className="mb-4 rounded-xl border border-red-200 bg-red-50 p-4 text-red-800 shadow-sm">
          <p className="font-semibold">Urgent: Academic Dismissal Risk</p>
          <p className="mt-1 text-sm">
            You have 3 or more failed subjects. This academic standing may result in dismissal from the program. Please proceed to the Office of the Registrar immediately for assistance and guidance on your academic status.
          </p>
        </div>
      )}

      <div className="flex flex-col gap-4 rounded-xl bg-[#003366] p-4 text-white md:flex-row md:items-center md:justify-between md:p-6">
        <div>
          <h2 className="text-base font-bold md:text-lg">{semesterLabel}</h2>
        </div>

        <div className="flex flex-wrap items-center gap-3 md:gap-4">
          {isDeansLister && (
            <div className="rounded-lg bg-green-600 px-4 py-2 font-bold">
              Dean&apos;s Lister
            </div>
          )}

          <div className="rounded-lg bg-white/20 px-4 py-2 text-center">
            <p className="text-xs">Total Units</p>
            <p className="font-bold">{totalUnits}</p>
          </div>

          <div className="rounded-lg bg-yellow-400 px-4 py-2 text-center font-bold text-[#003366]">
            <p className="text-xs">GWA</p>
            <p>{gwa}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StudentSummary;
