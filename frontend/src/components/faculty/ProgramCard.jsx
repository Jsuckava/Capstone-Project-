import React from "react";
import ReviewStatusBanner from "../chairperson/ReviewStatusBanner";

const ProgramCard = ({
  sectionName,
  sectionData,
  onClick,
  progress = 0,
  reviewStatus = "pending",
  reviewNote = "",
  onSubmit,
}) => {
  const totalStudents = sectionData.students?.length || 0;
  const displaySchedule = sectionData.schedule || "Not Available";
  const displayDay = sectionData.day || "Not Available";
  const isStarted = progress > 0;
  const isCompleted = progress >= 100;
  const isReturned = reviewStatus === "returned";
  const isSubmitted = reviewStatus === "submitted";
  const isApproved = reviewStatus === "approved";
  const isForwarded = reviewStatus === "forwarded";

  const getSubmitLabel = () => {
    if (isForwarded) return "Sent to Registrar";
    if (isApproved) return "Approved by Chairperson";
    if (isSubmitted) return "Submitted to Chairperson";
    if (isReturned) return "Resubmit to Chairperson";
    return "Submit to Chairperson";
  };

  return (
    <div
      onClick={onClick}
      className="cursor-pointer rounded-3xl bg-white p-6 shadow-md transition hover:-translate-y-1 hover:shadow-xl"
    >
      <div className="mb-3 flex items-center justify-between">
        <span className="rounded-xl bg-blue-50 px-3 py-1 text-xs font-bold text-blue-500">
          {sectionData.subjectCode}
        </span>

        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${
              isCompleted ? "bg-emerald-500" : isStarted ? "bg-yellow-500" : "bg-red-500"
            }`}
          />

          <span
            className={`text-xs font-bold ${
              isCompleted
                ? "text-emerald-600"
                : isStarted
                ? "text-yellow-600"
                : "text-red-600"
            }`}
          >
            {isCompleted ? "Completed" : isStarted ? "In Progress" : "Not Started"}
          </span>
        </div>
      </div>

      <h2 className="mb-3 text-lg font-extrabold text-slate-800">
        {sectionData.subjectTitle}
      </h2>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="font-bold text-[#003366]">{sectionName}</span>
        <span className="rounded-lg bg-violet-50 px-3 py-1 text-xs text-violet-700">
          {sectionData.sectionCourse}
        </span>
      </div>

      <div className="mb-4 flex flex-wrap gap-2 text-xs">
        <span className="rounded-lg bg-slate-100 px-3 py-1">Units: {sectionData.units}</span>
        <span className="rounded-lg bg-slate-100 px-3 py-1">{displaySchedule}</span>
        <span className="rounded-lg bg-slate-100 px-3 py-1">{displayDay}</span>
      </div>

      <hr className="my-3 border-slate-200" />

      <div className="mb-4 flex justify-between text-sm text-slate-500">
        <span>Students: {totalStudents}</span>
        <span>SY: {sectionData.schoolYear || "--"}</span>
        <span>{sectionData.semester}</span>
      </div>

      <div className="mb-4">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Encoding Progress
          </span>

          <span
            className={`text-sm font-bold ${
              isCompleted ? "text-emerald-600" : isStarted ? "text-yellow-600" : "text-red-600"
            }`}
          >
            {progress}%
          </span>
        </div>

        <div className="h-2 overflow-hidden rounded-full bg-slate-100">
          <div
            className={`h-2 rounded-full ${
              isCompleted ? "bg-emerald-500" : isStarted ? "bg-yellow-500" : "bg-red-500"
            }`}
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      <ReviewStatusBanner reviewStatus={reviewStatus} reviewNote={reviewNote} />

      <div className="mt-4 flex flex-col gap-3">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onClick();
          }}
          className="h-12 rounded-xl bg-[#003366] font-bold text-white transition hover:bg-[#002244]"
        >
          {isStarted ? "View Grades" : "Encode Now"}
        </button>

        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onSubmit?.();
          }}
          disabled={!isCompleted || isSubmitted || isApproved || isForwarded}
          className="h-12 rounded-xl border border-green-200 bg-green-50 font-bold text-green-700 transition hover:bg-green-500 hover:text-white disabled:cursor-not-allowed disabled:border-slate-200 disabled:bg-slate-100 disabled:text-slate-400"
        >
          {getSubmitLabel()}
        </button>
      </div>
    </div>
  );
};

export default ProgramCard;
