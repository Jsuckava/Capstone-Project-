import React from "react";

const EncodingBanner = ({ bannerState, daysLeft, formatDate, startDate, endDate }) => {
  if (bannerState === "closed_after") {
    return (
      <div className="mx-6 mt-5 rounded-xl border-l-4 border-slate-400 bg-slate-100 px-5 py-4 text-slate-600">
        <strong className="block text-slate-700">
          Grade Encoding Period is currently Closed
        </strong>
        <p className="mt-1 text-sm">
          The encoding deadline has passed as of{" "}
          <strong>{formatDate(endDate)}</strong>. Contact or visit the Registrar&apos;s
          Office for any concerns.
        </p>
      </div>
    );
  }

  if (bannerState === "closed_before") {
    return (
      <div className="mx-6 mt-5 rounded-xl border-l-4 border-slate-400 bg-white px-5 py-4 text-slate-600 shadow-sm">
        <strong className="block text-slate-700">
          Grade Encoding Period has not started yet
        </strong>
        <p className="mt-1 text-sm">
          Encoding opens on <strong>{formatDate(startDate)}</strong>. Please check back then.
        </p>
      </div>
    );
  }

  if (bannerState === "urgent") {
    return (
      <div className="mx-6 mt-5 rounded-xl border-l-4 border-red-500 bg-red-50 px-5 py-4 text-red-900">
        <strong className="block">
          Encoding Deadline in {daysLeft} {daysLeft === 1 ? "Day" : "Days"}!
        </strong>
        <p className="mt-1 text-sm">
          You have <strong>{daysLeft} {daysLeft === 1 ? "day" : "days"}</strong> left to
          submit grades before the deadline on <strong>{formatDate(endDate)}</strong>.
        </p>
      </div>
    );
  }

  return (
    <div className="mx-6 mt-5 rounded-xl border-l-4 border-green-500 bg-green-50 px-5 py-4 text-green-900">
      <strong className="block">Grade Encoding Period is Open!</strong>
      <p className="mt-1 text-sm">
        Finalize your section grades and upload to the Registrar by{" "}
        <strong>{formatDate(endDate)}</strong>.
      </p>
    </div>
  );
};

export default EncodingBanner;