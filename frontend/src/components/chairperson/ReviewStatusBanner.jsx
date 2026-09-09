import React from "react";
import {
  getReviewStatusClasses,
  getReviewStatusLabel,
} from "../../utils/chairpersonHelpers";

function ReviewStatusBanner({ reviewStatus, reviewNote }) {
  if (!reviewStatus || reviewStatus === "pending") return null;

  return (
    <div className={`mt-3 rounded-xl px-4 py-3 text-sm ${getReviewStatusClasses(reviewStatus)}`}>
      <p className="font-semibold">{getReviewStatusLabel(reviewStatus)}</p>
      {reviewStatus === "returned" && reviewNote ? (
        <p className="mt-1">Chairperson Note: {reviewNote}</p>
      ) : null}
    </div>
  );
}

export default ReviewStatusBanner;
