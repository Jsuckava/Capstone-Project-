export const GRADE_STATUS = {
  DRAFT: "draft",
  RETURNED: "returned",
  SUBMITTED: "submitted",
  APPROVED: "approved",
  FINALIZED: "finalized",
  CORRECTED: "corrected",
};

const compactStatus = (status = "") =>
  String(status || "")
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, "");

export const normalizeGradeStatus = (status) => {
  const normalized = compactStatus(status);

  if (!normalized) return GRADE_STATUS.DRAFT;
  if (normalized.includes("return") || normalized.includes("reject")) {
    return GRADE_STATUS.RETURNED;
  }
  if (normalized.includes("final")) return GRADE_STATUS.FINALIZED;
  if (normalized.includes("departmentapproved") || normalized.includes("approved") || normalized.includes("forwarded")) {
    return GRADE_STATUS.APPROVED;
  }
  if (normalized.includes("submitted") || normalized.includes("issued")) {
    return GRADE_STATUS.SUBMITTED;
  }
  if (normalized.includes("corrected")) return GRADE_STATUS.CORRECTED;

  return GRADE_STATUS.DRAFT;
};

export const isDepartmentApprovedGradeStatus = (status) =>
  normalizeGradeStatus(status) === GRADE_STATUS.APPROVED;

export const isChairpersonForwardedGradeStatus = (status) =>
  normalizeGradeStatus(status) === GRADE_STATUS.APPROVED;
