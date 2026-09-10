import {
  GRADE_STATUS,
  isChairpersonForwardedGradeStatus,
  isDepartmentApprovedGradeStatus,
  normalizeGradeStatus,
} from "./gradeStatus";

describe("grade workflow status helpers", () => {
  test.each(["Draft", "Returned", "SubmittedToChairperson", "ChairpersonApproved"])(
    "%s is not visible in the registrar commit queue",
    (status) => {
      expect(isDepartmentApprovedGradeStatus(status)).toBe(false);
      expect(isChairpersonForwardedGradeStatus(status)).toBe(false);
    }
  );

  test.each(["DepartmentApproved", "Forwarded", "ForwardedToRegistrar"])(
    "%s is visible in the registrar commit queue",
    (status) => {
      expect(isDepartmentApprovedGradeStatus(status)).toBe(true);
      expect(isChairpersonForwardedGradeStatus(status)).toBe(true);
    }
  );

  test("chairperson approval remains an approved review state", () => {
    expect(normalizeGradeStatus("ChairpersonApproved")).toBe(GRADE_STATUS.APPROVED);
  });
});
