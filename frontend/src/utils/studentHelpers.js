export const getPLVPoint = (midterm, finals) => {
  const avg = (midterm + finals) / 2;

  if (avg <= 0) return 0;
  if (avg >= 98.5) return 1.0;
  if (avg >= 94) return 1.25;
  if (avg >= 91) return 1.5;
  if (avg >= 88) return 1.75;
  if (avg >= 84) return 2.0;
  if (avg >= 81) return 2.25;
  if (avg >= 78) return 2.5;
  if (avg >= 75) return 3.0;
  return 5.0;
};

export const getTotalUnits = (subjects) =>
  subjects.reduce((sum, s) => sum + Number(s.units || 0), 0);

export const getCalculatedGWA = (subjects) => {
  const totalUnits = getTotalUnits(subjects);

  const total = subjects.reduce((sum, s) => {
    const finalGrade = Number(s.finalGrade);
    const eq = Number.isFinite(finalGrade)
      ? getPLVPoint(finalGrade, finalGrade)
      : getPLVPoint(Number(s.midterm), Number(s.finals));

    if (!Number.isFinite(eq)) return sum;

    return sum + eq * s.units;
  }, 0);

  return totalUnits ? (total / totalUnits).toFixed(2) : "0.00";
};

export const isDeanLister = (subjects, gwa) =>
  Number(gwa) <= 1.75;
