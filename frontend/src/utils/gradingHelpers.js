export const formatName = (student) => {
  if (student.firstName && student.lastName) {
    return `${student.lastName}, ${student.firstName}`;
  }

  if (student.name) {
    const parts = student.name.trim().split(" ");
    if (parts.length === 1) return student.name;

    const firstName = parts[0];
    const lastName = parts.slice(1).join(" ");

    return `${lastName}, ${firstName}`;
  }

  return "No Name";
};

export const getGradeEquivalent = (grade) => {
  const g = Number(grade);

  if (isNaN(g)) return "-";
  if (g <= 0) return "0";
  if (g >= 98.5) return "1.00";
  if (g >= 94) return "1.25";
  if (g >= 91) return "1.50";
  if (g >= 88) return "1.75";
  if (g >= 84) return "2.00";
  if (g >= 81) return "2.25";
  if (g >= 78) return "2.50";
  if (g >= 75) return "3.00";
  if (g < 75) return "5.00";

  return "-";
};

export const computeFinal = (grades, studentId, activeTerm) => {
  const student = grades[studentId] || {};
  const mid = Number(student.midterm);
  const fin = Number(student.finals);

  if (activeTerm === "midterm") return "-";

  if (activeTerm === "finals") {
    if (Number.isNaN(mid) || Number.isNaN(fin)) return "-";
    return ((mid + fin) / 2).toFixed(2);
  }

  return "-";
};

export const getStatus = (final, activeTerm) => {
  if (activeTerm === "midterm") return "-";
  if (final === "-") return "-";

  const equivalent = getGradeEquivalent(final);
  return equivalent === "5.00" ? "Failed" : "Passed";
};
