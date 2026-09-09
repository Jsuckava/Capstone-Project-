import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { getGradeEquivalent } from "./gradingHelpers";

export const exportGradingSheet = (
  selectedSection,
  grades,
  systemTerm,
  semester = "2nd Semester"
) => {
  const doc = new jsPDF();

  const formatName = (student) => {
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

  const getStandingCode = (standing) => {
    if (standing === "dropped") return "D";
    if (standing === "unofficially_dropped") return "UD";
    if (standing === "withdrawn") return "W";
    if (standing === "incomplete") return "INC";
    return null;
  };

  const computeFinal = (studentId) => {
    const studentRecord = grades[studentId] || {};
    const standingCode = getStandingCode(studentRecord.standing);

    if (standingCode) return standingCode;

    const mid = studentRecord.midterm;
    const fin = studentRecord.finals;

    if (["INC", "UD", "D", "W"].includes(mid)) return mid;
    if (["INC", "UD", "D", "W"].includes(fin)) return fin;

    const midterm = Number(mid);
    const finals = Number(fin);

    if (systemTerm === "midterm") {
      if (!midterm) return "-";
      return midterm.toFixed(2);
    }

    if (systemTerm === "finals") {
      if (!midterm || !finals) return "-";
      return ((midterm + finals) / 2).toFixed(2);
    }

    return "-";
  };

  const getStatus = (final) => {
    if (final === "D") return "Dropped";
    if (final === "UD") return "Unofficially Dropped";
    if (final === "W") return "Withdrawn";
    if (final === "INC") return "Incomplete";

    if (systemTerm === "midterm") {
      if (final === "-") return "Pending";
      return Number(final) >= 75 ? "Passed" : "Failed";
    }

    if (final === "-") return "Incomplete";
    return Number(final) >= 75 ? "Passed" : "Failed";
  };

  const totalStudents = selectedSection.students.length;
  let passed = 0;
  let failed = 0;

  const tableRows = selectedSection.students.map((student, index) => {
    const final = computeFinal(student.id);
    const status = getStatus(final);
    const isFlagged = grades[student.id]?.flagged;

    if (status === "Passed") passed++;
    if (status === "Failed") failed++;

    const displayName = isFlagged
      ? `[FLAGGED] ${formatName(student)}`
      : formatName(student);

    const gradeEquivalent =
      final !== "-" && !isNaN(final) ? getGradeEquivalent(final) : final;

    return [
      index + 1,
      student.id,
      displayName,
      final,
      gradeEquivalent,
      status,
    ];
  });

  const graded = passed + failed;
  const passRate = graded > 0 ? ((passed / graded) * 100).toFixed(1) : "0.0";

  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("UNIVERSITY OFFICIAL GRADING SHEET", 105, 20, { align: "center" });

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);

  doc.text("Academic Year: 2025-2026", 14, 35);
  doc.text(`Semester: ${selectedSection.semester || semester}`, 14, 43);
  doc.text(`Term: ${systemTerm === "midterm" ? "Midterm" : "Finals"}`, 14, 51);
  doc.text(`Course Code: ${selectedSection.subjectCode}`, 14, 59);
  doc.text(`Course Name: ${selectedSection.subjectTitle}`, 14, 67);
  doc.text(`Section: ${selectedSection.sectionName}`, 14, 75);
  doc.text(`Program: ${selectedSection.sectionCourse}`, 14, 83);
  doc.text(`Year Level: ${selectedSection.year}`, 14, 91);

  doc.text(`Total Students: ${totalStudents}`, 125, 35);
  doc.text(`Graded: ${graded}`, 125, 43);
  doc.text(`Passed: ${passed}`, 125, 51);
  doc.text(`Failed: ${failed}`, 125, 59);
  doc.text(`Pass Rate: ${passRate}%`, 125, 67);

  autoTable(doc, {
    startY: 103,
    head: [[
      "No.",
      "Student ID",
      "Student Name",
      "Grade\n(60-100)",
      "Grade Equivalent",
      "Status",
    ]],
    body: tableRows,
    theme: "grid",
    headStyles: {
      fillColor: [0, 51, 102],
      textColor: 255,
      fontStyle: "bold",
      halign: "center",
    },
    styles: {
      fontSize: 10,
      cellPadding: 3,
    },
    columnStyles: {
      0: { halign: "center", cellWidth: 12 },
      1: { halign: "center", cellWidth: 24 },
      2: { cellWidth: 54 },
      3: { halign: "center", cellWidth: 24 },
      4: { halign: "center", cellWidth: 26 },
      5: { halign: "center", cellWidth: 34 },
    },
    didParseCell: (data) => {
      const student = selectedSection.students[data.row.index];

      if (data.section === "body" && grades[student?.id]?.flagged) {
        data.cell.styles.fillColor = [255, 235, 238];
      }

      if (data.section === "body" && data.column.index === 5) {
        if (data.cell.raw === "Passed") {
          data.cell.styles.textColor = [34, 139, 34];
          data.cell.styles.fontStyle = "bold";
        } else if (data.cell.raw === "Failed") {
          data.cell.styles.textColor = [220, 53, 69];
          data.cell.styles.fontStyle = "bold";
        } else if (
          data.cell.raw === "Dropped" ||
          data.cell.raw === "Unofficially Dropped" ||
          data.cell.raw === "Withdrawn" ||
          data.cell.raw === "Incomplete"
        ) {
          data.cell.styles.textColor = [180, 120, 0];
          data.cell.styles.fontStyle = "bold";
        }
      }
    },
  });

  doc.save(`${selectedSection.sectionName}_${systemTerm}_grading_sheet.pdf`);
};
