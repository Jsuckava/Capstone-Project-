export const STUDENT_BATCHES_KEY = "chairpersonStudentBatches";
export const STUDENT_SUBMISSION_LOGS_KEY = "chairpersonSubmissionLogs";
export const AVAILABLE_YEAR_LEVELS = [
  "1st Year",
  "2nd Year",
  "3rd Year",
  "4th Year",
];
export const AVAILABLE_SECTION_CODES = [
  "1-1",
  "1-2",
  "1-3",
  "1-4",
  "2-1",
  "2-2",
  "3-1",
  "3-2",
  "4-1",
  "4-2",
];

export const YEAR_LEVEL_PREFIXES = {
  "1st Year": "1",
  "2nd Year": "2",
  "3rd Year": "3",
  "4th Year": "4",
};

// ECMAScript Date uses the proleptic Gregorian calendar. UTC avoids a local
// timezone rollover changing the year near midnight on January 1.
export const getGregorianCalendarYear = (date = new Date()) =>
  date.getUTCFullYear();

const getStudentIdYearPrefix = (year = "") => {
  const match = String(year).trim().match(/^(\d{4})(?:\D|$)/);
  return match ? match[1].slice(-2) : "";
};

export const getNextStudentId = (
  year = "",
  batches = [],
  persistedHighestSequence = 0
) => {
  const yearPrefix = getStudentIdYearPrefix(year);
  if (!yearPrefix) return "";

  const studentIdPattern = new RegExp(`^${yearPrefix}-(\\d{4})$`);
  let highestSequence = Math.max(Number(persistedHighestSequence) || 0, 0);

  batches.forEach((batch) => {
    [...(batch.students || []), ...(batch.removedStudents || [])].forEach(
      (student) => {
        const match = String(student?.studentId || "").trim().match(studentIdPattern);
        if (!match) return;
        highestSequence = Math.max(highestSequence, Number(match[1]));
      }
    );
  });

  const nextSequence = highestSequence + 1;
  return nextSequence <= 9999
    ? `${yearPrefix}-${String(nextSequence).padStart(4, "0")}`
    : "";
};

const PROGRAM_SECTION_PREFIXES = {
  "Bachelor of Early Childhood Education": "BECEd",
  "Bachelor of Secondary Education major in English": "BSEd English",
  "Bachelor of Secondary Education major in Filipino": "BSEd Filipino",
  "Bachelor of Secondary Education major in Mathematics": "BSEd Mathematics",
  "Bachelor of Secondary Education major in Science": "BSEd Science",
  "Bachelor of Secondary Education major in Social Studies": "BSEd Social Studies",
  "Bachelor of Science in Civil Engineering": "BSCE",
  "Bachelor of Science in Electrical Engineering": "BSEE",
  "Bachelor of Science in Information Technology": "BSIT",
  "Bachelor of Arts in Communication": "BAC",
  "Bachelor of Science in Psychology": "BSP",
  "Bachelor of Science in Social Work": "BSSW",
  "Bachelor of Public Administration": "BPA",
  "Bachelor of Science in Accountancy": "BSA",
  "Bachelor of Science in Business Administration major in Financial Management":
    "BSBA FM",
  "Bachelor of Science in Business Administration major in Human Resource Management":
    "BSBA HRM",
  "Bachelor of Science in Business Administration major in Marketing Management":
    "BSBA MM",
};

export const getProgramSectionPrefix = (program = "") =>
  PROGRAM_SECTION_PREFIXES[program] ||
  String(program)
    .split(/\s+/)
    .filter((word) => /^[A-Z]/.test(word))
    .map((word) => word[0])
    .join("") ||
  "SECTION";

export const getDefaultSectionName = (program = "", sectionCode = "") =>
  `${getProgramSectionPrefix(program)} ${sectionCode}`.trim();

const normalizeHeader = (value = "") =>
  String(value)
    .replace(/^\uFEFF/, "")
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ");

const getColumnIndex = (headers = [], acceptedHeaders = []) =>
  acceptedHeaders
    .map((header) => headers.indexOf(header))
    .find((index) => index !== -1) ?? -1;

export const parseCsvRows = (text = "") => {
  const rows = [];
  let row = [];
  let field = "";
  let insideQuotes = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const nextChar = text[index + 1];

    if (char === '"') {
      if (insideQuotes && nextChar === '"') {
        field += '"';
        index += 1;
      } else {
        insideQuotes = !insideQuotes;
      }
      continue;
    }

    if (char === "," && !insideQuotes) {
      row.push(field);
      field = "";
      continue;
    }

    if ((char === "\n" || char === "\r") && !insideQuotes) {
      if (char === "\r" && nextChar === "\n") index += 1;
      row.push(field);
      if (row.some((value) => String(value).trim())) rows.push(row);
      row = [];
      field = "";
      continue;
    }

    field += char;
  }

  row.push(field);
  if (row.some((value) => String(value).trim())) rows.push(row);

  return rows;
};

const escapeCsvValue = (value = "") => {
  const stringValue = String(value ?? "");

  if (/[",\n]/.test(stringValue)) {
    return `"${stringValue.replace(/"/g, '""')}"`;
  }

  return stringValue;
};

export const buildCsvContent = (rows = []) =>
  rows.map((row) => row.map(escapeCsvValue).join(",")).join("\n");

export const getStudentMiddleName = (student = {}) =>
  student.middleName || student.middleInitial || "";

export const parseStudentIdSpreadsheet = (text = "") => {
  const rows = parseCsvRows(text);

  if (rows.length < 2) return [];

  const headers = rows[0].map((header) => normalizeHeader(header));
  const studentIdIndex = getColumnIndex(headers, [
    "student id",
    "student no",
    "student number",
    "id number",
  ]);
  const sexIndex = getColumnIndex(headers, ["sex", "gender"]);
  const lastNameIndex = getColumnIndex(headers, ["last name", "surname", "last"]);
  const firstNameIndex = getColumnIndex(headers, [
    "first name",
    "given name",
    "first",
  ]);
  const middleNameIndex = getColumnIndex(headers, [
    "middle initial",
    "mi",
    "m i",
    "middle name",
  ]);
  const yearLevelIndex = getColumnIndex(headers, ["year level", "year", "level"]);

  if (
    studentIdIndex === -1 ||
    sexIndex === -1 ||
    lastNameIndex === -1 ||
    firstNameIndex === -1 ||
    middleNameIndex === -1
  ) {
    return [];
  }

  return rows
    .slice(1)
    .map((values) => ({
      studentId: values[studentIdIndex]?.trim() || "",
      sex: values[sexIndex]?.trim() || "",
      lastName: values[lastNameIndex]?.trim() || "",
      firstName: values[firstNameIndex]?.trim() || "",
      middleName: values[middleNameIndex]?.trim() || "",
      middleInitial: values[middleNameIndex]?.trim() || "",
      yearLevel:
        yearLevelIndex === -1 ? "1st Year" : values[yearLevelIndex]?.trim() || "1st Year",
      sectionCode: "",
    }))
    .filter(
      (student) =>
        student.studentId &&
        student.sex &&
        student.lastName &&
        student.firstName &&
        student.middleName
    );
};

export const buildStudentCsvContent = (students = [], options = {}) => {
  const { includeYearLevel = true } = options;
  const header = [
    "Student ID",
    "Sex",
    "Last Name",
    "First Name",
    "Middle Name",
  ];

  if (includeYearLevel) {
    header.push("Year Level");
  }

  const rows = students.map((student) =>
    includeYearLevel
      ? [
          student.studentId,
          student.sex,
          student.lastName,
          student.firstName,
          getStudentMiddleName(student),
          student.yearLevel || "",
        ]
      : [
          student.studentId,
          student.sex,
          student.lastName,
          student.firstName,
          getStudentMiddleName(student),
        ]
  );

  return buildCsvContent([header, ...rows]);
};

export const downloadCsvFile = (csvContent = "", fileName = "students.csv") => {
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.setAttribute("download", fileName);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

export const downloadStudentCsvFile = (students = [], fileName = "students.csv") => {
  downloadCsvFile(buildStudentCsvContent(students), fileName);
};

export const buildStudentMasterlistFromBatches = (batches = []) =>
  batches
    .filter((batch) => batch.status !== "Promoted")
    .flatMap((batch) =>
      (batch.students || []).map((student) => ({
        studentId: student.studentId,
        sex: student.sex || "",
        firstName: student.firstName || "",
        lastName: student.lastName || "",
        middleName: getStudentMiddleName(student),
        middleInitial: student.middleInitial || getStudentMiddleName(student),
        program: batch.program,
        yearLevel: student.yearLevel || "",
        section: student.sectionCode
          ? student.sectionName ||
            getDefaultSectionName(batch.program, student.sectionCode)
          : "",
        schoolYear: batch.batchYear,
        semester: batch.semester || student.semester || "",
        studentType: student.studentType || "Regular",
        remarks: student.remarks || "",
        repeatedSubjects: student.repeatedSubjects || "",
        irregularSubjects: student.irregularSubjects || [],
      }))
    );

export const buildGroupedSectionLists = (students = []) => {
  const grouped = {};

  students.forEach((student) => {
    if (!student.section || !student.yearLevel) return;

    const key = [
      student.program,
      student.yearLevel,
      student.section,
      student.schoolYear,
      student.semester,
    ].join("|");

    if (!grouped[key]) {
      grouped[key] = {
        key,
        program: student.program,
        yearLevel: student.yearLevel,
        section: student.section,
        schoolYear: student.schoolYear,
        semester: student.semester || "",
        students: [],
      };
    }

    grouped[key].students.push({
      studentId: student.studentId,
      sex: student.sex || "",
      firstName: student.firstName || "",
      lastName: student.lastName || "",
      middleName: getStudentMiddleName(student),
      middleInitial: student.middleInitial || getStudentMiddleName(student),
      studentType: student.studentType || "Regular",
      remarks: student.remarks || "",
      repeatedSubjects: student.repeatedSubjects || "",
      irregularSubjects: student.irregularSubjects || [],
    });
  });

  return Object.values(grouped);
};

export const syncSectionedStudentsToStorage = (batches = []) => {
  const studentMasterlist = buildStudentMasterlistFromBatches(batches);
  const groupedSections = buildGroupedSectionLists(studentMasterlist);
  const existingSectionKeys = new Set(
    groupedSections.map((section) =>
      [
        section.program,
        section.yearLevel,
        section.section,
        section.schoolYear,
        section.semester,
      ].join("|")
    )
  );
  const emptySectionPlans = batches
    .filter((batch) => batch.status !== "Promoted")
    .flatMap((batch) =>
      (batch.sectionPlans || [])
        .map((section) => {
          const sectionName =
            section.sectionName ||
            getDefaultSectionName(batch.program, section.sectionCode);
          const key = [
            batch.program,
            section.yearLevel || "",
            sectionName,
            batch.batchYear,
            batch.semester || "",
          ].join("|");

          return {
            key,
            program: batch.program,
            yearLevel: section.yearLevel || "",
            section: sectionName,
            schoolYear: batch.batchYear,
            semester: batch.semester || "",
            students: [],
          };
        })
        .filter((section) => {
          if (existingSectionKeys.has(section.key)) return false;
          existingSectionKeys.add(section.key);
          return true;
        })
    );

  localStorage.setItem("studentMasterlist", JSON.stringify(studentMasterlist));
  localStorage.setItem(
    "studentSections",
    JSON.stringify([...groupedSections, ...emptySectionPlans])
  );
};
