export const programOptions = [
  { code: 'BECED', name: 'Bachelor of Early Childhood Education' },
  { code: 'BSED-ENG', name: 'Bachelor of Secondary Education Major in English' },
  { code: 'BSED-FIL', name: 'Bachelor of Secondary Education Major in Filipino' },
  { code: 'BSED-MATH', name: 'Bachelor of Secondary Education Major in Mathematics' },
  { code: 'BSED-SCI', name: 'Bachelor of Secondary Education Major in Science' },
  { code: 'BSED-SOCSTUD', name: 'Bachelor of Secondary Education Major in Social Studies' },
  { code: 'BSCE', name: 'Bachelor of Science in Civil Engineering' },
  { code: 'BSEE', name: 'Bachelor of Science in Electrical Engineering' },
  { code: 'BSIT', name: 'Bachelor of Science in Information Technology' },
  { code: 'BAC', name: 'Bachelor of Arts in Communication' },
  { code: 'BSP', name: 'Bachelor of Science in Psychology' },
  { code: 'BSSW', name: 'Bachelor of Science in Social Work' },
  { code: 'BPA', name: 'Bachelor of Public Administration' },
  { code: 'BSA', name: 'Bachelor of Science in Accountancy' },
  { code: 'BSBA-FM', name: 'Bachelor of Science in Business Administration Major in Financial Management' },
  { code: 'BSBA-HRM', name: 'Bachelor of Science in Business Administration Major in Human Resource Management' },
  { code: 'BSBA-MM', name: 'Bachelor of Science in Business Administration Major in Marketing Management' },
];

export const programs = programOptions.map((program) => program.name);

export const facultyList = [
  {
    id: 1,
    name: "Juan Dela Cruz",
    program: "Bachelor of Science in Information Technology",
  },
  {
    id: 2,
    name: "Maria Santos",
    program: "Bachelor of Science in Accountancy",
  },
  {
    id: 3,
    name: "Pedro Reyes",
    program: "Bachelor of Secondary Education Major in English",
  },
  {
    id: 4,
    name: "Ana Lopez",
    program: "Bachelor of Science in Information Technology",
  },
];

export const sections = [
  {
    id: 1,
    section: "Bachelor of Science in Information Technology 1-1",
    program: "Bachelor of Science in Information Technology",
    yearLevel: "1st Year",
    schoolYear: "2025",
    semester: "",
  },
  {
    id: 2,
    section: "Bachelor of Science in Information Technology 1-2",
    program: "Bachelor of Science in Information Technology",
    yearLevel: "1st Year",
    schoolYear: "2025",
    semester: "",
  },
  {
    id: 3,
    section: "Bachelor of Science in Information Technology 2-1",
    program: "Bachelor of Science in Information Technology",
    yearLevel: "2nd Year",
    schoolYear: "2025",
    semester: "",
  },
  {
    id: 4,
    section: "Bachelor of Science in Accountancy 1-1",
    program: "Bachelor of Science in Accountancy",
    yearLevel: "1st Year",
    schoolYear: "2025",
    semester: "",
  },
  {
    id: 5,
    section: "Bachelor of Secondary Education Major in English 3-1",
    program: "Bachelor of Secondary Education Major in English",
    yearLevel: "3rd Year",
    schoolYear: "2025",
    semester: "",
  },
  {
    id: 6,
    section: "Bachelor of Science in Information Technology 1-1",
    program: "Bachelor of Science in Information Technology",
    yearLevel: "1st Year",
    schoolYear: "2026",
    semester: "",
  },
  {
    id: 7,
    section: "Bachelor of Science in Information Technology 1-2",
    program: "Bachelor of Science in Information Technology",
    yearLevel: "1st Year",
    schoolYear: "2026",
    semester: "",
  },
  {
    id: 8,
    section: "Bachelor of Science in Information Technology 1-3",
    program: "Bachelor of Science in Information Technology",
    yearLevel: "1st Year",
    schoolYear: "2026",
    semester: "",
  },
];

export const assignments = [
  {
    facultyId: 1,
    sectionId: 3,
    schoolYear: "2025",
    semester: "",
  },
];
