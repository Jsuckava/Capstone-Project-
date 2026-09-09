import { useEffect, useState } from "react";
import LoginPage from "./pages/LoginPage";
import StudentPortal from "./pages/StudentPortal";
import FacultyPortal from "./pages/FacultyPortal";
import RegistrarPortal from "./pages/RegistrarPortal";
import ChairpersonPortal from "./pages/ChairpersonPortal";
import { CHAIRPERSON_REVIEW_KEY } from "./utils/chairpersonHelpers";
import { getPublishedGradesForStudent } from "./utils/publishedGradesHelpers";

function App() {
  const [userRole, setUserRole] = useState(localStorage.getItem("userRole"));

  const [allGrades, setAllGrades] = useState(() => {
    const saved = localStorage.getItem("blockgo-allGrades");
    return saved ? JSON.parse(saved) : {};
  });

  useEffect(() => {
    localStorage.setItem("blockgo-allGrades", JSON.stringify(allGrades));
  }, [allGrades]);

  const handleLogin = (email) => {
    if (email === "faculty@gmail.com") {
      localStorage.setItem("userRole", "faculty");
      setUserRole("faculty");
    } else if (email === "student@gmail.com") {
      localStorage.setItem("userRole", "student");
      setUserRole("student");
    } else if (email === "registrar@gmail.com") {
      localStorage.setItem("userRole", "registrar");
      setUserRole("registrar");
    } else if (email === "chairperson@gmail.com") {
      localStorage.setItem("userRole", "chairperson");
      setUserRole("chairperson");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("userRole");
    setUserRole(null);
  };

  const handleResetEncodingSeason = () => {
    localStorage.removeItem("blockgo-allGrades");
    localStorage.removeItem(CHAIRPERSON_REVIEW_KEY);
    localStorage.removeItem("registrarAssignments");
    setAllGrades({});
  };

  const studentData = {
    firstName: "Jul",
    lastName: "Mar",
    middleName: "M",
    studentId: "23-1111",
    dateOfBirth: "January 01, 2005",
    phone: "09123456789",
    sex: "Male",
    email: "student@gmail.com",
    address: "Valenzuela City",
    subjects: [
      {
        code: "TEST 101",
        name: "Test Subject",
        units: 3,
        midterm: 80,
        finals: 90,
        finalGrade: "85.00",
        equivalent: "2.00",
        remarks: "Passed",
      },
    ],
  };

  console.log("Student Data in App.jsx:", studentData);
  // Helper function to calculate failed subjects
  const calculateFailedSubjects = (subjects) => {
    let failedCount = 0;
    subjects.forEach(sub => {
      const finalNumeric = sub.finalGrade
        ? Number(sub.finalGrade)
        : (Number(sub.midterm) + Number(sub.finals)) / 2;

      if (Number.isFinite(finalNumeric) && finalNumeric < 75) {
        failedCount++;
      }
    });
    return failedCount;
  };


  if (!userRole) {
    return <LoginPage onLogin={handleLogin} />;
  }
  if (userRole === "student") {
    const publishedSubjects = getPublishedGradesForStudent(studentData.studentId);
    const resolvedStudentData = {
      ...studentData,
      subjects: publishedSubjects.length ? publishedSubjects : studentData.subjects,
    };
    const failedSubjectsCount = calculateFailedSubjects(resolvedStudentData.subjects);
    return <StudentPortal studentData={resolvedStudentData} onLogout={handleLogout} failedSubjectsCount={failedSubjectsCount} />;
  }

  if (userRole === "faculty") {
    return (
      <FacultyPortal
        onLogout={handleLogout}
        allGrades={allGrades}
        setAllGrades={setAllGrades}
      />
    );
  }

  if (userRole === "registrar") {
    return (
      <RegistrarPortal
        onLogout={handleLogout}
        onResetEncodingSeason={handleResetEncodingSeason}
        allGrades={allGrades}
      />
    );
  }

  if (userRole === "chairperson") {
    return (
      <ChairpersonPortal
        onLogout={handleLogout}
        allGrades={allGrades}
      />
    );
  }

  return <LoginPage onLogin={handleLogin} />;
}

export default App;
