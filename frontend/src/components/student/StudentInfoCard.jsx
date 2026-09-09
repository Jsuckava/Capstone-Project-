import infoLogo from "../../assets/infoLogo.webp"; // Assuming infoLogo.webp exists in your assets folder
const StudentInfoCard = ({ studentData }) => {
  return (
    <div className="mx-4 mt-5 rounded-xl border border-[#003366] bg-gray-100 p-4 md:mx-6 md:p-6">
      <h3 className="mb-4 text-base font-bold text-[#003366] md:text-lg">
        Student Personal Information
      </h3>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 text-sm">

        <div>
          <p className="text-gray-500">First Name</p>
          <p className="font-semibold">{studentData.firstName}</p>
        </div>

        <div>
          <p className="text-gray-500">Last Name</p>
          <p className="font-semibold">{studentData.lastName}</p>
        </div>

        <div>
          <p className="text-gray-500">Middle Name</p>
          <p className="font-semibold">{studentData.middleName}</p>
        </div>

        <div>
          <p className="text-gray-500">Student ID</p>
          <p className="font-semibold">{studentData.studentId}</p>
        </div>

        <div>
          <p className="text-gray-500">Date of Birth</p>
          <p className="font-semibold">{studentData.dateOfBirth}</p>
        </div>

        <div>
          <p className="text-gray-500">Sex</p>
          <p className="font-semibold">{studentData.sex}</p>
        </div>

        <div>
          <p className="text-gray-500">Phone</p>
          <p className="font-semibold">{studentData.phone}</p>
        </div>

        <div>
          <p className="text-gray-500">Email</p>
          <p className="font-semibold break-words">{studentData.email}</p>
        </div>

        <div>
          <p className="text-gray-500">Program</p>
          <p className="font-semibold">{studentData.department || "Not assigned"}</p>
        </div>

        <div>
          <p className="text-gray-500">Year / Section</p>
          <p className="font-semibold">{studentData.yearLevel ? `Year ${studentData.yearLevel}` : "Year not assigned"} · {studentData.section || "No section"}</p>
        </div>

        <div>
          <p className="text-gray-500">Academic Period</p>
          <p className="font-semibold">{studentData.schoolYear || "Not assigned"} · {studentData.semester || "No semester"}</p>
        </div>

        <div>
          <p className="text-gray-500">Curriculum</p>
          <p className="font-semibold">{studentData.curriculumVersion || studentData.curriculumName || "Not assigned"}</p>
        </div>

        <div>
          <p className="text-gray-500">Enrollment Status</p>
          <p className="font-semibold">{studentData.enrollmentStatus || "Unassigned"}</p>
        </div>

        <div className="col-span-2 md:col-span-3">
          <p className="text-gray-500">Address</p>
          <p className="font-semibold">{studentData.address}</p>
        </div>

        <div className="col-span-2 md:col-span-3 border-t border-gray-300 pt-4 mt-4"></div>
        <p className="personal-info-note text-gray-600 col-span-2 flex items-center gap-2 md:col-span-2">
          <img src={infoLogo} alt="info Logo" className="info-logo h-5 w-5" />
          If your personal information is incorrect or requires an update, kindly visit the Office of the Registrar for assistance.
        </p>

      </div>
    </div>
  );
};

export default StudentInfoCard;
