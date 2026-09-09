import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import AcademicAssignment from "./AcademicAssignment";
import { fetchApprovedFaculties, fetchCurriculums, assignFacultyLoadToBackend } from "../../services/api";
jest.mock("../../services/api", () => ({ fetchApprovedFaculties: jest.fn(), fetchCurriculums: jest.fn(), assignFacultyLoadToBackend: jest.fn() }));
jest.mock("../../utils/sharedClientState", () => ({ pushAssignmentsSharedState: jest.fn() }));
jest.mock("./FacultyLoading", () => () => <div>Bulk import</div>);
beforeEach(() => {
  localStorage.clear(); jest.clearAllMocks();
  fetchApprovedFaculties.mockResolvedValue({ faculties: [{ id: 1, fullname: "Carlos Reyes", department: "Bachelor of Science in Information Technology" }] });
  fetchCurriculums.mockResolvedValue({ data: [{ programCode: "BSIT", status: "PUBLISHED", subjects: [{ subjectCode: "IT 321", subjectTitle: "Web Systems and Technologies", yearLevel: 3, semester: "SECOND", units: 3 }] }] });
  assignFacultyLoadToBackend.mockResolvedValue({ status: "Success" });
  localStorage.setItem("studentSections", JSON.stringify([{ program: "Bachelor of Science in Information Technology", yearLevel: "3rd Year", section: "IT 3A", schoolYear: "2026", semester: "2nd Semester", students: [] }]));
});
test("limits professors and programs to the chairperson department", async () => {
  fetchApprovedFaculties.mockResolvedValue({ faculties: [
    { id: 1, fullname: "Carlos Reyes", department: "Bachelor of Science in Information Technology" },
    { id: 2, fullname: "Other Professor", department: "Bachelor of Science in Accountancy" },
  ] });
  render(<AcademicAssignment chairpersonDepartment="Bachelor of Science in Information Technology"/>);
  expect(await screen.findByRole("button", { name: /Carlos Reyes/ })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Other Professor/ })).not.toBeInTheDocument();
  expect(screen.getByLabelText("Academic Program").options).toHaveLength(1);
});
test("stages assignments, prevents duplicates, and persists only on Save", async () => {
  render(<AcademicAssignment chairpersonDepartment="Bachelor of Science in Information Technology"/>);
  fireEvent.click(await screen.findByRole("button", { name: /Carlos Reyes/ }));
  fireEvent.click(screen.getByRole("radio", { name: "Select IT 321" }));
  fireEvent.change(screen.getByLabelText("Schedule for IT 3A"), { target: { value: "Mon 8:00 AM – 10:00 AM" } });
  fireEvent.click(screen.getByRole("button", { name: "＋ Assign" }));
  expect(localStorage.getItem("registrarAssignments")).toBeNull();
  expect(screen.getByText("1 pending assignment")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "＋ Assign" }));
  expect(screen.getByRole("status")).toHaveTextContent("already have an assignment");
  fireEvent.click(screen.getByRole("button", { name: "Save Assignments" }));
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Assignments saved successfully"));
  const saved = JSON.parse(localStorage.getItem("registrarAssignments"));
  expect(saved).toHaveLength(1);
  expect(saved[0]).toMatchObject({ facultyId: "1", subjectCode: "IT 321", sectionName: "IT 3A", schedule: "Mon 8:00 AM – 10:00 AM" });
  expect(assignFacultyLoadToBackend).toHaveBeenCalledTimes(1);
});
test("saves only the selected professor's pending load", async () => {
  fetchApprovedFaculties.mockResolvedValue({ faculties: [
    { id: 1, fullname: "Carlos Reyes", department: "Bachelor of Science in Information Technology" },
    { id: 2, fullname: "Ana Santos", department: "Bachelor of Science in Information Technology" },
  ] });
  render(<AcademicAssignment chairpersonDepartment="Bachelor of Science in Information Technology"/>);
  fireEvent.click(await screen.findByRole("button", { name: /Carlos Reyes/ }));
  fireEvent.click(screen.getByRole("radio", { name: "Select IT 321" }));
  fireEvent.click(screen.getByRole("button", { name: "＋ Assign" }));
  expect(screen.getByRole("button", { name: "Save Assignments" })).toBeEnabled();
  fireEvent.focus(screen.getByLabelText("Search professors"));
  fireEvent.click(screen.getByRole("button", { name: /Ana Santos/ }));
  expect(screen.getByRole("button", { name: "Save Assignments" })).toBeDisabled();

  fireEvent.focus(screen.getByLabelText("Search professors"));
  fireEvent.click(screen.getByRole("button", { name: /Carlos Reyes/ }));
  fireEvent.click(screen.getByRole("button", { name: "Save Assignments" }));
  await waitFor(() => expect(assignFacultyLoadToBackend).toHaveBeenCalledTimes(1));
  expect(JSON.parse(localStorage.getItem("registrarAssignments"))[0].facultyId).toBe("1");
});
test("allows removing a pending assignment without saving", async () => {
  render(<AcademicAssignment chairpersonDepartment="Bachelor of Science in Information Technology"/>);
  fireEvent.click(await screen.findByRole("button", { name: /Carlos Reyes/ }));
  fireEvent.click(screen.getByRole("radio", { name: "Select IT 321" }));
  fireEvent.click(screen.getByRole("button", { name: "＋ Assign" }));
  fireEvent.click(screen.getByRole("button", { name: "Remove IT 321 IT 3A" }));
  expect(screen.getByRole("button", { name: "Save Assignments" })).toBeDisabled();
  expect(localStorage.getItem("registrarAssignments")).toBeNull();
});

