import React, { useState, useEffect, useMemo, useRef } from "react";
import { fetchAcademicPrograms, fetchSystemLogs } from "../../services/api";

const TRANSACTIONS_PER_PAGE = 10;
const PAGE_BUTTONS_PER_GROUP = 5;

const getVisiblePageNumbers = (currentPage, totalPages) => {
  if (totalPages <= PAGE_BUTTONS_PER_GROUP) {
    return Array.from({ length: totalPages }, (_, index) => index + 1);
  }

  const calculatedGroupStart = Math.floor((currentPage - 1) / PAGE_BUTTONS_PER_GROUP)
    * PAGE_BUTTONS_PER_GROUP + 1;
  const isFinalGroup = calculatedGroupStart + PAGE_BUTTONS_PER_GROUP - 1 >= totalPages;
  const groupStart = isFinalGroup
    ? Math.max(1, totalPages - PAGE_BUTTONS_PER_GROUP + 1)
    : calculatedGroupStart;
  const pageNumbers = Array.from(
    { length: PAGE_BUTTONS_PER_GROUP },
    (_, index) => groupStart + index
  );

  return isFinalGroup
    ? ["ellipsis-first", ...pageNumbers]
    : [...pageNumbers, "ellipsis-last"];
};

const humanizeLabel = (value = "") => String(value)
  .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
  .replace(/[_-]+/g, " ")
  .trim()
  .toLowerCase()
  .replace(/\b\w/g, (letter) => letter.toUpperCase())
  .replace(/\bId\b/g, "ID");

const parseActionReason = (value) => {
  const rawValue = String(value || "").trim();
  if (!rawValue) return { action: "Activity", description: "No additional details provided." };

  const separatorIndex = rawValue.indexOf(":");
  if (separatorIndex >= 0) {
    const actionCode = rawValue.slice(0, separatorIndex).trim();
    const description = rawValue.slice(separatorIndex + 1).trim();
    return {
      action: humanizeLabel(actionCode) || "Activity",
      description: description || "No additional details provided.",
    };
  }

  if (/^[A-Z0-9_-]+$/.test(rawValue)) {
    return { action: humanizeLabel(rawValue), description: "No additional details provided." };
  }

  return { action: "Activity", description: rawValue };
};

const formatActionReason = (value) => {
  const { action, description } = parseActionReason(value);
  return `${action}: ${description}`;
};

const ActionReason = ({ value }) => {
  const { action, description } = parseActionReason(value);
  return (
    <div className="space-y-1.5">
      <span className="inline-flex rounded-full bg-indigo-50 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide text-indigo-700">
        {action}
      </span>
      <p className="leading-5 text-slate-700">{description}</p>
    </div>
  );
};

const firstValue = (...values) => values.find((value) => value !== null && value !== undefined && String(value).trim() !== "");

const normalizeAcademicTerm = (value) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized.includes("final")) return "Finals";
  if (normalized.includes("mid")) return "Midterms";
  return "";
};

const inferAcademicTerm = (record = {}) => {
  const explicitTerm = normalizeAcademicTerm(firstValue(record.term, record.grade_term, record.gradeTerm));
  if (explicitTerm) return explicitTerm;

  const gradePayload = parseStructuredValue(record.grade);
  if (gradePayload && typeof gradePayload === "object" && !Array.isArray(gradePayload)) {
    if (firstValue(gradePayload.finals, gradePayload.final, gradePayload.finalGrade)) return "Finals";
    if (firstValue(gradePayload.midterm, gradePayload.midterms, gradePayload.midtermGrade)) return "Midterms";
  }
  return "";
};

const getTransactionMetadata = (record = {}) => ({
  year: String(firstValue(record.school_year, record.schoolYear, record.year_level, record.yearLevel) || "").trim(),
  section: String(firstValue(record.section, record.record_section, record.recordSection, record.student_section, record.studentSection) || "").trim(),
  course: String(firstValue(record.program, record.program_code, record.programCode, record.course, record.department) || "").trim(),
  term: inferAcademicTerm(record),
});

const mergeTransactionMetadata = (...metadataValues) => metadataValues.reduce((merged, metadata) => ({
  year: merged.year || metadata?.year || "",
  section: merged.section || metadata?.section || "",
  course: merged.course || metadata?.course || "",
  term: merged.term || metadata?.term || "",
}), { year: "", section: "", course: "", term: "" });

const sortedUniqueValues = (values) => [...new Set(values.filter(Boolean))]
  .sort((left, right) => left.localeCompare(right, undefined, { numeric: true }));

const parseStructuredValue = (value) => {
  let parsed = value;
  for (let attempt = 0; attempt < 3 && typeof parsed === "string"; attempt += 1) {
    const trimmed = parsed.trim();
    if (!["{", "[", '"'].includes(trimmed.charAt(0))) break;
    try {
      const nextValue = JSON.parse(trimmed);
      if (nextValue === parsed) break;
      parsed = nextValue;
    } catch {
      break;
    }
  }
  return parsed;
};

const formatStructuredValue = (value) => {
  if (value === null || value === undefined || value === "") return "Not recorded";
  const parsed = parseStructuredValue(value);

  if (Array.isArray(parsed)) {
    return parsed.map(formatStructuredValue).join(", ") || "Not recorded";
  }

  if (parsed && typeof parsed === "object") {
    return Object.entries(parsed)
      .map(([key, entry]) => `${humanizeLabel(key)}: ${formatStructuredValue(entry)}`)
      .join(" · ");
  }

  if (typeof parsed === "boolean") return parsed ? "Yes" : "No";
  return String(parsed);
};

const StructuredAuditValue = ({ value, tone = "blue" }) => {
  const parsed = parseStructuredValue(value);
  const toneClasses = tone === "slate"
    ? "border-slate-200 bg-slate-50 text-slate-700"
    : "border-blue-200 bg-blue-50 text-blue-900";

  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    return (
      <dl className={`grid gap-x-3 gap-y-1 rounded-lg border p-3 text-xs sm:grid-cols-[max-content_1fr] ${toneClasses}`}>
        {Object.entries(parsed).map(([key, entry]) => (
          <React.Fragment key={key}>
            <dt className="font-bold">{humanizeLabel(key)}</dt>
            <dd className="min-w-0 break-words">{formatStructuredValue(entry)}</dd>
          </React.Fragment>
        ))}
      </dl>
    );
  }

  return <div className={`rounded-lg border px-3 py-2 text-xs font-semibold ${toneClasses}`}>{formatStructuredValue(parsed)}</div>;
};

function SystemLogs({ grades = [] }) {
  const [logs, setLogs] = useState([]);
  const [availableCourses, setAvailableCourses] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [dateFilter, setDateFilter] = useState("");
  const [yearFilter, setYearFilter] = useState("All");
  const [sectionFilter, setSectionFilter] = useState("All");
  const [courseFilter, setCourseFilter] = useState("All");
  const [termFilter, setTermFilter] = useState("All");
  const [currentPage, setCurrentPage] = useState(1);
  const hasOpenedTransactionLogs = useRef(false);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const data = await fetchSystemLogs();
        if (data.status === "Success") {
          setLogs(data.data || []);
        }
      } catch (e) {
        console.error("Failed to fetch system logs:", e);
      }
      setIsLoading(false);
    };
    fetchLogs();
  }, []);

  useEffect(() => {
    const loadAvailableCourses = async () => {
      try {
        const response = await fetchAcademicPrograms();
        setAvailableCourses(Array.isArray(response?.data) ? response.data : []);
      } catch (error) {
        console.error("Failed to fetch available academic courses:", error);
        setAvailableCourses([]);
      }
    };
    loadAvailableCourses();
  }, []);

  const gradeMetadataByRecordId = useMemo(() => {
    const metadata = new Map();
    grades.forEach((grade) => {
      const recordId = firstValue(grade.id, grade.recordId, grade.record_id);
      if (!recordId) return;
      metadata.set(String(recordId), getTransactionMetadata(grade));
    });
    return metadata;
  }, [grades]);

  const reportTransactions = useMemo(() => {
    const auditedRecordIds = new Set(logs.map((log) => String(log.recordId || "")).filter(Boolean));
    const ledgerTransactions = grades
      .filter((grade) => {
        const recordId = firstValue(grade.id, grade.recordId, grade.record_id);
        return recordId && !auditedRecordIds.has(String(recordId));
      })
      .map((grade) => {
        const recordId = String(firstValue(grade.id, grade.recordId, grade.record_id));
        const subject = firstValue(grade.subject_code, grade.subjectCode, grade.course, "academic record");
        return {
          id: `ledger-${recordId}`,
          recordId,
          oldGrade: null,
          newGrade: {
            grade: grade.grade,
            status: grade.status,
            transactionId: firstValue(grade.transaction_id, grade.transactionId, grade.transaction_hash, grade.transactionHash),
          },
          reason: `LEDGER_TRANSACTION: Grade transaction recorded for ${subject}.`,
          approvedBy: firstValue(grade.submitted_by, grade.submittedBy, grade.faculty_id, grade.facultyId, grade.professor_name, grade.professorName, "Ledger"),
          timestamp: firstValue(grade.timestamp, grade.date, new Date().toISOString()),
        };
      });

    return [...logs, ...ledgerTransactions].sort((left, right) =>
      new Date(right.timestamp || 0).getTime() - new Date(left.timestamp || 0).getTime()
    );
  }, [logs, grades]);

  const logsWithMetadata = useMemo(() => reportTransactions.map((log) => {
    const oldValue = parseStructuredValue(log.oldGrade);
    const newValue = parseStructuredValue(log.newGrade);
    const ledgerMetadata = gradeMetadataByRecordId.get(String(log.recordId || ""));
    const oldMetadata = oldValue && typeof oldValue === "object" && !Array.isArray(oldValue)
      ? getTransactionMetadata(oldValue)
      : {};
    const newMetadata = newValue && typeof newValue === "object" && !Array.isArray(newValue)
      ? getTransactionMetadata(newValue)
      : {};
    return { ...log, reportMetadata: mergeTransactionMetadata(ledgerMetadata, newMetadata, oldMetadata) };
  }), [reportTransactions, gradeMetadataByRecordId]);

  const yearOptions = useMemo(() => sortedUniqueValues(logsWithMetadata.map((log) => log.reportMetadata.year)), [logsWithMetadata]);
  const sectionOptions = useMemo(() => sortedUniqueValues(logsWithMetadata.map((log) => log.reportMetadata.section)), [logsWithMetadata]);
  const courseOptions = useMemo(() => availableCourses
    .map((program) => {
      const code = String(program.programCode || program.code || "").trim();
      const name = String(program.programName || program.name || "").trim();
      return {
        value: code || name,
        label: code && name ? `${code} — ${name}` : code || name,
        aliases: [code, name].filter(Boolean).map((value) => value.toLowerCase()),
      };
    })
    .filter((program) => program.value)
    .sort((left, right) => left.label.localeCompare(right.label)), [availableCourses]);

  const selectedCourse = useMemo(
    () => courseOptions.find((course) => course.value === courseFilter),
    [courseOptions, courseFilter]
  );

  const filteredLogs = logsWithMetadata.filter((log) => {
    const matchesSearch = 
      (log.recordId || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.reason || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      formatActionReason(log.reason).toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.approvedBy || "").toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesDate = dateFilter 
      ? log.timestamp && new Date(log.timestamp).toISOString().startsWith(dateFilter)
      : true;

    const matchesYear = yearFilter === "All" || log.reportMetadata.year === yearFilter;
    const matchesSection = sectionFilter === "All" || log.reportMetadata.section === sectionFilter;
    const transactionCourse = String(log.reportMetadata.course || "").trim().toLowerCase();
    const matchesCourse = courseFilter === "All" || Boolean(
      selectedCourse?.aliases.includes(transactionCourse)
    );
    const matchesTerm = termFilter === "All" || log.reportMetadata.term === termFilter;
    
    return matchesSearch && matchesDate && matchesYear && matchesSection && matchesCourse && matchesTerm;
  });

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / TRANSACTIONS_PER_PAGE));
  const visiblePageNumbers = getVisiblePageNumbers(currentPage, totalPages);
  const pageStartIndex = (currentPage - 1) * TRANSACTIONS_PER_PAGE;
  const paginatedLogs = filteredLogs.slice(pageStartIndex, pageStartIndex + TRANSACTIONS_PER_PAGE);
  const firstVisibleTransaction = filteredLogs.length === 0 ? 0 : pageStartIndex + 1;
  const lastVisibleTransaction = Math.min(pageStartIndex + TRANSACTIONS_PER_PAGE, filteredLogs.length);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, dateFilter, yearFilter, sectionFilter, courseFilter, termFilter]);

  useEffect(() => {
    if (isLoading) return;

    setCurrentPage((page) => {
      if (!hasOpenedTransactionLogs.current) {
        hasOpenedTransactionLogs.current = true;
        return totalPages;
      }
      return Math.min(page, totalPages);
    });
  }, [isLoading, totalPages]);

  const showAllTransactions = () => {
    setSearchTerm("");
    setDateFilter("");
    setYearFilter("All");
    setSectionFilter("All");
    setCourseFilter("All");
    setTermFilter("All");
    setCurrentPage(1);
  };

  const handleExportPDF = () => {
    try {
      const { jsPDF } = window.jspdf;
      const doc = new jsPDF();

      // Add Header
      doc.setTextColor(0, 51, 102); // #003366
      doc.setFontSize(20);
      doc.setFont("helvetica", "bold");
      doc.text("PLV SYSTEM ACTIVITY REPORT", 14, 22);
      
      doc.setFontSize(10);
      doc.setTextColor(100);
      doc.setFont("helvetica", "normal");
      doc.text("Pamantasan ng Lungsod ng Valenzuela", 14, 28);
      doc.text(`Generated on: ${new Date().toLocaleString()}`, 14, 33);
      doc.text(`Total Records: ${filteredLogs.length}`, 14, 38);
      doc.text(
        `Filters - School Year: ${yearFilter === "All" ? "All" : yearFilter} | Section: ${sectionFilter === "All" ? "All" : sectionFilter} | Course: ${courseFilter === "All" ? "All" : selectedCourse?.value || courseFilter} | Term: ${termFilter === "All" ? "All" : termFilter}`,
        14,
        43
      );

      // Add a line separator
      doc.setDrawColor(0, 51, 102);
      doc.setLineWidth(0.5);
      doc.line(14, 47, 196, 47);

      // Table Data
      const tableColumn = ["Timestamp", "User", "Action/Reason", "Record ID", "Change"];
      const tableRows = filteredLogs.map(log => [
        new Date(log.timestamp).toLocaleString(),
        log.approvedBy || "N/A",
        formatActionReason(log.reason),
        log.recordId || "N/A",
        log.oldGrade
          ? `${formatStructuredValue(log.oldGrade)} to ${formatStructuredValue(log.newGrade)}`
          : `Created: ${formatStructuredValue(log.newGrade)}`
      ]);

      // Generate Table
      doc.autoTable({
        head: [tableColumn],
        body: tableRows,
        startY: 53,
        theme: 'striped',
        headStyles: { fillColor: [0, 51, 102], fontSize: 9 },
        bodyStyles: { fontSize: 8 },
        alternateRowStyles: { fillColor: [245, 247, 250] },
      });

      // Footer
      const pageCount = doc.internal.getNumberOfPages();
      for(let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(150);
        doc.text(`Page ${i} of ${pageCount} - Secured via PLV Ledger`, 105, 285, { align: 'center' });
      }

      doc.save(`System_Activity_Log_${new Date().toISOString().split('T')[0]}.pdf`);
    } catch (error) {
      console.error("PDF Generation failed:", error);
      alert("Failed to generate PDF. Please try again.");
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-[#003366]">System Activity Logs</h2>
          
        </div>
        <button 
          onClick={handleExportPDF}
          className="rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white transition hover:bg-[#00264d]"
        >
          Export Log as PDF
        </button>
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-7">
        <div className="xl:col-span-2">
          <label className="block text-xs font-bold uppercase text-slate-400">Search Records/Users</label>
          <input 
            type="text" 
            placeholder="Search student ID, professor, or action..."
            className="mt-1 w-full rounded-lg border border-slate-200 p-2 text-sm outline-none focus:border-[#003366]"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div>
          <label className="block text-xs font-bold uppercase text-slate-400">Filter by Date</label>
          <input 
            type="date" 
            className="mt-1 w-full rounded-lg border border-slate-200 p-2 text-sm outline-none focus:border-[#003366]"
            value={dateFilter}
            onChange={(e) => setDateFilter(e.target.value)}
          />
        </div>
        <div>
          <label className="block text-xs font-bold uppercase text-slate-400">School Year</label>
          <select
            value={yearFilter}
            onChange={(event) => setYearFilter(event.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-200 bg-white p-2 text-sm outline-none focus:border-[#003366]"
          >
            <option value="All">All School Years</option>
            {yearOptions.map((year) => <option key={year} value={year}>{year}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold uppercase text-slate-400">Section</label>
          <select
            value={sectionFilter}
            onChange={(event) => setSectionFilter(event.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-200 bg-white p-2 text-sm outline-none focus:border-[#003366]"
          >
            <option value="All">All Sections</option>
            {sectionOptions.map((section) => <option key={section} value={section}>{section}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold uppercase text-slate-400">Course</label>
          <select
            value={courseFilter}
            onChange={(event) => setCourseFilter(event.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-200 bg-white p-2 text-sm outline-none focus:border-[#003366]"
          >
            <option value="All">All Courses</option>
            {courseOptions.map((course) => <option key={course.value} value={course.value}>{course.label}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-bold uppercase text-slate-400">Academic Term</label>
          <select
            value={termFilter}
            onChange={(event) => setTermFilter(event.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-200 bg-white p-2 text-sm outline-none focus:border-[#003366]"
          >
            <option value="All">All Terms</option>
            <option value="Midterms">Midterms</option>
            <option value="Finals">Finals</option>
          </select>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-50 px-4 py-3">
        <p className="text-sm font-medium text-slate-600">
          Showing <span className="font-bold text-[#003366]">{firstVisibleTransaction}-{lastVisibleTransaction}</span> of {filteredLogs.length} filtered transactions
        </p>
        <button
          type="button"
          onClick={showAllTransactions}
          className="rounded-lg border border-[#003366] bg-white px-4 py-2 text-sm font-bold text-[#003366] transition hover:bg-blue-50"
        >
          Show All Transactions
        </button>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full min-w-[1100px] text-left text-sm">
          <thead className="bg-slate-50 text-xs font-bold uppercase text-slate-500">
            <tr>
              <th className="px-6 py-4">Timestamp</th>
              <th className="px-6 py-4">User</th>
              <th className="px-6 py-4">Action/Reason</th>
              <th className="px-6 py-4">Record ID</th>
              <th className="min-w-[360px] px-6 py-4">Change</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {isLoading ? (
              <tr><td colSpan="5" className="px-6 py-10 text-center text-slate-400">Loading system logs...</td></tr>
            ) : filteredLogs.length === 0 ? (
              <tr><td colSpan="5" className="px-6 py-10 text-center text-slate-400">No activity logs found.</td></tr>
            ) : (
              paginatedLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50">
                  <td className="px-6 py-4 font-mono text-xs">{new Date(log.timestamp).toLocaleString()}</td>
                  <td className="px-6 py-4 font-semibold">{log.approvedBy}</td>
                  <td className="px-6 py-4"><ActionReason value={log.reason} /></td>
                  <td className="px-6 py-4 text-xs font-mono">{log.recordId}</td>
                  <td className="px-6 py-4">
                    {log.oldGrade ? (
                      <div className="space-y-2">
                        <p className="text-[10px] font-bold uppercase tracking-wide text-slate-500">Previous</p>
                        <StructuredAuditValue value={log.oldGrade} tone="slate" />
                        <p className="text-[10px] font-bold uppercase tracking-wide text-blue-600">Updated</p>
                        <StructuredAuditValue value={log.newGrade} />
                      </div>
                    ) : (
                      <div className="space-y-2">
                        <p className="text-[10px] font-bold uppercase tracking-wide text-blue-600">Created</p>
                        <StructuredAuditValue value={log.newGrade} />
                      </div>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {!isLoading && filteredLogs.length > 0 ? (
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-3">
          <div className="flex flex-wrap items-center justify-center gap-2" aria-label="Transaction log pagination">
            <button
              type="button"
              onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
              disabled={currentPage === 1}
              className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-bold text-[#003366] transition hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Previous
            </button>
            {visiblePageNumbers.map((page) => (
              typeof page === "number" ? (
                <button
                  key={page}
                  type="button"
                  aria-label={`Go to page ${page}`}
                  aria-current={currentPage === page ? "page" : undefined}
                  onClick={() => setCurrentPage(page)}
                  className={`min-w-10 rounded-lg border px-3 py-2 text-sm font-bold transition ${
                    currentPage === page
                      ? "border-[#003366] bg-[#003366] text-white"
                      : "border-slate-300 bg-white text-[#003366] hover:bg-blue-50"
                  }`}
                >
                  {page}
                </button>
              ) : (
                <button
                  key={page}
                  type="button"
                  aria-label={page === "ellipsis-first" ? "Go to first page" : "Go to last page"}
                  onClick={() => setCurrentPage(page === "ellipsis-first" ? 1 : totalPages)}
                  className="min-w-10 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-bold text-slate-500 transition hover:bg-blue-50 hover:text-[#003366]"
                >
                  &hellip;
                </button>
              )
            ))}
            <button
              type="button"
              onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))}
              disabled={currentPage === totalPages}
              className="rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white transition hover:bg-[#00264d] disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default SystemLogs;
