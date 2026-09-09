import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { fetchAllGrades, finalizeGrade, fetchPendingRequests, approveRegistrationRequest, denyRegistrationRequest, fetchApprovedStudents, assignStudent, fetchApprovedAdmins, assignDepartmentAdmin, revokeDepartmentAdmin, fetchApprovedFaculties, assignFaculty, dropStudent, revokeFaculty, openDecryptedIpfsFile, getSystemSetting, resetEncodingSeason } from '../../services/api';
import RegistrarHeader from './RegistrarHeader';
import RegistrarSidebar from './RegistrarSidebar';
import RegistrarDashboard from './RegistrarDashboard';
import StudentListImport from './StudentListImport';
import EncodingPeriod from './EncodingPeriod';
import SystemLogs from './SystemLogs';
import PdfReportViewer from '../shared/PdfReportViewer';
import Modal from '../../services/Modal';
import RegistrarStudentSectioning from './RegistrarStudentSectioning';
import RegistrarSectionsCreated from './RegistrarSectionsCreated';
import { isDepartmentApprovedGradeStatus } from '../../utils/gradeStatus';
import StaffAccountCreation from './StaffAccountCreation';
import CurriculumManagement from './CurriculumManagement';
import { programs } from '../../data/registrarData';
import RegistrarSupportTickets from './RegistrarSupportTickets';
import StudentEnrollmentManagement from './StudentEnrollmentManagement';
import PasswordManagement from './PasswordManagement';

const RegistrarGradesView = ({
    loggedInEmail = '',
    loggedInName = '',
    chatUnreadCount = 0,
    latestChatNotice = null,
    onOpenChat,
    onLogout,
}) => {
    const managementMenuItems = [
        { id: 'grades', label: 'Grades Ledger' },
        { id: 'assigning', label: 'Assigning' },
        { id: 'bulkEnroll', label: 'Student Enrollment' },
        { id: 'createAccounts', label: 'Create Staff Accounts' },
        { id: 'curriculum', label: 'Curriculum Management' },
        { id: 'tickets', label: 'Report System Error' },
        { id: 'passwordResets', label: 'Password Management' },
        { id: 'revokeAccounts', label: 'Account Revocation' },
    ];
    const [grades, setGrades] = useState([]);
    const [mainTab, setMainTab] = useState('dashboard'); 
    const [assignmentTab, setAssignmentTab] = useState('students');
    
    const [pendingRequests, setPendingRequests] = useState([]);
    const [requestSearchTerm, setRequestSearchTerm] = useState('');

    const [approvedStudents, setApprovedStudents] = useState([]);
    const [studentAssignments, setStudentAssignments] = useState({});
    const [approvedAdmins, setApprovedAdmins] = useState([]);
    const [adminAssignments, setAdminAssignments] = useState({});
    const [approvedFaculties, setApprovedFaculties] = useState([]);
    const [facultyAssignments, setFacultyAssignments] = useState({});

    const [stagedGrades, setStagedGrades] = useState([]);
    const [stagedLoading, setStagedLoading] = useState(false);
    const [activeSemester, setActiveSemester] = useState('2nd Semester');

    const [filterDept, setFilterDept] = useState('All');
    const [filterYear, setFilterYear] = useState('All');
    const [filterSection, setFilterSection] = useState('All');

    const departments = programs;
    const [sectioningDepartment, setSectioningDepartment] = useState(departments[0]);

    const [ipfsModalOpen, setIpfsModalOpen] = useState(false);
    const [ipfsCid, setIpfsCid] = useState("");
    const [vaultPassword, setVaultPassword] = useState("");
    const [showVaultPassword, setShowVaultPassword] = useState(false);
    const [confirmModal, setConfirmModal] = useState({ isOpen: false, title: "", message: "", onConfirm: null, isDestructive: false });
    const [chairpersonSearchTerm, setChairpersonSearchTerm] = useState('');
    const [facultySearchTerm, setFacultySearchTerm] = useState('');
    const [showChairpersonAccounts, setShowChairpersonAccounts] = useState(false);
    const [showFacultyDepartments, setShowFacultyDepartments] = useState(false);
    const [selectedFacultyDepartment, setSelectedFacultyDepartment] = useState('');
    const [selectedFacultyReview, setSelectedFacultyReview] = useState('');
    const [openedFacultySections, setOpenedFacultySections] = useState({});

    const revocationPreviewSections = [
        {
            title: 'Registrar',
            description: 'Registrar-level accounts that can be reviewed for access removal.',
            accounts: [
                { id: 'REG-001', name: 'PLV Registrar Office', role: 'Registrar', scope: 'Institution-wide registrar tools', status: 'Active' },
            ],
        },
        {
            title: 'Department Chairperson',
            description: 'Department chairperson accounts grouped by their assigned academic unit.',
            accounts: departments.slice(0, 4).map((department, index) => ({
                id: `CH-${String(index + 1).padStart(3, '0')}`,
                name: `Chairperson ${index + 1}`,
                role: 'Department Chairperson',
                scope: department,
                status: 'Active',
            })),
        },
        {
            title: 'Faculty per Chairperson',
            description: 'Faculty accounts shown under their chairperson assignment for revocation review.',
            accounts: [
                { id: 'FAC-101', name: 'Faculty Member 1', role: 'Faculty', scope: `${departments[0]} • Chairperson 1`, status: 'Active' },
                { id: 'FAC-102', name: 'Faculty Member 2', role: 'Faculty', scope: `${departments[1]} • Chairperson 2`, status: 'Active' },
                { id: 'FAC-103', name: 'Faculty Member 3', role: 'Faculty', scope: `${departments[2]} • Chairperson 3`, status: 'Active' },
                { id: 'FAC-104', name: 'Faculty Member 4', role: 'Faculty', scope: `${departments[3]} • Chairperson 4`, status: 'Active' },
            ],
        },
    ];
    void revocationPreviewSections;

    const chairpersonRevocationAccounts = useMemo(
        () =>
            [...approvedAdmins]
                .sort((a, b) =>
                    String(a.department || '').localeCompare(String(b.department || '')) ||
                    String(a.fullname || a.email || '').localeCompare(String(b.fullname || b.email || ''))
                )
                .map((admin) => ({
                    id: admin.id,
                    department: admin.department || 'Unassigned',
                    name: admin.fullname || admin.email || `Chairperson ${admin.id}`,
                    email: admin.email || '',
                    role: admin.role || 'Department Chairperson',
                    status: 'Active',
                })),
        [approvedAdmins]
    );

    const facultyRevocationDepartments = useMemo(
        () => {
            const grouped = approvedFaculties.reduce((acc, faculty) => {
                const department = faculty.department || 'Unassigned';
                if (!acc[department]) acc[department] = [];

                acc[department].push({
                    id: faculty.id,
                    name: faculty.fullname || faculty.email || `Faculty ${faculty.id}`,
                    email: faculty.email || '',
                    role: 'Faculty',
                    status: 'Active',
                });

                return acc;
            }, {});

            return Object.entries(grouped)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([department, accounts]) => ({
                    name: department,
                    chairperson: `${department} Chairperson`,
                    accounts: accounts.sort((a, b) => a.name.localeCompare(b.name)),
                }));
        },
        [approvedFaculties]
    );

    const filteredChairpersonAccounts = useMemo(() => {
        const query = chairpersonSearchTerm.trim().toLowerCase();
        if (!query) return chairpersonRevocationAccounts;

        return chairpersonRevocationAccounts.filter((account) =>
            [account.name, account.department, account.id].some((value) =>
                String(value || '').toLowerCase().includes(query)
            )
        );
    }, [chairpersonRevocationAccounts, chairpersonSearchTerm]);

    const filteredFacultyDepartments = useMemo(() => {
        const query = facultySearchTerm.trim().toLowerCase();
        if (!query) return facultyRevocationDepartments;

        return facultyRevocationDepartments
            .map((department) => ({
                ...department,
                accounts: department.accounts.filter((account) =>
                    [account.name, account.id, department.name].some((value) =>
                        String(value || '').toLowerCase().includes(query)
                    )
                ),
            }))
            .filter(
                (department) =>
                    department.name.toLowerCase().includes(query) ||
                    department.accounts.length > 0
            );
    }, [facultyRevocationDepartments, facultySearchTerm]);

    const selectedFacultyDepartmentData = useMemo(() => {
        if (!selectedFacultyDepartment) return null;
        return filteredFacultyDepartments.find(
            (department) => department.name === selectedFacultyDepartment
        ) || null;
    }, [filteredFacultyDepartments, selectedFacultyDepartment]);

    const assignmentWorkflowTabs = [
        {
            id: 'students',
            label: 'Assign Students',
            count: approvedStudents.length,
        },
        {
            id: 'chairpersons',
            label: 'Assign Chairperson',
            count: approvedAdmins.length,
        },
        {
            id: 'faculty',
            label: 'Assign Faculty',
            count: approvedFaculties.length,
        },
    ];

    useEffect(() => {
        const applyEncodingPeriod = (value) => {
            if (!value) return;
            const parsed = typeof value === 'string' ? JSON.parse(value) : value;
            setActiveSemester(parsed?.semester || '2nd Semester');
        };

        const loadEncodingPeriod = async () => {
            try {
                const res = await getSystemSetting('encoding_period');
                if (res.status === 'Success' && res.value) {
                    applyEncodingPeriod(res.value);
                }
            } catch (error) {
                console.error(error);
            }
        };

        const handleSystemSettingChanged = (event) => {
            const key = event.detail?.key || event.detail?.Key;
            const value = event.detail?.value || event.detail?.Value;
            if (key === 'encoding_period') applyEncodingPeriod(value);
        };

        loadEncodingPeriod();
        window.addEventListener('blockgo:system-setting-changed', handleSystemSettingChanged);

        return () => window.removeEventListener('blockgo:system-setting-changed', handleSystemSettingChanged);
    }, []);

    const loadGrades = useCallback(async () => {
        try {
            const response = await fetchAllGrades(loggedInEmail);
            setGrades(Array.isArray(response) ? response : (response.data || []));
        } catch (error) {
            console.error(`Could not fetch data: ${error.message}`);
        }
    }, [loggedInEmail]);

    const loadStagedGrades = useCallback(async () => {
        setStagedLoading(true);
        try {
            const response = await fetchAllGrades(loggedInEmail);
            const allData = Array.isArray(response) ? response : (response.data || []);
            const approvedGrades = allData.filter(g =>
                isDepartmentApprovedGradeStatus(g.status || g.Status || g.normalized_status)
            );
            const formattedStaged = approvedGrades.map(g => ({
                stagingId: g.id,
                studentHash: g.student_hash || g.studentId,
                subjectCode: g.subject_code,
                grade: g.grade,
                course: g.course,
                yearLevel: g.year_level || g.yearLevel || "N/A",
                section: g.section,
                status: g.status
            }));
            setStagedGrades(formattedStaged);
        } catch (error) { console.error('Error loading staged grades:', error); }
        setStagedLoading(false);
    }, [loggedInEmail]);

    const loadRequests = useCallback(async () => {
        try {
            const response = await fetchPendingRequests();
            if (response.status === 'Success') setPendingRequests([...(response.studentRequests || []), ...(response.staffRequests || [])]);
        } catch (error) { console.error('Error loading requests:', error); }
    }, []);

    const loadApprovedStudents = useCallback(async () => {
        try {
            const response = await fetchApprovedStudents();
            if (response.status === 'Success') setApprovedStudents(response.students || []);
        } catch (error) { console.error('Error loading students:', error); }
    }, []);

    const loadApprovedAdmins = useCallback(async () => {
        try {
            const response = await fetchApprovedAdmins();
            if (response.status === 'Success') setApprovedAdmins(response.admins || []);
        } catch (error) { console.error('Error loading admins:', error); }
    }, []);

    const loadApprovedFaculties = useCallback(async () => {
        try {
            const response = await fetchApprovedFaculties();
            if (response.status === 'Success') setApprovedFaculties(response.faculties || []);
        } catch (error) { console.error('Error loading faculties:', error); }
    }, []);

    const handleResetEncodingSeason = useCallback(async () => {
        try {
            await resetEncodingSeason();
            const resetEncodingPeriod = JSON.stringify({
                semester: '2nd Semester',
                startDate: '',
                endDate: '',
                term: 'midterm',
            });
            localStorage.removeItem('registrarAssignments');
            localStorage.setItem('encodingPeriod', resetEncodingPeriod);
            localStorage.setItem('facultyLoadResetAt', new Date().toISOString());
            window.dispatchEvent(
                new CustomEvent('blockgo:system-setting-changed', {
                    detail: {
                        key: 'encoding_period',
                        value: resetEncodingPeriod,
                    },
                })
            );
            window.dispatchEvent(
                new CustomEvent('blockgo:faculty-load-reset', {
                    detail: { clearedAt: new Date().toISOString() },
                })
            );
            await loadApprovedFaculties();
            await loadGrades();
        } catch (error) {
            alert(error.message || 'Failed to reset encoding season.');
            throw error;
        }
    }, [loadApprovedFaculties, loadGrades]);

    useEffect(() => { loadGrades(); }, [loadGrades]);

    useEffect(() => {
        if (mainTab === 'Requests') {
            loadRequests();
        }
        if (mainTab === 'finalization') {
            loadStagedGrades();
        }
    }, [mainTab, loadRequests, loadStagedGrades]);

    useEffect(() => {
        const handleAcademicDataChanged = () => {
            loadGrades();
            loadApprovedStudents();
            loadApprovedAdmins();
            loadApprovedFaculties();
            if (mainTab === 'Requests') loadRequests();
            if (mainTab === 'finalization') loadStagedGrades();
        };

        window.addEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
        return () => window.removeEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
    }, [mainTab, loadGrades, loadRequests, loadStagedGrades, loadApprovedStudents, loadApprovedAdmins, loadApprovedFaculties]);

    useEffect(() => {
        if (mainTab === 'assigning') {
            setAssignmentTab('students');
            loadApprovedStudents();
            loadApprovedAdmins();
            loadApprovedFaculties();
        }
        if (mainTab === 'grades') loadApprovedFaculties();
        if (mainTab === 'revokeAccounts') {
            loadApprovedAdmins();
            loadApprovedFaculties();
        }
        if (mainTab === 'passwordResets') {
            loadApprovedStudents();
            loadApprovedAdmins();
            loadApprovedFaculties();
        }
    }, [mainTab, loadApprovedStudents, loadApprovedAdmins, loadApprovedFaculties]);

    const submitStudentAssignment = async (id) => {
        const assignment = studentAssignments[id];
        if (!assignment || !assignment.department || !assignment.yearLevel || !assignment.sectionNum) return alert("Please provide department, year, and section.");
        try {
            const combinedSection = `${assignment.yearLevel}-${assignment.sectionNum}`;
            await assignStudent(id, { Department: assignment.department, Section: combinedSection });
            alert("Student assigned successfully!");
            loadApprovedStudents();
        } catch (error) { alert(`Failed to assign: ${error.message}`); }
    };

    const submitAdminAssignment = async (id) => {
        const assignment = adminAssignments[id];
        if (!assignment || !assignment.department) return alert("Please select a department.");
        try {
            await assignDepartmentAdmin(id, { Department: assignment.department });
            alert("Admin assigned successfully!");
            loadApprovedAdmins();
        } catch (error) { alert(`Failed to assign: ${error.message}`); }
    };

    const submitFacultyAssignment = async (id) => {
        const assignment = facultyAssignments[id];
        if (!assignment || !assignment.department || !assignment.section || !assignment.yearLevel || !assignment.subject) return alert("Please provide department, section, year level, and subject.");
        try {
            await assignFaculty(id, { Department: assignment.department, Section: assignment.section, YearLevel: assignment.yearLevel, Subject: assignment.subject });
            alert("Faculty assigned successfully!");
            loadApprovedFaculties();
        } catch (error) { alert(`Failed to assign: ${error.message}`); }
    };

    const groupedStagedGrades = useMemo(() => {
        const groups = {};
        stagedGrades.forEach(g => {
            const key = `${g.course}-${g.yearLevel}-${g.section}-${g.subjectCode}`;
            if (!groups[key]) {
                groups[key] = {
                    course: g.course,
                    yearLevel: g.yearLevel,
                    section: g.section,
                    subjectCode: g.subjectCode,
                    records: []
                };
            }
            groups[key].records.push(g);
        });
        
        return Object.values(groups).sort((a, b) => 
            String(a.course).localeCompare(String(b.course)) || 
            String(a.yearLevel).localeCompare(String(b.yearLevel)) || 
            String(a.section).localeCompare(String(b.section)) ||
            String(a.subjectCode).localeCompare(String(b.subjectCode))
        );
    }, [stagedGrades]);

    const handleFinalizeBatch = async (records) => {
        if (!window.confirm(`Are you sure you want to commit all ${records.length} grades in this section to the blockchain ledger?`)) return;
        
        try {
            for (const g of records) {
                await finalizeGrade(g.stagingId, loggedInEmail);
            }
            alert("Section grades officially committed to the ledger!");
            loadStagedGrades();
            loadGrades();
        } catch (err) {
            alert(`Finalization failed: ${err.message}`);
        }
    };

    const handleViewIpfs = (cid) => {
        setIpfsCid(cid);
        setVaultPassword("");
        setShowVaultPassword(false);
        setIpfsModalOpen(true);
    };

    const submitIpfsPassword = async () => {
        if (vaultPassword) {
            const viewerWindow = window.open('', "_blank");
            try {
                await openDecryptedIpfsFile(ipfsCid, vaultPassword, viewerWindow);
                setIpfsModalOpen(false);
            } catch (error) {
                if (viewerWindow) viewerWindow.close();
                alert(error.message);
            }
        } else {
            alert("Vault Password is required");
        }
    };

    const handleApproveRequest = async (id, type) => {
        setConfirmModal({
            isOpen: true,
            title: "Approve Request",
            message: `Are you sure you want to approve this ${type} registration request?`,
            onConfirm: async () => {
                try {
                    await approveRegistrationRequest(id, type);
                    alert("Request approved successfully!");
                    loadRequests(); 
                } catch (error) { alert(`Failed to approve: ${error.message}`); }
                setConfirmModal(prev => ({ ...prev, isOpen: false }));
            }
        });
    };

    const handleDenyRequest = async (id) => {
        setConfirmModal({
            isOpen: true,
            title: "Deny Request",
            message: "Are you sure you want to deny this request?",
            isDestructive: true,
            onConfirm: async () => {
                try {
                    await denyRegistrationRequest(id);
                    alert("Request denied and removed.");
                    loadRequests(); 
                } catch (error) { alert(`Failed to deny: ${error.message}`); }
                setConfirmModal(prev => ({ ...prev, isOpen: false }));
            }
        });
    };

    const handleDropStudent = async (id, name) => {
        setConfirmModal({
            isOpen: true,
            title: "Drop Student",
            message: `Are you sure you want to drop ${name}? This will revoke their system access completely.`,
            isDestructive: true,
            onConfirm: async () => {
                try {
                    await dropStudent(id);
                    alert(`${name} has been dropped and access revoked.`);
                    loadApprovedStudents();
                } catch (error) {
                    alert(error.message);
                }
                setConfirmModal(prev => ({ ...prev, isOpen: false }));
            }
        });
    };

    const handleRevokeFaculty = async (id, name) => {
        setConfirmModal({
            isOpen: true,
            title: "Revoke Faculty Account",
            message: `Are you sure you want to revoke ${name}? This will remove their system account and Fabric wallet access.`,
            isDestructive: true,
            onConfirm: async () => {
                try {
                    await revokeFaculty(id);
                    alert(`${name} has been revoked.`);
                    await loadApprovedFaculties();
                } catch (error) {
                    alert(error.message || 'Failed to revoke faculty account.');
                }
                setConfirmModal(prev => ({ ...prev, isOpen: false }));
            }
        });
    };

    const handleRevokeChairperson = async (id, name) => {
        setConfirmModal({
            isOpen: true,
            title: "Revoke Chairperson Account",
            message: `Are you sure you want to revoke ${name}? This will remove their department admin account and Fabric wallet access.`,
            isDestructive: true,
            onConfirm: async () => {
                try {
                    await revokeDepartmentAdmin(id);
                    setApprovedAdmins((current) => current.filter((admin) => admin.id !== id));
                    alert(`${name} has been revoked.`);
                    await loadApprovedAdmins();
                } catch (error) {
                    alert(error.message || 'Failed to revoke chairperson account.');
                }
                setConfirmModal(prev => ({ ...prev, isOpen: false }));
            }
        });
    };

    const sortedAndFilteredRequests = useMemo(() => {
        let sortableItems = [...pendingRequests];
        const searchTerm = requestSearchTerm.toLowerCase();
        return sortableItems.filter(req => Object.values(req).some(val => String(val).toLowerCase().includes(searchTerm)));
    }, [pendingRequests, requestSearchTerm]);

    const filteredGrades = grades.filter(grade => {
        if (!loggedInEmail) return false;
        const matchesDept = filterDept === 'All' || (grade.course || "").includes(filterDept) || (grade.subject_code || "").includes(filterDept);
        const matchesYear = filterYear === 'All' || (String(grade.year_level) === filterYear) || (grade.subject_code?.match(/[A-Za-z]+-?(\d)/)?.[1] === filterYear);
        const matchesSection = filterSection === 'All' || (String(grade.section) === filterSection) || (grade.section?.includes(filterSection));
        return matchesDept && matchesYear && matchesSection;
    });

    const parseGradePayload = useCallback((rawGrade) => {
        if (!rawGrade) return {};
        if (typeof rawGrade === 'object') return rawGrade;
        if (typeof rawGrade === 'string' && rawGrade.trim().startsWith('{')) {
            try {
                return JSON.parse(rawGrade);
            } catch (error) {
                return {};
            }
        }
        return { finalAverage: rawGrade };
    }, []);

    const formatGradePayload = useCallback((rawGrade) => {
        const payload = parseGradePayload(rawGrade);
        const values = [
            payload.midterm ? `Midterm: ${payload.midterm}` : null,
            payload.finals ? `Finals: ${payload.finals}` : null,
            payload.finalAverage ? `Equivalent: ${payload.finalAverage}` : null,
        ].filter(Boolean);
        return values.length > 0 ? values.join(' · ') : 'Not recorded';
    }, [parseGradePayload]);

    const formatStudentStanding = useCallback((standing) => {
        switch (standing) {
            case 'dropped':
                return 'Dropped (D)';
            case 'unofficially_dropped':
                return 'Unofficial Dropped (UD)';
            case 'withdrawn':
                return 'Withdrawn (W)';
            case 'incomplete':
                return 'Incomplete (INC)';
            default:
                return 'Active';
        }
    }, []);

    const facultyNameLookup = useMemo(
        () =>
            approvedFaculties.reduce((acc, faculty) => {
                const key = String(faculty.email || '').trim().toLowerCase();
                if (key) acc[key] = faculty.fullname || faculty.email || key;
                return acc;
            }, {}),
        [approvedFaculties]
    );

    const facultyMonitoringRecords = useMemo(
        () =>
            filteredGrades.map((grade) => {
                const payload = parseGradePayload(grade.grade);
                const standing = payload.standing || payload.remarks || 'active';
                const facultyEmail = grade.facultyId || grade.faculty_id || 'N/A';
                const normalizedFacultyEmail = String(facultyEmail).trim().toLowerCase();
                const facultyName = facultyNameLookup[normalizedFacultyEmail] || facultyEmail;
                const sectionName = grade.section || 'Unassigned Section';

                return {
                    ...grade,
                    payload,
                    standing,
                    standingLabel: formatStudentStanding(standing),
                    hasPriorityStatus: ['dropped', 'unofficially_dropped', 'withdrawn', 'incomplete'].includes(standing),
                    facultyEmail,
                    facultyName,
                    sectionName,
                    studentDisplayId: grade.student_no || grade.studentNo || grade.student_hash || grade.studentId || 'N/A',
                    studentDisplayName: grade.student_name || grade.studentName || 'Unknown Student',
                    midterm: payload.midterm || '',
                    finals: payload.finals || '',
                    finalAverage: payload.finalAverage || payload.final || payload.grade || '',
                    flagged: !!payload.flagged,
                };
            }),
        [filteredGrades, parseGradePayload, facultyNameLookup, formatStudentStanding]
    );

    const facultyMonitoringList = useMemo(() => {
        const grouped = facultyMonitoringRecords.reduce((acc, record) => {
            const key = String(record.facultyEmail || 'n/a').trim().toLowerCase();
            if (!acc[key]) {
                acc[key] = {
                    facultyKey: key,
                    facultyName: record.facultyName,
                    facultyEmail: record.facultyEmail,
                    records: [],
                };
            }

            acc[key].records.push(record);
            return acc;
        }, {});

        return Object.values(grouped)
            .map((faculty) => {
                const sections = Object.values(
                    faculty.records.reduce((acc, record) => {
                        const sectionKey = `${record.sectionName}|||${record.course || ''}`;
                        if (!acc[sectionKey]) {
                            acc[sectionKey] = {
                                sectionKey,
                                sectionName: record.sectionName,
                                department: record.course || 'N/A',
                                records: [],
                            };
                        }
                        acc[sectionKey].records.push(record);
                        return acc;
                    }, {})
                ).sort((left, right) => {
                    const leftPriority = left.records.some((record) => record.hasPriorityStatus) ? 1 : 0;
                    const rightPriority = right.records.some((record) => record.hasPriorityStatus) ? 1 : 0;
                    return rightPriority - leftPriority || left.sectionName.localeCompare(right.sectionName);
                });

                return {
                    ...faculty,
                    sections,
                    totalSections: sections.length,
                    totalRecords: faculty.records.length,
                    priorityCount: faculty.records.filter((record) => record.hasPriorityStatus).length,
                    flaggedCount: faculty.records.filter((record) => record.flagged).length,
                    hasPriorityStatus: faculty.records.some((record) => record.hasPriorityStatus),
                };
            })
            .sort((left, right) =>
                Number(right.hasPriorityStatus) - Number(left.hasPriorityStatus) ||
                right.priorityCount - left.priorityCount ||
                left.facultyName.localeCompare(right.facultyName)
            );
    }, [facultyMonitoringRecords]);

    const selectedFacultyMonitoringData = useMemo(() => {
        if (!selectedFacultyReview) return facultyMonitoringList[0] || null;
        return facultyMonitoringList.find((faculty) => faculty.facultyKey === selectedFacultyReview) || facultyMonitoringList[0] || null;
    }, [facultyMonitoringList, selectedFacultyReview]);

    useEffect(() => {
        if (!selectedFacultyMonitoringData) {
            setSelectedFacultyReview('');
            return;
        }

        if (selectedFacultyReview !== selectedFacultyMonitoringData.facultyKey) {
            setSelectedFacultyReview(selectedFacultyMonitoringData.facultyKey);
        }
    }, [selectedFacultyMonitoringData, selectedFacultyReview]);

    const toggleFacultySectionView = (sectionKey) => {
        setOpenedFacultySections((prev) => ({
            ...prev,
            [sectionKey]: !prev[sectionKey],
        }));
    };

    const handleDownloadLedgerPDF = () => {
        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF('l', 'mm', 'a4');
            doc.setTextColor(0, 51, 102);
            doc.setFontSize(22);
            doc.text("PLV OFFICIAL GRADES LEDGER", 14, 20);
            doc.setFontSize(10);
            doc.setTextColor(100);
            doc.text(`Academic Audit Report - Blockchain Verified`, 14, 27);
            doc.text(`Filter - Dept: ${filterDept} | Year: ${filterYear} | Section: ${filterSection}`, 14, 32);
            doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 37);

            const tableColumn = ["Record ID", "Student Hash", "Subject", "Grade", "Faculty", "Year", "Section", "Status"];
            const tableRows = filteredGrades.map(g => [
                g.id,
                g.student_hash || g.studentId || "N/A",
                g.subject_code,
                g.grade,
                g.facultyId || g.faculty_id || "N/A",
                g.year_level || "N/A",
                g.section || "N/A",
                g.status
            ]);

            doc.autoTable({
                head: [tableColumn],
                body: tableRows,
                startY: 42,
                theme: 'grid',
                headStyles: { fillColor: [0, 51, 102], fontSize: 8 },
                bodyStyles: { fontSize: 7 },
            });
            doc.save(`Grades_Ledger_Audit_${new Date().toISOString().split('T')[0]}.pdf`);
        } catch (error) { alert("Failed to export PDF."); }
    };

    const handleExportFacultySummaryPDF = (facultyData) => {
        if (!facultyData) return;
        try {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF('p', 'mm', 'a4');
            
            doc.setTextColor(0, 51, 102);
            doc.setFontSize(16);
            doc.setFont("helvetica", "bold");
            doc.text("PAMANTASAN NG LUNGSOD NG VALENZUELA", 105, 20, { align: 'center' });
            
            doc.setFontSize(12);
            doc.text("FACULTY ENCODING SUMMARY REPORT", 105, 28, { align: 'center' });
            
            doc.setFontSize(10);
            doc.setFont("helvetica", "normal");
            doc.setTextColor(100);
            doc.text(`Faculty Name: ${facultyData.facultyName}`, 14, 45);
            doc.text(`Email: ${facultyData.facultyEmail}`, 14, 50);
            doc.text(`Total Sections Encoded: ${facultyData.totalSections}`, 14, 55);
            doc.text(`Total Records: ${facultyData.totalRecords}`, 14, 60);
            doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 65);
            
            let startY = 75;
            
            facultyData.sections.forEach((section, index) => {
                doc.setFontSize(11);
                doc.setTextColor(0, 51, 102);
                doc.setFont("helvetica", "bold");
                doc.text(`Section: ${section.sectionName} (${section.department})`, 14, startY);
                
                const tableColumn = ["Student ID", "Student Name", "Subj", "Mid", "Fin", "Final", "Status"];
                const tableRows = section.records.map(r => [
                    r.studentDisplayId,
                    r.studentDisplayName,
                    r.subject_code || '--',
                    r.midterm || '--',
                    r.finals || '--',
                    r.finalAverage || '--',
                    r.status || 'N/A'
                ]);
                
                doc.autoTable({
                    head: [tableColumn],
                    body: tableRows,
                    startY: startY + 4,
                    theme: 'grid',
                    headStyles: { fillColor: [0, 51, 102], fontSize: 8 },
                    bodyStyles: { fontSize: 8 },
                    margin: { left: 14, right: 14 }
                });
                
                startY = doc.lastAutoTable.finalY + 15;
                
                if (startY > 250 && index < facultyData.sections.length - 1) {
                    doc.addPage();
                    startY = 20;
                }
            });
            
            if (startY > 230) {
                doc.addPage();
                startY = 20;
            }
            
            doc.setFontSize(10);
            doc.setFont("helvetica", "normal");
            doc.setTextColor(0, 0, 0);
            
            startY += 20;
            doc.text("Prepared by:", 14, startY);
            doc.text("Verified & Received by:", 120, startY);
            
            startY += 15;
            doc.setLineWidth(0.5);
            doc.line(14, startY, 74, startY);
            doc.line(120, startY, 180, startY);
            
            startY += 5;
            doc.setFont("helvetica", "bold");
            doc.text(facultyData.facultyName, 44, startY, { align: 'center' });
            doc.text("University Registrar", 150, startY, { align: 'center' });
            
            doc.setFont("helvetica", "normal");
            doc.text("Faculty / Instructor", 44, startY + 5, { align: 'center' });
            doc.text("Pamantasan ng Lungsod ng Valenzuela", 150, startY + 5, { align: 'center' });
            
            doc.save(`Faculty_Summary_${facultyData.facultyName.replace(/\s+/g, '_')}.pdf`);
        } catch (error) { 
            console.error(error);
            alert("Failed to export PDF."); 
        }
    };

    return (
        <div className="flex h-screen w-full flex-col bg-slate-50 font-sans fixed inset-0 z-[100] overflow-auto">
            <RegistrarHeader registrarData={{ name: loggedInName, semester: activeSemester }} onLogout={onLogout} />
            <div className="flex flex-col md:flex-row flex-1 overflow-hidden p-4 md:p-6 gap-6">
                <RegistrarSidebar
                    activeTab={mainTab}
                    setActiveTab={setMainTab}
                    chatUnreadCount={chatUnreadCount}
                    latestChatNotice={latestChatNotice}
                    onOpenChat={onOpenChat}
                    managementDefaultTab="grades"
                    managementMenuItems={managementMenuItems}
                />
                <main className="flex-1 overflow-y-auto pb-24 pr-2">
                    {mainTab === 'dashboard' && <RegistrarDashboard grades={grades} />}
                    {mainTab === 'encoding' && <EncodingPeriod onResetEncodingSeason={handleResetEncodingSeason} />}
                    {mainTab === 'studentlist' && <StudentListImport />}
                    {mainTab === 'sectioning' && (
                        <div className="space-y-3">
                            <div>
                                <h2 className="text-xl font-bold text-slate-900">Department Sections</h2>
                                
                            </div>
                            <div className="grid gap-3 rounded-lg border border-slate-200 bg-white p-3 shadow-sm lg:grid-cols-[1fr_250px] lg:items-end">
                                <label className="block">
                                    <span className="mb-1 block text-[11px] font-semibold text-slate-600">Department</span>
                                    <select
                                        value={sectioningDepartment}
                                        onChange={(event) => setSectioningDepartment(event.target.value)}
                                        className="h-9 w-full rounded-md border border-slate-300 bg-white px-3 text-xs outline-none focus:border-[#003366]"
                                    >
                                        {departments.map((department) => (
                                            <option key={department} value={department}>
                                                {department}
                                            </option>
                                        ))}
                                    </select>
                                </label>
                                
                            </div>
                            <RegistrarStudentSectioning chairpersonDepartment={sectioningDepartment} />
                        </div>
                    )}
                    {mainTab === 'bulkEnroll' && (
                        <StudentEnrollmentManagement programs={departments} />
                    )}
                    {mainTab === 'createAccounts' && <StaffAccountCreation />}
                    {mainTab === 'curriculum' && <CurriculumManagement />}
                    {mainTab === 'tickets' && <RegistrarSupportTickets />}
                    {mainTab === 'passwordResets' && <PasswordManagement
                        students={approvedStudents}
                        faculties={approvedFaculties}
                        departmentAdmins={approvedAdmins}
                        onRefresh={() => Promise.all([loadApprovedStudents(), loadApprovedAdmins(), loadApprovedFaculties()])}
                    />}
                    {mainTab === 'sectionsCreated' && <RegistrarSectionsCreated />}
                    {mainTab === 'reports' && (
                        <div className="flex flex-col gap-8">
                            <SystemLogs grades={grades} />
                            <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                                <h3 className="mb-6 text-xl font-bold text-[#003366]">System Compliance Report Preview</h3>
                                <PdfReportViewer title="PLV System Activity & Compliance" />
                            </div>
                        </div>
                    )}
                    {mainTab === 'grades' && (
                        <>
                            <div className="mb-6 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                                <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
                                    <div className="flex flex-wrap items-center gap-4">
                                        <select value={filterDept} onChange={(e) => setFilterDept(e.target.value)} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold outline-none focus:border-[#003366]">
                                            <option value="All">All Departments</option>
                                            {departments.map(d => <option key={d} value={d}>{d}</option>)}
                                        </select>
                                        <select value={filterYear} onChange={(e) => setFilterYear(e.target.value)} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold outline-none focus:border-[#003366]">
                                            <option value="All">All Year Level</option>
                                            <option value="1">1st Year</option><option value="2">2nd Year</option><option value="3">3rd Year</option><option value="4">4th Year</option>
                                        </select>
                                        <select value={filterSection} onChange={(e) => setFilterSection(e.target.value)} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold outline-none focus:border-[#003366]">
                                            <option value="All">All Sections</option>
                                            {[...Array(15)].map((_, i) => <option key={i+1} value={String(i+1)}>{i+1}</option>)}
                                        </select>
                                    </div>
                                    <div className="flex gap-3">
                                        <button onClick={handleDownloadLedgerPDF} className="rounded-xl bg-emerald-600 px-5 py-2 text-sm font-bold text-white transition hover:bg-emerald-700">Export PDF</button>
                                        <button onClick={loadGrades} className="rounded-xl bg-[#003366] px-5 py-2 text-sm font-bold text-white transition hover:bg-[#00264d]">Refresh</button>
                                    </div>
                                </div>
                            </div>
                            <div className="grid gap-6 xl:grid-cols-[340px_minmax(0,1fr)]">
                                <aside className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
                                    <div className="border-b border-slate-200 px-5 py-4">
                                        <h3 className="text-lg font-bold text-[#003366]">Faculty Encoding Monitoring</h3>
                                        
                                    </div>
                                    <div className="max-h-[720px] overflow-y-auto p-4">
                                        {facultyMonitoringList.length === 0 ? (
                                            <div className="rounded-2xl border border-dashed border-slate-200 p-6 text-center text-sm text-slate-500">
                                                No faculty submissions matched the current filters.
                                            </div>
                                        ) : facultyMonitoringList.map((faculty) => {
                                            const isSelected = selectedFacultyMonitoringData?.facultyKey === faculty.facultyKey;
                                            return (
                                                <button
                                                    key={faculty.facultyKey}
                                                    type="button"
                                                    onClick={() => setSelectedFacultyReview(faculty.facultyKey)}
                                                    className={`mb-3 w-full rounded-2xl border p-4 text-left transition ${
                                                        isSelected
                                                            ? 'border-[#003366] bg-[#003366]/5 shadow-sm'
                                                            : 'border-slate-200 bg-slate-50 hover:border-slate-300'
                                                    }`}
                                                >
                                                    <div className="flex items-start justify-between gap-3">
                                                        <div>
                                                            <p className="text-sm font-bold text-slate-900">{faculty.facultyName}</p>
                                                            <p className="mt-1 break-all text-xs text-slate-500">{faculty.facultyEmail}</p>
                                                        </div>
                                                        {faculty.hasPriorityStatus ? (
                                                            <span className="rounded-full bg-red-100 px-3 py-1 text-[10px] font-bold uppercase text-red-700">
                                                                Priority
                                                            </span>
                                                        ) : null}
                                                    </div>
                                                    <div className="mt-3 flex flex-wrap gap-2 text-[11px] font-semibold text-slate-600">
                                                        <span className="rounded-full bg-white px-3 py-1">Sections: {faculty.totalSections}</span>
                                                        <span className="rounded-full bg-white px-3 py-1">Records: {faculty.totalRecords}</span>
                                                        <span className="rounded-full bg-white px-3 py-1">Special Status: {faculty.priorityCount}</span>
                                                        <span className="rounded-full bg-white px-3 py-1">Flagged: {faculty.flaggedCount}</span>
                                                    </div>
                                                </button>
                                            );
                                        })}
                                    </div>
                                </aside>

                                <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                                    {!selectedFacultyMonitoringData ? (
                                        <div className="rounded-2xl border border-dashed border-slate-200 p-10 text-center text-slate-500">
                                            Select a faculty submission to review encoded sections.
                                        </div>
                                    ) : (
                                        <div className="space-y-5">
                                            <div className="flex flex-col gap-3 border-b border-slate-200 pb-4 lg:flex-row lg:items-center lg:justify-between">
                                                <div>
                                                    <h3 className="text-xl font-bold text-[#003366]">{selectedFacultyMonitoringData.facultyName}</h3>
                                                    <p className="text-sm text-slate-500">{selectedFacultyMonitoringData.facultyEmail}</p>
                                                </div>
                                                <div className="flex flex-wrap gap-2 text-xs font-semibold text-slate-600">
                                                    <span className="rounded-full bg-slate-100 px-3 py-2">Sections: {selectedFacultyMonitoringData.totalSections}</span>
                                                    <span className="rounded-full bg-slate-100 px-3 py-2">Records: {selectedFacultyMonitoringData.totalRecords}</span>
                                                    <span className="rounded-full bg-red-50 px-3 py-2 text-red-700">D / UD / W / INC: {selectedFacultyMonitoringData.priorityCount}</span>
                                                    <span className="rounded-full bg-amber-50 px-3 py-2 text-amber-700">Flagged: {selectedFacultyMonitoringData.flaggedCount}</span>
                                                </div>
                                                <div className="flex flex-wrap gap-2 mt-2 lg:mt-0">
                                                    <button onClick={() => handleExportFacultySummaryPDF(selectedFacultyMonitoringData)} className="rounded-xl border border-[#003366] bg-white px-4 py-2 text-sm font-bold text-[#003366] transition hover:bg-[#003366] hover:text-white">
                                                        Export Summary for Signing
                                                    </button>
                                                </div>
                                            </div>

                                            <div className="space-y-4">
                                                {selectedFacultyMonitoringData.sections.map((section) => {
                                                    const isOpen = !!openedFacultySections[section.sectionKey];
                                                    const sectionPriorityCount = section.records.filter((record) => record.hasPriorityStatus).length;
                                                    return (
                                                        <div key={section.sectionKey} className="overflow-hidden rounded-2xl border border-slate-200 bg-slate-50">
                                                            <div className="flex flex-col gap-3 border-b border-slate-200 px-4 py-4 lg:flex-row lg:items-center lg:justify-between">
                                                                <div>
                                                                    <p className="text-base font-bold text-slate-900">{section.sectionName}</p>
                                                                    <p className="text-sm text-slate-500">{section.department}</p>
                                                                </div>
                                                                <div className="flex flex-wrap items-center gap-2">
                                                                    <span className="rounded-full bg-white px-3 py-2 text-[11px] font-semibold text-slate-600">Encoded Grades: {section.records.length}</span>
                                                                    {sectionPriorityCount > 0 ? (
                                                                        <span className="rounded-full bg-red-100 px-3 py-2 text-[11px] font-semibold text-red-700">Special Status: {sectionPriorityCount}</span>
                                                                    ) : null}
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => toggleFacultySectionView(section.sectionKey)}
                                                                        className="rounded-xl bg-[#003366] px-4 py-2 text-sm font-bold text-white transition hover:bg-[#00264d]"
                                                                    >
                                                                        {isOpen ? 'Hide Grades' : 'View Grades'}
                                                                    </button>
                                                                </div>
                                                            </div>

                                                            {isOpen ? (
                                                                <div className="overflow-x-auto">
                                                                    <table className="w-full min-w-[950px] text-left text-sm">
                                                                        <thead>
                                                                            <tr className="bg-[#003366] text-white">
                                                                                <th className="p-4">Student ID</th>
                                                                                <th className="p-4">Student Name</th>
                                                                                <th className="p-4">Subject</th>
                                                                                <th className="p-4">Midterm</th>
                                                                                <th className="p-4">Finals</th>
                                                                                <th className="p-4">Final Rating</th>
                                                                                <th className="p-4">Student Status</th>
                                                                                <th className="p-4">Record Status</th>
                                                                                <th className="p-4">Flags</th>
                                                                                <th className="p-4">Actions</th>
                                                                            </tr>
                                                                        </thead>
                                                                        <tbody>
                                                                            {section.records
                                                                                .slice()
                                                                                .sort((left, right) =>
                                                                                    Number(right.hasPriorityStatus) - Number(left.hasPriorityStatus) ||
                                                                                    left.studentDisplayId.localeCompare(right.studentDisplayId)
                                                                                )
                                                                                .map((record) => (
                                                                                    <tr key={record.id} className={`border-b border-slate-100 hover:bg-white ${record.hasPriorityStatus ? 'bg-red-50/60' : ''}`}>
                                                                                        <td className="p-4 font-semibold text-slate-700">{record.studentDisplayId}</td>
                                                                                        <td className="p-4">{record.studentDisplayName}</td>
                                                                                        <td className="p-4 font-bold text-slate-800">{record.subject_code || 'N/A'}</td>
                                                                                        <td className="p-4">{record.midterm || '--'}</td>
                                                                                        <td className="p-4">{record.finals || '--'}</td>
                                                                                        <td className="p-4 font-black text-[#003366]">{record.finalAverage || '--'}</td>
                                                                                        <td className="p-4">
                                                                                            <span className={`rounded-full px-3 py-1 text-[10px] font-bold uppercase ${
                                                                                                record.hasPriorityStatus ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-700'
                                                                                            }`}>
                                                                                                {record.standingLabel}
                                                                                            </span>
                                                                                        </td>
                                                                                        <td className="p-4">
                                                                                            <span className="rounded-full bg-slate-100 px-3 py-1 text-[10px] font-bold uppercase text-slate-700">
                                                                                                {record.status || 'N/A'}
                                                                                            </span>
                                                                                        </td>
                                                                                        <td className="p-4">
                                                                                            {record.flagged ? (
                                                                                                <span className="rounded-full bg-amber-100 px-3 py-1 text-[10px] font-bold uppercase text-amber-700">Flagged</span>
                                                                                            ) : (
                                                                                                <span className="text-xs text-slate-400">--</span>
                                                                                            )}
                                                                                        </td>
                                                                                        <td className="p-4">
                                                                                            <div className="flex flex-col items-start gap-2">
                                                                                                {(record.ipfs_cid || record.IpfsCID) ? <button onClick={() => handleViewIpfs(record.ipfs_cid || record.IpfsCID)} className="font-bold text-blue-600 hover:underline">View File</button> : <span className="text-xs text-slate-400">No File</span>}
                                                                                            </div>
                                                                                        </td>
                                                                                    </tr>
                                                                                ))}
                                                                        </tbody>
                                                                    </table>
                                                                </div>
                                                            ) : null}
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    )}
                                </section>
                            </div>
                        </>
                    )}
                    {mainTab === 'finalization' && (
                        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                            <div className="mb-6 flex items-center justify-between">
                                <h3 className="text-xl font-bold text-[#003366]">Grades Pending Ledger Entry</h3>
                                <button onClick={loadStagedGrades} className="rounded-lg bg-slate-100 px-4 py-2 text-sm font-bold text-slate-700 hover:bg-slate-200">Refresh Staging</button>
                            </div>
                            {stagedLoading ? <p>Loading staged records...</p> : (
                                <div className="space-y-6">
                                    {groupedStagedGrades.length === 0 ? (
                                        <div className="rounded-xl border border-dashed border-slate-300 p-10 text-center text-slate-500 bg-slate-50">
                                            No grades approved by departments waiting for finalization.
                                        </div>
                                    ) : (
                                        groupedStagedGrades.map((group, index) => (
                                            <div key={index} className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm">
                                                <div className="flex flex-col md:flex-row md:items-center justify-between bg-slate-50 p-5 border-b border-slate-200">
                                                    <div>
                                                        <h4 className="font-bold text-[#003366] text-lg">
                                                            {group.course} — {group.yearLevel} / {group.section}
                                                        </h4>
                                                        <p className="text-sm font-semibold text-slate-500 mt-1">
                                                            Subject: <span className="text-blue-600">{group.subjectCode}</span> 
                                                            <span className="mx-2">•</span> 
                                                            {group.records.length} pending grade(s)
                                                        </p>
                                                    </div>
                                                    <button 
                                                        onClick={() => handleFinalizeBatch(group.records)}
                                                        className="mt-3 md:mt-0 rounded-lg bg-emerald-600 px-5 py-2.5 text-sm font-bold text-white transition hover:bg-emerald-700 shadow-sm"
                                                    >
                                                        Finalize All to Ledger
                                                    </button>
                                                </div>
                                                <div className="overflow-x-auto">
                                                    <table className="w-full text-left text-sm">
                                                        <thead>
                                                            <tr className="bg-white text-slate-500 border-b border-slate-200">
                                                                <th className="p-4 font-semibold">Student (Hashed)</th>
                                                                <th className="p-4 font-semibold text-center">Grade</th>
                                                                <th className="p-4 font-semibold text-center">Status</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {group.records.map((sg) => (
                                                                <tr key={sg.stagingId} className="border-b border-slate-50 hover:bg-slate-50">
                                                                    <td className="p-4 font-mono text-[11px] text-slate-600">{sg.studentHash}</td>
                                                                    <td className="p-4 font-bold text-blue-700 text-center text-sm">{formatGradePayload(sg.grade)}</td>
                                                                    <td className="p-4 text-center">
                                                                        <span className="rounded-full bg-emerald-100 px-3 py-1 text-[10px] font-bold uppercase text-emerald-700">
                                                                            {sg.status}
                                                                        </span>
                                                                    </td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                    {mainTab === 'Requests' && (
                        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
                            <div className="border-b border-slate-200 p-4">
                                <input type="text" placeholder="Search..." value={requestSearchTerm} onChange={e => setRequestSearchTerm(e.target.value)} className="w-full rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 outline-none" />
                            </div>
                            <div className="overflow-x-auto"><table className="w-full min-w-[800px] text-left text-sm">
                                <thead>
                                    <tr className="bg-[#003366] text-white">
                                        <th className="p-4">Role</th><th className="p-4">Name</th><th className="p-4">Student No.</th><th className="p-4">Email</th><th className="p-4">Department</th><th className="p-4">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {sortedAndFilteredRequests.map((req) => (
                                        <tr key={req.requestid} className="border-b border-slate-100 hover:bg-slate-50">
                                            <td className="p-4 font-bold capitalize text-slate-800">{req.role}</td>
                                            <td className="p-4">{req.fullname}</td>
                                            <td className="p-4">{req.studentno || 'N/A'}</td>
                                            <td className="p-4 text-slate-500">{req.email}</td>
                                            <td className="p-4">{req.department}</td>
                                            <td className="p-4">
                                                <button onClick={() => handleDenyRequest(req.requestid)} className="mr-2 rounded-lg bg-red-500 px-3 py-1 text-xs font-bold text-white hover:bg-red-600">Deny</button>
                                                <button onClick={() => handleApproveRequest(req.requestid, req.role)} className="rounded-lg bg-emerald-600 px-3 py-1 text-xs font-bold text-white hover:bg-emerald-700">Approve</button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table></div>
                        </div>
                    )}
                    {mainTab === 'assigning' && (
                        <div className="space-y-5">
                            <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-sm">
                                <div className="grid gap-3 lg:grid-cols-3">
                                    {assignmentWorkflowTabs.map((tab, index) => (
                                        <button
                                            key={tab.id}
                                            type="button"
                                            onClick={() => setAssignmentTab(tab.id)}
                                            className={`rounded-2xl border px-4 py-4 text-left transition ${
                                                assignmentTab === tab.id
                                                    ? 'border-[#003366] bg-[#003366] text-white shadow-sm'
                                                    : 'border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100'
                                            }`}
                                        >
                                            <p className="mt-2 text-base font-bold">{tab.label}</p>
                                            
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {assignmentTab === 'students' && (
                                <div className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
                                    <div className="border-b border-slate-200 px-5 py-4">
                                        <h4 className="text-lg font-bold text-[#003366]">Assign Students</h4>
                                    </div>
                                    <div className="space-y-4 p-4">
                                        {approvedStudents.length === 0 ? (
                                            <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
                                                No approved students waiting for assignment.
                                            </div>
                                        ) : approvedStudents.map((student) => (
                                            <div key={student.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                                                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                                                    <div className="space-y-2">
                                                        <div>
                                                            <p className="text-base font-bold text-slate-800">{student.fullname}</p>
                                                            <p className="text-sm text-slate-500">Student No. {student.studentno}</p>
                                                        </div>
                                                        <span className={`inline-block rounded-full px-3 py-1 text-xs font-bold ${student.assignmentStatus === 'Unassigned' ? 'bg-yellow-100 text-yellow-800' : 'bg-blue-100 text-blue-800'}`}>{student.assignmentStatus}</span>
                                                    </div>

                                                    <div className="grid flex-1 gap-3 lg:max-w-3xl lg:grid-cols-[minmax(0,1.8fr)_minmax(0,1fr)_auto]">
                                                        <label className="block">
                                                            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Department</span>
                                                            <select defaultValue="" onChange={(e) => setStudentAssignments(prev => ({...prev, [student.id]: {...prev[student.id], department: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]">
                                                                <option value="" disabled>Select department</option>
                                                                {departments.map(d => <option key={d} value={d}>{d}</option>)}
                                                            </select>
                                                        </label>
                                                        <div className="grid gap-3 sm:grid-cols-2">
                                                            <label className="block">
                                                                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Year</span>
                                                                <select defaultValue="" onChange={(e) => setStudentAssignments(prev => ({...prev, [student.id]: {...prev[student.id], yearLevel: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]">
                                                                    <option value="" disabled>Select year</option>
                                                                    <option value="1">1st</option><option value="2">2nd</option><option value="3">3rd</option><option value="4">4th</option>
                                                                </select>
                                                            </label>
                                                            <label className="block">
                                                                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Section</span>
                                                                <select defaultValue="" onChange={(e) => setStudentAssignments(prev => ({...prev, [student.id]: {...prev[student.id], sectionNum: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]">
                                                                    <option value="" disabled>Select section</option>
                                                                    {[...Array(15)].map((_, i) => <option key={i+1} value={i+1}>{i+1}</option>)}
                                                                </select>
                                                            </label>
                                                        </div>
                                                        <div className="flex flex-col gap-2 sm:flex-row lg:flex-col">
                                                            <button onClick={() => submitStudentAssignment(student.id)} className="rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white hover:bg-[#00264d]">Assign</button>
                                                            <button onClick={() => handleDropStudent(student.id, student.fullname)} className="rounded-lg bg-red-500 px-4 py-2 text-sm font-bold text-white hover:bg-red-600">Drop</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {assignmentTab === 'chairpersons' && (
                                <div className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
                                    <div className="border-b border-slate-200 px-5 py-4">
                                        <h4 className="text-lg font-bold text-[#003366]">Assign Chairperson</h4>
                                    </div>
                                    <div className="space-y-4 p-4">
                                        {approvedAdmins.length === 0 ? (
                                            <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
                                                No approved department admins waiting for assignment.
                                            </div>
                                        ) : approvedAdmins.map((admin) => (
                                            <div key={admin.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                                                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                                                    <div className="space-y-2 lg:max-w-sm">
                                                        <div>
                                                            <p className="text-base font-bold text-slate-800">{admin.fullname}</p>
                                                            <p className="text-sm capitalize text-slate-500">{admin.role}</p>
                                                            <p className="break-all text-sm text-slate-500">{admin.email}</p>
                                                        </div>
                                                        <div>
                                                            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Current Department</span>
                                                            <span className={`inline-block rounded-full px-3 py-1 text-xs font-bold ${admin.department === 'Unassigned' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>{admin.department}</span>
                                                        </div>
                                                    </div>

                                                    <div className="grid flex-1 gap-3 lg:max-w-2xl lg:grid-cols-[minmax(0,1fr)_auto]">
                                                        <label className="block">
                                                            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Assign New Department</span>
                                                            <select defaultValue="" onChange={(e) => setAdminAssignments(prev => ({...prev, [admin.id]: {department: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]">
                                                                <option value="" disabled>Select department</option>
                                                                {departments.map(d => <option key={d} value={d}>{d}</option>)}
                                                            </select>
                                                        </label>
                                                        <div className="flex items-end">
                                                            <button onClick={() => submitAdminAssignment(admin.id)} className="w-full rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white hover:bg-[#00264d] lg:w-auto">Assign</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {assignmentTab === 'faculty' && (
                                <div className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
                                    <div className="border-b border-slate-200 px-5 py-4">
                                        <h4 className="text-lg font-bold text-[#003366]">Assign Faculty</h4>
                                    </div>
                                    <div className="space-y-4 p-4">
                                        {approvedFaculties.length === 0 ? (
                                            <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
                                                No approved faculty members waiting for assignment.
                                            </div>
                                        ) : approvedFaculties.map((faculty) => (
                                            <div key={faculty.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                                                <div className="flex flex-col gap-4">
                                                    <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
                                                        <div className="space-y-2">
                                                            <div>
                                                                <p className="text-base font-bold text-slate-800">{faculty.fullname}</p>
                                                                <p className="break-all text-sm text-slate-500">{faculty.email}</p>
                                                            </div>
                                                            <div>
                                                                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Current Assignment</span>
                                                                {(!faculty.department || faculty.department === 'Unassigned')
                                                                    ? <span className="inline-block rounded-full bg-red-100 px-3 py-1 text-xs font-bold text-red-800">Unassigned</span>
                                                                    : <span className="inline-block rounded-lg bg-green-100 px-3 py-1 text-xs font-bold text-green-800">{faculty.department} - {faculty.yearLevel}{faculty.section}</span>}
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div className="grid gap-3 xl:grid-cols-[minmax(0,1.8fr)_minmax(0,0.9fr)_minmax(0,0.9fr)_minmax(0,1fr)_auto]">
                                                        <label className="block">
                                                            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Department</span>
                                                            <select defaultValue="" onChange={(e) => setFacultyAssignments(prev => ({...prev, [faculty.id]: {...prev[faculty.id], department: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]">
                                                                <option value="" disabled>Select department</option>
                                                                {departments.map(d => <option key={d} value={d}>{d}</option>)}
                                                            </select>
                                                        </label>
                                                        <label className="block">
                                                            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Section</span>
                                                            <select defaultValue="" onChange={(e) => setFacultyAssignments(prev => ({...prev, [faculty.id]: {...prev[faculty.id], section: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]">
                                                                <option value="" disabled>Select section</option>
                                                                {[...Array(15)].map((_, i) => <option key={i+1} value={i+1}>{i+1}</option>)}
                                                            </select>
                                                        </label>
                                                        <label className="block">
                                                            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Year</span>
                                                            <select defaultValue="" onChange={(e) => setFacultyAssignments(prev => ({...prev, [faculty.id]: {...prev[faculty.id], yearLevel: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]">
                                                                <option value="" disabled>Select year</option>
                                                                <option value="1">1st</option><option value="2">2nd</option><option value="3">3rd</option><option value="4">4th</option>
                                                            </select>
                                                        </label>
                                                        <label className="block">
                                                            <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500">Subject</span>
                                                            <input type="text" placeholder="Subject Code" onChange={(e) => setFacultyAssignments(prev => ({...prev, [faculty.id]: {...prev[faculty.id], subject: e.target.value}}))} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-[#003366]" />
                                                        </label>
                                                        <div className="flex items-end">
                                                            <button onClick={() => submitFacultyAssignment(faculty.id)} className="w-full rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white hover:bg-[#00264d] xl:w-auto">Assign</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                    {mainTab === 'revokeAccounts' && (
                        <div className="space-y-5">
                            <div className="rounded-2xl border border-amber-200 bg-amber-50 p-5 shadow-sm">
                                <h3 className="text-lg font-bold text-[#003366]">Account Revocation</h3>
                                <p className="mt-2 text-sm text-slate-600">
                                    Registrar accounts cannot be revoked from this screen. Student drops and faculty revocations remove system access and call the Fabric revocation flow.
                                </p>
                            </div>

                            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                                <div className="border-b border-slate-200 px-5 py-4">
                                    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                                        <div>
                                            <h4 className="text-base font-bold text-[#003366]">Chairperson</h4>
                                            
                                        </div>
                                        <button
                                            type="button"
                                            onClick={() => setShowChairpersonAccounts((current) => !current)}
                                            className="rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white hover:bg-[#00264d]"
                                        >
                                            {showChairpersonAccounts ? 'Hide Chairperson Accounts' : 'Show Chairperson Accounts'}
                                        </button>
                                    </div>
                                </div>

                                {showChairpersonAccounts && (
                                    <div className="space-y-4 p-4">
                                        <input
                                            type="text"
                                            value={chairpersonSearchTerm}
                                            onChange={(event) => setChairpersonSearchTerm(event.target.value)}
                                            placeholder="Search chairperson account..."
                                            className="w-full rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                                        />

                                        {filteredChairpersonAccounts.length === 0 ? (
                                            <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
                                                No chairperson account matched your search.
                                            </div>
                                        ) : filteredChairpersonAccounts.map((account) => (
                                            <div key={account.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                                                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                                                    <div>
                                                        <p className="text-base font-bold text-slate-800">{account.department}</p>
                                                        <p className="text-sm text-slate-500">{account.name}</p>
                                                        <p className="mt-2 text-sm text-slate-600">Account ID: {account.id}</p>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleRevokeChairperson(account.id, account.name)}
                                                        className="rounded-lg bg-red-600 px-4 py-2 text-sm font-bold text-white hover:bg-red-700"
                                                    >
                                                        Revoke Account
                                                    </button>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
                                <div className="border-b border-slate-200 px-5 py-4">
                                    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                                        <div>
                                            <h4 className="text-base font-bold text-[#003366]">Faculty</h4>
                                            
                                        </div>
                                        <button
                                            type="button"
                                            onClick={() => {
                                                setShowFacultyDepartments((current) => !current);
                                                if (showFacultyDepartments) setSelectedFacultyDepartment('');
                                            }}
                                            className="rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white hover:bg-[#00264d]"
                                        >
                                            {showFacultyDepartments ? 'Hide Faculty Departments' : 'Show Faculty Departments'}
                                        </button>
                                    </div>
                                </div>

                                {showFacultyDepartments && (
                                    <div className="space-y-4 p-4">
                                        <input
                                            type="text"
                                            value={facultySearchTerm}
                                            onChange={(event) => setFacultySearchTerm(event.target.value)}
                                            placeholder="Search faculty account or department..."
                                            className="w-full rounded-xl border border-slate-300 bg-slate-50 px-4 py-3 text-sm outline-none focus:border-[#003366]"
                                        />

                                        <div className="grid gap-3 lg:grid-cols-[minmax(0,320px)_minmax(0,1fr)]">
                                            <div className="space-y-3">
                                                {filteredFacultyDepartments.length === 0 ? (
                                                    <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
                                                        No department or faculty account matched your search.
                                                    </div>
                                                ) : filteredFacultyDepartments.map((department) => (
                                                    <button
                                                        key={department.name}
                                                        type="button"
                                                        onClick={() => setSelectedFacultyDepartment(department.name)}
                                                        className={`w-full rounded-2xl border px-4 py-4 text-left transition ${
                                                            selectedFacultyDepartment === department.name
                                                                ? 'border-[#003366] bg-[#003366] text-white'
                                                                : 'border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100'
                                                        }`}
                                                    >
                                                        <p className="font-bold">{department.name}</p>
                                                        <p className={`mt-1 text-sm ${selectedFacultyDepartment === department.name ? 'text-slate-100' : 'text-slate-500'}`}>
                                                            {department.accounts.length} faculty account{department.accounts.length === 1 ? '' : 's'}
                                                        </p>
                                                    </button>
                                                ))}
                                            </div>

                                            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                                                {!selectedFacultyDepartmentData ? (
                                                    <div className="flex h-full min-h-[220px] items-center justify-center text-center text-slate-500">
                                                        Select a department to view faculty accounts.
                                                    </div>
                                                ) : (
                                                    <div className="space-y-4">
                                                        <div className="border-b border-slate-200 pb-3">
                                                            <h5 className="text-base font-bold text-[#003366]">{selectedFacultyDepartmentData.name}</h5>
                                                            <p className="mt-1 text-sm text-slate-500">Under {selectedFacultyDepartmentData.chairperson}</p>
                                                        </div>

                                                        {selectedFacultyDepartmentData.accounts.length === 0 ? (
                                                            <div className="rounded-2xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
                                                                No faculty account matched your search in this department.
                                                            </div>
                                                        ) : selectedFacultyDepartmentData.accounts.map((account) => (
                                                            <div key={account.id} className="rounded-2xl border border-slate-200 bg-white p-4">
                                                                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                                                                    <div>
                                                                        <p className="text-base font-bold text-slate-800">{account.name}</p>
                                                                        <p className="text-sm text-slate-500">{account.role}</p>
                                                                        <p className="mt-2 text-sm text-slate-600">Account ID: {account.id}</p>
                                                                    </div>
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => handleRevokeFaculty(account.id, account.name)}
                                                                        className="rounded-lg bg-red-600 px-4 py-2 text-sm font-bold text-white hover:bg-red-700"
                                                                    >
                                                                        Revoke Account
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </main>
            </div>
            <Modal isOpen={ipfsModalOpen} onClose={() => setIpfsModalOpen(false)} title="IPFS Vault Decryption">
                <div className="flex flex-col gap-4">
                    <p className="text-sm text-slate-600">This academic record is encrypted and distributed across the PLV IPFS Network. Enter the Vault Password to view the decrypted content.</p>
                    <div className="relative">
                        <input type={showVaultPassword ? "text" : "password"} value={vaultPassword} onChange={(e) => setVaultPassword(e.target.value)} className="w-full rounded-xl border border-slate-300 px-4 py-3 pr-10 text-sm outline-none focus:border-[#003366]" placeholder="Enter Vault Password" onKeyDown={(e) => e.key === 'Enter' && submitIpfsPassword()} autoFocus />
                        <button type="button" onClick={() => setShowVaultPassword(!showVaultPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-[#003366]">
                            {showVaultPassword ? (
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                            ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5"><path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
                            )}
                        </button>
                    </div>
                    <div className="flex justify-end gap-3 mt-4">
                        <button onClick={() => setIpfsModalOpen(false)} className="rounded-xl border border-slate-300 bg-white px-5 py-2.5 text-sm font-bold text-slate-700 transition hover:bg-slate-50">Cancel</button>
                        <button onClick={submitIpfsPassword} className="rounded-xl bg-[#003366] px-5 py-2.5 text-sm font-bold text-white transition hover:bg-[#00264d]">Decrypt & View</button>
                    </div>
                </div>
            </Modal>            
            <Modal isOpen={confirmModal.isOpen} onClose={() => setConfirmModal({ ...confirmModal, isOpen: false })} title={confirmModal.title}>
                <div className="flex flex-col gap-4">
                    <p className="text-sm text-slate-600">{confirmModal.message}</p>
                    <div className="flex justify-end gap-3 mt-4">
                        <button onClick={() => setConfirmModal({ ...confirmModal, isOpen: false })} className="rounded-xl border border-slate-300 bg-white px-5 py-2.5 text-sm font-bold text-slate-700 transition hover:bg-slate-50">Cancel</button>
                        <button onClick={confirmModal.onConfirm} className={`rounded-xl px-5 py-2.5 text-sm font-bold text-white transition ${confirmModal.isDestructive ? 'bg-red-600 hover:bg-red-700' : 'bg-emerald-600 hover:bg-emerald-700'}`}>Confirm</button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
export default RegistrarGradesView;
