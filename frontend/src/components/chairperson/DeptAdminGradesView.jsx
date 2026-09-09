import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { fetchAllGrades, approveGrade, finalizeGrade, returnGrade, batchUploadGrades, fetchFacultySections, fetchFacultyStudents, fetchDepartmentSections, batchEnrollStudentsToSection, dropStudent, fetchApprovedFaculties, unassignFacultySection, openDecryptedIpfsFile, getSystemSetting, issueGrade } from '../../services/api';
import { useNotification } from '../../services/NotificationContext';
import ChairpersonHeader from './ChairpersonHeader';
import ChairpersonSidebar from './ChairpersonSidebar';
import CurriculumBuilder from './CurriculumBuilder';
import ChairpersonOverview from './ChairpersonOverview';
import FacultyStatusTable from '../faculty/FacultyStatusTable';
import SectionReviewPanel from './SectionReviewPanel';
import Modal from '../../services/Modal';
import StudentSectioning from './StudentSectioning';
import AcademicAssignment from './AcademicAssignment';
import { getGradeEquivalent } from '../../utils/gradingHelpers';

const getRecordGrade = (record) => record?.grade || record?.Grade || '';

const getRecordStudentKey = (record) => (
    record?.studentId ||
    record?.StudentId ||
    record?.student_hash ||
    record?.studentHash ||
    record?.StudentHash ||
    ''
);

const getRecordSubjectKey = (record) => (
    record?.subjectCode ||
    record?.SubjectCode ||
    record?.subject_code ||
    record?.course ||
    record?.Course ||
    ''
);

const getRecordSectionKey = (record) => (
    record?.section ||
    record?.Section ||
    ''
);

const getRecordIpfsCid = (record) => (
    record?.ipfsCid ||
    record?.IpfsCID ||
    record?.ipfs_cid ||
    ''
);

const getRecordFacultyKey = (record) => (
    record?.facultyId ||
    record?.faculty_id ||
    record?.FacultyId ||
    ''
);

const getSavedRegistrarAssignments = () => {
    try {
        const saved = JSON.parse(localStorage.getItem('registrarAssignments') || '[]');
        return Array.isArray(saved) ? saved : [];
    } catch (error) {
        return [];
    }
};
const resolveAssignmentFacultyIdentity = (assignment, facultyIdentityByAssignmentId = new Map()) => {
    const directIdentity = normalizeFacultyIdentity(
        assignment?.facultyEmail || assignment?.email || assignment?.facultyId || ''
    );

    if (directIdentity && String(assignment?.facultyId || '').includes('@')) {
        return directIdentity;
    }

    const mappedIdentity = facultyIdentityByAssignmentId.get(String(assignment?.facultyId || '').trim());
    if (mappedIdentity) {
        return mappedIdentity;
    }

    return directIdentity;
};

const getAssignmentStudentKey = (student) => (
    student?.studentId ||
    student?.id ||
    student?.studentno ||
    student?.studentNo ||
    student?.email ||
    ''
);

const resolveAssignmentForGradeRecord = (record, assignments = [], facultyIdentityByAssignmentId = new Map()) => {
    const normalizedFacultyId = normalizeFacultyIdentity(getRecordFacultyKey(record));
    const normalizedStudentKey = normalizeText(getRecordStudentKey(record));
    const normalizedSubjectCode = normalizeText(getRecordSubjectKey(record));
    const normalizedSemester = normalizeText(record?.semester || record?.Semester || '');
    const normalizedSchoolYear = normalizeText(record?.schoolYear || record?.SchoolYear || '');

    const matchingAssignments = assignments.filter((assignment) => {
        const assignmentFacultyKey = normalizeFacultyIdentity(
            resolveAssignmentFacultyIdentity(assignment, facultyIdentityByAssignmentId)
        );

        if (!assignmentFacultyKey || assignmentFacultyKey !== normalizedFacultyId) {
            return false;
        }

        const assignmentSemester = normalizeText(assignment?.semester);
        const assignmentSchoolYear = normalizeText(assignment?.schoolYear);
        const assignmentSubjectCode = normalizeText(assignment?.subjectCode);

        if (normalizedSemester && assignmentSemester && assignmentSemester !== normalizedSemester) {
            return false;
        }

        if (normalizedSchoolYear && assignmentSchoolYear && assignmentSchoolYear !== normalizedSchoolYear) {
            return false;
        }

        if (normalizedSubjectCode && assignmentSubjectCode && assignmentSubjectCode !== normalizedSubjectCode) {
            return false;
        }

        return true;
    });

    if (!matchingAssignments.length) {
        return null;
    }

    const rosterMatchedAssignment = matchingAssignments.find((assignment) =>
        Array.isArray(assignment?.rosterStudents) &&
        assignment.rosterStudents.some(
            (student) => normalizeText(getAssignmentStudentKey(student)) === normalizedStudentKey
        )
    );

    return rosterMatchedAssignment || matchingAssignments[0] || null;
};

const normalizeFacultyIdentity = (value = '') => {
    let normalized = String(value || '').trim();

    if (normalized.length > 40 && !normalized.includes('@')) {
        try {
            const decoded = atob(normalized);
            const cnMatch = decoded.match(/CN=([^,]+)/);
            if (cnMatch && cnMatch[1]) normalized = cnMatch[1];
        } catch (e) {}
    }

    return normalizeText(normalized);
};

const parseStoredGrade = (rawGrade) => {
    if (!rawGrade) return { midterm: '', finals: '', finalAverage: '', standing: 'active', flagged: false };
    if (typeof rawGrade === 'number') return { midterm: '', finals: '', finalAverage: rawGrade, standing: 'active', flagged: false };
    if (typeof rawGrade === 'string' && rawGrade.trim().startsWith('{')) {
        try {
            const parsed = JSON.parse(rawGrade);
                
                let computedRaw = parsed.finalAverage || parsed.final || parsed.grade || '';
                const mid = parseFloat(parsed.midterm);
                const fin = parseFloat(parsed.finals);
                if (!isNaN(mid) && !isNaN(fin)) {
                    computedRaw = ((mid + fin) / 2).toFixed(2);
                } else if (!isNaN(mid)) {
                    computedRaw = mid.toFixed(2);
                } else if (!isNaN(fin)) {
                    computedRaw = fin.toFixed(2);
                }

            return {
                midterm: parsed.midterm || '',
                finals: parsed.finals || '',
                    finalAverage: computedRaw,
                standing: parsed.standing || parsed.remarks || 'active',
                flagged: !!parsed.flagged,
            };
        } catch (e) {
            return { midterm: '', finals: '', finalAverage: rawGrade, standing: 'active', flagged: false };
        }
    }
    return { midterm: '', finals: '', finalAverage: rawGrade, standing: 'active', flagged: false };
};

const normalizeText = (value = '') => String(value || '').trim().toLowerCase();
const canChairpersonReturnStatus = (status = '') => {
    const normalized = normalizeText(status);
    if (normalized.includes('finalized') || normalized.includes('forwarded')) return false;
    return (
        normalized === '' ||
        normalized.includes('issued') ||
        normalized.includes('submitted') ||
        normalized.includes('approved')
    );
};
const parseStatusTimestamp = (value) => {
    if (!value) return 0;
    const parsed = new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
};
const SECTION_STATUS_PRIORITY = {
    pending: 0,
    returned: 1,
    submitted: 2,
    approved: 3,
    forwarded: 4,
};
const hasEncodedValue = (value) => String(value ?? '').trim() !== '';
const getRecordStudentNumber = (record) => (
    record?.student_no ||
    record?.studentNo ||
    ''
);
const getRecordStudentName = (record) => (
    record?.student_name ||
    record?.studentName ||
    ''
);
const isPlaceholderStudentName = (value = '') => {
    const normalizedValue = normalizeText(value);
    return !normalizedValue || normalizedValue === 'student';
};
const isPlaceholderStudentId = (value = '') => {
    const normalizedValue = String(value || '').trim().toLowerCase();
    return (
        !normalizedValue ||
        normalizedValue === 'unknown' ||
        normalizedValue.endsWith('@plv.edu.ph')
    );
};
const splitStudentName = (fullName = '') => {
    const normalizedName = String(fullName || '').trim();
    if (!normalizedName) {
        return { firstName: '', lastName: '' };
    }

    if (normalizedName.includes(',')) {
        const [lastName, ...rest] = normalizedName.split(',');
        return {
            lastName: String(lastName || '').trim(),
            firstName: rest.join(',').trim(),
        };
    }

    const parts = normalizedName.split(/\s+/).filter(Boolean);
    if (parts.length === 1) {
        return { firstName: parts[0], lastName: '' };
    }

    return {
        firstName: parts.slice(0, -1).join(' '),
        lastName: parts.slice(-1).join(' '),
    };
};
const extractSectionCode = (value = '') => {
    const match = String(value || '').match(/\b([1-4]-\d+)\b/i);
    return match ? normalizeText(match[1]) : '';
};
const normalizeSectionIdentity = (value = '') =>
    normalizeText(String(value || '').replace(/\([^)]*\)/g, ' ').replace(/\s+/g, ' ').trim());
const sectionsMatch = (left = '', right = '') => {
    const normalizedLeft = normalizeSectionIdentity(left);
    const normalizedRight = normalizeSectionIdentity(right);
    const leftCode = extractSectionCode(left);
    const rightCode = extractSectionCode(right);

    if (!normalizedLeft || !normalizedRight) return false;
    if (normalizedLeft === normalizedRight) return true;
    if (normalizedLeft.includes(normalizedRight) || normalizedRight.includes(normalizedLeft)) return true;
    if (leftCode && rightCode && leftCode === rightCode) return true;

    return false;
};
const buildSectionDisplayName = ({
    departmentName = '',
    sectionValue = '',
    subjectCode = '',
} = {}) => {
    const normalizedSectionValue = String(sectionValue || '').trim();
    if (!normalizedSectionValue) return '';

    const normalizedDepartmentName = String(departmentName || '').trim();
    const normalizedSubjectCode = String(subjectCode || '').trim();

    if (!normalizedDepartmentName) {
        return normalizedSubjectCode
            ? `${normalizedSectionValue} (${normalizedSubjectCode})`
            : normalizedSectionValue;
    }

    if (normalizedSubjectCode) {
        return `${normalizedDepartmentName} ${normalizedSectionValue} (${normalizedSubjectCode})`;
    }

    return `${normalizedDepartmentName} ${normalizedSectionValue}`;
};
const getSavedStudentSections = () => {
    try {
        const saved = JSON.parse(localStorage.getItem('studentSections') || '[]');
        return Array.isArray(saved) ? saved : [];
    } catch (error) {
        return [];
    }
};
const findSavedSectionRoster = ({
    studentSections = [],
    assignment = null,
    departmentName = '',
    sectionName = '',
    schoolYear = '',
    semester = '',
} = {}) => {
    const matchedSection = studentSections.find((section) => {
        const sameProgram =
            normalizeText(section?.program) ===
            normalizeText(assignment?.program || departmentName);
        const sameSection =
            sectionsMatch(
                section?.section,
                assignment?.sectionName || sectionName
            );
        const sameSchoolYear =
            !normalizeText(section?.schoolYear) ||
            !normalizeText(assignment?.schoolYear || schoolYear) ||
            normalizeText(section?.schoolYear) ===
                normalizeText(assignment?.schoolYear || schoolYear);
        const sameSemester =
            !normalizeText(section?.semester) ||
            !normalizeText(assignment?.semester || semester) ||
            normalizeText(section?.semester) ===
                normalizeText(assignment?.semester || semester);

        return sameProgram && sameSection && sameSchoolYear && sameSemester;
    });

    return Array.isArray(matchedSection?.students) ? matchedSection.students : [];
};
const resolveAssignmentForSectionGroup = (group, assignments = [], facultyIdentityByAssignmentId = new Map()) =>
    assignments.find((assignment) => {
        const sameFaculty =
            normalizeFacultyIdentity(
                resolveAssignmentFacultyIdentity(assignment, facultyIdentityByAssignmentId)
            ) === normalizeText(group?.facultyId);
        const sameProgram =
            normalizeText(assignment?.program) === normalizeText(group?.department);
        const sameSection = sectionsMatch(assignment?.sectionName, group?.sectionName);
        const sameSubject =
            !normalizeText(assignment?.subjectCode) ||
            !normalizeText(group?.subjectCode) ||
            normalizeText(assignment?.subjectCode) === normalizeText(group?.subjectCode);
        const sameSchoolYear =
            !normalizeText(assignment?.schoolYear) ||
            !normalizeText(group?.schoolYear) ||
            normalizeText(assignment?.schoolYear) === normalizeText(group?.schoolYear);
        const sameSemester =
            !normalizeText(assignment?.semester) ||
            !normalizeText(group?.semester) ||
            normalizeText(assignment?.semester) === normalizeText(group?.semester);

        return sameFaculty && sameProgram && sameSection && sameSubject && sameSchoolYear && sameSemester;
    }) || null;
const resolveStudentIdentityForRecord = ({
    record,
    assignment,
    studentSections = [],
    departmentName = '',
    sectionName = '',
    schoolYear = '',
    semester = '',
}) => {
    const recordStudentKey = normalizeText(getRecordStudentKey(record));
    const recordStudentNumber = String(getRecordStudentNumber(record) || '').trim();
    const recordStudentName = String(getRecordStudentName(record) || '').trim();
    const rosterStudents =
        (Array.isArray(assignment?.rosterStudents) && assignment.rosterStudents.length
            ? assignment.rosterStudents
            : findSavedSectionRoster({
                studentSections,
                assignment,
                departmentName,
                sectionName,
                schoolYear,
                semester,
            })) || [];

    const rosterMatch = rosterStudents.length
        ? rosterStudents.find((student) => {
            const candidateKeys = [
                student?.studentId,
                student?.id,
                student?.studentno,
                student?.studentNo,
                student?.email,
            ]
                .map((value) => normalizeText(value))
                .filter(Boolean);

            return (
                (recordStudentKey && candidateKeys.includes(recordStudentKey)) ||
                (recordStudentNumber && candidateKeys.includes(normalizeText(recordStudentNumber)))
            );
        })
        : null;
    const soleRosterStudent = rosterStudents.length === 1 ? rosterStudents[0] : null;
    const fallbackRosterStudent =
        rosterMatch ||
        (
            soleRosterStudent &&
            isPlaceholderStudentId(recordStudentNumber || getRecordStudentKey(record)) &&
            isPlaceholderStudentName(recordStudentName)
                ? soleRosterStudent
                : null
        );

    const rosterStudentId =
        fallbackRosterStudent?.studentId ||
        fallbackRosterStudent?.id ||
        fallbackRosterStudent?.studentno ||
        fallbackRosterStudent?.studentNo ||
        '';
    const rosterStudentName =
        fallbackRosterStudent?.fullname ||
        fallbackRosterStudent?.name ||
        [fallbackRosterStudent?.lastName, fallbackRosterStudent?.firstName].filter(Boolean).join(', ') ||
        (rosterStudentId ? `Student ${rosterStudentId}` : '');

    let finalStudentName = 
        (!isPlaceholderStudentName(recordStudentName) && recordStudentName) ||
        rosterStudentName ||
        recordStudentName ||
        'Student';
        
    if (finalStudentName.includes('@')) {
        finalStudentName = finalStudentName.split('@')[0];
    }

    return {
        studentId:
            (!isPlaceholderStudentId(recordStudentNumber) && recordStudentNumber) ||
            (!isPlaceholderStudentId(recordStudentKey) && getRecordStudentKey(record)) ||
            rosterStudentId ||
            getRecordStudentKey(record) ||
            recordStudentNumber ||
            'Unknown',
        studentName: finalStudentName,
    };
};
const getDepartmentSectionSnapshot = (department = '') => {
    try {
        const saved = JSON.parse(localStorage.getItem('studentSections') || '[]');
        return saved
            .filter((section) => normalizeText(section.program) === normalizeText(department))
            .map((section) => ({
                key: [
                    normalizeText(section.program),
                    normalizeText(section.yearLevel),
                    normalizeText(section.section),
                    normalizeText(section.schoolYear),
                    normalizeText(section.semester),
                ].join('|'),
                sectionName: section.section || 'Unnamed Section',
                serialized: JSON.stringify(section),
            }))
            .sort((a, b) => a.key.localeCompare(b.key));
    } catch (error) {
        return [];
    }
};

const DeptAdminGradesView = ({ loggedInEmail = '', loggedInName = '', userRole = '', department = '', onLogout }) => {
    const [grades, setGrades] = useState([]);
    
    const { addNotification } = useNotification();
    const [mainTab, setMainTab] = useState('grades'); 
    const [selectedReviewSection, setSelectedReviewSection] = useState(null);
    const [uploadFile, setUploadFile] = useState(null);
    const [isUploading, setIsUploading] = useState(false);
    const [mySections, setMySections] = useState([]);
    const [myStudents, setMyStudents] = useState([]);
    const [selectedMySection, setSelectedMySection] = useState(null);

    const [academicSections, setAcademicSections] = useState([]);
    const [enrollFile, setEnrollFile] = useState(null);
    const [isEnrolling, setIsEnrolling] = useState(false);
    const [departmentFaculties, setDepartmentFaculties] = useState([]);
    const [classGrades, setClassGrades] = useState({});
    const [classValidationErrors, setClassValidationErrors] = useState({});
    const [isSavingGrades, setIsSavingGrades] = useState(false);

    const [ipfsModalOpen, setIpfsModalOpen] = useState(false);
    const [ipfsCid, setIpfsCid] = useState("");
    const [vaultPassword, setVaultPassword] = useState("");
    const [showVaultPassword, setShowVaultPassword] = useState(false);
    const [confirmModal, setConfirmModal] = useState({ isOpen: false, title: "", message: "", onConfirm: null });

    const [passThreshold, setPassThreshold] = useState(75);
    const [statusFilter, setStatusFilter] = useState("All");
    const [activeSemester, setActiveSemester] = useState("2nd Semester");
    const [activeEncodingTerm, setActiveEncodingTerm] = useState("midterm");
    const lastSectionSnapshotRef = useRef([]);
    const lastNotifiedSectionChangeRef = useRef('');

    useEffect(() => {
        const fetchThreshold = async () => {
            try {
                const data = await getSystemSetting('pass_fail_threshold');
                if (data.status === "Success" && data.value) {
                    setPassThreshold(parseFloat(data.value));
                }
            } catch (e) {
                console.warn("Using default pass/fail threshold");
            }
        };
        fetchThreshold();
    }, []);

    useEffect(() => {
        lastSectionSnapshotRef.current = getDepartmentSectionSnapshot(department);
    }, [department]);

    useEffect(() => {
        const applyEncodingPeriod = (value) => {
            if (!value) return;
            const parsed = typeof value === 'string' ? JSON.parse(value) : value;
            setActiveSemester(parsed?.semester || "2nd Semester");
            setActiveEncodingTerm(parsed?.term === "finals" ? "finals" : "midterm");
        };

        const loadEncodingPeriod = async () => {
            try {
                const data = await getSystemSetting('encoding_period');
                if (data.status === "Success" && data.value) {
                    applyEncodingPeriod(data.value);
                }
            } catch (e) {
                console.warn("Using default semester");
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

    const deptMetrics = useMemo(() => {
        const facultySet = new Set();
        const sectionMap = {};

        grades.forEach(g => {
            let facId = g.facultyId || g.faculty_id || g.FacultyId || 'Unknown';
            
            // Clean up Fabric Base64 X.509 Identity
            if (facId.length > 40 && !facId.includes('@')) {
                try {
                    const decoded = atob(facId);
                    const cnMatch = decoded.match(/CN=([^,]+)/);
                    if (cnMatch && cnMatch[1]) facId = cnMatch[1];
                } catch(e) {}
            }

            const course = g.course || g.Course || g.subject_code || g.subjectCode || 'Unknown Section';
            const status = g.status || g.Status || '';

            if (facId !== 'Unknown') facultySet.add(facId);

            // Group statuses per unique section rather than per student grade
            const sectionKey = `${facId}-${course}`;
            if (!sectionMap[sectionKey]) {
                sectionMap[sectionKey] = status;
            } else {
                const current = sectionMap[sectionKey].toLowerCase();
                const next = status.toLowerCase();
                // Escalate status if mixed
                if (next === 'finalized' || (next.includes('approved') && current.includes('issued'))) {
                    sectionMap[sectionKey] = status;
                }
            }
        });

        let submitted = 0, approved = 0, forwarded = 0, returned = 0;
        Object.values(sectionMap).forEach(st => {
            const s = st.toLowerCase();
            if (s.includes('issued') || s.includes('submitted')) submitted++;
            if (s.includes('approved')) approved++;
            if (s.includes('finalized') || s.includes('forwarded')) forwarded++;
            if (s.includes('returned') || s.includes('rejected')) returned++;
        });

        return {
            totalFaculty: facultySet.size,
            totalSections: Object.keys(sectionMap).length,
            submittedSections: submitted,
            approvedSections: approved,
            returnedSections: returned,
            forwardedSections: forwarded
        };
    }, [grades]);

    const facultyRows = useMemo(() => {
        const groups = {};
        const savedAssignments = getSavedRegistrarAssignments();
        const savedStudentSections = getSavedStudentSections();
        const facultyIdentityByAssignmentId = new Map(
            departmentFaculties.map((faculty) => [
                String(faculty.id ?? '').trim(),
                normalizeFacultyIdentity(faculty.email || faculty.facultyId || faculty.id),
            ])
        );
        const facultyNameMap = new Map(
            departmentFaculties.map((faculty) => [
                normalizeFacultyIdentity(faculty.email || faculty.facultyId || faculty.id),
                faculty.fullname || faculty.fullName || faculty.email || "Unknown Faculty",
            ])
        );

        grades.forEach(g => {
            let facId = g.facultyId || g.faculty_id || g.FacultyId || 'Unknown';
            const normalizedFacultyId = normalizeFacultyIdentity(facId);
            if (normalizedFacultyId) {
                facId = normalizedFacultyId;
            }

            const subjectCode =
                g.subject_code ||
                g.subjectCode ||
                g.SubjectCode ||
                'Unknown Subject';
            const departmentName =
                g.department ||
                g.course ||
                g.Course ||
                'Unknown Department';
            const matchedAssignment = resolveAssignmentForGradeRecord(
                g,
                savedAssignments,
                facultyIdentityByAssignmentId
            );
            const recordSectionName =
                getRecordSectionKey(g) ||
                g.record_section ||
                g.RecordSection ||
                '';
            const profiledSectionName = buildSectionDisplayName({
                departmentName,
                sectionValue: g.student_section || g.studentSection || '',
                subjectCode,
            });
            const sectionName =
                recordSectionName ||
                profiledSectionName ||
                matchedAssignment?.sectionName ||
                departmentName ||
                'Unknown Section';
            const resolvedSubjectCode =
                subjectCode ||
                matchedAssignment?.subjectCode ||
                'Unknown Subject';
            const resolvedDepartmentName =
                departmentName ||
                matchedAssignment?.program ||
                'Unknown Department';
            const schoolYear = g.schoolYear || g.SchoolYear || matchedAssignment?.schoolYear || '2024';
            const semester = g.semester || g.Semester || matchedAssignment?.semester || '2nd Semester';
            const status = (g.status || g.Status || '').toLowerCase();
            const key = [
                facId,
                normalizeText(resolvedDepartmentName),
                normalizeText(sectionName),
                normalizeText(resolvedSubjectCode),
                normalizeText(schoolYear),
                normalizeText(semester),
            ].join('|');

            if (!groups[key]) {
                groups[key] = {
                    reviewKey: key,
                    facultyName: facultyNameMap.get(normalizedFacultyId) || facId,
                    facultyId: facId,
                    department: resolvedDepartmentName,
                    sectionName,
                    subjectCode: resolvedSubjectCode,
                    schoolYear,
                    semester,
                    totalStudents: 0,
                    encodedCount: 0,
                    progress: 0,
                    facultyEncodingStatus: 'In Progress',
                    reviewStatus: 'pending',
                    grades: {},
                    students: [],
                    rawStudentEntries: [],
                    ipfsCid: g.ipfs_cid || g.IpfsCID || g.ipfsCid || null,
                    earliestEncodedAt: g.date || g.Date || null,
                    latestStatusTimestamp: 0,
                    latestStatusPriority: 0,
                };
            }
            
            // Ensure the CID is captured even if the first student's record lacked it
            if (!groups[key].ipfsCid && (g.ipfs_cid || g.IpfsCID || g.ipfsCid)) {
                groups[key].ipfsCid = g.ipfs_cid || g.IpfsCID || g.ipfsCid;
            }
            groups[key].totalStudents += 1;

            const parsedGrade = parseStoredGrade(getRecordGrade(g));
            const gradeVal = parsedGrade.finalAverage;
            if (
                hasEncodedValue(parsedGrade.midterm) ||
                hasEncodedValue(parsedGrade.finals) ||
                hasEncodedValue(gradeVal)
            ) {
                groups[key].encodedCount += 1;
            }
            if (g.date || g.Date) {
                const currentEarliest = groups[key].earliestEncodedAt ? new Date(groups[key].earliestEncodedAt).getTime() : Number.POSITIVE_INFINITY;
                const incomingDate = new Date(g.date || g.Date).getTime();
                if (!Number.isNaN(incomingDate) && incomingDate < currentEarliest) {
                    groups[key].earliestEncodedAt = g.date || g.Date;
                }
            }
            
            const resolvedStudentIdentity = resolveStudentIdentityForRecord({
                record: g,
                assignment: matchedAssignment,
                studentSections: savedStudentSections,
                departmentName: resolvedDepartmentName,
                sectionName,
                schoolYear,
                semester,
            });
            const studentNumber = resolvedStudentIdentity.studentId || getRecordStudentNumber(g) || getRecordStudentKey(g) || 'Unknown';
            const studentKey = studentNumber || getRecordStudentKey(g) || 'Unknown';
            const studentName = resolvedStudentIdentity.studentName || getRecordStudentName(g);
            const { firstName, lastName } = splitStudentName(studentName);

            if (!groups[key].students.some((student) => String(student.studentId) === String(studentKey))) {
                groups[key].students.push({
                    studentId: studentKey,
                    studentNo: studentNumber,
                    fullName: studentName || studentNumber,
                    lastName,
                    firstName,
                });
            }
            groups[key].grades[studentKey] = {
                midterm: parsedGrade.midterm || '-',
                finals: parsedGrade.finals || '-',
                finalAverage: gradeVal || '-',
                standing: parsedGrade.standing || g.remarks || g.Remarks || 'active',
                flagged: parsedGrade.flagged || g.flagged || g.Flagged === true || String(g.flagged).toLowerCase() === "true"
            };
            groups[key].rawStudentEntries.push({
                studentKey,
                studentNumber,
                studentName,
                grade: groups[key].grades[studentKey],
            });
            
            let normalizedReviewStatus = 'pending';
            if (status.includes('finalized') || status.includes('forwarded')) normalizedReviewStatus = 'forwarded';
            else if (status.includes('approved')) normalizedReviewStatus = 'approved';
            else if (status.includes('issued') || status.includes('submitted') || status === '') normalizedReviewStatus = 'submitted';
            else if (status.includes('returned') || status.includes('rejected')) normalizedReviewStatus = 'returned';

            const incomingTimestamp = parseStatusTimestamp(g.date || g.Date);
            const incomingPriority = SECTION_STATUS_PRIORITY[normalizedReviewStatus] || 0;
            const shouldReplaceStatus =
                incomingTimestamp > (groups[key].latestStatusTimestamp || 0) ||
                (
                    incomingTimestamp === (groups[key].latestStatusTimestamp || 0) &&
                    incomingPriority >= (groups[key].latestStatusPriority || 0)
                );

            if (shouldReplaceStatus) {
                groups[key].reviewStatus = normalizedReviewStatus;
                groups[key].latestStatusTimestamp = incomingTimestamp;
                groups[key].latestStatusPriority = incomingPriority;
            }
        });
        return Object.values(groups).map(g => {
            const matchedAssignment = resolveAssignmentForSectionGroup(
                g,
                savedAssignments,
                facultyIdentityByAssignmentId
            );
            const rosterStudents =
                (Array.isArray(matchedAssignment?.rosterStudents) && matchedAssignment.rosterStudents.length
                    ? matchedAssignment.rosterStudents
                    : findSavedSectionRoster({
                        studentSections: savedStudentSections,
                        assignment: matchedAssignment,
                        departmentName: g.department,
                        sectionName: g.sectionName,
                        schoolYear: g.schoolYear,
                        semester: g.semester,
                    })) || [];

            if (rosterStudents.length) {
                const placeholderOnly =
                    g.students.length > 0 &&
                    g.students.every(
                        (student) =>
                            isPlaceholderStudentId(student.studentNo || student.studentId) ||
                            isPlaceholderStudentName(student.fullName || `${student.lastName || ''}, ${student.firstName || ''}`)
                    );

                if (placeholderOnly || rosterStudents.length === g.students.length) {
                    const remappedGrades = {};

                    g.students = rosterStudents.map((student, index) => {
                        const rosterStudentId =
                            student.studentId ||
                            student.id ||
                            student.studentno ||
                            student.studentNo ||
                            `student-${index + 1}`;
                        const rosterStudentName =
                            student.fullname ||
                            student.name ||
                            [student.lastName, student.firstName].filter(Boolean).join(', ') ||
                            (rosterStudentId.includes('@') ? rosterStudentId.split('@')[0] : rosterStudentId);
                        const rawEntry = g.rawStudentEntries[index] || g.rawStudentEntries.find((entry) =>
                            normalizeText(entry.studentNumber) === normalizeText(rosterStudentId)
                        ) || null;
                        const gradeRecord =
                            (rawEntry && rawEntry.grade) ||
                            g.grades[rosterStudentId] ||
                            {};

                        remappedGrades[rosterStudentId] = gradeRecord;

                        return {
                            studentId: rosterStudentId,
                            studentNo: rosterStudentId,
                            fullName: rosterStudentName,
                            lastName: student.lastName || splitStudentName(rosterStudentName).lastName,
                            firstName: student.firstName || splitStudentName(rosterStudentName).firstName,
                        };
                    });

                    g.grades = remappedGrades;
                }
            }

            if (!g.ipfsCid) {
                const recoveredIpfsCid = grades
                    .filter((record) => {
                        const recordSubject = normalizeText(getRecordSubjectKey(record));
                        const groupSubjects = [
                            g.subjectCode,
                            g.sectionName,
                            g.department,
                        ]
                            .map((value) => normalizeText(value))
                            .filter(Boolean);

                        return (
                            normalizeFacultyIdentity(record.facultyId || record.faculty_id || record.FacultyId) === normalizeText(g.facultyId) &&
                            (
                                groupSubjects.includes(recordSubject) ||
                                (
                                    normalizeText(record.semester || record.Semester) === normalizeText(g.semester) &&
                                    normalizeText(record.schoolYear || record.SchoolYear) === normalizeText(g.schoolYear)
                                )
                            )
                        );
                    })
                    .map((record) => getRecordIpfsCid(record))
                    .find(Boolean);

                if (recoveredIpfsCid) {
                    g.ipfsCid = recoveredIpfsCid;
                } else {
                    const facultyWideFallback = grades
                        .filter((record) =>
                            normalizeFacultyIdentity(record.facultyId || record.faculty_id || record.FacultyId) === normalizeText(g.facultyId)
                        )
                        .map((record) => getRecordIpfsCid(record))
                        .find(Boolean);

                    g.ipfsCid = facultyWideFallback || null;
                }
            }

            g.progress = g.totalStudents > 0 ? Math.round((g.encodedCount / g.totalStudents) * 100) : 0;
            g.facultyEncodingStatus = g.progress === 100 ? 'Completed' : 'In Progress';
            return g;
        });
    }, [departmentFaculties, grades]);

    useEffect(() => {
        if (!selectedReviewSection?.reviewKey) return;

        const latestSelectedSection =
            facultyRows.find((row) => row.reviewKey === selectedReviewSection.reviewKey) ||
            null;

        if (!latestSelectedSection) {
            setSelectedReviewSection(null);
            return;
        }

        const backfilledIpfsCid =
            latestSelectedSection.ipfsCid ||
            grades
                .filter((record) => {
                    const recordSubject = normalizeText(getRecordSubjectKey(record));
                    const subjectCandidates = [
                        latestSelectedSection.subjectCode,
                        latestSelectedSection.sectionName,
                        latestSelectedSection.department,
                    ]
                        .map((value) => normalizeText(value))
                        .filter(Boolean);

                    return (
                        normalizeFacultyIdentity(record.facultyId || record.faculty_id || record.FacultyId) === normalizeText(latestSelectedSection.facultyId) &&
                        (
                            subjectCandidates.includes(recordSubject) ||
                            (
                                normalizeText(record.semester || record.Semester) === normalizeText(latestSelectedSection.semester) &&
                                normalizeText(record.schoolYear || record.SchoolYear) === normalizeText(latestSelectedSection.schoolYear)
                            )
                        )
                    );
                })
                .map((record) => getRecordIpfsCid(record))
                .find(Boolean) ||
            grades
                .filter((record) =>
                    normalizeFacultyIdentity(record.facultyId || record.faculty_id || record.FacultyId) === normalizeText(latestSelectedSection.facultyId)
                )
                .map((record) => getRecordIpfsCid(record))
                .find(Boolean) ||
            null;

        const nextSelectedSection = {
            ...latestSelectedSection,
            ipfsCid: backfilledIpfsCid,
        };

        if (
            latestSelectedSection !== selectedReviewSection ||
            nextSelectedSection.ipfsCid !== selectedReviewSection.ipfsCid
        ) {
            setSelectedReviewSection(nextSelectedSection);
        }
    }, [facultyRows, grades, selectedReviewSection]);

    const loadGrades = useCallback(async () => {
        try {
            const response = await fetchAllGrades(loggedInEmail);
            setGrades(Array.isArray(response) ? response : (response.data || []));
        } catch (error) {
            console.error(`Could not fetch blockchain data: ${error.message}`);
        }
    }, [loggedInEmail]);

    useEffect(() => { loadGrades(); }, [loadGrades]);

    const loadMyClasses = useCallback(async () => {
        try {
            const secRes = await fetchFacultySections(loggedInEmail);
            if (secRes.status === 'Success' || secRes.sections) setMySections(secRes.sections || secRes.data || []);
            
            const stuRes = await fetchFacultyStudents(loggedInEmail);
            if (stuRes.status === 'Success' || stuRes.students) setMyStudents(stuRes.students || stuRes.data || []);
        } catch (e) { console.error("Failed to load classes:", e); }
    }, [loggedInEmail]);

    useEffect(() => {
        if (mainTab === 'myClasses') loadMyClasses();
    }, [mainTab, loadMyClasses]);

    const loadDepartmentFaculties = useCallback(async () => {
        try {
            const res = await fetchApprovedFaculties();
            if (res.status === 'Success') {
                setDepartmentFaculties(res.faculties.filter(f => f.department === department));
            }
        } catch(e) { console.error(e); }
    }, [department]);

    const loadAcademicSections = useCallback(async () => {
        if (!department) return;
        try {
            const res = await fetchDepartmentSections(department);
            if (res.status === 'Success') {
                setAcademicSections(res.data || []);
            }
        } catch (e) {
            addNotification(`Failed to load sections: ${e.message}`, 'error');
        }
    }, [department, addNotification]);

    useEffect(() => {
        const notifySectionStorageChanges = () => {
            const previousSnapshot = lastSectionSnapshotRef.current;
            const nextSnapshot = getDepartmentSectionSnapshot(department);
            const previousMap = new Map(previousSnapshot.map((item) => [item.key, item]));

            const createdSections = nextSnapshot.filter((item) => !previousMap.has(item.key));
            const updatedSections = nextSnapshot.filter((item) => {
                const previous = previousMap.get(item.key);
                return previous && previous.serialized !== item.serialized;
            });

            createdSections.forEach((item) => {
                const notificationKey = `created|${item.key}|${item.serialized}`;
                if (lastNotifiedSectionChangeRef.current === notificationKey) return;
                lastNotifiedSectionChangeRef.current = notificationKey;
                addNotification(
                    `New section created in ${department}: ${item.sectionName}`,
                    'success'
                );
            });

            updatedSections.forEach((item) => {
                const notificationKey = `updated|${item.key}|${item.serialized}`;
                if (lastNotifiedSectionChangeRef.current === notificationKey) return;
                lastNotifiedSectionChangeRef.current = notificationKey;
                addNotification(
                    `Section updated in ${department}: ${item.sectionName}`,
                    'success'
                );
            });

            lastSectionSnapshotRef.current = nextSnapshot;
        };

        const handleAcademicDataChanged = (event) => {
            const reason = event.detail?.Reason || event.detail?.reason || '';
            const changedDepartment = event.detail?.Department || event.detail?.department || '';
            const actor = event.detail?.Actor || event.detail?.actor || '';
            const sameDepartment = normalizeText(changedDepartment) === normalizeText(department);
            const sameActor = normalizeText(actor) === normalizeText(loggedInEmail);

            if (sameDepartment && !sameActor) {
                if (reason === 'section_created') {
                    addNotification(
                        `Registrar created a new section in ${department}.`,
                        'success'
                    );
                }

                if (reason === 'masterlist_uploaded' || reason === 'students_enrolled') {
                    addNotification(
                        `Registrar updated section records in ${department}.`,
                        'success'
                    );
                }
            }

            loadGrades();
            loadMyClasses();
            loadAcademicSections();
            loadDepartmentFaculties();
            notifySectionStorageChanges();
        };

        const handleStorageChanged = (event) => {
            if (event.key === 'studentSections') {
                notifySectionStorageChanges();
                loadAcademicSections();
                loadMyClasses();
            }
        };

        window.addEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
        window.addEventListener('storage', handleStorageChanged);
        return () => {
            window.removeEventListener('blockgo:academic-data-changed', handleAcademicDataChanged);
            window.removeEventListener('storage', handleStorageChanged);
        };
    }, [addNotification, department, loadGrades, loggedInEmail, mainTab, loadMyClasses, loadAcademicSections, loadDepartmentFaculties]);

    useEffect(() => {
        loadAcademicSections();
        loadDepartmentFaculties();
        loadMyClasses();
    }, [loadAcademicSections, loadDepartmentFaculties, loadMyClasses]);

    useEffect(() => {
        if (mainTab === 'assignment' || mainTab === 'myClasses') {
            loadAcademicSections();
        }
        if (['assignment', 'forReview', 'returned', 'approved', 'forwarded', 'flagged'].includes(mainTab)) {
            loadDepartmentFaculties();
        }
    }, [mainTab, loadAcademicSections, loadDepartmentFaculties]);

    const getGradeStatus = useCallback((finalGrade) => {
        const n = parseFloat(finalGrade);
        if (isNaN(n)) return 'Incomplete';
        // Handle both PLV 1.0-5.0 system and 100-60 base systems
        if (passThreshold <= 5.0) {
             return n <= passThreshold ? 'Passed' : 'Failed';
        }
        return n >= passThreshold ? 'Passed' : 'Failed';
    }, [passThreshold]);

    useEffect(() => {
        if (selectedMySection && mainTab === 'myClasses') {
            const initialGrades = {};
            const sectionStudents = myStudents.filter(s => 
                s.department === selectedMySection.department && 
                String(s.yearLevel) === String(selectedMySection.yearLevel) && 
                String(s.sectionNum || s.section) === String(selectedMySection.sectionNum || selectedMySection.section)
            );
            sectionStudents.forEach(student => {
                const existing = grades.find(g => {
                    const studentKey = getRecordStudentKey(g);
                    const subjectKey = getRecordSubjectKey(g);
                    return (studentKey === student.studentno || studentKey === student.email) &&
                        (subjectKey === selectedMySection.subject || subjectKey === selectedMySection.department);
                });
                const parsedGrade = parseStoredGrade(getRecordGrade(existing));
                initialGrades[student.id] = {
                    ...parsedGrade,
                    standing: student.assignmentStatus || 'Enrolled',
                    flagged: existing?.flagged || false,
                    remarks: existing?.remarks || ''
                };
            });
            setClassGrades(initialGrades);
        }
    }, [selectedMySection, myStudents, grades, mainTab]);

    const validateGrade = (value) => {
        const num = parseFloat(value);
        if (value === '' || value === '0' || num === 0) return '';
        if (isNaN(num)) return 'Must be a number';
        if (num < 60 || num > 100) return 'Must be 60–100';
        return '';
    };

    const handleClassGradeChange = (studentId, field, value) => {
        if (field === 'midterm' || field === 'finals') {
            const error = validateGrade(value);
            setClassValidationErrors(prev => ({
                ...prev,
                [studentId]: { ...prev[studentId], [field]: error }
            }));
        }

        setClassGrades(prev => {
            const studentGrade = prev[studentId] || {};
            const updated = { ...studentGrade, [field]: value };
            
            if (field === 'midterm' || field === 'finals') {
                const mid = field === 'midterm' ? value : updated.midterm;
                const fin = field === 'finals' ? value : updated.finals;
                if (mid && fin && !isNaN(mid) && !isNaN(fin)) {
                    updated.finalAverage = ((parseFloat(mid) + parseFloat(fin)) / 2).toFixed(2);
                } else {
                    updated.finalAverage = '';
                }
            }
            return { ...prev, [studentId]: updated };
        });
    };

    const handleBulkApprove = async () => {
        if (!selectedReviewSection) return;
        try {
            const recordsToApprove = grades.filter(g => {
                const facId = g.facultyId || g.faculty_id || g.FacultyId || 'Unknown';
                const status = (g.status || g.Status || '').toLowerCase();
                const normalizedFacultyId = normalizeFacultyIdentity(facId) || facId;
                const subjectCode = g.subject_code || g.subjectCode || g.SubjectCode || '';
                const departmentName = g.department || g.course || g.Course || '';
                const sectionName =
                    getRecordSectionKey(g) ||
                    g.record_section ||
                    buildSectionDisplayName({
                        departmentName,
                        sectionValue: g.student_section || g.studentSection || '',
                        subjectCode,
                    }) ||
                    departmentName;
                const schoolYear = g.schoolYear || g.SchoolYear || '2024';
                const semester = g.semester || g.Semester || '2nd Semester';

                return (
                    normalizeText(normalizedFacultyId) === normalizeText(selectedReviewSection.facultyId) &&
                    normalizeText(sectionName) === normalizeText(selectedReviewSection.sectionName) &&
                    normalizeText(subjectCode) === normalizeText(selectedReviewSection.subjectCode) &&
                    normalizeText(schoolYear) === normalizeText(selectedReviewSection.schoolYear) &&
                    normalizeText(semester) === normalizeText(selectedReviewSection.semester) &&
                    (status.includes('issued') || status.includes('submitted') || status === '')
                );
            });
            
            for (const g of recordsToApprove) await approveGrade(g.id, loggedInEmail);
            addNotification("Section approved successfully!", "success");
            setSelectedReviewSection(null);
            loadGrades();
        } catch(e) { addNotification(`Error approving section: ${e.message}`, "error"); }
    };

    const handleBulkForward = async () => {
        if (!selectedReviewSection) return;
        try {
            const recordsToForward = grades.filter(g => {
                const facId = g.facultyId || g.faculty_id || g.FacultyId || 'Unknown';
                const status = (g.status || g.Status || '').toLowerCase();
                const normalizedFacultyId = normalizeFacultyIdentity(facId) || facId;
                const subjectCode = g.subject_code || g.subjectCode || g.SubjectCode || '';
                const departmentName = g.department || g.course || g.Course || '';
                const sectionName =
                    getRecordSectionKey(g) ||
                    g.record_section ||
                    buildSectionDisplayName({
                        departmentName,
                        sectionValue: g.student_section || g.studentSection || '',
                        subjectCode,
                    }) ||
                    departmentName;
                const schoolYear = g.schoolYear || g.SchoolYear || '2024';
                const semester = g.semester || g.Semester || '2nd Semester';

                return (
                    normalizeText(normalizedFacultyId) === normalizeText(selectedReviewSection.facultyId) &&
                    normalizeText(sectionName) === normalizeText(selectedReviewSection.sectionName) &&
                    normalizeText(subjectCode) === normalizeText(selectedReviewSection.subjectCode) &&
                    normalizeText(schoolYear) === normalizeText(selectedReviewSection.schoolYear) &&
                    normalizeText(semester) === normalizeText(selectedReviewSection.semester) &&
                    (status.includes('issued') || status.includes('submitted') || status.includes('approve'))
                );
            });

            for (const g of recordsToForward) await finalizeGrade(g.id, loggedInEmail);
            addNotification("Section forwarded to Registrar successfully!", "success");
            setSelectedReviewSection(null);
            loadGrades();
        } catch(e) { addNotification(`Error forwarding section: ${e.message}`, "error"); }
    };

    const handleBulkReturn = async (notes) => {
        if (!selectedReviewSection) return;
        try {
            const recordsToReturn = grades.filter(g => {
                const facId = g.facultyId || g.faculty_id || g.FacultyId || 'Unknown';
                const status = (g.status || g.Status || '').toLowerCase();
                const normalizedFacultyId = normalizeFacultyIdentity(facId) || facId;
                const subjectCode = g.subject_code || g.subjectCode || g.SubjectCode || '';
                const departmentName = g.department || g.course || g.Course || '';
                const sectionName =
                    getRecordSectionKey(g) ||
                    g.record_section ||
                    buildSectionDisplayName({
                        departmentName,
                        sectionValue: g.student_section || g.studentSection || '',
                        subjectCode,
                    }) ||
                    departmentName;
                const schoolYear = g.schoolYear || g.SchoolYear || '2024';
                const semester = g.semester || g.Semester || '2nd Semester';

                return (
                    normalizeText(normalizedFacultyId) === normalizeText(selectedReviewSection.facultyId) &&
                    normalizeText(sectionName) === normalizeText(selectedReviewSection.sectionName) &&
                    normalizeText(subjectCode) === normalizeText(selectedReviewSection.subjectCode) &&
                    normalizeText(schoolYear) === normalizeText(selectedReviewSection.schoolYear) &&
                    normalizeText(semester) === normalizeText(selectedReviewSection.semester) &&
                    canChairpersonReturnStatus(status)
                );
            });
            
            for (const g of recordsToReturn) {
                if (typeof returnGrade === 'function') {
                    await returnGrade(g.id, notes, loggedInEmail);
                }
            }
            addNotification("Section returned to faculty successfully!", "success");
            setSelectedReviewSection(null);
            loadGrades();
        } catch(e) { addNotification(`Error returning section: ${e.message}`, "error"); }
    };

    const handleBulkUpload = async () => {
        if (!uploadFile) return;
        setIsUploading(true);
        try {
            const semester = selectedMySection?.semester || "2nd Semester";
            const schoolYear = selectedMySection?.schoolYear || "2024";
            const course = selectedMySection?.department || selectedMySection?.subject || "Unknown";
            const facultyId = loggedInEmail;
            const section = `${selectedMySection?.department || ''} ${selectedMySection?.sectionNum || selectedMySection?.section || ''}${selectedMySection?.subject ? ` (${selectedMySection.subject})` : ''}`.trim();

            const res = await batchUploadGrades(uploadFile, semester, schoolYear, course, facultyId, activeEncodingTerm, section);
            if (res.status === 'Success' || res.status === 'Partial Success') {
                addNotification(`Uploaded successfully! Processed: ${res.totalProcessed}, Success: ${res.successful}`, 'success');
                setUploadFile(null);
                const fileInput = document.getElementById('chair-grade-upload');
                if (fileInput) fileInput.value = '';
                loadGrades();
            } else {
                addNotification(`Upload failed: ${res.message}`, 'error');
            }
        } catch (e) {
            addNotification(`Error: ${e.message}`, 'error');
        }
        setIsUploading(false);
    };

    const handleSaveClassGrades = async () => {
        const hasErrors = Object.values(classValidationErrors).some(errs => errs.midterm || errs.finals);
        if (hasErrors) {
            addNotification('Please fix validation errors before saving.', 'error');
            return;
        }

        setIsSavingGrades(true);
        try {
            const sectionStudents = myStudents.filter(s => 
                s.department === selectedMySection.department && 
                String(s.yearLevel) === String(selectedMySection.yearLevel) && 
                String(s.sectionNum || s.section) === String(selectedMySection.sectionNum || selectedMySection.section)
            );

            for (const student of sectionStudents) {
                const cg = classGrades[student.id];
                if (!cg || (!cg.midterm && !cg.finals && !cg.finalAverage)) continue;
                
                const gradePayload = JSON.stringify({ midterm: cg.midterm, finals: cg.finals, finalAverage: cg.finalAverage });
                const sectionName = `${selectedMySection.department || ''} ${selectedMySection.sectionNum || selectedMySection.section || ''}${selectedMySection.subject ? ` (${selectedMySection.subject})` : ''}`.trim();
                const payload = {
                    student_id: student.studentno || student.email || student.id,
                    student_name: student.fullname || student.name || [student.lastName, student.firstName].filter(Boolean).join(', '),
                    student_hash: student.email || student.studentno || student.id,
                    section: sectionName,
                    year_level: selectedMySection.yearLevel || '',
                    faculty_id: loggedInEmail,
                    subject_code: selectedMySection.subject || 'Unknown',
                    subject_name: selectedMySection.subject || 'Unknown',
                    professor_name: loggedInName || loggedInEmail,
                    program: selectedMySection.department || '',
                    term: activeEncodingTerm || 'midterm',
                    units: Number(selectedMySection.units) || 3,
                    course: selectedMySection.department,
                    semester: selectedMySection.semester || activeSemester || "2nd Semester",
                    school_year: selectedMySection.schoolYear || "2024",
                    grade: gradePayload,
                    status: "Issued",
                    date: new Date().toISOString().split('T')[0]
                };
                await issueGrade(payload);
            }
            addNotification('Grades saved successfully to the ledger!', 'success');
            loadGrades();
        } catch (e) { addNotification(`Error saving grades: ${e.message}`, 'error'); }
        setIsSavingGrades(false);
    };

    const handleExportClassGrades = () => {
        if (!selectedMySection) return;
        const sectionStudents = myStudents.filter(s => 
            s.department === selectedMySection.department && 
            String(s.yearLevel) === String(selectedMySection.yearLevel) && 
            String(s.sectionNum || s.section) === String(selectedMySection.sectionNum || selectedMySection.section)
        );
        
        const headers = ["Student ID", "Student Name", "Midterm", "Finals", "Final Grade"];
        const rows = sectionStudents.map(student => {
            const cg = classGrades[student.id] || {};
            return [student.studentno || student.email, `"${student.fullname}"`, cg.midterm || "", cg.finals || "", cg.finalAverage || ""].join(",");
        });
        
        const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows].join("\n");
        const link = document.createElement("a");
        link.href = encodeURI(csvContent);
        link.setAttribute("download", `${selectedMySection.department}_${selectedMySection.yearLevel}-${selectedMySection.sectionNum || selectedMySection.section}_Grades.csv`);
        link.click();
    };

    const handleBulkEnrollMyClass = async () => {
        if (!enrollFile || !selectedMySection) return;
        
        const matchedSection = academicSections.find(sec => 
            sec.department === selectedMySection.department && 
            String(sec.yearLevel) === String(selectedMySection.yearLevel) && 
            String(sec.sectionNum) === String(selectedMySection.sectionNum || selectedMySection.section)
        );

        if (!matchedSection) {
            addNotification("Could not resolve section ID. Please use the Academic Assignment tab.", "error");
            return;
        }

        setIsEnrolling(true);
        try {
            const res = await batchEnrollStudentsToSection(enrollFile, matchedSection.id);
            if (res.status === 'Success') {
                addNotification(res.message || 'Students enrolled successfully!', 'success');
                setEnrollFile(null);
                const fileInput = document.getElementById('myclass-student-enroll-upload');
                if (fileInput) fileInput.value = '';
                loadMyClasses();
            } else {
                addNotification(res.message || 'Enrollment failed.', 'error');
            }
        } catch (err) {
            addNotification(err.message, 'error');
        }
        setIsEnrolling(false);
    };

    const handleUnassignSection = async () => {
        if (!selectedMySection) return;
        setConfirmModal({
            isOpen: true,
            title: "Unassign Class",
            message: `Are you sure you want to unassign ${selectedMySection.department} ${selectedMySection.yearLevel}-${selectedMySection.sectionNum || selectedMySection.section} from your classes?`,
            onConfirm: async () => {
                try {
                    await unassignFacultySection(loggedInEmail, selectedMySection.department, selectedMySection.yearLevel, selectedMySection.sectionNum || selectedMySection.section);
                    addNotification("Class unassigned successfully.", "success");
                    setSelectedMySection(null);
                    loadMyClasses();
                } catch (e) {
                    addNotification(e.message, "error");
                }
                setConfirmModal({ isOpen: false, title: "", message: "", onConfirm: null });
            }
        });
    };

    const handleDropStudent = async (id, name) => {
        setConfirmModal({
            isOpen: true,
            title: "Drop Student",
            message: `Are you sure you want to drop ${name}? This will revoke their system access completely.`,
            onConfirm: async () => {
                try {
                    await dropStudent(id);
                    addNotification(`${name} has been dropped and access revoked.`, 'success');
                    loadMyClasses();
                } catch (e) {
                    addNotification(e.message, 'error');
                }
                setConfirmModal({ isOpen: false, title: "", message: "", onConfirm: null });
            }
        });
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
                addNotification(error.message, "error");
            }
        } else {
            addNotification("Vault Password is required", "error");
        }
    };

    const activeChairTab = mainTab;

    return (
        <div className="flex h-screen w-full flex-col bg-slate-50 font-sans fixed inset-0 z-[100] overflow-auto">
            <ChairpersonHeader chairpersonData={{ name: loggedInName, department, semester: activeSemester }} departmentCount={deptMetrics.totalFaculty} onLogout={onLogout} />
            <div className="flex flex-col md:flex-row flex-1 overflow-hidden p-4 md:p-6 gap-6">
                <ChairpersonSidebar activeTab={activeChairTab === 'grades' ? 'dashboard' : activeChairTab} setActiveTab={setMainTab} />
                <main className="flex-1 overflow-y-auto pr-2">
                    {(activeChairTab === 'dashboard' || activeChairTab === 'grades') && <ChairpersonOverview metrics={deptMetrics} />}
                        {['forReview', 'returned', 'approved', 'forwarded', 'flagged'].includes(activeChairTab) && (
                        <div className="flex flex-col gap-6">
                            <FacultyStatusTable 
                                rows={facultyRows.filter(r => {
                                    if (activeChairTab === 'forReview') return r.reviewStatus === 'submitted' || r.reviewStatus === 'pending';
                                    if (activeChairTab === 'returned') return r.reviewStatus === 'returned';
                                    if (activeChairTab === 'approved') return r.reviewStatus === 'approved';
                                    if (activeChairTab === 'forwarded') return r.reviewStatus === 'forwarded';
                                        if (activeChairTab === 'flagged') return Object.values(r.grades).some(g => g.flagged);
                                    return true;
                                })}
                                allRows={facultyRows}
                                selectedReviewKey={selectedReviewSection?.reviewKey} 
                                onSelectSection={setSelectedReviewSection}
                                onViewIpfs={handleViewIpfs}
                                viewMode={activeChairTab}
                            />
                            {selectedReviewSection && (
                                <SectionReviewPanel 
                                    selectedSection={selectedReviewSection} 
                                    activeTerm={activeEncodingTerm}
                                    onApprove={handleBulkApprove} 
                                    onSubmitToRegistrar={handleBulkForward} 
                                    onSendBack={(notes) => handleBulkReturn(notes)} 
                                    onViewIpfs={handleViewIpfs}
                                />
                            )}
                        </div>
                    )}
                    {activeChairTab === 'sectioning' && (
                        <div className="flex flex-col gap-6">
                            <StudentSectioning chairpersonDepartment={department} />
                        </div>
                    )}
                    {activeChairTab === 'curriculum' && (
                        <CurriculumBuilder department={department} />
                    )}
                    {activeChairTab === 'myClasses' && (
                        <div className="flex flex-col gap-6">
                            {!selectedMySection ? (
                                <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
                                    <h2 className="mb-4 text-xl font-bold text-[#003366]">My Assigned Classes</h2>
                                    {mySections.length === 0 ? (
                                        <p className="text-slate-500">You have no assigned classes yet.</p>
                                    ) : (
                                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                            {mySections.map((sec, idx) => (
                                                <div key={idx} onClick={() => setSelectedMySection(sec)} className="cursor-pointer rounded-xl border border-slate-200 bg-slate-50 p-5 transition hover:border-[#003366] hover:shadow-md">
                                                    <h3 className="font-bold text-lg text-[#003366]">{sec.department} {sec.yearLevel}-{sec.sectionNum || sec.section}</h3>
                                                    <p className="text-sm font-bold text-blue-800 mt-1">{sec.subject || 'No Subject Assigned'}</p>
                                                    <p className="text-sm text-slate-500 mt-1">Manage Class & Upload Grades</p>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
                                    <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
                                        <button onClick={() => setSelectedMySection(null)} className="flex items-center gap-2 text-sm font-bold text-[#003366] hover:underline">
                                            ← Back to Classes
                                        </button>
                                        <button onClick={handleUnassignSection} className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm font-bold text-red-600 transition hover:bg-red-100">
                                            Unassign Class
                                        </button>
                                    </div>
                                    <h2 className="text-xl font-bold text-[#003366] mb-6">{selectedMySection.department} {selectedMySection.yearLevel}-{selectedMySection.sectionNum || selectedMySection.section} ({selectedMySection.subject})</h2>
                                    
                                    <div className="mb-6 rounded-xl bg-slate-50 p-5 border border-slate-200 flex flex-col md:flex-row md:items-end gap-4">
                                        <div className="flex-1">
                                            <h3 className="font-bold text-emerald-700 mb-2">Enroll Missing Students</h3>
                                            
                                            <input 
                                                id="myclass-student-enroll-upload"
                                                type="file" 
                                                accept=".csv, .xlsx"
                                                onChange={(e) => setEnrollFile(e.target.files[0])}
                                                className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-emerald-50 file:text-emerald-700 hover:file:bg-emerald-100"
                                            />
                                        </div>
                                        <button 
                                            onClick={handleBulkEnrollMyClass}
                                            disabled={!enrollFile || isEnrolling}
                                            className="rounded-xl bg-emerald-600 px-5 py-2.5 text-sm font-bold text-white transition hover:bg-emerald-700 disabled:opacity-50"
                                        >
                                            {isEnrolling ? 'Enrolling...' : 'Bulk Enroll Students'}
                                        </button>
                                    </div>

                                    <div className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-md mt-6">
                                        <div className="flex flex-col gap-4 px-6 py-5 md:flex-row md:items-center md:justify-between bg-slate-50 border-b border-slate-200">
                                            <div className="flex flex-col gap-1">
                                                <div className="flex items-center gap-3">
                                                    <span className="shrink-0 rounded-lg bg-blue-100 px-3 py-1 text-sm font-bold text-blue-700">
                                                        {selectedMySection.subject || 'Subject'}
                                                    </span>
                                                    <h2 className="text-xl font-bold text-[#003366]">
                                                        Section: {selectedMySection.yearLevel}-{selectedMySection.sectionNum || selectedMySection.section}
                                                    </h2>
                                                </div>
                                            </div>
                                            <div className="flex flex-wrap items-center gap-3">
                                                <select 
                                                    value={statusFilter} 
                                                    onChange={e => setStatusFilter(e.target.value)} 
                                                    className="rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm font-bold text-slate-700 outline-none focus:border-[#003366]"
                                                >
                                                    <option value="All">All Statuses</option>
                                                    <option value="Enrolled">Active</option>
                                                    <option value="Dropped">Dropped</option>
                                                    <option value="UD">UD</option>
                                                    <option value="W">W</option>
                                                    <option value="INC">INC</option>
                                                </select>
                                                <div className="relative overflow-hidden">
                                                    <input 
                                                        type="file" 
                                                        accept=".csv, .xlsx"
                                                        onChange={(e) => setUploadFile(e.target.files[0])}
                                                        className="absolute inset-0 z-10 h-full w-full cursor-pointer opacity-0"
                                                    />
                                                    <button
                                                        disabled={isUploading}
                                                        className="rounded-lg bg-yellow-400 px-4 py-2.5 text-sm font-bold text-[#003366] transition hover:bg-yellow-500 disabled:opacity-50"
                                                    >
                                                        {uploadFile ? `Selected: ${uploadFile.name.substring(0, 10)}...` : 'Select File'}
                                                    </button>
                                                </div>
                                                {uploadFile && (
                                                    <button
                                                        onClick={handleBulkUpload}
                                                        disabled={isUploading}
                                                        className="rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-bold text-white transition hover:bg-blue-700 disabled:opacity-50"
                                                    >
                                                        {isUploading ? 'Uploading...' : 'Confirm Upload'}
                                                    </button>
                                                )}
                                                <button
                                                    onClick={handleExportClassGrades}
                                                    className="rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-bold text-slate-700 transition hover:bg-slate-50"
                                                >
                                                    Export CSV
                                                </button>
                                                <button
                                                    onClick={handleSaveClassGrades}
                                                    disabled={isSavingGrades || Object.values(classValidationErrors).some(errs => errs.midterm || errs.finals)}
                                                    className="rounded-xl bg-[#003366] px-5 py-2.5 text-sm font-bold text-white transition hover:bg-[#00264d] disabled:opacity-50"
                                                >
                                                    {isSavingGrades ? 'Saving to Ledger...' : 'Save Grades to Ledger'}
                                                </button>
                                            </div>
                                        </div>

                                        <div className="overflow-x-auto">
                                            <table className="w-full min-w-[900px]">
                                                <thead>
                                                    <tr className="border-b-4 border-yellow-400 bg-[#003b78] text-white">
                                                        <th className="px-6 py-4 text-left text-[15px] font-bold uppercase tracking-wide">Student ID</th>
                                                        <th className="px-6 py-4 text-left text-[15px] font-bold uppercase tracking-wide">Student Name</th>
                                                        <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">Midterm <span className="font-normal text-slate-300">(60-100)</span></th>
                                                        <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">Finals <span className="font-normal text-slate-300">(60-100)</span></th>
                                                        <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">Final Grade</th>
                                                        <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">Equivalent</th>
                                                        <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">Status</th>
                                                        <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">Standing</th>
                                                        <th className="px-6 py-4 text-center text-[15px] font-bold uppercase tracking-wide">Action</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {myStudents.filter(s => s.department === selectedMySection.department && String(s.yearLevel) === String(selectedMySection.yearLevel) && String(s.sectionNum || s.section) === String(selectedMySection.sectionNum || selectedMySection.section))
                                                    .filter(s => {
                                                        const standing = (classGrades[s.id] || {}).standing || 'Enrolled';
                                                        return statusFilter === "All" || standing === statusFilter;
                                                    })
                                                    .map(student => {
                                                        const studentData = classGrades[student.id] || {};
                                                        const final = studentData.finalAverage || '-';
                                                        const status = getGradeStatus(final);
                                                        const standing = studentData.standing || 'Enrolled';
                                                        const isFlagged = studentData.flagged;
                                                        const errors = classValidationErrors[student.id] || {};
                                                        const hasError = errors.midterm || errors.finals;

                                                        return (
                                                            <tr key={student.id} className={`border-b border-slate-200 hover:bg-slate-50 ${hasError || isFlagged ? 'bg-red-50' : 'bg-white'}`}>
                                                                <td className="px-6 py-5 font-semibold text-slate-700">{student.studentno}</td>
                                                                <td className="px-6 py-5 font-medium text-slate-800">{student.fullname}</td>
                                                                <td className="px-6 py-5 text-center">
                                                                    <div className="relative inline-block">
                                                                        <input type="number" min="60" max="100" value={studentData.midterm || ''} onChange={(e) => handleClassGradeChange(student.id, 'midterm', e.target.value)} className={`h-10 w-20 rounded-xl border px-2 text-center outline-none focus:ring-2 focus:ring-[#003366]/20 ${errors.midterm ? 'border-red-500 bg-red-50' : 'border-slate-300 bg-white'}`} placeholder="60-100" />
                                                                        {errors.midterm && <div className="absolute left-1/2 -translate-x-1/2 -bottom-5 whitespace-nowrap text-[10px] font-bold text-red-600">{errors.midterm}</div>}
                                                                    </div>
                                                                </td>
                                                                <td className="px-6 py-5 text-center">
                                                                    <div className="relative inline-block">
                                                                        <input type="number" min="60" max="100" value={studentData.finals || ''} onChange={(e) => handleClassGradeChange(student.id, 'finals', e.target.value)} className={`h-10 w-20 rounded-xl border px-2 text-center outline-none focus:ring-2 focus:ring-[#003366]/20 ${errors.finals ? 'border-red-500 bg-red-50' : 'border-slate-300 bg-white'}`} placeholder="60-100" />
                                                                        {errors.finals && <div className="absolute left-1/2 -translate-x-1/2 -bottom-5 whitespace-nowrap text-[10px] font-bold text-red-600">{errors.finals}</div>}
                                                                    </div>
                                                                </td>
                                                                <td className="px-6 py-5 text-center font-bold text-[#003366] text-lg">{final}</td>
                                                                <td className="px-6 py-5 text-center font-bold text-slate-700">{final !== '-' && !isNaN(final) ? getGradeEquivalent(final) : final}</td>
                                                                <td className="px-6 py-5 text-center">
                                                                    <span className={`inline-flex rounded-full px-3 py-1 text-xs font-bold ${status === 'Passed' ? 'bg-green-100 text-green-700' : status === 'Failed' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>{status}</span>
                                                                </td>
                                                                <td className="px-6 py-5 text-center">
                                                                    <select value={standing} onChange={(e) => handleClassGradeChange(student.id, 'standing', e.target.value)} className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium outline-none text-slate-700">
                                                                        <option value="Enrolled">Active</option>
                                                                        <option value="Dropped">Dropped</option>
                                                                        <option value="UD">UD</option>
                                                                        <option value="W">W</option>
                                                                        <option value="INC">INC</option>
                                                                    </select>
                                                                </td>
                                                                <td className="px-6 py-5 text-center">
                                                                    <button onClick={() => handleDropStudent(student.id, student.fullname)} className="rounded-lg bg-red-50 px-3 py-1.5 text-xs font-bold text-red-600 transition hover:bg-red-100 border border-red-200">Drop</button>
                                                                </td>
                                                            </tr>
                                                        );
                                                    })}
                                                    {myStudents.filter(s => s.department === selectedMySection.department && String(s.yearLevel) === String(selectedMySection.yearLevel) && String(s.sectionNum || s.section) === String(selectedMySection.sectionNum || selectedMySection.section)).length === 0 && (
                                                        <tr><td colSpan="9" className="p-8 text-center text-slate-500 bg-slate-50 rounded-b-xl text-base">No students are currently assigned to this section.</td></tr>
                                                    )}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                    {activeChairTab === 'assignment' && (
                        <AcademicAssignment key={department} chairpersonDepartment={department} />
                    )}
                </main>
            </div>
            {/* IPFS Vault Password Modal */}
            <Modal isOpen={ipfsModalOpen} onClose={() => setIpfsModalOpen(false)} title="IPFS Vault Decryption">
                <div className="flex flex-col gap-4">
                    <p className="text-sm text-slate-600">
                        This academic record is encrypted and distributed across the PLV IPFS Network. 
                        Enter the Vault Password to view the decrypted content.
                    </p>
                    <div className="relative">
                        <input 
                            type={showVaultPassword ? "text" : "password"} 
                            value={vaultPassword} 
                            onChange={(e) => setVaultPassword(e.target.value)} 
                            className="w-full rounded-xl border border-slate-300 px-4 py-3 pr-10 text-sm outline-none focus:border-[#003366]" 
                            placeholder="Enter Vault Password" 
                            onKeyDown={(e) => e.key === 'Enter' && submitIpfsPassword()}
                            autoFocus
                        />
                        <button
                            type="button"
                            onClick={() => setShowVaultPassword(!showVaultPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-[#003366]"
                            title={showVaultPassword ? "Hide Password" : "Show Password"}
                        >
                            {showVaultPassword ? (
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5"><path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>
                            ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                </svg>
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

export default DeptAdminGradesView;
