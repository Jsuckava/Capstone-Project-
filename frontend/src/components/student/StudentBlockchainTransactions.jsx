import React, { useCallback, useEffect, useState } from 'react';
import { fetchStudentBlockchainTransactions } from '../../services/api';
import { getGradeEquivalent } from '../../utils/gradingHelpers';

const TRANSACTIONS_PER_PAGE = 10;

const shortenHash = (value = '') => value.length > 18 ? `${value.slice(0, 9)}…${value.slice(-9)}` : value;
const displayEquivalent = (grade) => {
  const numericGrade = Number(grade);
  if (!Number.isFinite(numericGrade)) return '—';
  return numericGrade > 5 ? getGradeEquivalent(numericGrade) : numericGrade.toFixed(2);
};
const displayTransactionDate = (value) => {
  if (!value) return '—';

  const parsedDate = new Date(value);
  if (!Number.isNaN(parsedDate.getTime())) return parsedDate.toLocaleString();

  const fabricTimestamp = String(value).match(/^seconds:\s*(-?\d+)\s+nanos:\s*(\d+)\s*$/i);
  if (fabricTimestamp) {
    const milliseconds = Number(fabricTimestamp[1]) * 1000 + Number(fabricTimestamp[2]) / 1_000_000;
    const convertedDate = new Date(milliseconds);
    if (!Number.isNaN(convertedDate.getTime())) return convertedDate.toLocaleString();
  }

  return 'Date unavailable';
};

const StudentBlockchainTransactions = () => {
  const [transactions, setTransactions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedHash, setExpandedHash] = useState('');
  const [copiedHash, setCopiedHash] = useState('');
  const [currentPage, setCurrentPage] = useState(1);

  const load = useCallback(async () => {
  setLoading(true);
  setError('');

  try {
    const response = await fetchStudentBlockchainTransactions();

    const transactionData = Array.isArray(response?.data)
      ? response.data
      : Array.isArray(response)
        ? response
        : [];

    setTransactions(transactionData);
    setCurrentPage(1);
  } catch (err) {
    setTransactions([]);
    setError(
      err?.message ||
      'Unable to retrieve blockchain transactions.'
    );
  } finally {
    setLoading(false);
  }
}, []);;

  useEffect(() => { load(); }, [load]);

  const copyHash = async (hash) => {
    await navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    window.setTimeout(() => setCopiedHash(''), 1500);
  };

  const totalPages = Math.max(1, Math.ceil(transactions.length / TRANSACTIONS_PER_PAGE));
  const pageStartIndex = (currentPage - 1) * TRANSACTIONS_PER_PAGE;
  const paginatedTransactions = transactions.slice(pageStartIndex, pageStartIndex + TRANSACTIONS_PER_PAGE);
  const firstVisibleTransaction = transactions.length === 0 ? 0 : pageStartIndex + 1;
  const lastVisibleTransaction = Math.min(pageStartIndex + TRANSACTIONS_PER_PAGE, transactions.length);

  if (loading) return <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-slate-500">Loading your private blockchain transaction history…</div>;

  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="text-xl font-bold text-[#003366]">Blockchain Transactions</h2></div>
        <button type="button" onClick={load} className="rounded-lg bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-200">Refresh</button>
      </div>
      {error ? <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div> : null}
      {!error && transactions.length === 0 ? <div className="rounded-xl border border-dashed border-slate-300 p-8 text-center text-slate-500">No blockchain transactions are available for your account yet.</div> : null}
      {transactions.length > 0 ? (
        <div className="overflow-x-auto rounded-xl border border-slate-200">
          <table className="min-w-full divide-y divide-slate-200 text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-4 py-3">Date</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Student ID</th><th className="px-4 py-3">Subject</th><th className="px-4 py-3">Professor</th><th className="px-4 py-3">Academic Period</th><th className="px-4 py-3">Term</th><th className="px-4 py-3">Grade</th><th className="px-4 py-3">Equivalent</th><th className="px-4 py-3">Hash / Transaction ID</th><th className="px-4 py-3">Status</th></tr></thead>
            <tbody className="divide-y divide-slate-100">
              {paginatedTransactions.map((transaction, index) => {
                const hash = transaction.transactionHash || transaction.transactionId || '';
                return (
                  <tr key={`${transaction.transactionId}-${index}`} className="align-top hover:bg-slate-50">
                    <td className="whitespace-nowrap px-4 py-3">{displayTransactionDate(transaction.timestamp)}</td>
                    <td className="px-4 py-3 font-semibold">{String(transaction.transactionType || '').replaceAll('_', ' ')}</td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{transaction.studentId || '—'}</td>
                    <td className="px-4 py-3"><span className="font-bold text-[#003366]">{transaction.subjectCode}</span><span className="block text-xs text-slate-500">{transaction.subjectTitle}</span></td>
                    <td className="px-4 py-3">{transaction.professor || 'Not recorded'}</td><td className="whitespace-nowrap px-4 py-3"><span className="block">{transaction.semester || '—'}</span><span className="text-xs text-slate-500">{transaction.schoolYear || '—'}</span></td><td className="px-4 py-3 capitalize">{transaction.term || '—'}</td><td className="px-4 py-3 font-bold">{transaction.grade || '—'}</td><td className="px-4 py-3 font-bold text-[#003366]">{displayEquivalent(transaction.grade)}</td>
                    <td className="min-w-[240px] px-4 py-3"><code className="block break-all text-xs">{expandedHash === hash ? hash : shortenHash(hash)}</code><div className="mt-2 flex gap-2"><button type="button" onClick={() => setExpandedHash(expandedHash === hash ? '' : hash)} className="text-xs font-semibold text-blue-700 hover:underline">{expandedHash === hash ? 'Shorten' : 'View Full Hash'}</button><button type="button" onClick={() => copyHash(hash)} className="text-xs font-semibold text-blue-700 hover:underline">{copiedHash === hash ? 'Copied' : 'Copy Hash'}</button></div></td>
                    <td className="px-4 py-3"><span className="rounded-full bg-blue-100 px-2 py-1 text-xs font-semibold text-blue-800">{transaction.status}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 bg-slate-50 px-4 py-3">
            <p className="text-sm font-medium text-slate-600">
              Showing <span className="font-bold text-[#003366]">{firstVisibleTransaction}-{lastVisibleTransaction}</span> of {transactions.length} · Page {currentPage} of {totalPages}
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                disabled={currentPage === 1}
                className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-bold text-[#003366] transition hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Previous
              </button>
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
        </div>
      ) : null}
      
    </section>
  );
};

export default StudentBlockchainTransactions;
