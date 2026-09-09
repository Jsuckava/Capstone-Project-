import React, { useMemo, useState } from 'react';
import { resetManagedAccountPassword } from '../../services/api';
import PasswordResetRequests from './PasswordResetRequests';

const PasswordManagement = ({ students = [], faculties = [], departmentAdmins = [], onRefresh }) => {
  const [roleFilter, setRoleFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState(null);

  const accounts = useMemo(() => {
    const byId = new Map();
    const add = (items, role, roleLabel) => items.forEach((account) => {
      if (!account?.id) return;
      byId.set(`${role}:${account.id}`, { ...account, key: `${role}:${account.id}`, role, roleLabel, name: account.fullname || account.fullName || account.email, accountCode: account.studentno || account.accountId || account.email });
    });
    add(students, 'student', 'Student');
    add(faculties.filter((account) => !departmentAdmins.some((admin) => admin.id === account.id)), 'faculty', 'Faculty');
    add(departmentAdmins, 'department_admin', 'Department Administrator');
    return Array.from(byId.values()).sort((left, right) => left.name.localeCompare(right.name));
  }, [students, faculties, departmentAdmins]);

  const visibleAccounts = useMemo(() => {
    const query = search.trim().toLowerCase();
    return accounts.filter((account) => (roleFilter === 'all' || account.role === roleFilter) && (!query || [account.name, account.email, account.accountCode, account.department].some((value) => String(value || '').toLowerCase().includes(query))));
  }, [accounts, roleFilter, search]);

  const selected = accounts.find((account) => account.key === selectedId);
  const resetPassword = async (event) => {
    event.preventDefault(); setNotice(null);
    if (!selected) return setNotice({ type: 'error', message: 'Select an account first.' });
    if (newPassword.length < 8 || newPassword.length > 128) return setNotice({ type: 'error', message: 'Password must be between 8 and 128 characters.' });
    if (newPassword !== confirmPassword) return setNotice({ type: 'error', message: 'The password confirmation does not match.' });
    if (!window.confirm(`Reset the password for ${selected.name} (${selected.roleLabel})?`)) return;
    setSaving(true);
    try {
      const response = await resetManagedAccountPassword(selected.id, newPassword);
      setNotice({ type: 'success', message: response?.message || `Password reset for ${selected.email}.` });
      setNewPassword(''); setConfirmPassword('');
    } catch (error) { setNotice({ type: 'error', message: error.message || 'Unable to reset the password.' }); }
    finally { setSaving(false); }
  };

  const fieldClass = 'mt-1.5 h-9 w-full rounded-md border border-slate-300 bg-white px-3 text-xs font-normal outline-none transition focus:border-blue-500 focus:ring-2 focus:ring-blue-100';
  const SearchIcon = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>;
  const LockIcon = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></svg>;

  return <div className="space-y-3">
    {notice && <div className={`rounded-md border px-3 py-2 text-xs ${notice.type === 'error' ? 'border-red-200 bg-red-50 text-red-700' : 'border-emerald-200 bg-emerald-50 text-emerald-800'}`}>{notice.message}</div>}

    <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm sm:p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2"><span className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-50 text-blue-600"><SearchIcon /></span><h2 className="text-sm font-bold text-slate-800">Find Account</h2></div>
        <button type="button" onClick={onRefresh} className="text-[10px] font-semibold text-blue-700 hover:underline">Refresh accounts</button>
      </div>
      <div className="space-y-3">
        <label className="block text-[11px] font-semibold text-slate-700">Account Type<select value={roleFilter} onChange={(event) => { setRoleFilter(event.target.value); setSelectedId(''); }} className={fieldClass}><option value="all">All Accounts</option><option value="student">Students</option><option value="faculty">Faculty</option><option value="department_admin">Department Administrators</option></select></label>
        <label className="block text-[11px] font-semibold text-slate-700">Search Account<span className="relative mt-1.5 block"><span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"><SearchIcon /></span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name, ID, email, or department..." className="h-9 w-full rounded-md border border-slate-300 pl-9 pr-3 text-xs font-normal outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100" /></span></label>
        <label className="block text-[11px] font-semibold text-slate-700">Account<select required value={selectedId} onChange={(event) => setSelectedId(event.target.value)} className={fieldClass}><option value="">Select an account</option>{visibleAccounts.map((account) => <option key={account.key} value={account.key}>{account.roleLabel} — {account.name} — {account.accountCode}</option>)}</select></label>
      </div>
    </section>

    <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm sm:p-4">
      <div className="mb-3 flex items-center gap-2"><span className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-50 text-blue-600"><LockIcon /></span><h2 className="text-sm font-bold text-slate-800">New Password</h2></div>
      <form onSubmit={resetPassword}>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="block text-[11px] font-semibold text-slate-700">New Password<input required minLength="8" maxLength="128" type={showPassword ? 'text' : 'password'} autoComplete="new-password" placeholder="Enter new password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} className={fieldClass} /></label>
          <label className="block text-[11px] font-semibold text-slate-700">Confirm Password<input required minLength="8" maxLength="128" type={showPassword ? 'text' : 'password'} autoComplete="new-password" placeholder="Confirm new password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} className={fieldClass} /></label>
        </div>
        <label className="mt-2.5 flex w-fit items-center gap-2 text-[10px] text-slate-600"><input type="checkbox" checked={showPassword} onChange={(event) => setShowPassword(event.target.checked)} className="h-3 w-3" />Show passwords</label>
        <div className="mt-3 flex flex-wrap items-end justify-between gap-3"><p className="text-[10px] text-slate-500">Password must contain at least 8 characters.</p><button disabled={saving || !selected} className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"><LockIcon />{saving ? 'Resetting…' : 'Reset Password'}</button></div>
      </form>
    </section>
    <PasswordResetRequests />
  </div>;
};

export default PasswordManagement;
