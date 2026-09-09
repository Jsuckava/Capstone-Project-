import React, { useCallback, useEffect, useState } from 'react';
import { createRegistrarAccount, deleteRegistrarAccount, fetchRegistrarAccounts, resetManagedAccountPassword, updateRegistrarAccount } from '../../services/api';

const emptyForm = { registrarId: '', fullName: '', email: '', password: '' };
const MAXIMUM_REGISTRAR_ACCOUNTS = 2;

const RegistrarAccountManagement = () => {
  const [accounts, setAccounts] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState(null);
  const [edits, setEdits] = useState({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetchRegistrarAccounts();
      setAccounts(Array.isArray(response?.data) ? response.data : []);
    } catch (error) { setNotice({ type: 'error', message: error.message }); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const create = async (event) => {
    event.preventDefault(); setSaving(true); setNotice(null);
    try {
      const response = await createRegistrarAccount(form);
      setNotice({ type: response?.data?.warning ? 'warning' : 'success', message: response?.data?.warning || 'Registrar account created successfully.' });
      setForm(emptyForm); await load();
    } catch (error) { setNotice({ type: 'error', message: error.message }); }
    finally { setSaving(false); }
  };

  const saveEmail = async (account) => {
    const email = (edits[account.id]?.email || '').trim();
    if (!email) return;
    setSaving(true); setNotice(null);
    try {
      const response = await updateRegistrarAccount(account.id, { email });
      setNotice({ type: response?.data?.warning ? 'warning' : 'success', message: response?.data?.warning || 'Registrar email updated.' });
      setEdits((current) => ({ ...current, [account.id]: { ...current[account.id], email: '' } }));
      await load();
    } catch (error) { setNotice({ type: 'error', message: error.message }); }
    finally { setSaving(false); }
  };

  const resetPassword = async (account) => {
    const edit = edits[account.id] || {};
    if ((edit.password || '').length < 8) return setNotice({ type: 'error', message: 'The new password must contain at least 8 characters.' });
    if (edit.password !== edit.confirmPassword) return setNotice({ type: 'error', message: 'The password confirmation does not match.' });
    if (!window.confirm(`Reset the password for Registrar ${account.email}?`)) return;
    setSaving(true); setNotice(null);
    try {
      const response = await resetManagedAccountPassword(account.id, edit.password);
      setNotice({ type: 'success', message: response?.message || 'Registrar password reset successfully.' });
      setEdits((current) => ({ ...current, [account.id]: { ...current[account.id], password: '', confirmPassword: '' } }));
    } catch (error) { setNotice({ type: 'error', message: error.message }); }
    finally { setSaving(false); }
  };

  const deleteAccount = async (account) => {
    if (!window.confirm(`Delete Registrar ${account.email}? This revokes access and frees one Registrar slot.`)) return;
    setSaving(true); setNotice(null);
    try {
      const response = await deleteRegistrarAccount(account.id);
      setNotice({ type: response?.data?.warning ? 'warning' : 'success', message: response?.data?.warning || response?.message || 'Registrar account deleted.' });
      await load();
    } catch (error) { setNotice({ type: 'error', message: error.message }); }
    finally { setSaving(false); }
  };

  const canCreate = accounts.length < MAXIMUM_REGISTRAR_ACCOUNTS;
  const noticeClass = notice?.type === 'error' ? 'bg-red-50 text-red-700' : notice?.type === 'warning' ? 'bg-amber-50 text-amber-800' : 'bg-emerald-50 text-emerald-800';
  return <div className="space-y-6">
    {notice ? <div className={`rounded-lg p-3 text-sm ${noticeClass}`}>{notice.message}</div> : null}
    <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-xl font-bold text-[#003366]">Create Registrar Account</h2><p className="mt-1 text-sm text-slate-500">At most two current Registrar accounts are allowed.</p></div><span className={`rounded-full px-3 py-1 text-sm font-bold ${canCreate ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}`}>{accounts.length} / {MAXIMUM_REGISTRAR_ACCOUNTS} Registrar accounts</span></div>
      {loading ? <p className="mt-5 text-sm text-slate-500">Checking Registrar slots...</p> : canCreate ? <form onSubmit={create} className="mt-5 grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">Registrar ID<input required value={form.registrarId} onChange={(event) => setForm({ ...form, registrarId: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-normal" /></label>
        <label className="text-sm font-semibold">Full Name<input required value={form.fullName} onChange={(event) => setForm({ ...form, fullName: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-normal" /></label>
        <label className="text-sm font-semibold">Email<input required type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-normal" /></label>
        <label className="text-sm font-semibold">Temporary Password<input required minLength="8" type="password" autoComplete="new-password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 font-normal" /></label>
        <button disabled={saving} className="rounded-lg bg-[#003366] px-4 py-2.5 font-bold text-white disabled:opacity-50 md:col-span-2">{saving ? 'Saving…' : 'Create Registrar'}</button>
      </form> : <div className="mt-5 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm font-semibold text-amber-800">The two-Registrar limit has been reached. Update an existing account or delete one to create another Registrar.</div>}
    </section>
    <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="mb-4 flex justify-between"><div><h2 className="text-xl font-bold text-[#003366]">Registrar Access</h2></div><button onClick={load} className="rounded-lg bg-slate-100 px-3 py-2 text-sm font-semibold">Refresh</button></div>
      {loading ? <p className="py-8 text-center text-slate-500">Loading accounts…</p> : <div className="space-y-4">{accounts.map((account) => {
        const edit = edits[account.id] || {};
        const updateEdit = (changes) => setEdits((current) => ({ ...current, [account.id]: { ...edit, ...changes } }));
        return <div key={account.id} className="rounded-xl border border-slate-200 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-bold text-slate-800">{account.fullName}</p><p className="text-xs text-slate-500">{account.accountId} · Registrar</p></div><button disabled={saving} onClick={() => deleteAccount(account)} className="rounded-lg bg-red-100 px-3 py-2 text-sm font-bold text-red-700 disabled:opacity-50">Delete Registrar</button></div>
          <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_auto]"><label className="text-xs font-semibold text-slate-600">New Email<input type="email" placeholder={account.email} value={edit.email || ''} onChange={(event) => updateEdit({ email: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal" /></label><button disabled={saving || !edit.email} onClick={() => saveEmail(account)} className="self-end rounded-lg bg-[#003366] px-4 py-2 text-sm font-bold text-white disabled:opacity-50">Update Email</button></div>
          <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_1fr_auto]"><label className="text-xs font-semibold text-slate-600">New Password<input type="password" minLength="8" maxLength="128" autoComplete="new-password" value={edit.password || ''} onChange={(event) => updateEdit({ password: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal" /></label><label className="text-xs font-semibold text-slate-600">Confirm Password<input type="password" minLength="8" maxLength="128" autoComplete="new-password" value={edit.confirmPassword || ''} onChange={(event) => updateEdit({ confirmPassword: event.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal" /></label><button disabled={saving || !edit.password} onClick={() => resetPassword(account)} className="self-end rounded-lg bg-amber-500 px-4 py-2 text-sm font-bold text-slate-900 disabled:opacity-50">Reset Password</button></div>
        </div>;
      })}{accounts.length === 0 ? <p className="py-8 text-center text-slate-500">No Registrar accounts found.</p> : null}</div>}
    </section>
  </div>;
};

export default RegistrarAccountManagement;
