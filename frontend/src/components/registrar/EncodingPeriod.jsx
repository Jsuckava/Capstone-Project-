import React, { useEffect, useState } from "react";
import { getSystemSetting, updateSystemSetting } from "../../services/api";

function EncodingPeriod({ onResetEncodingSeason }) {
  const [period, setPeriod] = useState({
    semester: "2nd Semester",
    startDate: "",
    endDate: "",
    term: "midterm",
  });
  const [statusMessage, setStatusMessage] = useState("");
  const [isResettingSeason, setIsResettingSeason] = useState(false);
  const [savedPeriod, setSavedPeriod] = useState(null);

  const isSuccessStatusMessage =
    statusMessage === "Encoding period saved successfully." ||
    statusMessage ===
      "Encoding season reset successfully. Faculty assigned sections were cleared, saved sections were kept, and the encoding period was closed.";

  useEffect(() => {
    const loadSavedPeriod = async () => {
      try {
        const res = await getSystemSetting("encoding_period");
        if (res.status === "Success" && res.value) {
          const savedPeriod = JSON.parse(res.value);
          setPeriod({
            semester: savedPeriod?.semester || "2nd Semester",
            startDate: savedPeriod?.startDate || "",
            endDate: savedPeriod?.endDate || "",
            term: savedPeriod?.term || "midterm",
          });
          setSavedPeriod(savedPeriod);
        } else {
          setStatusMessage("No saved encoding period yet.");
        }
      } catch (error) {
        setStatusMessage("No saved encoding period yet.");
      }
    };

    loadSavedPeriod();
  }, []);

  const { semester, startDate, endDate, term } = period;

  const updatePeriod = (field, value) => {
    setPeriod((current) => ({ ...current, [field]: value }));
  };

  const getBannerStatus = (schedule = period) => {
    if (!schedule.startDate || !schedule.endDate) return "Not Set";

    const today = new Date();
    const start = new Date(schedule.startDate);
    const end = new Date(schedule.endDate);

    start.setHours(0, 0, 0, 0);
    end.setHours(23, 59, 59, 999);
    today.setHours(0, 0, 0, 0);

    if (today < start) return "Closed (Not Started Yet)";
    if (today > end) return "Closed";
    
    const diffTime = end - today;
    const daysLeft = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (daysLeft <= 3) return "Urgent";
    return "Open";
  };

  const handleSave = async () => {
    const encodingData = {
      ...period,
    };

    try {
      await updateSystemSetting("encoding_period", JSON.stringify(encodingData));
      localStorage.setItem("encodingPeriod", JSON.stringify(encodingData));
      window.dispatchEvent(
        new CustomEvent("blockgo:system-setting-changed", {
          detail: {
            key: "encoding_period",
            value: JSON.stringify(encodingData),
          },
        })
      );
      setStatusMessage("Encoding period saved successfully.");
      setSavedPeriod(encodingData);
    } catch (error) {
      setStatusMessage(error.message || "Failed to save encoding period.");
    }
  };

  const handleResetSeason = async () => {
    const shouldReset = window.confirm(
      "Reset this encoding season? This will clear assigned faculty sections for the current encoding cycle, but will keep the saved student sections."
    );

    if (!shouldReset) return;

    try {
      setIsResettingSeason(true);
      await onResetEncodingSeason?.();
      setPeriod({
        semester: "2nd Semester",
        startDate: "",
        endDate: "",
        term: "midterm",
      });
      setSavedPeriod(null);
      setStatusMessage(
        "Encoding season reset successfully. Faculty assigned sections were cleared, saved sections were kept, and the encoding period was closed."
      );
      alert(
        "Encoding season has been reset. Faculty assigned sections are now cleared, saved sections were kept, and the encoding period is now closed."
      );
    } catch (error) {
      setStatusMessage(
        error?.message || "Failed to reset encoding season."
      );
    } finally {
      setIsResettingSeason(false);
    }
  };

  const formatDate = (value) => {
    if (!value) return "Not set";
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      timeZone: "UTC",
    }).format(new Date(`${value}T00:00:00Z`));
  };

  const formatDay = (value) => {
    if (!value) return "Select a date";
    return new Intl.DateTimeFormat("en-US", {
      weekday: "long",
      timeZone: "UTC",
    }).format(new Date(`${value}T00:00:00Z`));
  };

  return (
    <div className="space-y-3">
      <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm md:p-4">
        <div className="flex items-center justify-between gap-4">
          <h3 className="text-base font-bold text-slate-900">Encoding Period Control</h3>

          <span
            className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold ${
              getBannerStatus() === "Open"
                ? "border-green-200 bg-green-50 text-green-700"
                : getBannerStatus() === "Urgent"
                ? "border-amber-200 bg-amber-50 text-amber-700"
                : "border-red-200 bg-red-50 text-red-600"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-current" />
            {getBannerStatus()}
          </span>
        </div>

        {(statusMessage || !savedPeriod) && (
          <div
            className={`mt-3 flex items-center gap-2 rounded-md border px-3 py-2 text-xs ${
              isSuccessStatusMessage
                ? "border border-green-200 bg-green-50 text-green-700"
                : "border-blue-200 bg-blue-50/60 text-slate-600"
            }`}
          >
            <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white ${isSuccessStatusMessage ? "bg-green-600" : "bg-blue-700"}`}>i</span>
            <span>{statusMessage || "No saved encoding period yet."}</span>
          </div>
        )}

        <div className="mt-3 grid grid-cols-1 items-end gap-3 md:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_auto_1fr]">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700">Semester</label>
            <select
              value={semester}
              onChange={(e) => updatePeriod("semester", e.target.value)}
              className="h-9 w-full rounded-md border border-slate-300 bg-white px-3 text-xs font-medium text-slate-800 outline-none focus:border-blue-700 focus:ring-2 focus:ring-blue-100"
            >
              <option value="1st Semester">1st Semester</option>
              <option value="2nd Semester">2nd Semester</option>
              <option value="Summer">Summer</option>
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700">Encoding Term</label>
            <select
              value={term}
              onChange={(e) => updatePeriod("term", e.target.value)}
              className="h-9 w-full rounded-md border border-slate-300 bg-white px-3 text-xs font-medium text-slate-800 outline-none focus:border-blue-700 focus:ring-2 focus:ring-blue-100"
            >
              <option value="midterm">Midterms</option>
              <option value="finals">Finals</option>
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700">Start Date</label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => updatePeriod("startDate", e.target.value)}
              onClick={(e) => e.currentTarget.showPicker?.()}
              className="h-9 w-full rounded-md border border-slate-300 bg-white px-3 text-xs font-medium text-slate-800 outline-none focus:border-blue-700 focus:ring-2 focus:ring-blue-100"
            />
          </div>

          <span className="mb-2 hidden rounded-full bg-slate-100 px-2 py-1 text-[10px] font-medium text-slate-600 xl:block">to</span>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-700">End Date</label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => updatePeriod("endDate", e.target.value)}
              onClick={(e) => e.currentTarget.showPicker?.()}
              className="h-9 w-full rounded-md border border-slate-300 bg-white px-3 text-xs font-medium text-slate-800 outline-none focus:border-blue-700 focus:ring-2 focus:ring-blue-100"
            />
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={handleSave}
            className="inline-flex items-center gap-1.5 rounded-md bg-[#0b3478] px-3 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-[#08285e]"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-4 w-4"><path d="M5 3h12l2 2v16H5z"/><path d="M8 3v6h8V3M8 21v-7h8v7"/></svg>
            Save Schedule
          </button>

          <button
            type="button"
            onClick={handleResetSeason}
            disabled={isResettingSeason}
            className="inline-flex items-center gap-1.5 rounded-md border border-red-400 bg-white px-3 py-2 text-xs font-semibold text-red-600 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4"><path d="M20 7v5h-5"/><path d="M19 12a7 7 0 1 1-2-5"/></svg>
            {isResettingSeason ? "Resetting..." : "Reset Encoding Season"}
          </button>
        </div>
      </section>

      <section className="rounded-lg border border-slate-200 bg-white p-3 shadow-sm md:p-4">
        <h3 className="text-base font-bold text-slate-900">Current Schedule</h3>

        <div className="mt-3 grid grid-cols-1 overflow-hidden rounded-md border border-blue-100 bg-blue-50/30 sm:grid-cols-2 xl:grid-cols-5">
          <div className="p-3 xl:border-r xl:border-slate-200">
            <p className="text-[10px] text-slate-500">Semester</p>
            <p className="mt-1.5 text-xs font-semibold text-slate-900">{savedPeriod?.semester || "Not set"}</p>
          </div>

          <div className="p-3 xl:border-r xl:border-slate-200">
            <p className="text-[10px] text-slate-500">Encoding Term</p>
            <p className="mt-1.5 text-xs font-semibold text-slate-900">
              {savedPeriod ? (savedPeriod.term === "midterm" ? "Midterms" : "Finals") : "Not set"}
            </p>
          </div>

          <div className="p-3 xl:border-r xl:border-slate-200">
            <p className="text-[10px] text-slate-500">Start Date</p>
            <p className="mt-1.5 text-xs font-semibold text-slate-900">{formatDate(savedPeriod?.startDate)}</p>
            <p className="mt-1 text-xs text-slate-500">{formatDay(savedPeriod?.startDate)}{savedPeriod?.startDate ? " • 12:00 AM" : ""}</p>
          </div>

          <div className="p-3 xl:border-r xl:border-slate-200">
            <p className="text-[10px] text-slate-500">End Date</p>
            <p className="mt-1.5 text-xs font-semibold text-slate-900">{formatDate(savedPeriod?.endDate)}</p>
            <p className="mt-1 text-xs text-slate-500">{formatDay(savedPeriod?.endDate)}{savedPeriod?.endDate ? " • 11:59 PM" : ""}</p>
          </div>

          <div className="p-3">
            <p className="text-[10px] text-slate-500">Faculty Banner Status</p>
            <span className={`mt-1.5 inline-flex rounded-full px-2 py-1 text-[10px] font-semibold ${getBannerStatus(savedPeriod || {}) === "Open" ? "bg-green-100 text-green-700" : getBannerStatus(savedPeriod || {}) === "Urgent" ? "bg-amber-100 text-amber-700" : "bg-red-100 text-red-600"}`}>
              {getBannerStatus(savedPeriod || {})}
            </span>
          </div>
        </div>
      </section>
    </div>
  );
}

export default EncodingPeriod;
