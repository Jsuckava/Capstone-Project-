import React from "react";

const iconPaths = {
  dashboard: <><path d="M3 11.5 12 4l9 7.5" /><path d="M5.5 10v10h13V10M9.5 20v-6h5v6" /></>,
  encoding: <><rect x="5" y="5" width="14" height="15" rx="2" /><path d="M8 3v4m8-4v4M8 10h8m-8 4h5" /></>,
  enrollment: <><path d="m3 9 9-5 9 5-9 5z" /><path d="M7 12v4c2.8 2.1 7.2 2.1 10 0v-4M21 9v6" /></>,
  sectioning: <><path d="M7 3h8l4 4v14H7z" /><path d="M15 3v5h5M10 12h6m-6 4h6" /></>,
  sectionsCreated: <><circle cx="6" cy="7" r="2" /><circle cx="18" cy="17" r="2" /><path d="M8 7h9m-5-3v6M6 9v8h10" /></>,
  monitoring: <><path d="M3 7h6l2-2h10v14H3z" /><path d="M3 9h18" /></>,
  finalization: <><path d="M7 3h8l4 4v14H7z" /><path d="M15 3v5h5m-9 6 2 2 4-4" /></>,
  reports: <><path d="M7 3h8l4 4v14H7z" /><path d="M15 3v5h5M10 12h6m-6 4h6" /></>,
};

function SidebarIcon({ name }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4 shrink-0">
      {iconPaths[name]}
    </svg>
  );
}

function RegistrarSidebar({
  activeTab,
  setActiveTab,
  chatUnreadCount = 0,
  latestChatNotice = null,
  onOpenChat,
  managementDefaultTab = "grades",
  managementMenuItems = [],
}) {
  const managementTabs = [
    "monitoring",
    "grades",
    "assigning",
    "createAccounts",
    "tickets",
    "passwordResets",
    "revokeAccounts",
    "assignStudents",
    "assignAdmins",
    "assignFaculties",
  ];
  const [isManagementOpen, setIsManagementOpen] = React.useState(() =>
    managementTabs.includes(activeTab)
  );
  const enrollmentTabs = ["bulkEnroll", "sectioning", "sectionsCreated", "curriculum"];
  const enrollmentMenuItems = [
    { id: "bulkEnroll", label: "Student Enrollment" },
    { id: "sectioning", label: "Department Sections" },
    { id: "sectionsCreated", label: "Sections Created" },
    { id: "curriculum", label: "Curriculum Management" },
  ];
  const operationsMenuItems = managementMenuItems.filter(
    (item) => !enrollmentTabs.includes(item.id) && item.id !== "Requests"
  );
  const [isEnrollmentOpen, setIsEnrollmentOpen] = React.useState(() =>
    enrollmentTabs.includes(activeTab)
  );
  const menuItems = [
  { id: "dashboard", label: "Dashboard" },
  { id: "encoding", label: "Encoding Period" },
  { id: "enrollment", label: "Enrollment Management" },
  { id: "monitoring", label: "Operations" },
  { id: "finalization", label: "Grade Finalization" },
  { id: "reports", label: "Reports & PDF" },
];

  return (
    <aside className="w-full max-w-[230px] self-start overflow-x-hidden overflow-y-auto rounded-2xl border border-slate-200 bg-white p-2.5 shadow-sm [scrollbar-gutter:stable] md:h-[calc(100vh-7.5rem)] md:shrink-0 lg:sticky lg:top-6">
      <div className="mb-3 border-b border-slate-200 pb-2">
        <h2 className="text-base font-bold text-[#003366]">Registrar Panel</h2>

        {onOpenChat && (
          <button
            type="button"
            onClick={onOpenChat}
            className="mt-2 w-full rounded-xl border border-blue-100 bg-blue-50 px-3 py-2 text-left transition hover:bg-blue-100"
          >
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm font-bold text-[#003366]">Chat Notifications</span>
              {chatUnreadCount > 0 && (
                <span className="flex h-6 min-w-6 items-center justify-center rounded-full bg-red-500 px-2 text-xs font-bold text-white">
                  {chatUnreadCount > 9 ? "9+" : chatUnreadCount}
                </span>
              )}
            </div>
            <p className="mt-1 truncate text-xs text-slate-500">
              {latestChatNotice
                ? `${latestChatNotice.from}: ${latestChatNotice.message}`
                : "No new chat messages"}
            </p>
          </button>
        )}
      </div>

      <nav className="flex flex-col gap-1">
        {menuItems.map((item) => {
          const isManagementItem = item.id === "monitoring";
          const isEnrollmentItem = item.id === "enrollment";
          const isActive = isEnrollmentItem
            ? enrollmentTabs.includes(activeTab)
            : isManagementItem
            ? managementTabs.includes(activeTab)
            : activeTab === item.id;
          const isDropdownHighlighted =
            (isEnrollmentItem && isEnrollmentOpen) ||
            (isManagementItem && isManagementOpen);

          return (
            <React.Fragment key={item.id}>
              <button
                type="button"
                onClick={() => {
                  if (isEnrollmentItem) {
                    const willOpen = !isEnrollmentOpen;
                    setIsEnrollmentOpen(willOpen);
                    if (willOpen && !enrollmentTabs.includes(activeTab)) {
                      setActiveTab("bulkEnroll");
                    }
                    return;
                  }

                  if (!isManagementItem) {
                    setActiveTab(item.id);
                    return;
                  }

                  const willOpen = !isManagementOpen;
                  setIsManagementOpen(willOpen);
                  if (willOpen && !managementTabs.includes(activeTab)) {
                    setActiveTab(managementDefaultTab);
                  }
                }}
                className={`flex w-full items-center justify-between whitespace-nowrap rounded-xl border-b-2 px-2.5 py-2 text-left text-xs font-medium transition ${
                  isActive || isDropdownHighlighted
                    ? "border-yellow-400 bg-[#003366] text-yellow-400 shadow-sm"
                    : "border-transparent text-slate-700 hover:bg-slate-100"
                }`}
              >
                <span className="flex min-w-0 items-center gap-2 whitespace-nowrap">
                  <SidebarIcon name={item.id} />
                  <span className="whitespace-nowrap">{item.label}</span>
                </span>
                {(isEnrollmentItem || (isManagementItem && operationsMenuItems.length > 0)) && (
                  <svg
                    aria-hidden="true"
                    viewBox="0 0 20 20"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className={`ml-2 h-4 w-4 shrink-0 transition-transform ${
                      (isEnrollmentItem ? isEnrollmentOpen : isManagementOpen) ? "rotate-180" : ""
                    }`}
                  >
                    <path d="m6 8 4 4 4-4" />
                  </svg>
                )}
              </button>

              {isEnrollmentItem && isEnrollmentOpen && (
                <div className="ml-3 flex flex-col border-l-2 border-blue-100 py-1 pl-3">
                  {enrollmentMenuItems.map((enrollmentItem) => (
                    <button
                      key={enrollmentItem.id}
                      type="button"
                      onClick={() => setActiveTab(enrollmentItem.id)}
                      className={`w-full rounded-lg px-1.5 py-2 text-left text-[11px] font-medium transition ${
                        activeTab === enrollmentItem.id
                          ? "bg-blue-50 font-semibold text-blue-700"
                          : "text-slate-600 hover:bg-slate-100 hover:text-[#003366]"
                      }`}
                    >
                      <span className="mr-2 text-blue-500">&#8226;</span>
                      {enrollmentItem.label}
                    </button>
                  ))}
                </div>
              )}

              {isManagementItem && isManagementOpen && operationsMenuItems.length > 0 && (
                <div className="ml-1.5 flex flex-col gap-1 border-l border-blue-100 pl-1.5">
                  {operationsMenuItems.map((managementItem) => (
                    <button
                      key={managementItem.id}
                      type="button"
                      onClick={() => setActiveTab(managementItem.id)}
                      className={`w-full whitespace-nowrap rounded-lg px-1.5 py-2 text-left text-[11px] font-medium transition ${
                        activeTab === managementItem.id
                          ? "bg-blue-100 font-semibold text-blue-700"
                          : "text-slate-600 hover:bg-slate-100 hover:text-[#003366]"
                      }`}
                    >
                      <span className="mr-1.5 text-blue-500">&#8226;</span>
                      {managementItem.label}
                    </button>
                  ))}
                </div>
              )}
            </React.Fragment>
          );
        })}
      </nav>
    </aside>
  );
}

export default RegistrarSidebar;
