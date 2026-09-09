import React, { useState, useEffect, useCallback } from 'react';
import plvlogo from '../assets/plvlogo.png';
import { fetchDepartmentTemplates, reviewTemplate } from '../../services/api';

const DepartmentAdminTemplateReview = ({ adminData, onLogout }) => {
  const [templates, setTemplates] = useState([]);
  const [activeTemplate, setActiveTemplate] = useState(null);
  const [activeTab, setActiveTab] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(false);

  const fetchTemplates = useCallback(async () => {
    setLoading(true);
    try {
      // Fallback to empty string if department is undefined to avoid 404s
      const dept = adminData?.department || '';
      if (!dept) {
         setLoading(false);
         return;
      }

      const data = await fetchDepartmentTemplates(dept);
      
      if (data.status === "Success") {
        setTemplates(Array.isArray(data.templates) ? data.templates : []);
      }
    } catch (error) {
      console.error("Error fetching templates:", error);
      setTemplates([]);
    }
    setLoading(false);
  }, [adminData]);

  useEffect(() => {
    fetchTemplates();
  }, [fetchTemplates]);

  const handleReview = async (id, status) => {
    if (!window.confirm(`Are you sure you want to ${status.toLowerCase()} this grading template?`)) return;
    
    try {
      const data = await reviewTemplate(id, status);
      if (data.status === "Success") {
        alert(`Template successfully ${status.toLowerCase()}.`);
        setActiveTemplate(null);
        fetchTemplates(); // Refresh the list
      } else {
        alert(`Error: ${data.message}`);
      }
    } catch (error) {
      alert(`Network error: ${error.message}`);
    }
  };

  const totalTemplates = templates.length;
  const pendingCount = templates.filter(t => t.status === "Pending").length;
  const approvedCount = templates.filter(t => t.status === "Approved").length;
  const rejectedCount = templates.filter(t => t.status === "Rejected").length;

  const tabData = [
    { label: "All", count: totalTemplates, color: "gold", progress: totalTemplates > 0 ? 100 : 0 },
    { label: "Pending", count: pendingCount, color: "blue", progress: totalTemplates > 0 ? (pendingCount / totalTemplates) * 100 : 0 },
    { label: "Approved", count: approvedCount, color: "green", progress: totalTemplates > 0 ? (approvedCount / totalTemplates) * 100 : 0 },
    { label: "Rejected", count: rejectedCount, color: "red", progress: totalTemplates > 0 ? (rejectedCount / totalTemplates) * 100 : 0 },
  ];

  const filteredTemplates = templates.filter(t => {
    const matchesTab = activeTab === "All" || t.status === activeTab;
    const matchesSearch = t.templateName?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesTab && matchesSearch;
  });

  const getStatusClasses = (status) => {
    switch(status) {
      case 'Approved': return { dot: 'dot-done', label: 'status-done', bar: 'bar-done' };
      case 'Rejected': return { dot: 'dot-none', label: 'failed', bar: 'bar-none' }; // 'failed' maps to red text in your CSS
      case 'Pending': default: return { dot: 'dot-partial', label: 'status-partial', bar: 'bar-partial' };
    }
  };

  return (
    <div className="portal-container">
      {/* ── TOP NAV ── */}
      <nav className="header-greetings">
        <div className="greeting-text">
          <div className="greeting-text-content">
            <img src={plvlogo} alt="PLV Logo" className="plv-header-logo" />
            <h1>Welcome, {adminData?.fullName || "Admin"}!</h1>
          </div>
          <button className="logout-btn" onClick={onLogout}>LOGOUT</button>
        </div>
      </nav>

      {/* ── HEADER ── */}
      <header className="student-header">
        <div>
          <h1 style={{ margin: 0 }}>{adminData?.fullName}</h1>
          <h2 style={{ fontSize: '1.2rem', opacity: 0.9 }}>Department Head</h2>
          <p>{adminData?.department || "Unassigned"} Department</p>
        </div>
        <div className="summary-section">
          <div className="stat-card"><span>Total Templates</span><div className="stat-val">{totalTemplates}</div></div>
          <div className="stat-card gold"><span>Pending Review</span><div className="stat-val">{pendingCount}</div></div>
        </div>
      </header>

      {/* ── DYNAMIC BANNER ── */}
      {pendingCount > 0 ? (
        <div className="encoding-banner banner-urgent">
          <div>
            <strong>Action Required!</strong>
            <p>You have <strong>{pendingCount}</strong> grading {pendingCount === 1 ? 'template' : 'templates'} awaiting your approval before faculty can use them.</p>
          </div>
        </div>
      ) : (
        <div className="encoding-banner banner-open">
          <div>
            <strong>All Caught Up!</strong>
            <p>There are no pending grading templates requiring your review right now.</p>
          </div>
        </div>
      )}

      {!activeTemplate ? (
        <>
          {/* ── FILTER TABS ── */}
          <div className="filter-tabs-container">
            {tabData.map((tab) => (
              <div key={tab.label} className={`filter-tab ${activeTab === tab.label ? 'active' : ''}`} onClick={() => setActiveTab(tab.label)}>
                <div className="tab-top">
                  <span className="tab-label">{tab.label}</span>
                  <span className="tab-count-pill">{tab.count}</span>
                </div>
                <div className="tab-progress-bg">
                  <div className={`tab-progress-bar ${tab.color}`} style={{ width: `${tab.progress}%` }}></div>
                </div>
              </div>
            ))}
          </div>

          {/* ── SEARCH ROW ── */}
          <div className="search-row">
            <div className="search-container">
              <input type="text" placeholder="Search by template name..." className="search-input" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
              <span className="search-icon">🔍</span>
            </div>
          </div>

          <h2 className="year-title">{searchQuery ? `Results for "${searchQuery}"` : `${activeTab} Templates`}</h2>

          {/* ── TEMPLATE GRID ── */}
          <div className="section-grid">
            {loading && <p style={{ gridColumn: '1 / -1', textAlign: 'center' }}>Loading templates...</p>}
            {!loading && filteredTemplates.length === 0 && (
               <p style={{ gridColumn: '1 / -1', textAlign: 'center', color: '#777' }}>No templates found.</p>
            )}
            
            {filteredTemplates.map((t) => {
              const colsCount = t.formulaConfig?.columns?.length || 0;
              const sClass = getStatusClasses(t.status);
              
              return (
                <div key={t.id} className="section-card">
                  <div className="card-top-row">
                    <div className="subject-pill">ID: {t.id}</div>
                    <div className={`status-dot-wrap ${sClass.dot}`}>
                      <div className="status-dot"></div>
                      <span className={`status-dot-label ${sClass.label}`}>{t.status}</span>
                    </div>
                  </div>
                  <h2 className="subject-title" style={{ marginTop: '10px' }}>{t.templateName}</h2>
                  <div className="section-dept-row">
                    <span className="section-name">{t.createdAt ? new Date(t.createdAt).toLocaleDateString() : 'Unknown Date'}</span>
                    <span className="dept-pill">{colsCount + 2} Total Columns</span>
                  </div>
                  <hr className="card-divider" />
                  <div className="section-actions" style={{ justifyContent: 'center' }}>
                    <button className={`view-btn ${t.status === 'Pending' ? 'encode-now' : ''}`} style={{ width: '100%' }} onClick={() => setActiveTemplate(t)}>
                      {t.status === 'Pending' ? 'Review Blueprint' : 'View Template Details'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      ) : (
        /* ── TEMPLATE DETAILS VIEW ── */
        <div className="grading-view">
          <button className="back-btn" onClick={() => setActiveTemplate(null)}>← Back to Templates</button>

          <div className="table-container">
            <div className="table-header-custom">
              <div className="table-header-inner">
                <div>
                  <span className="subject-pill" style={{ marginRight: 8 }}>ID: {activeTemplate.id}</span>
                  <h3 style={{ display: 'inline', color: '#003366' }}>{activeTemplate.templateName}</h3>
                  <span className={`section-status-badge badge-${activeTemplate.status.toLowerCase()}`} style={{ marginLeft: 12 }}>
                    {activeTemplate.status}
                  </span>
                </div>
              </div>
            </div>

            <table className="plv-table">
              <thead>
                <tr>
                  <th>Excel Column</th>
                  <th>Header Name</th>
                  <th>Data Type</th>
                  <th>Formula Pattern</th>
                </tr>
              </thead>
              <tbody>
                <tr><td className="sub-code">A</td><td>Student Name</td><td><span className="status-pill passed">Locked</span></td><td>—</td></tr>
                <tr><td className="sub-code">B</td><td>Student No.</td><td><span className="status-pill passed">Locked</span></td><td>—</td></tr>
                {activeTemplate.formulaConfig?.columns?.map((col, i) => (
                  <tr key={i}>
                    <td className="sub-code">{col.id}</td>
                    <td><strong>{col.header}</strong></td>
                    <td><span className={`status-pill ${col.type === 'formula' ? 'incomplete' : 'passed'}`} style={{textTransform: 'capitalize'}}>{col.type}</span></td>
                    <td className="final-point" style={{ textAlign: 'left', fontWeight: 'normal', fontFamily: 'monospace', color: col.type === 'formula' ? '#1967d2' : '#777' }}>
                      {col.value || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {activeTemplate.status === 'Pending' && (
              <div className="table-footer">
                <p className="footer-note">
                  <strong>Accept Template</strong> — Approves this blueprint allowing Faculty to generate Excel grading sheets with it.<br/>
                  <strong>Reject Template</strong> — Returns it back to the Registrar with a rejected status.
                </p>
                <div className="footer-actions">
                  <button className="btn-save-all" onClick={() => handleReview(activeTemplate.id, 'Rejected')} style={{ backgroundColor: '#dc3545', color: 'white', border: 'none' }}>
                     Reject Template
                  </button>
                  <button className="btn-submit" onClick={() => handleReview(activeTemplate.id, 'Approved')}>
                     Accept Template
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default DepartmentAdminTemplateReview;
