import React, { useState } from 'react';
import { createGradeTemplate } from '../../services/api';


const programs = [
  "Bachelor of Early Childhood Education",
  "Bachelor of Secondary Education Major in English",
  "Bachelor of Secondary Education Major in Filipino",
  "Bachelor of Secondary Education Major in Mathematics",
  "Bachelor of Secondary Education Major in Science",
  "Bachelor of Secondary Education Major in Social Studies",
  "Bachelor of Science in Civil Engineering",
  "Bachelor of Science in Electrical Engineering",
  "Bachelor of Science in Information Technology",
  "Bachelor of Arts in Communication",
  "Bachelor of Science in Psychology",
  "Bachelor of Science in Social Work",
  "Bachelor of Public Administration",
  "Bachelor of Science in Accountancy",
  "Bachelor of Science in Business Administration Major in Financial Management",
  "Bachelor of Science in Business Administration Major in Human Resource Management",
  "Bachelor of Science in Business Administration Major in Marketing Management"
];

const FormulaBuilder = () => {
  const [templateName, setTemplateName] = useState('');
  const [department, setDepartment] = useState('Bachelor of Science in Information Technology');
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  const [columns, setColumns] = useState([
    { id: 'C', header: 'Quiz 1', type: 'input', value: '' },
    { id: 'D', header: 'Exam 1', type: 'input', value: '' },
    { id: 'E', header: 'Final Grade', type: 'formula', value: '=(C{row} * 0.3) + (D{row} * 0.7)' }
  ]);

  const getNextColumnId = () => {
    if (columns.length === 0) return 'C';
    const lastId = columns[columns.length - 1].id;
    // Move to the next letter in the alphabet (Simple implementation, works up to Z)
    return String.fromCharCode(lastId.charCodeAt(0) + 1);
  };

  const addColumn = (type) => {
    const nextId = getNextColumnId();
    setColumns([...columns, { id: nextId, header: `New ${type}`, type, value: '' }]);
  };

  const updateColumn = (index, field, newValue) => {
    const updated = [...columns];
    updated[index][field] = newValue;
    setColumns(updated);
  };

  const handleSave = async () => {
    if (!templateName) {
      alert("Please provide a template name.");
      return;
    }

    setIsSubmitting(true);
    try {
      const payload = {
        templateName,
        department,
        formulaConfig: { columns } 
      };

      const result = await createGradeTemplate(payload);
      alert(result.message || "Template submitted for approval successfully!");
      setTemplateName('');
    } catch (error) {
      console.error("Error saving template:", error);
      alert(error.message || "Failed to save the template.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ background: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)', marginBottom: '20px' }}>
      <h3 style={{ color: '#003366', marginTop: 0 }}>Create Grade Template</h3>
      
      <div style={{ display: 'flex', gap: '15px', marginBottom: '20px' }}>
        <input type="text" placeholder="Template Name (e.g. standard-it-grading)" value={templateName} onChange={(e) => setTemplateName(e.target.value)} style={{ padding: '8px', flex: 1 }} />
        <select value={department} onChange={(e) => setDepartment(e.target.value)} style={{ padding: '8px' }}>
          {programs.map((prog) => (
            <option key={prog} value={prog}>{prog}</option>
          ))}
        </select>
      </div>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '20px' }}>
         <div style={{ background: '#e9ecef', padding: '10px', borderRadius: '4px', fontWeight: 'bold' }}>
           A: Student Name | B: Student No. (Locked)
         </div>
         {columns.map((col, index) => (
           <div key={col.id} style={{ display: 'flex', gap: '10px', alignItems: 'center', background: '#f8f9fa', padding: '10px', borderRadius: '4px' }}>
             <strong style={{ width: '20px' }}>{col.id}</strong>
             <input type="text" value={col.header} onChange={(e) => updateColumn(index, 'header', e.target.value)} style={{ padding: '6px', flex: 1 }} />
             <span style={{ fontSize: '0.85em', color: '#666', width: '60px', textAlign: 'center' }}>({col.type})</span>
             {col.type === 'formula' && (
               <input type="text" placeholder="e.g. =(C{row}*0.5) + (D{row}*0.5)" value={col.value} onChange={(e) => updateColumn(index, 'value', e.target.value)} style={{ padding: '6px', flex: 2 }} />
             )}
           </div>
         ))}
      </div>

      <div style={{ display: 'flex', gap: '10px' }}>
        <button onClick={() => addColumn('input')} style={{ padding: '8px 16px', cursor: 'pointer', background: '#6c757d', color: 'white', border: 'none', borderRadius: '4px' }}>+ Add Raw Score Col</button>
        <button onClick={() => addColumn('formula')} style={{ padding: '8px 16px', cursor: 'pointer', background: '#17a2b8', color: 'white', border: 'none', borderRadius: '4px' }}>+ Add Formula Col</button>
        <div style={{ flex: 1 }}></div>
        <button onClick={handleSave} disabled={isSubmitting} style={{ padding: '8px 24px', cursor: 'pointer', background: '#003366', color: 'white', border: 'none', borderRadius: '4px', fontWeight: 'bold' }}>
          {isSubmitting ? 'Saving...' : 'Submit for Approval'}
        </button>
      </div>
    </div>
  );
};

export default FormulaBuilder;
