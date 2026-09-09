import React, { useState } from 'react';

const PdfReportViewer = ({ title = "PDF Report Viewer", pdfUrl }) => {
    const [zoom, setZoom] = useState(1.0);
    const [rotation, setRotation] = useState(0);
    const [page, setPage] = useState(1);
    const totalPages = 2; // Mock total pages

    const handleZoomIn = () => setZoom(prev => prev + 0.25);
    const handleZoomOut = () => setZoom(prev => (prev > 0.25 ? prev - 0.25 : prev));
    const handleRotate = () => setRotation(prev => (prev + 90) % 360);

    return (
        <div className="flex flex-col h-[600px] w-full max-w-[900px] border border-slate-200 rounded-lg overflow-hidden bg-white shadow-lg mx-auto">
            <div className="h-12 bg-[#F3F3F3] border-b border-slate-200 flex items-center px-4 justify-between select-none">
                <div className="flex items-center space-x-1">
                    <button className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-slate-700">T</button>
                    <button className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-slate-700">A</button>
                    <button className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-slate-700">a</button>
                    <div className="w-[1px] h-6 bg-slate-300 mx-2"></div>
                    <button className="px-3 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-sm font-medium text-slate-700">
                    </button>
                </div>
                <div className="flex items-center space-x-1">
                    <button onClick={handleZoomOut} className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-lg text-slate-700">−</button>
                    <button onClick={handleZoomIn} className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-lg text-slate-700">+</button>
                    <button className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-slate-700">↔</button>
                    <div className="w-[1px] h-6 bg-slate-300 mx-2"></div>
                    <input 
                        type="text" 
                        value={page} 
                        onChange={(e) => setPage(e.target.value)}
                        className="w-10 h-6 border border-slate-300 rounded text-center text-sm focus:outline-none focus:border-[#003366]" 
                    />
                    <span className="text-sm text-slate-500 ml-2">of {totalPages}</span>
                    <div className="w-[1px] h-6 bg-slate-300 mx-2"></div>
                    <button onClick={handleRotate} className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-slate-700">↻</button>
                    <div className="w-[1px] h-6 bg-slate-300 mx-2"></div>
                    <button className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-slate-700" title="Print">📖</button>
                    <button 
                        onClick={() => {
                            const { jsPDF } = window.jspdf;
                            const doc = new jsPDF();
                            doc.setTextColor(0, 51, 102);
                            doc.setFontSize(22);
                            doc.text("ACADEMIC REPORT", 14, 25);
                            doc.setFontSize(10);
                            doc.setTextColor(100);
                            doc.text("Pamantasan ng Lungsod ng Valenzuela", 14, 32);
                            doc.text(`Title: ${title}`, 14, 45);
                            doc.text(`Date: ${new Date().toLocaleDateString()}`, 14, 52);
                            doc.line(14, 55, 196, 55);
                            doc.autoTable({
                                head: [['Detail', 'Value', 'Status']],
                                body: [
                                    ['Department Compliance', '100.00%', 'VERIFIED'],
                                    ['Blockchain Sync', 'Real-time', 'ACTIVE'],
                                    ['Pending Revisions', '0 Records', 'NONE']
                                ],
                                startY: 60,
                                headStyles: { fillColor: [0, 51, 102] }
                            });
                            doc.save(`${title.replace(/\s+/g, '_')}.pdf`);
                        }}
                        className="w-8 h-8 flex items-center justify-center hover:bg-slate-200 rounded transition-colors text-slate-700" 
                        title="Download PDF"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M7.5 12L12 16.5m0 0L16.5 12M12 16.5V3" />
                        </svg>
                    </button>
                </div>

                {/* Right Section - Empty for now to match layout */}
                <div className="w-32"></div>
            </div>

            {/* Content Area */}
            <div className="flex-1 bg-[#E0E0E0] overflow-auto flex items-center justify-center p-8">
                <div 
                    className="bg-white shadow-2xl transition-all duration-300 origin-center"
                    style={{ 
                        transform: `scale(${zoom}) rotate(${rotation}deg)`,
                        width: '600px',
                        height: '800px',
                        display: 'flex',
                        flexDirection: 'column'
                    }}
                >
                    {/* Mock PDF Page Content */}
                    <div className="p-12 h-full flex flex-col">
                        <div className="border-b-2 border-[#003366] pb-4 mb-6 flex justify-between items-end">
                            <div>
                                <h2 className="text-[#003366] font-bold text-2xl">ACADEMIC REPORT</h2>
                                <p className="text-slate-500 text-sm">Pamantasan ng Lungsod ng Valenzuela</p>
                            </div>
                            <div className="text-right">
                                <p className="text-xs text-slate-400 font-mono uppercase tracking-widest">Secured via Ledger</p>
                                <p className="text-xs text-slate-500">Date: {new Date().toLocaleDateString()}</p>
                            </div>
                        </div>

                        <div className="flex-1 space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1">
                                    <p className="text-[10px] text-slate-400 font-bold uppercase">Report Title</p>
                                    <p className="text-sm font-semibold">{title}</p>
                                </div>
                                <div className="space-y-1 text-right">
                                    <p className="text-[10px] text-slate-400 font-bold uppercase">Reference ID</p>
                                    <p className="text-sm font-mono">BGO-REPORT-2026-X42</p>
                                </div>
                            </div>

                            <div className="mt-8">
                                <table className="w-full text-sm">
                                    <thead>
                                        <tr className="border-b border-slate-200 text-left">
                                            <th className="py-2">Detail</th>
                                            <th className="py-2">Value</th>
                                            <th className="py-2 text-right">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr className="border-b border-slate-100">
                                            <td className="py-3 font-medium">Department Compliance</td>
                                            <td className="py-3">100.00%</td>
                                            <td className="py-3 text-right text-emerald-600 font-bold">VERIFIED</td>
                                        </tr>
                                        <tr className="border-b border-slate-100">
                                            <td className="py-3 font-medium">Blockchain Sync</td>
                                            <td className="py-3">Real-time</td>
                                            <td className="py-3 text-right text-emerald-600 font-bold">ACTIVE</td>
                                        </tr>
                                        <tr className="border-b border-slate-100">
                                            <td className="py-3 font-medium">Pending Revisions</td>
                                            <td className="py-3">0 Records</td>
                                            <td className="py-3 text-right text-slate-400 font-bold">NONE</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>

                            <div className="mt-auto pt-8 border-t border-slate-100">
                                <p className="text-[10px] text-slate-400 text-center italic">
                                    This is a computer-generated document. No signature is required.
                                    The authenticity of this report can be verified on the PLV Blockchain network.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PdfReportViewer;