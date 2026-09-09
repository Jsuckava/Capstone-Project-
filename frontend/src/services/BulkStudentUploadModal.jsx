import React, { useState } from 'react';
import Modal from '../shared/Modal';
import { batchUploadStudents } from '../../services/api';

const BulkStudentUploadModal = ({ isOpen, onClose, onUploadComplete, userDepartment }) => {
    const [file, setFile] = useState(null);
    const [isUploading, setIsUploading] = useState(false);
    const [uploadResult, setUploadResult] = useState(null);
    const [error, setError] = useState('');

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
        setError('');
        setUploadResult(null);
    };

    const handleUpload = async () => {
        if (!file) {
            setError('Please select a file to upload.');
            return;
        }

        setIsUploading(true);
        setError('');
        setUploadResult(null);

        try {
            const result = await batchUploadStudents(file, userDepartment);
            setUploadResult(result);
            if (onUploadComplete) onUploadComplete();
        } catch (err) {
            setError(err.message || 'An unknown error occurred during upload.');
        } finally {
            setIsUploading(false);
        }
    };

    const handleClose = () => {
        setFile(null);
        setIsUploading(false);
        setUploadResult(null);
        setError('');
        onClose();
    };

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title="Bulk Enroll Students">
            <div className="flex flex-col gap-4">
                <p className="text-sm text-slate-600">
                    Upload a <strong>.xlsx</strong> or <strong>.csv</strong> file with student data. The system will automatically create accounts, set default passwords from birthdays, and enroll them.
                </p>
                
                <div>
                    <label htmlFor="file-upload" className="block text-sm font-medium text-slate-700 mb-1">Student Data File</label>
                    <input id="file-upload" type="file" accept=".csv, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, application/vnd.ms-excel" onChange={handleFileChange} className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-[#003366] file:text-white hover:file:bg-[#00264d]" />
                </div>

                {error && <p className="text-sm text-red-600">{error}</p>}

                {uploadResult && (
                    <div className={`p-4 rounded-lg ${uploadResult.failed > 0 ? 'bg-yellow-50 border-yellow-300' : 'bg-green-50 border-green-300'} border`}>
                        <h4 className="font-bold text-lg">{uploadResult.status}</h4>
                        <p>Successfully enrolled: {uploadResult.successful}</p>
                        <p>Failed: {uploadResult.failed}</p>
                        {uploadResult.errors?.length > 0 && (
                            <div className="mt-2">
                                <h5 className="font-semibold">Error Details:</h5>
                                <ul className="list-disc list-inside text-sm max-h-40 overflow-y-auto">
                                    {uploadResult.errors.map((err, i) => <li key={i}><strong>{err.identifier}:</strong> {err.reason}</li>)}
                                </ul>
                            </div>
                        )}
                    </div>
                )}

                <div className="flex justify-end gap-3 mt-4">
                    <button onClick={handleClose} className="rounded-full bg-slate-200 px-5 py-2 text-sm font-bold text-slate-800 transition hover:bg-slate-300">Close</button>
                    <button onClick={handleUpload} disabled={!file || isUploading} className="rounded-full bg-[#003366] px-5 py-2 text-sm font-bold text-white transition hover:bg-[#00264d] disabled:cursor-not-allowed disabled:opacity-50">{isUploading ? 'Uploading...' : 'Upload & Enroll'}</button>
                </div>
            </div>
        </Modal>
    );
};

export default BulkStudentUploadModal;