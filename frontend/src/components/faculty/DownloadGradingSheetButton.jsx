import { downloadGradingSheet } from '../../services/api';
import React, { useState } from 'react';
import { downloadTemplateButtonClass } from '../shared/downloadButtonStyles';

const DownloadGradingSheetButton = ({ department, section }) => {
    const [isDownloading, setIsDownloading] = useState(false);

    const handleDownload = async () => {
        setIsDownloading(true);
        try {
            // This leverages api.js to correctly route to port 5000 and attach the JWT
            await downloadGradingSheet(department, section);
        } catch (error) {
            alert(`Download Error: ${error.message}`);
        } finally {
            setIsDownloading(false);
        }
    };

    return (
        <button 
            className={downloadTemplateButtonClass}
            onClick={handleDownload}
            disabled={isDownloading}
        >
            {isDownloading ? 'Downloading...' : 'Download Grading Sheet'}
        </button>
    );
};

export default DownloadGradingSheetButton;
