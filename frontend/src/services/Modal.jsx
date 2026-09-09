import React from 'react';

const Modal = ({ isOpen, onClose, title, children }) => {
    if (!isOpen) return null;

    return (
        <div 
            className="fixed inset-0 z-[1001] flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm"
            onClick={onClose}
        >
            <div 
                className="relative w-full max-w-lg rounded-xl bg-white p-6 shadow-2xl"
                onClick={e => e.stopPropagation()}
            >
                <div className="flex items-center justify-between border-b border-slate-200 pb-4 mb-4">
                    <h3 className="text-xl font-bold text-[#003366]">{title}</h3>
                    <button 
                        onClick={onClose} 
                        className="text-3xl leading-none text-slate-400 transition hover:text-slate-600"
                    >
                        &times;
                    </button>
                </div>
                <div>{children}</div>
            </div>
        </div>
    );
};

export default Modal;