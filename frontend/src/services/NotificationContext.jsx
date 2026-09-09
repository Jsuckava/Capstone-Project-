import React, { createContext, useState, useCallback, useContext } from 'react';

const NotificationContext = createContext({
    addNotification: (message, type) => console.warn("NotificationProvider missing! Message:", message)
});

export const useNotification = () => useContext(NotificationContext);

const Notification = ({ message, type, onDismiss }) => {
    const baseClasses = "max-w-sm rounded-lg p-4 shadow-lg cursor-pointer transition-transform transform";
    const typeClasses = {
        success: "bg-green-100 border border-green-400 text-green-800",
        error: "bg-red-100 border border-red-400 text-red-800",
        notice: "bg-blue-50 border-2 border-[#003366] text-[#003366] font-semibold",
    };

    return (
        <div className={`${baseClasses} ${typeClasses[type] || typeClasses.success}`} onClick={onDismiss}>
            {message}
        </div>
    );
};

export const NotificationProvider = ({ children }) => {
    const [notifications, setNotifications] = useState([]);

    const addNotification = useCallback((message, type = 'success') => {
        const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
        setNotifications((prev) => [...prev, { id, message, type }].slice(-4));
        setTimeout(() => {
            setNotifications((prev) => prev.filter((notification) => notification.id !== id));
        }, type === 'notice' ? 10000 : 5000);
    }, []);

    const dismissNotification = (id) => {
        setNotifications((prev) => prev.filter((notification) => notification.id !== id));
    };

    return (
        <NotificationContext.Provider value={{ addNotification }}>
            {children}
            {notifications.length > 0 && (
                <div className="fixed top-5 right-5 z-[2000] flex max-w-sm flex-col gap-3">
                    {notifications.map((notification) => (
                        <Notification
                            key={notification.id}
                            message={notification.message}
                            type={notification.type}
                            onDismiss={() => dismissNotification(notification.id)}
                        />
                    ))}
                </div>
            )}
        </NotificationContext.Provider>
    );
};
