module.exports = function createLogger(service) {
    const write = (level) => (details, message) => {
        const text = typeof details === 'string' ? details : (message || '');
        const metadata = typeof details === 'string' ? undefined : details;
        const output = metadata ? [`[${service}] ${text}`, metadata] : [`[${service}] ${text}`];
        (console[level] || console.log)(...output);
    };
    return { debug: write('debug'), info: write('info'), warn: write('warn'), error: write('error'), fatal: write('error') };
};
