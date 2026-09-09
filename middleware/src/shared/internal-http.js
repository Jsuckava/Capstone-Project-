async function requestJson(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 10000);
    try {
        const response = await fetch(url, {
            method: options.method || 'GET',
            headers: {
                accept: 'application/json',
                ...(options.body === undefined ? {} : { 'content-type': 'application/json' }),
                ...(options.headers || {})
            },
            body: options.body === undefined ? undefined : JSON.stringify(options.body),
            signal: controller.signal
        });
        const text = await response.text();
        let data;
        try { data = text ? JSON.parse(text) : {}; } catch { data = { message: text }; }
        if (!response.ok) {
            const error = new Error(data.error || data.message || `Request failed with status ${response.status}.`);
            error.status = response.status;
            error.response = data;
            throw error;
        }
        return data;
    } finally {
        clearTimeout(timeout);
    }
}

module.exports = { requestJson };
