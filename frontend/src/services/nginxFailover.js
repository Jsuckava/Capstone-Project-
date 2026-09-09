const HEALTH_PATH = '/nginx-health';
const DEFAULT_CHECK_INTERVAL_MS = 10000;
const DEFAULT_TIMEOUT_MS = 2500;
const FAILURES_BEFORE_FAILOVER = 2;
const SHIELD_PORTS = ['8080', '8090', '8100'];

const normalizeOrigin = (origin) => {
  if (!origin) return '';
  return origin.replace(/\/$/, '');
};

const unique = (items) => Array.from(new Set(items.filter(Boolean)));

const getConfiguredShieldOrigins = () => {
  const configured = process.env.REACT_APP_NGINX_SHIELDS || '';
  return configured
    .split(',')
    .map((origin) => normalizeOrigin(origin.trim()))
    .filter(Boolean);
};

export const getNginxShieldOrigins = () => {
  if (typeof window === 'undefined') return [];

  const { protocol, hostname, origin } = window.location;
  const sameHostOrigins = SHIELD_PORTS.map((port) => `${protocol}//${hostname}:${port}`);
  const localOrigins = SHIELD_PORTS.map((port) => `http://localhost:${port}`);

  return unique([
    normalizeOrigin(origin),
    ...getConfiguredShieldOrigins(),
    ...sameHostOrigins,
    ...localOrigins,
  ]);
};

const checkShieldHealth = async (origin, timeoutMs = DEFAULT_TIMEOUT_MS) => {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${origin}${HEALTH_PATH}?t=${Date.now()}`, {
      cache: 'no-store',
      signal: controller.signal,
    });
    return response.ok;
  } catch {
    return false;
  } finally {
    window.clearTimeout(timeout);
  }
};

export const findHealthyNginxShield = async (excludeOrigin = '') => {
  const currentOrigin = normalizeOrigin(excludeOrigin);
  const origins = getNginxShieldOrigins().filter((origin) => origin !== currentOrigin);

  for (const origin of origins) {
    if (await checkShieldHealth(origin)) {
      return origin;
    }
  }

  return null;
};

export const startNginxFailoverMonitor = ({
  onFailover,
  intervalMs = DEFAULT_CHECK_INTERVAL_MS,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) => {
  if (typeof window === 'undefined') {
    return () => {};
  }

  // A standalone localhost frontend has no middleware/Nginx health endpoint.
  // Do not let infrastructure authentication or failover block local portal access.
  if (process.env.NODE_ENV === 'development') {
    return () => {};
  }

  let stopped = false;
  let running = false;
  let failureCount = 0;
  const currentOrigin = normalizeOrigin(window.location.origin);

  const check = async () => {
    if (stopped || running) return;
    running = true;

    const isCurrentHealthy = await checkShieldHealth(currentOrigin, timeoutMs);
    if (isCurrentHealthy) {
      failureCount = 0;
      running = false;
      return;
    }

    failureCount += 1;
    if (failureCount < FAILURES_BEFORE_FAILOVER) {
      running = false;
      return;
    }

    const nextOrigin = await findHealthyNginxShield(currentOrigin);
    if (nextOrigin && !stopped) {
      stopped = true;
      onFailover?.(nextOrigin);
    }

    running = false;
  };

  const intervalId = window.setInterval(check, intervalMs);
  window.setTimeout(check, 1000);

  return () => {
    stopped = true;
    window.clearInterval(intervalId);
  };
};
