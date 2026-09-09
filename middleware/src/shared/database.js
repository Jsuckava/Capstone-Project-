const { Pool } = require('pg');
const { parsePositiveInt } = require('./config');

let pools;

function createPool(max) {
    let mainIp = process.env.MAIN_CAMPUS_IP;
    if (mainIp === 'host-gateway') mainIp = '127.0.0.1';
    const configuredHost = process.env.POSTGRES_HOST || mainIp || '127.0.0.1';
    return new Pool({
        user: process.env.POSTGRES_USER || 'postgres',
        host: configuredHost === 'postgres' ? (mainIp || '127.0.0.1') : configuredHost,
        database: process.env.POSTGRES_DB || 'ActivityLogs',
        password: process.env.POSTGRES_PASS || 'password',
        port: parsePositiveInt(process.env.POSTGRES_PORT, 5432),
        max,
        idleTimeoutMillis: 30000
    });
}

function getPools() {
    if (!pools) {
        const max = parsePositiveInt(process.env.POSTGRES_POOL_MAX, 5);
        pools = { read: createPool(max), write: createPool(max) };
    }
    return pools;
}

async function closePools() {
    if (!pools) return;
    await Promise.allSettled([pools.read.end(), pools.write.end()]);
    pools = undefined;
}

module.exports = { closePools, getPools };
