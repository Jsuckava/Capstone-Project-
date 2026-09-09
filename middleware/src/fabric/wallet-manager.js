const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { isContainerized, middlewareRoot } = require('../shared/config');
const { normalizeAuthRole } = require('../shared/roles');

const scryptAsync = util.promisify(crypto.scrypt);
const walletCache = new Map();
let Wallets;

const retryableCouchDbCodes = new Set([
    'ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'ESOCKETTIMEDOUT',
    'EAI_AGAIN', 'ENETDOWN', 'ENETUNREACH', 'EHOSTDOWN', 'EHOSTUNREACH'
]);

function fabricWallets() {
    if (!Wallets) ({ Wallets } = require('fabric-network'));
    return Wallets;
}

function walletLocation(role) {
    const normalized = normalizeAuthRole(role);
    const user = process.env.COUCHDB_USER || 'PLVADMIN';
    const pass = process.env.COUCHDB_PASS || 'PLVSYSTEM2026';
    const host = isContainerized() ? 'host.docker.internal' : '127.0.0.1';
    const withCredentials = (configured, fallbackPort) => {
        const url = new URL(configured || `http://${host}:${fallbackPort}`);
        if (!url.username) url.username = user;
        if (!url.password) url.password = pass;
        return url.toString().replace(/\/$/, '');
    };
    if (normalized === 'faculty') return { suffix: 'faculty', url: withCredentials(process.env.COUCHDB_WALLET_FACULTY_URL, 6990) };
    if (normalized === 'department_admin') return { suffix: 'department', url: withCredentials(process.env.COUCHDB_WALLET_DEPARTMENT_URL, 7990) };
    return { suffix: 'registrar', url: withCredentials(process.env.COUCHDB_WALLET_REGISTRAR_URL || process.env.COUCHDB_WALLET_URL, 5990) };
}

async function encryptPrivateKey(privateKey, password) {
    const salt = crypto.randomBytes(16);
    const key = await scryptAsync(password, salt, 32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(privateKey, 'utf8'), cipher.final()]);
    return `ENC:${salt.toString('hex')}:${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted.toString('hex')}`;
}

async function decryptPrivateKey(value, password) {
    if (!value?.startsWith('ENC:')) return value;
    const parts = value.split(':');
    let key;
    let iv;
    let tag;
    let encrypted;
    if (parts.length === 5) {
        key = await scryptAsync(password, Buffer.from(parts[1], 'hex'), 32);
        [, , iv, tag, encrypted] = parts;
    } else if (parts.length === 4) {
        key = await scryptAsync(password, 'salt', 32);
        [, iv, tag, encrypted] = parts;
    } else {
        throw new Error('Invalid encrypted private key format.');
    }
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
}

function isRetryableCouchDbError(error) {
    const code = String(error?.code || error?.cause?.code || '').toUpperCase();
    const status = Number(error?.statusCode || error?.status || error?.response?.status || 0);
    const message = String(error?.message || '').toLowerCase();
    return retryableCouchDbCodes.has(code)
        || [408, 429, 500, 502, 503, 504].includes(status)
        || /socket hang up|connection (?:closed|reset|refused)|network error|timed?\s*out/.test(message);
}

async function createRawWallet(role) {
    const location = walletLocation(role);
    return location.url
        ? fabricWallets().newCouchDBWallet(location.url, `fabric_wallet_${location.suffix}`)
        : fabricWallets().newFileSystemWallet(path.join(middlewareRoot, 'wallet'));
}

async function refreshWallet(state) {
    if (!state.refreshing) {
        state.refreshing = createRawWallet(state.role)
            .then((wallet) => {
                state.current = wallet;
                return wallet;
            })
            .finally(() => { state.refreshing = null; });
    }
    return state.refreshing;
}

function resilientWallet(role, initialWallet) {
    const state = { role, current: initialWallet, refreshing: null };
    const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;

    const invoke = async (method, args, transformResult) => {
        try {
            const result = await state.current[method](...args);
            return transformResult ? await transformResult(result) : result;
        } catch (error) {
            if (!isRetryableCouchDbError(error)) throw error;
            const refreshed = await refreshWallet(state);
            const result = await refreshed[method](...args);
            return transformResult ? await transformResult(result) : result;
        }
    };

    return {
        get: (label) => invoke('get', [label], async (stored) => {
            if (!stored || !encryptionKey) return stored;
            const copy = structuredClone(stored);
            if (copy?.credentials?.privateKey) copy.credentials.privateKey = await decryptPrivateKey(copy.credentials.privateKey, encryptionKey);
            return copy;
        }),
        put: async (label, identity) => {
            let value = identity;
            if (encryptionKey && identity?.credentials?.privateKey && !identity.credentials.privateKey.startsWith('ENC:')) {
                value = structuredClone(identity);
                value.credentials.privateKey = await encryptPrivateKey(value.credentials.privateKey, encryptionKey);
            }
            return invoke('put', [label, value]);
        },
        remove: (label) => invoke('remove', [label]),
        list: () => invoke('list', []),
        getProviderRegistry: () => state.current.getProviderRegistry()
    };
}

async function getWallet(role = 'registrar') {
    const normalized = normalizeAuthRole(role) || 'registrar';
    if (walletCache.has(normalized)) return walletCache.get(normalized);
    const wallet = resilientWallet(normalized, await createRawWallet(normalized));
    walletCache.set(normalized, wallet);
    return wallet;
}

async function checkWallets() {
    const results = {};
    for (const role of ['registrar', 'faculty', 'department_admin']) {
        const identities = await (await getWallet(role)).list();
        results[role] = { status: 'reachable', identities: identities.length };
    }
    return results;
}

async function findIdentity(username, roleHint) {
    const roles = roleHint ? [normalizeAuthRole(roleHint)] : ['registrar', 'faculty', 'department_admin'];
    for (const role of roles) {
        const wallet = await getWallet(role);
        const identity = await wallet.get(username);
        if (identity) return { identity, role, wallet };
    }
    return null;
}

module.exports = { checkWallets, findIdentity, getWallet, isRetryableCouchDbError };
