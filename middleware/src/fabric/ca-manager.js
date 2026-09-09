const fs = require('fs');
const path = require('path');
const { isContainerized, middlewareRoot } = require('../shared/config');
const { normalizeAuthRole } = require('../shared/roles');
const { getWallet } = require('./wallet-manager');

const cache = new Map();
let FabricCAServices;

function caConstructor() {
    if (!FabricCAServices) FabricCAServices = require('fabric-ca-client');
    return FabricCAServices;
}

function existingFiles(candidates) {
    return [...new Set(candidates.filter(Boolean).map((candidate) => path.resolve(middlewareRoot, candidate)).filter(fs.existsSync))];
}

function getCAConfig(role) {
    const normalized = normalizeAuthRole(role) || 'registrar';
    if (cache.has(normalized)) return cache.get(normalized);
    let config;
    if (normalized === 'faculty') {
        config = {
            url: process.env.FABRIC_CA_FACULTY_URL || (isContainerized() ? 'https://ca-faculty.plv-annex-campus.svc.cluster.local:7054' : 'https://localhost:8054'),
            name: 'ca-faculty', adminLabel: 'admin-faculty', mspId: 'FacultyMSP',
            certs: existingFiles([process.env.FABRIC_CA_FACULTY_CERT, process.env.FABRIC_CA_FACULTY_TLS_CERT, '../network/fabric-ca/faculty/ca-cert.pem', '../network/fabric-ca/faculty/tls-cert.pem'])
        };
    } else if (normalized === 'department_admin') {
        config = {
            url: process.env.FABRIC_CA_DEPARTMENT_URL || (isContainerized() ? 'https://ca-department.plv-pubad-campus.svc.cluster.local:7054' : 'https://localhost:9054'),
            name: 'ca-department', adminLabel: 'admin-department', mspId: 'DepartmentMSP',
            certs: existingFiles([process.env.FABRIC_CA_DEPARTMENT_CERT, process.env.FABRIC_CA_DEPARTMENT_TLS_CERT, '../network/fabric-ca/department/ca-cert.pem', '../network/fabric-ca/department/tls-cert.pem'])
        };
    } else {
        config = {
            url: process.env.FABRIC_CA_REGISTRAR_URL || (isContainerized() ? 'https://ca-registrar.plv-main-campus.svc.cluster.local:7054' : 'https://localhost:7054'),
            name: 'ca-registrar', adminLabel: 'admin-registrar', mspId: 'RegistrarMSP',
            certs: existingFiles([process.env.FABRIC_CA_REGISTRAR_CERT, process.env.FABRIC_CA_REGISTRAR_TLS_CERT, '../network/fabric-ca/registrar/ca-cert.pem', '../network/fabric-ca/registrar/tls-cert.pem'])
        };
    }
    const trustedRoots = config.certs.map((file) => fs.readFileSync(file, 'utf8'));
    const insecure = String(process.env.FABRIC_CA_INSECURE_TLS || 'false').toLowerCase() === 'true';
    if (!trustedRoots.length && !insecure) throw new Error(`No Fabric CA TLS trust root was found for ${normalized}.`);
    config.tlsOptions = { trustedRoots, verify: !insecure };
    const FabricCA = caConstructor();
    config.client = new FabricCA(config.url, config.tlsOptions, config.name);
    config.role = normalized;
    cache.set(normalized, config);
    return config;
}

async function ensureAdminEnrolled(role) {
    const config = getCAConfig(role);
    const wallet = await getWallet(config.role);
    if (await wallet.get(config.adminLabel)) return config;
    const enrollment = await config.client.enroll({
        enrollmentID: 'admin',
        enrollmentSecret: process.env.BOOTSTRAP_REGISTRAR_PASS || 'adminpw'
    });
    await wallet.put(config.adminLabel, {
        credentials: { certificate: enrollment.certificate, privateKey: enrollment.key.toBytes() },
        mspId: config.mspId,
        type: 'X.509'
    });
    return config;
}

function registrationPayload(username, password, role) {
    const normalized = normalizeAuthRole(role);
    return {
        enrollmentID: username,
        enrollmentSecret: password,
        role: ['registrar', 'department_admin'].includes(normalized) ? 'admin' : 'client',
        attrs: [
            { name: 'role', value: normalized, ecert: true },
            { name: 'grade.manage', value: normalized === 'faculty' ? 'true' : 'false', ecert: true }
        ]
    };
}

async function adminUser(config, wallet) {
    const identity = await wallet.get(config.adminLabel);
    if (!identity) throw new Error(`Fabric admin '${config.adminLabel}' is not enrolled.`);
    return wallet.getProviderRegistry().getProvider(identity.type).getUserContext(identity, 'admin');
}

async function registerIdentity(username, password, role) {
    const config = await ensureAdminEnrolled(role);
    const wallet = await getWallet(config.role);
    const user = await adminUser(config, wallet);
    try {
        return await config.client.register(registrationPayload(username, password, role), user);
    } catch (error) {
        if (String(error).toLowerCase().includes('already registered')) return password;
        if (String(error).includes('code: 20') || String(error).includes('Authentication failure')) {
            await wallet.remove(config.adminLabel);
            const refreshed = await ensureAdminEnrolled(role);
            return refreshed.client.register(registrationPayload(username, password, role), await adminUser(refreshed, wallet));
        }
        throw error;
    }
}

async function enrollIdentity(username, password, role) {
    const config = getCAConfig(role);
    const wallet = await getWallet(config.role);
    const enrollment = await config.client.enroll({
        enrollmentID: username, enrollmentSecret: password,
        attr_reqs: [{ name: 'role', optional: true }, { name: 'grade.manage', optional: true }]
    });
    await wallet.put(username, {
        credentials: { certificate: enrollment.certificate, privateKey: enrollment.key.toBytes() },
        mspId: config.mspId, type: 'X.509'
    });
    return { wallet, identity: await wallet.get(username), config };
}

function cacheStats() {
    return { entries: cache.size };
}

module.exports = { adminUser, cacheStats, enrollIdentity, ensureAdminEnrolled, getCAConfig, registerIdentity, registrationPayload };
