const { Wallets } = require('fabric-network');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../network/.env'), override: true });

async function pruneWallet(role, port) {
    const user = process.env.COUCHDB_USER || 'PLVADMIN';
    const pass = process.env.COUCHDB_PASS || 'PLVSYSTEM2026';
    const host = '127.0.0.1';
    const couchUrl = `http://${user}:${pass}@${host}:${port}`;
    const walletName = `fabric_wallet_${role}`;

    console.log(`Connecting to CouchDB wallet at ${couchUrl} [${walletName}]...`);
    try {
        const wallet = await Wallets.newCouchDBWallet(couchUrl, walletName);
        const identities = await wallet.list();
        
        if (identities.length === 0) {
            console.log(`  No identities found in ${walletName}.\n`);
            return;
        }

        console.log(`  Found ${identities.length} identities in ${walletName}. Pruning...`);
        for (const label of identities) {
            await wallet.remove(label);
            console.log(`  - Removed: ${label}`);
        }
        console.log(`  Successfully pruned ${walletName}.\n`);
    } catch (error) {
        console.error(`  Failed to prune ${walletName}: ${error.message}\n`);
    }
}

async function main() {
    console.log('--- PRUNING ALL COUCHDB WALLETS ---\n');
    await pruneWallet('registrar', 5990);
    await pruneWallet('faculty', 6990);
    await pruneWallet('department', 7990);
    console.log('--- WALLET PRUNING COMPLETE ---');
}

main();
