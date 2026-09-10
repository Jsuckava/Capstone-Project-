const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const excluded = new Set(['node_modules', 'uploads', '.git']);

function javascriptFiles(directory) {
    return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
        if (excluded.has(entry.name)) return [];
        const target = path.join(directory, entry.name);
        if (entry.isDirectory()) return javascriptFiles(target);
        return entry.isFile() && entry.name.endsWith('.js') ? [target] : [];
    });
}

let failed = false;
for (const file of javascriptFiles(root)) {
    const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
    if (result.status !== 0) {
        failed = true;
        process.stderr.write(result.stderr || result.stdout || `Syntax check failed: ${file}\n`);
    }
}

if (failed) process.exit(1);
console.log('Middleware JavaScript syntax checks passed.');
