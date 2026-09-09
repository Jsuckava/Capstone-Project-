const { parentPort, workerData } = require('worker_threads');
const { spawn } = require('child_process');
const fs = require('fs');

const { mapperPath, filePath, facultyId, INTERNAL_API_KEY, term } = workerData;

const pythonProcess = spawn('python3', [
    mapperPath,
    filePath,
    facultyId,
    INTERNAL_API_KEY,
    term || ''
]);

let output = '';
let errorOutput = '';
let settled = false;

const cleanupFile = (done = () => {}) => {
    fs.unlink(filePath, (err) => {
        if (err && err.code !== 'ENOENT') console.error('File cleanup error:', err);
        done();
    });
};

pythonProcess.stdout.on('data', (data) => output += data.toString());
pythonProcess.stderr.on('data', (data) => errorOutput += data.toString());

const uploadTimeout = setTimeout(() => {
    if (settled) return;
    settled = true;
    pythonProcess.kill('SIGTERM');
    parentPort.postMessage({ status: 'error', error: 'Batch upload timeout' });
    cleanupFile(() => process.exit(1));
}, 5 * 60 * 1000);

pythonProcess.on('error', (err) => {
    if (settled) return;
    settled = true;
    clearTimeout(uploadTimeout);
    cleanupFile(() => parentPort.postMessage({ status: 'error', error: err.message }));
});

pythonProcess.on('close', (code) => {
    if (settled) return;
    settled = true;
    clearTimeout(uploadTimeout);

    if (code === 0) {
        cleanupFile(() => parentPort.postMessage({ status: 'success', output }));
    } else {
        cleanupFile(() => parentPort.postMessage({ status: 'error', error: 'Mapper process failed', exitCode: code, output, errorOutput }));
    }
});
