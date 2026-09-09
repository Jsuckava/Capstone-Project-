const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { Worker } = require('worker_threads');
const { authenticateJWT } = require('../shared/auth');
const { middlewareRoot } = require('../shared/config');
const createLogger = require('../shared/logger');
const { createServiceApp, installErrorHandler, listen } = require('../shared/service-app');

const serviceName = 'grade-upload-service';
const logger = createLogger(serviceName);
const { app } = createServiceApp(serviceName, logger);
const uploadDir = path.join(middlewareRoot, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

const garbageCollector = setInterval(async () => {
    try {
        const now = Date.now();
        for (const file of await fs.promises.readdir(uploadDir)) {
            if (file.startsWith('.')) continue;
            const fullPath = path.join(uploadDir, file);
            const stat = await fs.promises.stat(fullPath);
            if (now - stat.mtimeMs > 2 * 60 * 60 * 1000) await fs.promises.unlink(fullPath);
        }
    } catch (error) { logger.warn({ err: error }, 'Upload garbage collection failed'); }
}, 60 * 60 * 1000);
garbageCollector.unref();

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, callback) => callback(null, uploadDir),
        filename: (req, file, callback) => callback(null, `${Date.now()}-${path.basename(file.originalname)}`)
    }),
    limits: { fileSize: 15 * 1024 * 1024 },
    fileFilter: (req, file, callback) => {
        const valid = ['.csv', '.xlsx', '.xls'].includes(path.extname(file.originalname).toLowerCase());
        callback(valid ? null : new Error('INVALID_FILE_TYPE'), valid);
    }
}).single('excel');

function uploadMiddleware(req, res, next) {
    upload(req, res, (error) => {
        if (error instanceof multer.MulterError) return res.status(400).json({ error: `Upload error: ${error.message}.` });
        if (error?.message === 'INVALID_FILE_TYPE') return res.status(400).json({ error: 'Only Excel (.xlsx, .xls) and CSV (.csv) files are allowed.' });
        if (error) return next(error);
        next();
    });
}

app.post(['/api/batch-upload', '/api/upload-grades'], authenticateJWT(), uploadMiddleware, async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded. Expected form-data field "excel".' });
    const mapperPath = path.join(middlewareRoot, 'mapper.py');
    const workerPath = path.join(middlewareRoot, 'uploadWorker.js');
    if (!fs.existsSync(mapperPath)) return res.status(500).json({ error: 'Mapper script not found', expected: mapperPath });
    const facultyId = req.body.facultyId || req.body.username || req.user?.username || 'admin';
    const worker = new Worker(workerPath, {
        workerData: {
            mapperPath, filePath: req.file.path, facultyId,
            INTERNAL_API_KEY: process.env.INTERNAL_API_KEY,
            term: req.body.term || ''
        }
    });
    let settled = false;
    const respond = (status, payload) => {
        if (settled || res.headersSent) return;
        settled = true;
        res.status(status).json(payload);
    };
    worker.on('message', (message) => {
        if (message.status === 'success') respond(200, { status: 'success', message: 'Batch grades processed successfully', output: message.output });
        else respond(500, { status: 'error', ...message });
    });
    worker.on('error', (error) => respond(500, { status: 'error', error: `Worker process failed: ${error.message}` }));
    worker.on('exit', (code) => { if (code !== 0) respond(500, { status: 'error', error: `Worker stopped with exit code ${code}` }); });
});

app.get('/api/ready', (req, res) => {
    const mapper = fs.existsSync(path.join(middlewareRoot, 'mapper.py'));
    const worker = fs.existsSync(path.join(middlewareRoot, 'uploadWorker.js'));
    res.status(mapper && worker ? 200 : 503).json({ status: mapper && worker ? 'ready' : 'not_ready', mapper, worker });
});

installErrorHandler(app, logger);
listen(app, serviceName, 4004, logger, () => clearInterval(garbageCollector));
