'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

/* =========================================================
   AZAD HEALTH
   Secure Patient + Doctor + Prescription API
   V1 Integrated Backend
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'medivoice-data');
const DB_FILE = path.join(DATA_DIR, 'database.json');

const APP_VERSION = '6.0.0';

const SESSION_DAYS = 7;
const MAX_BODY = 2 * 1024 * 1024;
const MAX_REPORT_TEXT = 200000;

const ADMIN_KEY = process.env.MEDIVOICE_ADMIN_KEY || '';

/* =========================================================
   DATABASE
========================================================= */

function emptyDatabase() {
    return {
        users: [],
        patients: [],
        doctors: [],
        prescriptions: [],
        medicines: [],
        medicineEvents: [],
        caregivers: [],
        healthRecords: [],
        reports: [],
        partners: [],
        partnerDoctors: [],
        partnerTests: [],
        partnerCommercials: [],
        partnerBookings: [],
        pharmacyReferrals: [],
        sessions: [],
        notifications: [],
        auditLogs: []
    };
}

function ensureDatabase() {
    fs.mkdirSync(DATA_DIR, { recursive: true });

    if (!fs.existsSync(DB_FILE)) {
        writeDatabase(emptyDatabase());
    }
}

function readDatabase() {
    ensureDatabase();

    try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        const db = JSON.parse(raw);

        const base = emptyDatabase();

        for (const key of Object.keys(base)) {
            if (!Array.isArray(db[key])) {
                db[key] = [];
            }
        }

        return db;
    } catch (error) {
        console.error('Database read error:', error);

        if (!fs.existsSync(DB_FILE)) {
            const db = emptyDatabase();
            writeDatabase(db);
            return db;
        }

        throw error;
    }
}

function writeDatabase(db) {
    fs.mkdirSync(DATA_DIR, { recursive: true });

    const temp = DB_FILE + '.tmp';

    fs.writeFileSync(
        temp,
        JSON.stringify(db, null, 2),
        'utf8'
    );

    fs.renameSync(temp, DB_FILE);
}

/* =========================================================
   SECURITY HELPERS
========================================================= */

function randomId(prefix = 'id') {
    return (
        prefix +
        '_' +
        crypto.randomBytes(12).toString('hex')
    );
}

function randomToken() {
    return crypto.randomBytes(48).toString('hex');
}

function hashSessionToken(token) {
    return crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
}

function now() {
    return new Date().toISOString();
}

function addDays(date, days) {
    const d = new Date(date);
    d.setDate(d.getDate() + days);
    return d.toISOString();
}

/* =========================================================
   PASSWORD
========================================================= */

const PBKDF2_ITERATIONS = 120000;
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');

    const hash = crypto
        .pbkdf2Sync(
            password,
            salt,
            PBKDF2_ITERATIONS,
            PBKDF2_KEYLEN,
            PBKDF2_DIGEST
        )
        .toString('hex');

    return {
        salt,
        hash
    };
}

function verifyPassword(password, storedHash, salt) {
    const hash = crypto
        .pbkdf2Sync(
            password,
            salt,
            PBKDF2_ITERATIONS,
            PBKDF2_KEYLEN,
            PBKDF2_DIGEST
        )
        .toString('hex');

    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(storedHash, 'hex');

    if (a.length !== b.length) {
        return false;
    }

    return crypto.timingSafeEqual(a, b);
}

/* =========================================================
   VALIDATION
========================================================= */

function cleanString(value, max = 500) {
    if (typeof value !== 'string') {
        return '';
    }

    return value
        .trim()
        .replace(/\0/g, '')
        .slice(0, max);
}

function validPhone(phone) {
    return /^[0-9+\-\s()]{6,25}$/.test(phone);
}

function validPassword(password) {
    return (
        typeof password === 'string' &&
        password.length >= 8 &&
        password.length <= 200
    );
}

function validRole(role) {
    return role === 'patient' || role === 'doctor';
}

/* =========================================================
   RATE LIMIT
========================================================= */

const rateMap = new Map();

function rateLimit(key, limit = 30, windowMs = 60 * 1000) {
    const current = Date.now();

    const item = rateMap.get(key);

    if (!item || current - item.start > windowMs) {
        rateMap.set(key, {
            start: current,
            count: 1
        });

        return true;
    }

    item.count++;

    return item.count <= limit;
}

/* =========================================================
   AUDIT
========================================================= */

function audit(db, action, userId, details = {}) {
    db.auditLogs.push({
        id: randomId('audit'),
        action,
        userId: userId || null,
        details,
        createdAt: now()
    });

    if (db.auditLogs.length > 5000) {
        db.auditLogs.splice(
            0,
            db.auditLogs.length - 5000
        );
    }
}

/* =========================================================
   HTTP RESPONSE
========================================================= */

function securityHeaders() {
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy':
            'camera=(self), microphone=(self), geolocation=()',
        'Content-Security-Policy':
            "default-src 'self' https://cdn.jsdelivr.net; " +
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: blob:; " +
            "connect-src 'self';"
    };
}

function send(res, status, data, extraHeaders = {}) {
    const body =
        typeof data === 'string'
            ? data
            : JSON.stringify(data);

    const headers = {
        ...securityHeaders(),
        'Content-Type':
            typeof data === 'string'
                ? 'text/plain; charset=utf-8'
                : 'application/json; charset=utf-8',
        'Content-Length':
            Buffer.byteLength(body),
        ...extraHeaders
    };

    res.writeHead(status, headers);
    res.end(body);
}

function ok(res, data = {}) {
    send(res, 200, {
        success: true,
        ...data
    });
}

function created(res, data = {}) {
    send(res, 201, {
        success: true,
        ...data
    });
}

function fail(res, status, message) {
    send(res, status, {
        success: false,
        error: message
    });
}

/* =========================================================
   CORS
   Same-origin deployment does not require *
========================================================= */

function applyCors(req, res) {
    const origin = req.headers.origin;

    if (!origin) {
        return;
    }

    const allowed = (
        process.env.ALLOWED_ORIGINS || ''
    )
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);

    if (allowed.includes(origin)) {
        res.setHeader(
            'Access-Control-Allow-Origin',
            origin
        );

        res.setHeader(
            'Vary',
            'Origin'
        );

        res.setHeader(
            'Access-Control-Allow-Headers',
            'Content-Type, Authorization, X-Admin-Key'
        );

        res.setHeader(
            'Access-Control-Allow-Methods',
            'GET,POST,PUT,PATCH,DELETE,OPTIONS'
        );
    }
}

/* =========================================================
   REQUEST BODY
========================================================= */

function readBody(req) {
    return new Promise((resolve, reject) => {
        let size = 0;
        const chunks = [];

        req.on('data', chunk => {
            size += chunk.length;

            if (size > MAX_BODY) {
                reject(
                    new Error('REQUEST_TOO_LARGE')
                );

                req.destroy();
                return;
            }

            chunks.push(chunk);
        });

        req.on('end', () => {
            try {
                const raw = Buffer
                    .concat(chunks)
                    .toString('utf8');

                if (!raw) {
                    resolve({});
                    return;
                }

                resolve(JSON.parse(raw));
            } catch (error) {
                reject(
                    new Error('INVALID_JSON')
                );
            }
        });

        req.on('error', reject);
    });
}

/* =========================================================
   AUTH
========================================================= */

function getBearerToken(req) {
    const auth =
        req.headers.authorization || '';

    if (!auth.startsWith('Bearer ')) {
        return null;
    }

    return auth.slice(7).trim();
}

function safeUser(user) {
    if (!user) {
        return null;
    }

    return {
        id: user.id,
        role: user.role,
        name: user.name,
        phone: user.phone,
        status: user.status,
        createdAt: user.createdAt
    };
}

function authenticate(req, db) {
    const token = getBearerToken(req);

    if (!token) {
        return null;
    }

    const tokenHash =
        hashSessionToken(token);

    const sessionIndex =
        db.sessions.findIndex(
            session =>
                session.tokenHash === tokenHash
        );

    if (sessionIndex === -1) {
        return null;
    }

    const session =
        db.sessions[sessionIndex];

    if (
        new Date(session.expiresAt).getTime() <
        Date.now()
    ) {
        db.sessions.splice(sessionIndex, 1);
        writeDatabase(db);
        return null;
    }

    const user =
        db.users.find(
            u => u.id === session.userId
        );

    if (!user) {
        return null;
    }

    return {
        user,
        session
    };
}

function createSession(db, user) {
    const rawToken = randomToken();

    db.sessions.push({
        id: randomId('session'),
        userId: user.id,
        tokenHash: hashSessionToken(rawToken),
        createdAt: now(),
        expiresAt: addDays(
            new Date(),
            SESSION_DAYS
        )
    });

    return rawToken;
}

/* =========================================================
   AUTHORIZATION
========================================================= */

function requireAuth(req, res, db) {
    const auth = authenticate(req, db);

    if (!auth) {
        fail(
            res,
            401,
            'Authentication required.'
        );

        return null;
    }

    return auth;
}

function requireRole(req, res, db, role) {
    const auth =
        requireAuth(req, res, db);

    if (!auth) {
        return null;
    }

    if (auth.user.role !== role) {
        fail(
            res,
            403,
            'Access denied.'
        );

        return null;
    }

    return auth;
}

/* =========================================================
   PATIENT HELPERS
========================================================= */

function patientForUser(db, userId) {
    return db.patients.find(
        p => p.userId === userId
    );
}

function doctorForUser(db, userId) {
    return db.doctors.find(
        d => d.userId === userId
    );
}

/* =========================================================
   STATIC FILE
========================================================= */

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

function safeStaticPath(urlPath) {
    let pathname = decodeURIComponent(urlPath);

    if (
        pathname === '/' ||
        pathname === '/medivoice/' ||
        pathname === '/index.html'
    ) {
        pathname = '/index.html';
    }

    if (
        pathname.startsWith('/api/') ||
        pathname === '/api'
    ) {
        return null;
    }

    const relative =
        pathname.replace(/^\/+/, '');

    const absolute =
        path.resolve(ROOT, relative);

    const relativeCheck =
        path.relative(ROOT, absolute);

    if (
        relativeCheck.startsWith('..') ||
        path.isAbsolute(relativeCheck)
    ) {
        return null;
    }

    return absolute;
}

function serveStatic(req, res, pathname) {
    const filePath =
        safeStaticPath(pathname);

    if (!filePath) {
        fail(res, 404, 'Not found.');
        return;
    }

    fs.stat(filePath, (error, stat) => {
        if (error || !stat.isFile()) {
            fail(res, 404, 'File not found.');
            return;
        }

        const ext =
            path.extname(filePath)
                .toLowerCase();

        const contentType =
            MIME[ext] ||
            'application/octet-stream';

        res.writeHead(200, {
            ...securityHeaders(),
            'Content-Type': contentType
        });

        fs.createReadStream(filePath)
            .pipe(res);
    });
}

/* =========================================================
   API ROUTER
========================================================= */

async function handleApi(req, res, url, db) {

    const pathname = url.pathname;

    /* -----------------------------------------
       HEALTH
    ----------------------------------------- */

    if (
        req.method === 'GET' &&
        (
            pathname === '/api/health' ||
            pathname === '/medivoice/api/health'
        )
    ) {
        return ok(res, {
            service: 'AZAD Health',
            version: APP_VERSION,
            status: 'online',
            time: now()
        });
    }

    if (
        req.method === 'GET' &&
        pathname === '/api/status'
    ) {
        return ok(res, {
            service: 'AZAD Health',
            status: 'online'
        });
    }

    if (
        req.method === 'GET' &&
        pathname === '/api/version'
    ) {
        return ok(res, {
            version: APP_VERSION
        });
    }

    /* -----------------------------------------
       PUBLIC PARTNERS
    ----------------------------------------- */

    if (
        req.method === 'GET' &&
        pathname === '/api/partners'
    ) {
        return ok(res, {
            partners: db.partners
        });
    }

    /* -----------------------------------------
       REGISTER
    ----------------------------------------- */

    if (
        req.method === 'POST' &&
        pathname === '/api/auth/register'
    ) {

        const ip =
            req.socket.remoteAddress || 'unknown';

        if (
            !rateLimit(
                'register:' + ip,
                5,
                15 * 60 * 1000
            )
        ) {
            return fail(
                res,
                429,
                'Too many registration attempts.'
            );
        }

        const body =
            await readBody(req);

        const name =
            cleanString(body.name, 100);

        const phone =
            cleanString(body.phone, 30);

        const password =
            body.password;

        const role =
            cleanString(body.role, 20);

        if (!name) {
            return fail(
                res,
                400,
                'Name is required.'
            );
        }

        if (!validPhone(phone)) {
            return fail(
                res,
                400,
                'Valid phone number is required.'
            );
        }

        if (!validPassword(password)) {
            return fail(
                res,
                400,
                'Password must contain at least 8 characters.'
            );
        }

        if (!validRole(role)) {
            return fail(
                res,
                400,
                'Role must be patient or doctor.'
            );
        }

        const existing =
            db.users.find(
                u => u.phone === phone
            );

        if (existing) {
            return fail(
                res,
                409,
                'This phone number is already registered.'
            );
        }

        const passwordData =
            hashPassword(password);

        const user = {
            id: randomId('user'),
            name,
            phone,
            role,
            passwordHash: passwordData.hash,
            passwordSalt: passwordData.salt,
            status:
                role === 'doctor'
                    ? 'pending_verification'
                    : 'active',
            createdAt: now()
        };

        db.users.push(user);

        if (role === 'patient') {

            db.patients.push({
                id: randomId('patient'),
                userId: user.id,
                name,
                phone,
                createdAt: now()
            });

        } else {

            db.doctors.push({
                id: randomId('doctor'),
                userId: user.id,
                name,
                phone,
                verificationStatus:
                    'pending',
                createdAt: now()
            });

        }

        const token =
            createSession(db, user);

        audit(
            db,
            'USER_REGISTER',
            user.id,
            { role }
        );

        writeDatabase(db);

        return created(res, {
            token,
            user: safeUser(user)
        });
    }

    /* -----------------------------------------
       LOGIN
    ----------------------------------------- */

    if (
        req.method === 'POST' &&
        pathname === '/api/auth/login'
    ) {

        const ip =
            req.socket.remoteAddress || 'unknown';

        if (
            !rateLimit(
                'login:' + ip,
                10,
                15 * 60 * 1000
            )
        ) {
            return fail(
                res,
                429,
                'Too many login attempts. Try again later.'
            );
        }

        const body =
            await readBody(req);

        const phone =
            cleanString(body.phone, 30);

        const password =
            body.password;

        if (!phone || !password) {
            return fail(
                res,
                400,
                'Phone and password are required.'
            );
        }

        const user =
            db.users.find(
                u => u.phone === phone
            );

        if (
            !user ||
            !verifyPassword(
                password,
                user.passwordHash,
                user.passwordSalt
            )
        ) {
            return fail(
                res,
                401,
                'Invalid login credentials.'
            );
        }

        if (user.status === 'suspended') {
            return fail(
                res,
                403,
                'Account suspended.'
            );
        }

        const token =
            createSession(db, user);

        audit(
            db,
            'USER_LOGIN',
            user.id
        );

        writeDatabase(db);

        return ok(res, {
            token,
            user: safeUser(user)
        });
    }

    /* -----------------------------------------
       LOGOUT
    ----------------------------------------- */

    if (
        req.method === 'POST' &&
        pathname === '/api/auth/logout'
    ) {

        const auth =
            authenticate(req, db);

        if (auth) {

            db.sessions =
                db.sessions.filter(
                    s =>
                        s.id !==
                        auth.session.id
                );

            audit(
                db,
                'USER_LOGOUT',
                auth.user.id
            );

            writeDatabase(db);
        }

        return ok(res);
    }

    /* -----------------------------------------
       ME
    ----------------------------------------- */

    if (
        req.method === 'GET' &&
        pathname === '/api/me'
    ) {

        const auth =
            requireAuth(req, res, db);

        if (!auth) return;

        return ok(res, {
            user: safeUser(auth.user)
        });
    }

    /* -----------------------------------------
       PATIENT PROFILE
    ----------------------------------------- */

    if (
        pathname === '/api/patient/profile'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        if (!patient) {
            return fail(
                res,
                404,
                'Patient profile not found.'
            );
        }

        if (req.method === 'GET') {
            return ok(res, {
                profile: patient
            });
        }

        if (
            req.method === 'PUT' ||
            req.method === 'PATCH'
        ) {

            const body =
                await readBody(req);

            const name =
                cleanString(
                    body.name,
                    100
                );

            if (name) {
                patient.name = name;
                auth.user.name = name;
            }

            if (body.dateOfBirth !== undefined) {
                patient.dateOfBirth =
                    cleanString(
                        body.dateOfBirth,
                        30
                    );
            }

            if (body.gender !== undefined) {
                patient.gender =
                    cleanString(
                        body.gender,
                        30
                    );
            }

            if (body.bloodGroup !== undefined) {
                patient.bloodGroup =
                    cleanString(
                        body.bloodGroup,
                        20
                    );
            }

            if (body.address !== undefined) {
                patient.address =
                    cleanString(
                        body.address,
                        300
                    );
            }

            patient.updatedAt = now();

            audit(
                db,
                'PATIENT_PROFILE_UPDATE',
                auth.user.id
            );

            writeDatabase(db);

            return ok(res, {
                profile: patient
            });
        }
    }

    /* -----------------------------------------
       PATIENT MEDICINES
    ----------------------------------------- */

    if (
        pathname === '/api/patient/medicines'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        if (!patient) {
            return fail(
                res,
                404,
                'Patient not found.'
            );
        }

        if (req.method === 'GET') {

            const medicines =
                db.medicines.filter(
                    m =>
                        m.patientId ===
                        patient.id &&
                        !m.deleted
                );

            return ok(res, {
                medicines
            });
        }

        if (req.method === 'POST') {

            const body =
                await readBody(req);

            const name =
                cleanString(
                    body.name,
                    150
                );

            const dose =
                cleanString(
                    body.dose,
                    100
                );

            const time =
                cleanString(
                    body.time,
                    20
                );

            const foodRule =
                cleanString(
                    body.foodRule,
                    100
                );

            const startDate =
                cleanString(
                    body.startDate,
                    30
                );

            const endDate =
                cleanString(
                    body.endDate,
                    30
                );

            if (!name || !time) {
                return fail(
                    res,
                    400,
                    'Medicine name and time are required.'
                );
            }

            const medicine = {
                id: randomId('med'),
                patientId: patient.id,
                name,
                dose,
                time,
                foodRule,
                startDate,
                endDate,
                active: true,
                createdAt: now()
            };

            db.medicines.push(medicine);

            audit(
                db,
                'MEDICINE_CREATE',
                auth.user.id,
                {
                    medicineId:
                        medicine.id
                }
            );

            writeDatabase(db);

            return created(res, {
                medicine
            });
        }
    }

    /* -----------------------------------------
       MEDICINE ACTION
    ----------------------------------------- */

    const medicineAction =
        pathname.match(
            /^\/api\/patient\/medicines\/([^/]+)\/(taken|missed)$/
        );

    if (medicineAction) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const medicineId =
            medicineAction[1];

        const action =
            medicineAction[2];

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        const medicine =
            db.medicines.find(
                m =>
                    m.id === medicineId &&
                    m.patientId === patient.id &&
                    !m.deleted
            );

        if (!medicine) {
            return fail(
                res,
                404,
                'Medicine not found.'
            );
        }

        if (req.method !== 'POST') {
            return fail(
                res,
                405,
                'Method not allowed.'
            );
        }

        const event = {
            id: randomId('mevent'),
            medicineId,
            patientId: patient.id,
            action,
            createdAt: now()
        };

        db.medicineEvents.push(event);

        audit(
            db,
            'MEDICINE_' + action.toUpperCase(),
            auth.user.id,
            {
                medicineId
            }
        );

        writeDatabase(db);

        return created(res, {
            event
        });
    }

    /* -----------------------------------------
       DELETE MEDICINE
    ----------------------------------------- */

    const medicineDelete =
        pathname.match(
            /^\/api\/patient\/medicines\/([^/]+)$/
        );

    if (
        medicineDelete &&
        req.method === 'DELETE'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        const medicine =
            db.medicines.find(
                m =>
                    m.id ===
                        medicineDelete[1] &&
                    m.patientId ===
                        patient.id
            );

        if (!medicine) {
            return fail(
                res,
                404,
                'Medicine not found.'
            );
        }

        medicine.deleted = true;
        medicine.active = false;
        medicine.deletedAt = now();

        audit(
            db,
            'MEDICINE_DELETE',
            auth.user.id,
            {
                medicineId:
                    medicine.id
            }
        );

        writeDatabase(db);

        return ok(res);
    }

    /* -----------------------------------------
       MEDICINE EVENTS
    ----------------------------------------- */

    if (
        req.method === 'GET' &&
        pathname ===
            '/api/patient/medicine-events'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        const events =
            db.medicineEvents
                .filter(
                    e =>
                        e.patientId ===
                        patient.id
                )
                .sort(
                    (a, b) =>
                        new Date(b.createdAt) -
                        new Date(a.createdAt)
                );

        return ok(res, {
            events
        });
    }

    /* -----------------------------------------
       HEALTH RECORDS
    ----------------------------------------- */

    if (
        pathname ===
        '/api/patient/health'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        if (req.method === 'GET') {

            const records =
                db.healthRecords
                    .filter(
                        r =>
                            r.patientId ===
                            patient.id
                    )
                    .sort(
                        (a, b) =>
                            new Date(b.createdAt) -
                            new Date(a.createdAt)
                    );

            return ok(res, {
                records
            });
        }

        if (req.method === 'POST') {

            const body =
                await readBody(req);

            const type =
                cleanString(
                    body.type,
                    50
                );

            const value =
                cleanString(
                    body.value,
                    200
                );

            const unit =
                cleanString(
                    body.unit,
                    50
                );

            const notes =
                cleanString(
                    body.notes,
                    500
                );

            if (!type || !value) {
                return fail(
                    res,
                    400,
                    'Health record type and value are required.'
                );
            }

            const record = {
                id: randomId('health'),
                patientId: patient.id,
                type,
                value,
                unit,
                notes,
                createdAt: now()
            };

            db.healthRecords.push(record);

            audit(
                db,
                'HEALTH_RECORD_CREATE',
                auth.user.id,
                {
                    type
                }
            );

            writeDatabase(db);

            return created(res, {
                record
            });
        }
    }

    /* -----------------------------------------
       PRESCRIPTIONS - PATIENT
    ----------------------------------------- */

    if (
        req.method === 'GET' &&
        pathname ===
            '/api/patient/prescriptions'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        const prescriptions =
            db.prescriptions
                .filter(
                    p =>
                        p.patientId ===
                        patient.id
                )
                .sort(
                    (a, b) =>
                        new Date(b.createdAt) -
                        new Date(a.createdAt)
                );

        return ok(res, {
            prescriptions
        });
    }

    /* -----------------------------------------
       REPORTS
    ----------------------------------------- */

    if (
        pathname ===
        '/api/patient/reports'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        if (req.method === 'GET') {

            const reports =
                db.reports
                    .filter(
                        r =>
                            r.patientId ===
                            patient.id
                    )
                    .sort(
                        (a, b) =>
                            new Date(b.createdAt) -
                            new Date(a.createdAt)
                    );

            return ok(res, {
                reports
            });
        }

        if (req.method === 'POST') {

            const body =
                await readBody(req);

            const text =
                cleanString(
                    body.text,
                    MAX_REPORT_TEXT
                );

            if (!text) {
                return fail(
                    res,
                    400,
                    'Report text is required.'
                );
            }

            const report = {
                id: randomId('report'),
                patientId: patient.id,
                type:
                    cleanString(
                        body.type,
                        50
                    ) ||
                    'medical_report',
                text,
                createdAt: now()
            };

            db.reports.push(report);

            audit(
                db,
                'REPORT_CREATE',
                auth.user.id,
                {
                    reportId:
                        report.id
                }
            );

            writeDatabase(db);

            return created(res, {
                report
            });
        }
    }

    /* -----------------------------------------
       NOTIFICATIONS
    ----------------------------------------- */

    if (
        pathname ===
        '/api/notifications'
    ) {

        const auth =
            requireAuth(
                req,
                res,
                db
            );

        if (!auth) return;

        if (req.method === 'GET') {

            const notifications =
                db.notifications
                    .filter(
                        n =>
                            n.userId ===
                            auth.user.id
                    )
                    .sort(
                        (a, b) =>
                            new Date(b.createdAt) -
                            new Date(a.createdAt)
                    );

            return ok(res, {
                notifications
            });
        }

        if (req.method === 'POST') {

            const body =
                await readBody(req);

            const notificationId =
                cleanString(
                    body.id,
                    100
                );

            const notification =
                db.notifications.find(
                    n =>
                        n.id ===
                        notificationId &&
                        n.userId ===
                        auth.user.id
                );

            if (!notification) {
                return fail(
                    res,
                    404,
                    'Notification not found.'
                );
            }

            notification.read = true;
            notification.readAt = now();

            writeDatabase(db);

            return ok(res);
        }
    }

    /* -----------------------------------------
       CAREGIVERS
    ----------------------------------------- */

    if (
        pathname ===
        '/api/caregivers'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        if (req.method === 'GET') {

            return ok(res, {
                caregivers:
                    db.caregivers.filter(
                        c =>
                            c.patientId ===
                            patient.id
                    )
            });
        }

        if (req.method === 'POST') {

            const body =
                await readBody(req);

            const name =
                cleanString(
                    body.name,
                    100
                );

            const phone =
                cleanString(
                    body.phone,
                    30
                );

            const relation =
                cleanString(
                    body.relation,
                    50
                );

            if (!name || !phone) {
                return fail(
                    res,
                    400,
                    'Caregiver name and phone are required.'
                );
            }

            const caregiver = {
                id: randomId('caregiver'),
                patientId: patient.id,
                name,
                phone,
                relation,
                createdAt: now()
            };

            db.caregivers.push(caregiver);

            writeDatabase(db);

            return created(res, {
                caregiver
            });
        }
    }

    /* -----------------------------------------
       DOCTOR CREATE PRESCRIPTION
    ----------------------------------------- */

    if (
        req.method === 'POST' &&
        pathname === '/api/prescriptions'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'doctor'
            );

        if (!auth) return;

        if (
            auth.user.status !==
            'active'
        ) {
            return fail(
                res,
                403,
                'Doctor verification is required.'
            );
        }

        const doctor =
            doctorForUser(
                db,
                auth.user.id
            );

        const body =
            await readBody(req);

        const patientId =
            cleanString(
                body.patientId,
                100
            );

        const diagnosis =
            cleanString(
                body.diagnosis,
                1000
            );

        const notes =
            cleanString(
                body.notes,
                3000
            );

        if (!patientId) {
            return fail(
                res,
                400,
                'Patient ID is required.'
            );
        }

        const patient =
            db.patients.find(
                p =>
                    p.id ===
                    patientId
            );

        if (!patient) {
            return fail(
                res,
                404,
                'Patient not found.'
            );
        }

        const medicines =
            Array.isArray(body.medicines)
                ? body.medicines
                    .slice(0, 30)
                    .map(m => ({
                        name:
                            cleanString(
                                m.name,
                                150
                            ),
                        dose:
                            cleanString(
                                m.dose,
                                100
                            ),
                        time:
                            cleanString(
                                m.time,
                                20
                            ),
                        foodRule:
                            cleanString(
                                m.foodRule,
                                100
                            ),
                        startDate:
                            cleanString(
                                m.startDate,
                                30
                            ),
                        endDate:
                            cleanString(
                                m.endDate,
                                30
                            )
                    }))
                    .filter(
                        m => m.name
                    )
                : [];

        const prescription = {
            id: randomId('rx'),
            patientId,
            doctorId: doctor.id,
            diagnosis,
            notes,
            medicines,
            createdAt: now()
        };

        db.prescriptions.push(
            prescription
        );

        for (const medicine of medicines) {

            db.medicines.push({
                id: randomId('med'),
                patientId,
                prescriptionId:
                    prescription.id,
                prescribedBy:
                    doctor.id,
                ...medicine,
                active: true,
                createdAt: now()
            });
        }

        db.notifications.push({
            id: randomId('notification'),
            userId:
                patient.userId,
            type: 'prescription',
            title:
                'নতুন Prescription',
            message:
                'আপনার জন্য নতুন prescription দেওয়া হয়েছে।',
            referenceId:
                prescription.id,
            read: false,
            createdAt: now()
        });

        audit(
            db,
            'PRESCRIPTION_CREATE',
            auth.user.id,
            {
                prescriptionId:
                    prescription.id,
                patientId
            }
        );

        writeDatabase(db);

        return created(res, {
            prescription
        });
    }

    /* -----------------------------------------
       DOCTOR PATIENTS
       Prototype relationship filtering:
       only patients explicitly assigned to doctor
       in future partner/consent module.
    ----------------------------------------- */

    if (
        req.method === 'GET' &&
        pathname === '/api/doctor/patients'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'doctor'
            );

        if (!auth) return;

        if (
            auth.user.status !==
            'active'
        ) {
            return fail(
                res,
                403,
                'Doctor verification is required.'
            );
        }

        /*
          Do NOT expose the entire patient database
          here. Only return patients who already have
          a prescription relationship with this doctor.
        */

        const doctor =
            doctorForUser(
                db,
                auth.user.id
            );

        const patientIds =
            new Set(
                db.prescriptions
                    .filter(
                        p =>
                            p.doctorId ===
                            doctor.id
                    )
                    .map(
                        p =>
                            p.patientId
                    )
            );

        const patients =
            db.patients
                .filter(
                    p =>
                        patientIds.has(
                            p.id
                        )
                )
                .map(p => ({
                    id: p.id,
                    name: p.name,
                    phone: p.phone
                }));

        return ok(res, {
            patients
        });
    }

    /* -----------------------------------------
       DOCTOR PRESCRIPTIONS
    ----------------------------------------- */

    if (
        req.method === 'GET' &&
        pathname ===
            '/api/doctor/prescriptions'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'doctor'
            );

        if (!auth) return;

        const doctor =
            doctorForUser(
                db,
                auth.user.id
            );

        const prescriptions =
            db.prescriptions
                .filter(
                    p =>
                        p.doctorId ===
                        doctor.id
                )
                .sort(
                    (a, b) =>
                        new Date(b.createdAt) -
                        new Date(a.createdAt)
                );

        return ok(res, {
            prescriptions
        });
    }

    /* -----------------------------------------
       DOCTOR VERIFY
       Admin key is now REQUIRED.
    ----------------------------------------- */

    if (
        req.method === 'POST' &&
        pathname === '/api/doctor/verify'
    ) {

        if (!ADMIN_KEY) {
            return fail(
                res,
                503,
                'Doctor verification is not configured.'
            );
        }

        const suppliedKey =
            req.headers['x-admin-key'];

        if (
            !suppliedKey ||
            suppliedKey !== ADMIN_KEY
        ) {
            return fail(
                res,
                403,
                'Admin authorization required.'
            );
        }

        const body =
            await readBody(req);

        const doctorUserId =
            cleanString(
                body.userId,
                100
            );

        const user =
            db.users.find(
                u =>
                    u.id ===
                    doctorUserId &&
                    u.role === 'doctor'
            );

        if (!user) {
            return fail(
                res,
                404,
                'Doctor not found.'
            );
        }

        user.status = 'active';

        const doctor =
            doctorForUser(
                db,
                user.id
            );

        if (doctor) {
            doctor.verificationStatus =
                'verified';

            doctor.verifiedAt =
                now();
        }

        audit(
            db,
            'DOCTOR_VERIFY',
            user.id
        );

        writeDatabase(db);

        return ok(res, {
            user: safeUser(user)
        });
    }

    /* -----------------------------------------
       PHARMACY REFERRALS
    ----------------------------------------- */

    if (
        pathname ===
        '/api/pharmacy/referrals'
    ) {

        const auth =
            requireRole(
                req,
                res,
                db,
                'patient'
            );

        if (!auth) return;

        const patient =
            patientForUser(
                db,
                auth.user.id
            );

        if (req.method === 'GET') {

            return ok(res, {
                referrals:
                    db.pharmacyReferrals
                        .filter(
                            r =>
                                r.patientId ===
                                patient.id
                        )
            });
        }

        if (req.method === 'POST') {

            const body =
                await readBody(req);

            const partnerId =
                cleanString(
                    body.partnerId,
                    100
                );

            const prescriptionId =
                cleanString(
                    body.prescriptionId,
                    100
                );

            const referral = {
                id: randomId('ref'),
                patientId: patient.id,
                partnerId,
                prescriptionId,
                status: 'created',
                createdAt: now()
            };

            db.pharmacyReferrals.push(
                referral
            );

            writeDatabase(db);

            return created(res, {
                referral
            });
        }
    }

    /* -----------------------------------------
       UNKNOWN API
    ----------------------------------------- */

    return fail(
        res,
        404,
        'API endpoint not found.'
    );
}

/* =========================================================
   SERVER
========================================================= */

ensureDatabase();

const server =
    http.createServer(
        async (req, res) => {

            applyCors(req, res);

            if (
                req.method === 'OPTIONS'
            ) {
                res.writeHead(204, {
                    ...securityHeaders(),
                    'Access-Control-Allow-Headers':
                        'Content-Type, Authorization, X-Admin-Key',
                    'Access-Control-Allow-Methods':
                        'GET,POST,PUT,PATCH,DELETE,OPTIONS'
                });

                res.end();
                return;
            }

            const url =
                new URL(
                    req.url,
                    `http://${req.headers.host || 'localhost'}`
                );

            const pathname =
                url.pathname;

            const db =
                readDatabase();

            try {

                if (
                    pathname.startsWith('/api/') ||
                    pathname === '/api'
                ) {

                    await handleApi(
                        req,
                        res,
                        url,
                        db
                    );

                    return;
                }

                serveStatic(
                    req,
                    res,
                    pathname
                );

            } catch (error) {

                console.error(
                    'SERVER ERROR:',
                    error
                );

                if (
                    error.message ===
                    'REQUEST_TOO_LARGE'
                ) {
                    return fail(
                        res,
                        413,
                        'Request too large.'
                    );
                }

                if (
                    error.message ===
                    'INVALID_JSON'
                ) {
                    return fail(
                        res,
                        400,
                        'Invalid JSON body.'
                    );
                }

                return fail(
                    res,
                    500,
                    'Internal server error.'
                );
            }
        }
    );

server.listen(
    PORT,
    HOST,
    () => {
        console.log('');
        console.log(
            '======================================'
        );
        console.log(
            '        AZAD HEALTH BACKEND'
        );
        console.log(
            '======================================'
        );
        console.log(
            `Version : ${APP_VERSION}`
        );
        console.log(
            `Server  : http://localhost:${PORT}`
        );
        console.log(
            `Data    : ${DB_FILE}`
        );
        console.log(
            '======================================'
        );
        console.log('');
    }
);
