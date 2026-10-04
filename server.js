'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const APP_NAME = 'Medivoice';
const APP_VERSION = '4.1.0';

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const DATA_DIR = path.join(__dirname, 'medivoice-data');
const DB_FILE = path.join(DATA_DIR, 'database.json');
const BACKUP_FILE = path.join(DATA_DIR, 'database.backup.json');

const SESSION_DAYS = 7;
const ADMIN_KEY = process.env.MEDIVOICE_ADMIN_KEY || '';

const MAX_BODY = 2 * 1024 * 1024;

/* =========================================================
   DATABASE
========================================================= */

function baseDb() {
    return {
        users: [],
        patientProfiles: [],
        doctorProfiles: [],
        prescriptions: [],
        medicines: [],
        medicineEvents: [],
        caregiverContacts: [],
        notifications: [],
        healthRecords: [],
        auditLogs: []
    };
}

function ensureDb() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(
            DB_FILE,
            JSON.stringify(baseDb(), null, 2),
            'utf8'
        );
    }
}

function loadDb() {
    ensureDb();

    try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');

        const db = JSON.parse(raw || '{}');
        const base = baseDb();

        for (const key of Object.keys(base)) {
            if (!Array.isArray(db[key])) {
                db[key] = [];
            }
        }

        return db;
    } catch (error) {
        console.error('Database read error:', error);

        return baseDb();
    }
}

function saveDb(db) {
    ensureDb();

    try {
        if (fs.existsSync(DB_FILE)) {
            fs.copyFileSync(DB_FILE, BACKUP_FILE);
        }

        const tempFile = DB_FILE + '.tmp';

        fs.writeFileSync(
            tempFile,
            JSON.stringify(db, null, 2),
            'utf8'
        );

        fs.renameSync(tempFile, DB_FILE);
    } catch (error) {
        console.error('Database save error:', error);
        throw error;
    }
}

/* =========================================================
   HELPERS
========================================================= */

function now() {
    return new Date().toISOString();
}

function makeId(prefix) {
    return (
        prefix +
        '_' +
        crypto.randomBytes(12).toString('hex')
    );
}

function cleanString(value, max = 500) {
    if (
        value === undefined ||
        value === null
    ) {
        return '';
    }

    return String(value)
        .trim()
        .slice(0, max);
}

function normalizeEmail(value) {
    return cleanString(value, 200)
        .toLowerCase();
}

function validEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function numberValue(value) {
    if (
        value === undefined ||
        value === null ||
        value === ''
    ) {
        return null;
    }

    const number = Number(value);

    return Number.isFinite(number)
        ? number
        : null;
}

/* =========================================================
   PASSWORD
========================================================= */

function hashPassword(password) {
    const salt =
        crypto.randomBytes(16).toString('hex');

    const hash =
        crypto.pbkdf2Sync(
            String(password),
            salt,
            120000,
            64,
            'sha512'
        ).toString('hex');

    return {
        salt,
        hash
    };
}

function verifyPassword(
    password,
    salt,
    storedHash
) {
    try {
        const hash =
            crypto.pbkdf2Sync(
                String(password),
                salt,
                120000,
                64,
                'sha512'
            );

        return crypto.timingSafeEqual(
            hash,
            Buffer.from(
                storedHash,
                'hex'
            )
        );
    } catch {
        return false;
    }
}

/* =========================================================
   RESPONSE
========================================================= */

function setHeaders(response) {
    response.setHeader(
        'Access-Control-Allow-Origin',
        '*'
    );

    response.setHeader(
        'Access-Control-Allow-Methods',
        'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    );

    response.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-Admin-Key'
    );

    response.setHeader(
        'Content-Type',
        'application/json; charset=utf-8'
    );
}

function send(
    response,
    statusCode,
    payload
) {
    setHeaders(response);

    response.writeHead(statusCode);

    response.end(
        JSON.stringify(payload)
    );
}

function success(
    response,
    statusCode,
    data = {}
) {
    send(
        response,
        statusCode,
        {
            success: true,
            ...data
        }
    );
}

function failure(
    response,
    statusCode,
    error
) {
    send(
        response,
        statusCode,
        {
            success: false,
            error
        }
    );
}

/* =========================================================
   BODY
========================================================= */

function readBody(request) {
    return new Promise(
        (resolve, reject) => {
            let body = '';

            request.on(
                'data',
                chunk => {
                    body +=
                        chunk.toString();

                    if (
                        body.length >
                        MAX_BODY
                    ) {
                        reject(
                            new Error(
                                'Request body too large.'
                            )
                        );

                        request.destroy();
                    }
                }
            );

            request.on(
                'end',
                () => {
                    if (!body.trim()) {
                        resolve({});
                        return;
                    }

                    try {
                        resolve(
                            JSON.parse(body)
                        );
                    } catch {
                        reject(
                            new Error(
                                'Invalid JSON body.'
                            )
                        );
                    }
                }
            );

            request.on(
                'error',
                reject
            );
        }
    );
}

/* =========================================================
   SAFE USER
========================================================= */

function safeUser(user) {
    if (!user) {
        return null;
    }

    return {
        id: user.id,
        role: user.role,
        name: user.name,
        email: user.email,
        phone: user.phone || '',
        verificationStatus:
            user.verificationStatus ||
            null,
        createdAt: user.createdAt
    };
}

/* =========================================================
   SESSIONS
========================================================= */

const sessions = new Map();

function getToken(request) {
    const authorization =
        request.headers.authorization || '';

    if (
        authorization.startsWith(
            'Bearer '
        )
    ) {
        return authorization
            .slice(7)
            .trim();
    }

    return '';
}

function getCurrentUser(
    request,
    db
) {
    const token =
        getToken(request);

    if (!token) {
        return null;
    }

    const session =
        sessions.get(token);

    if (!session) {
        return null;
    }

    if (
        session.expiresAt <
        Date.now()
    ) {
        sessions.delete(token);
        return null;
    }

    return (
        db.users.find(
            user =>
                user.id ===
                session.userId
        ) || null
    );
}

function requireLogin(
    request,
    response,
    db
) {
    const user =
        getCurrentUser(
            request,
            db
        );

    if (!user) {
        failure(
            response,
            401,
            'Login required.'
        );

        return null;
    }

    return user;
}

function requireRole(
    response,
    user,
    role
) {
    if (!user) {
        failure(
            response,
            401,
            'Login required.'
        );

        return false;
    }

    if (user.role !== role) {
        failure(
            response,
            403,
            'Access denied.'
        );

        return false;
    }

    return true;
}

function requireVerifiedDoctor(
    response,
    user
) {
    if (
        !requireRole(
            response,
            user,
            'doctor'
        )
    ) {
        return false;
    }

    if (
        user.verificationStatus !==
        'verified'
    ) {
        failure(
            response,
            403,
            'Doctor account is not verified.'
        );

        return false;
    }

    return true;
}

/* =========================================================
   AUDIT
========================================================= */

function audit(
    db,
    userId,
    action,
    details = {}
) {
    db.auditLogs.push({
        id: makeId('audit'),
        userId: userId || null,
        action,
        details,
        createdAt: now()
    });

    if (
        db.auditLogs.length >
        5000
    ) {
        db.auditLogs =
            db.auditLogs.slice(
                -5000
            );
    }
}

/* =========================================================
   NOTIFICATION
========================================================= */

function addNotification(
    db,
    userId,
    type,
    title,
    message,
    meta = {}
) {
    db.notifications.push({
        id: makeId('note'),
        userId,
        type,
        title,
        message,
        meta,
        read: false,
        createdAt: now()
    });
}

/* =========================================================
   MEDICINE OBJECT
========================================================= */

function createMedicine(
    patientId,
    body,
    extra = {}
) {
    let times = [];

    if (
        Array.isArray(
            body.times
        )
    ) {
        times =
            body.times
                .map(
                    value =>
                        cleanString(
                            value,
                            20
                        )
                )
                .filter(Boolean);
    } else if (
        cleanString(
            body.time,
            20
        )
    ) {
        times = [
            cleanString(
                body.time,
                20
            )
        ];
    }

    return {
        id: makeId('medicine'),

        patientId,

        name:
            cleanString(
                body.name,
                200
            ),

        genericName:
            cleanString(
                body.genericName,
                200
            ),

        dosage:
            cleanString(
                body.dosage ||
                    body.dose,
                200
            ),

        frequency:
            cleanString(
                body.frequency,
                200
            ),

        times,

        mealTiming:
            cleanString(
                body.mealTiming ||
                    body.meal,
                50
            ),

        startDate:
            cleanString(
                body.startDate,
                30
            ),

        endDate:
            cleanString(
                body.endDate,
                30
            ),

        duration:
            cleanString(
                body.duration,
                100
            ),

        instructions:
            cleanString(
                body.instructions ||
                    body.notes,
                1000
            ),

        prescriptionId:
            extra.prescriptionId ||
            cleanString(
                body.prescriptionId,
                200
            ),

        doctorId:
            extra.doctorId ||
            cleanString(
                body.doctorId,
                200
            ),

        doctorApproved:
            extra.doctorApproved === true ||
            body.doctorApproved === true,

        active:
            body.active !== false,

        reminderEnabled:
            body.reminderEnabled !== false,

        createdAt: now(),

        updatedAt: now()
    };
}

/* =========================================================
   MEDICINE EVENT
========================================================= */

function medicineEvent(
    db,
    user,
    medicine,
    status,
    note = ''
) {
    const event = {
        id: makeId('medevent'),

        medicineId:
            medicine.id,

        patientId:
            user.id,

        status,

        note:
            cleanString(
                note,
                500
            ),

        takenAt: now()
    };

    db.medicineEvents.push(
        event
    );

    if (
        status === 'taken'
    ) {
        addNotification(
            db,
            user.id,
            'medicine_taken',
            'Medicine recorded',
            `${medicine.name} marked as taken.`,
            {
                medicineId:
                    medicine.id
            }
        );
    }

    return event;
}

/* =========================================================
   CAREGIVER NOTIFICATION
========================================================= */

function notifyCaregivers(
    db,
    patientId,
    title,
    message,
    meta = {}
) {
    const caregivers =
        db.caregiverContacts.filter(
            caregiver =>
                caregiver.patientId ===
                    patientId &&
                caregiver.active !== false
        );

    for (
        const caregiver of caregivers
    ) {
        addNotification(
            db,
            caregiver.userId ||
                null,
            'caregiver',
            title,
            message,
            {
                ...meta,
                caregiverId:
                    caregiver.id,
                contact:
                    caregiver.contact
            }
        );
    }
}

/* =========================================================
   PATH NORMALIZATION
========================================================= */

function normalizePathname(
    pathname
) {
    if (
        pathname ===
            '/medivoice' ||
        pathname ===
            '/medivoice/'
    ) {
        return '/';
    }

    if (
        pathname.startsWith(
            '/medivoice/'
        )
    ) {
        pathname =
            pathname.slice(
                '/medivoice'.length
            );
    }

    if (
        !pathname.startsWith('/')
    ) {
        pathname =
            '/' + pathname;
    }

    return pathname;
}

/* =========================================================
   ROUTER
========================================================= */

async function router(
    request,
    response
) {
    setHeaders(response);

    if (
        request.method ===
        'OPTIONS'
    ) {
        response.writeHead(204);
        response.end();
        return;
    }

    try {
        const parsed =
            new URL(
                request.url,
                `http://${request.headers.host || 'localhost'}`
            );

        const method =
            request.method;

        const pathname =
            normalizePathname(
                parsed.pathname
            );

        const query =
            parsed.searchParams;

        const db =
            loadDb();

        /* =================================================
           PUBLIC STATUS
        ================================================= */

        if (
            method === 'GET' &&
            (
                pathname === '/' ||
                pathname ===
                    '/api/status' ||
                pathname ===
                    '/api/version' ||
                pathname ===
                    '/api/health'
            )
        ) {
            success(
                response,
                200,
                {
                    app:
                        APP_NAME,

                    backend:
                        'online',

                    version:
                        APP_VERSION,

                    time:
                        now(),

                    message:
                        'MediVoice backend is running.'
                }
            );

            return;
        }

        /* =================================================
           REGISTER
        ================================================= */

        if (
            method === 'POST' &&
            pathname ===
                '/api/register'
        ) {
            const body =
                await readBody(
                    request
                );

            const name =
                cleanString(
                    body.name,
                    120
                );

            const email =
                normalizeEmail(
                    body.email
                );

            const password =
                String(
                    body.password ||
                        ''
                );

            const role =
                cleanString(
                    body.role ||
                        'patient',
                    30
                ).toLowerCase();

            if (
                !name ||
                !validEmail(email) ||
                password.length < 6 ||
                ![
                    'patient',
                    'doctor'
                ].includes(role)
            ) {
                failure(
                    response,
                    400,
                    'Valid name, email, password and role are required.'
                );

                return;
            }

            if (
                db.users.some(
                    user =>
                        user.email ===
                        email
                )
            ) {
                failure(
                    response,
                    409,
                    'Email already registered.'
                );

                return;
            }

            const passwordData =
                hashPassword(
                    password
                );

            const user = {
                id:
                    makeId('user'),

                name,

                email,

                phone:
                    cleanString(
                        body.phone,
                        50
                    ),

                role,

                passwordHash:
                    passwordData.hash,

                passwordSalt:
                    passwordData.salt,

                verificationStatus:
                    role === 'doctor'
                        ? 'pending'
                        : 'not_required',

                createdAt:
                    now(),

                updatedAt:
                    now()
            };

            db.users.push(
                user
            );

            if (
                role === 'patient'
            ) {
                db.patientProfiles.push({
                    id:
                        makeId(
                            'profile'
                        ),

                    userId:
                        user.id,

                    name,

                    email,

                    phone:
                        user.phone,

                    dateOfBirth:
                        cleanString(
                            body.dateOfBirth,
                            30
                        ),

                    gender:
                        cleanString(
                            body.gender,
                            30
                        ),

                    bloodGroup:
                        cleanString(
                            body.bloodGroup,
                            20
                        ),

                    address:
                        cleanString(
                            body.address,
                            500
                        ),

                    emergencyContact:
                        cleanString(
                            body.emergencyContact,
                            100
                        ),

                    nid:
                        cleanString(
                            body.nid,
                            100
                        ),

                    createdAt:
                        now(),

                    updatedAt:
                        now()
                });
            }

            if (
                role === 'doctor'
            ) {
                db.doctorProfiles.push({
                    id:
                        makeId(
                            'profile'
                        ),

                    userId:
                        user.id,

                    name,

                    email,

                    phone:
                        user.phone,

                    specialization:
                        cleanString(
                            body.specialization,
                            120
                        ),

                    licenseNumber:
                        cleanString(
                            body.licenseNumber,
                            120
                        ),

                    chamber:
                        cleanString(
                            body.chamber,
                            300
                        ),

                    qualification:
                        cleanString(
                            body.qualification,
                            300
                        ),

                    createdAt:
                        now(),

                    updatedAt:
                        now()
                });
            }

            audit(
                db,
                user.id,
                'REGISTER',
                {
                    role
                }
            );

            saveDb(db);

            success(
                response,
                201,
                {
                    user:
                        safeUser(
                            user
                        ),

                    message:
                        role ===
                        'doctor'
                            ? 'Doctor registered. Verification is pending.'
                            : 'Registration successful.'
                }
            );

            return;
        }

        /* =================================================
           LOGIN
        ================================================= */

        if (
            method === 'POST' &&
            pathname ===
                '/api/login'
        ) {
            const body =
                await readBody(
                    request
                );

            const email =
                normalizeEmail(
                    body.email
                );

            const password =
                String(
                    body.password ||
                        ''
                );

            const user =
                db.users.find(
                    item =>
                        item.email ===
                        email
                );

            if (
                !user ||
                !verifyPassword(
                    password,
                    user.passwordSalt,
                    user.passwordHash
                )
            ) {
                failure(
                    response,
                    401,
                    'Invalid email or password.'
                );

                return;
            }

            const token =
                crypto
                    .randomBytes(32)
                    .toString(
                        'hex'
                    );

            sessions.set(
                token,
                {
                    userId:
                        user.id,

                    expiresAt:
                        Date.now() +
                        SESSION_DAYS *
                            24 *
                            60 *
                            60 *
                            1000
                }
            );

            audit(
                db,
                user.id,
                'LOGIN'
            );

            saveDb(db);

            success(
                response,
                200,
                {
                    token,

                    user:
                        safeUser(
                            user
                        )
                }
            );

            return;
        }

        /* =================================================
           LOGOUT
        ================================================= */

        if (
            method === 'POST' &&
            pathname ===
                '/api/logout'
        ) {
            const token =
                getToken(
                    request
                );

            const user =
                getCurrentUser(
                    request,
                    db
                );

            if (token) {
                sessions.delete(
                    token
                );
            }

            if (user) {
                audit(
                    db,
                    user.id,
                    'LOGOUT'
                );

                saveDb(db);
            }

            success(
                response,
                200,
                {
                    message:
                        'Logged out successfully.'
                }
            );

            return;
        }

        /* =================================================
           ADMIN
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/admin/doctors'
        ) {
            if (
                !ADMIN_KEY ||
                request.headers[
                    'x-admin-key'
                ] !== ADMIN_KEY
            ) {
                failure(
                    response,
                    403,
                    'Admin access denied.'
                );

                return;
            }

            success(
                response,
                200,
                {
                    doctors:
                        db.users
                            .filter(
                                user =>
                                    user.role ===
                                    'doctor'
                            )
                            .map(
                                user => ({
                                    ...safeUser(
                                        user
                                    ),

                                    profile:
                                        db.doctorProfiles.find(
                                            profile =>
                                                profile.userId ===
                                                user.id
                                        ) ||
                                        null
                                })
                            )
                }
            );

            return;
        }

        if (
            method === 'POST' &&
            pathname ===
                '/api/admin/doctor/verify'
        ) {
            if (
                !ADMIN_KEY ||
                request.headers[
                    'x-admin-key'
                ] !== ADMIN_KEY
            ) {
                failure(
                    response,
                    403,
                    'Admin access denied.'
                );

                return;
            }

            const body =
                await readBody(
                    request
                );

            const doctor =
                db.users.find(
                    user =>
                        user.id ===
                            cleanString(
                                body.doctorId,
                                200
                            ) &&
                        user.role ===
                            'doctor'
                );

            if (!doctor) {
                failure(
                    response,
                    404,
                    'Doctor not found.'
                );

                return;
            }

            doctor.verificationStatus =
                'verified';

            doctor.updatedAt =
                now();

            saveDb(db);

            success(
                response,
                200,
                {
                    doctor:
                        safeUser(
                            doctor
                        )
                }
            );

            return;
        }

        if (
            method === 'POST' &&
            pathname ===
                '/api/admin/doctor/reject'
        ) {
            if (
                !ADMIN_KEY ||
                request.headers[
                    'x-admin-key'
                ] !== ADMIN_KEY
            ) {
                failure(
                    response,
                    403,
                    'Admin access denied.'
                );

                return;
            }

            const body =
                await readBody(
                    request
                );

            const doctor =
                db.users.find(
                    user =>
                        user.id ===
                            cleanString(
                                body.doctorId,
                                200
                            ) &&
                        user.role ===
                            'doctor'
                );

            if (!doctor) {
                failure(
                    response,
                    404,
                    'Doctor not found.'
                );

                return;
            }

            doctor.verificationStatus =
                'rejected';

            doctor.updatedAt =
                now();

            saveDb(db);

            success(
                response,
                200,
                {
                    doctor:
                        safeUser(
                            doctor
                        )
                }
            );

            return;
        }

        /* =================================================
           LOGIN REQUIRED FROM HERE
        ================================================= */

        const user =
            requireLogin(
                request,
                response,
                db
            );

        if (!user) {
            return;
        }

        /* =================================================
           ME
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/me'
        ) {
            const profile =
                user.role ===
                'patient'
                    ? db.patientProfiles.find(
                          item =>
                              item.userId ===
                              user.id
                      )
                    : db.doctorProfiles.find(
                          item =>
                              item.userId ===
                              user.id
                      );

            success(
                response,
                200,
                {
                    user:
                        safeUser(
                            user
                        ),

                    profile:
                        profile ||
                        null
                }
            );

            return;
        }

        /* =================================================
           PATIENT PROFILE
        ================================================= */

        if (
            pathname ===
                '/api/patient/profile'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            if (
                method === 'GET'
            ) {
                success(
                    response,
                    200,
                    {
                        profile:
                            db.patientProfiles.find(
                                item =>
                                    item.userId ===
                                    user.id
                            ) ||
                            null
                    }
                );

                return;
            }

            if (
                [
                    'POST',
                    'PUT',
                    'PATCH'
                ].includes(method)
            ) {
                const body =
                    await readBody(
                        request
                    );

                let profile =
                    db.patientProfiles.find(
                        item =>
                            item.userId ===
                            user.id
                    );

                if (!profile) {
                    profile = {
                        id:
                            makeId(
                                'profile'
                            ),

                        userId:
                            user.id,

                        createdAt:
                            now()
                    };

                    db.patientProfiles.push(
                        profile
                    );
                }

                const allowed = [
                    'name',
                    'phone',
                    'dateOfBirth',
                    'gender',
                    'bloodGroup',
                    'address',
                    'emergencyContact',
                    'nid'
                ];

                for (
                    const key of allowed
                ) {
                    if (
                        body[key] !==
                        undefined
                    ) {
                        profile[key] =
                            cleanString(
                                body[key],
                                500
                            );
                    }
                }

                profile.updatedAt =
                    now();

                if (profile.name) {
                    user.name =
                        profile.name;
                }

                if (profile.phone) {
                    user.phone =
                        profile.phone;
                }

                user.updatedAt =
                    now();

                saveDb(db);

                success(
                    response,
                    200,
                    {
                        profile
                    }
                );

                return;
            }
        }

        /* =================================================
           DOCTOR PROFILE
        ================================================= */

        if (
            pathname ===
                '/api/doctor/profile'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'doctor'
                )
            ) {
                return;
            }

            if (
                method === 'GET'
            ) {
                success(
                    response,
                    200,
                    {
                        profile:
                            db.doctorProfiles.find(
                                item =>
                                    item.userId ===
                                    user.id
                            ) ||
                            null,

                        verificationStatus:
                            user.verificationStatus
                    }
                );

                return;
            }

            if (
                [
                    'POST',
                    'PUT',
                    'PATCH'
                ].includes(method)
            ) {
                const body =
                    await readBody(
                        request
                    );

                let profile =
                    db.doctorProfiles.find(
                        item =>
                            item.userId ===
                            user.id
                    );

                if (!profile) {
                    profile = {
                        id:
                            makeId(
                                'profile'
                            ),

                        userId:
                            user.id,

                        createdAt:
                            now()
                    };

                    db.doctorProfiles.push(
                        profile
                    );
                }

                const allowed = [
                    'name',
                    'phone',
                    'specialization',
                    'licenseNumber',
                    'chamber',
                    'qualification'
                ];

                for (
                    const key of allowed
                ) {
                    if (
                        body[key] !==
                        undefined
                    ) {
                        profile[key] =
                            cleanString(
                                body[key],
                                500
                            );
                    }
                }

                profile.updatedAt =
                    now();

                saveDb(db);

                success(
                    response,
                    200,
                    {
                        profile,

                        verificationStatus:
                            user.verificationStatus
                    }
                );

                return;
            }
        }

        /* =================================================
           DOCTOR PATIENT LIST
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/doctor/patients'
        ) {
            if (
                !requireVerifiedDoctor(
                    response,
                    user
                )
            ) {
                return;
            }

            success(
                response,
                200,
                {
                    patients:
                        db.patientProfiles.map(
                            profile => ({
                                ...profile,

                                user:
                                    safeUser(
                                        db.users.find(
                                            item =>
                                                item.id ===
                                                profile.userId
                                        )
                                    )
                            })
                        )
                }
            );

            return;
        }

        /* =================================================
           DOCTOR CREATE PRESCRIPTION
        ================================================= */

        if (
            method === 'POST' &&
            (
                pathname ===
                    '/api/doctor/prescriptions' ||
                pathname ===
                    '/api/prescriptions'
            )
        ) {
            if (
                !requireVerifiedDoctor(
                    response,
                    user
                )
            ) {
                return;
            }

            const body =
                await readBody(
                    request
                );

            const patientId =
                cleanString(
                    body.patientId,
                    200
                );

            const patient =
                db.users.find(
                    item =>
                        item.id ===
                            patientId &&
                        item.role ===
                            'patient'
                );

            if (!patient) {
                failure(
                    response,
                    404,
                    'Patient not found.'
                );

                return;
            }

            const medicines =
                Array.isArray(
                    body.medicines
                )
                    ? body.medicines
                    : [];

            const prescription = {
                id:
                    makeId('rx'),

                doctorId:
                    user.id,

                patientId,

                diagnosis:
                    cleanString(
                        body.diagnosis,
                        1000
                    ),

                notes:
                    cleanString(
                        body.notes,
                        2000
                    ),

                medicines:
                    medicines.map(
                        medicine => ({
                            name:
                                cleanString(
                                    medicine.name,
                                    200
                                ),

                            genericName:
                                cleanString(
                                    medicine.genericName,
                                    200
                                ),

                            dosage:
                                cleanString(
                                    medicine.dosage ||
                                        medicine.dose,
                                    200
                                ),

                            frequency:
                                cleanString(
                                    medicine.frequency,
                                    200
                                ),

                            times:
                                Array.isArray(
                                    medicine.times
                                )
                                    ? medicine.times
                                          .map(
                                              time =>
                                                  cleanString(
                                                      time,
                                                      20
                                                  )
                                          )
                                          .filter(
                                              Boolean
                                          )
                                    : [
                                          cleanString(
                                              medicine.time,
                                              20
                                          )
                                      ].filter(
                                          Boolean
                                      ),

                            mealTiming:
                                cleanString(
                                    medicine.mealTiming ||
                                        medicine.meal,
                                    50
                                ),

                            startDate:
                                cleanString(
                                    medicine.startDate,
                                    30
                                ),

                            endDate:
                                cleanString(
                                    medicine.endDate,
                                    30
                                ),

                            duration:
                                cleanString(
                                    medicine.duration,
                                    100
                                ),

                            instructions:
                                cleanString(
                                    medicine.instructions ||
                                        medicine.notes,
                                    1000
                                )
                        })
                    ),

                createdAt:
                    now()
            };

            db.prescriptions.push(
                prescription
            );

            for (
                const medicineData of
                    prescription.medicines
            ) {
                if (
                    !medicineData.name
                ) {
                    continue;
                }

                const medicine =
                    createMedicine(
                        patientId,
                        medicineData,
                        {
                            prescriptionId:
                                prescription.id,

                            doctorId:
                                user.id,

                            doctorApproved:
                                true
                        }
                    );

                db.medicines.push(
                    medicine
                );

                addNotification(
                    db,
                    patientId,
                    'prescription',
                    'New prescription',
                    `${medicine.name} was prescribed by Dr. ${user.name}.`,
                    {
                        prescriptionId:
                            prescription.id,

                        medicineId:
                            medicine.id
                    }
                );
            }

            audit(
                db,
                user.id,
                'CREATE_PRESCRIPTION',
                {
                    prescriptionId:
                        prescription.id,

                    patientId
                }
            );

            saveDb(db);

            success(
                response,
                201,
                {
                    prescription
                }
            );

            return;
        }

        /* =================================================
           PATIENT PRESCRIPTIONS
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/patient/prescriptions'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            const prescriptions =
                db.prescriptions
                    .filter(
                        item =>
                            item.patientId ===
                            user.id
                    )
                    .map(
                        prescription => ({
                            ...prescription,

                            doctor:
                                safeUser(
                                    db.users.find(
                                        doctor =>
                                            doctor.id ===
                                            prescription.doctorId
                                    )
                                )
                        })
                    );

            success(
                response,
                200,
                {
                    prescriptions
                }
            );

            return;
        }

        /* =================================================
           DOCTOR PRESCRIPTIONS
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/doctor/prescriptions'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'doctor'
                )
            ) {
                return;
            }

            success(
                response,
                200,
                {
                    prescriptions:
                        db.prescriptions.filter(
                            item =>
                                item.doctorId ===
                                user.id
                        )
                }
            );

            return;
        }

        /* =================================================
           PATIENT MEDICINES
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/patient/medicines'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            success(
                response,
                200,
                {
                    medicines:
                        db.medicines.filter(
                            medicine =>
                                medicine.patientId ===
                                user.id
                        )
                }
            );

            return;
        }

        /* =================================================
           ADD MEDICINE
        ================================================= */

        if (
            method === 'POST' &&
            pathname ===
                '/api/patient/medicines'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            const body =
                await readBody(
                    request
                );

            const medicine =
                createMedicine(
                    user.id,
                    body
                );

            if (
                !medicine.name
            ) {
                failure(
                    response,
                    400,
                    'Medicine name is required.'
                );

                return;
            }

            db.medicines.push(
                medicine
            );

            audit(
                db,
                user.id,
                'ADD_MEDICINE',
                {
                    medicineId:
                        medicine.id
                }
            );

            saveDb(db);

            success(
                response,
                201,
                {
                    medicine
                }
            );

            return;
        }

        /* =================================================
           MEDICINE UPDATE / DELETE
        ================================================= */

        const medicineMatch =
            pathname.match(
                /^\/api\/patient\/medicines\/([^/]+)$/
            );

        if (
            medicineMatch
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            const medicine =
                db.medicines.find(
                    item =>
                        item.id ===
                            medicineMatch[1] &&
                        item.patientId ===
                            user.id
                );

            if (!medicine) {
                failure(
                    response,
                    404,
                    'Medicine not found.'
                );

                return;
            }

            if (
                method === 'PATCH' ||
                method === 'PUT'
            ) {
                const body =
                    await readBody(
                        request
                    );

                const fields = [
                    'name',
                    'genericName',
                    'dosage',
                    'frequency',
                    'mealTiming',
                    'startDate',
                    'endDate',
                    'duration',
                    'instructions',
                    'prescriptionId',
                    'doctorId'
                ];

                for (
                    const field of
                        fields
                ) {
                    if (
                        body[field] !==
                        undefined
                    ) {
                        medicine[field] =
                            cleanString(
                                body[field],
                                1000
                            );
                    }
                }

                if (
                    body.times !==
                    undefined
                ) {
                    medicine.times =
                        Array.isArray(
                            body.times
                        )
                            ? body.times
                                  .map(
                                      time =>
                                          cleanString(
                                              time,
                                              20
                                          )
                                  )
                                  .filter(
                                      Boolean
                                  )
                            : [];
                }

                if (
                    body.active !==
                    undefined
                ) {
                    medicine.active =
                        Boolean(
                            body.active
                        );
                }

                if (
                    body.reminderEnabled !==
                    undefined
                ) {
                    medicine.reminderEnabled =
                        Boolean(
                            body.reminderEnabled
                        );
                }

                medicine.updatedAt =
                    now();

                saveDb(db);

                success(
                    response,
                    200,
                    {
                        medicine
                    }
                );

                return;
            }

            if (
                method === 'DELETE'
            ) {
                medicine.active =
                    false;

                medicine.reminderEnabled =
                    false;

                medicine.updatedAt =
                    now();

                saveDb(db);

                success(
                    response,
                    200,
                    {
                        message:
                            'Medicine reminder stopped.',

                        medicine
                    }
                );

                return;
            }
        }

        /* =================================================
           TODAY REMINDERS
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/patient/reminders/today'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            const today =
                now().slice(
                    0,
                    10
                );

            const reminders =
                db.medicines
                    .filter(
                        medicine =>
                            medicine.patientId ===
                                user.id &&
                            medicine.active &&
                            medicine.reminderEnabled &&
                            (
                                !medicine.startDate ||
                                medicine.startDate <=
                                    today
                            ) &&
                            (
                                !medicine.endDate ||
                                medicine.endDate >=
                                    today
                            )
                    )
                    .map(
                        medicine => ({
                            ...medicine,

                            times:
                                medicine.times ||
                                []
                        })
                    );

            success(
                response,
                200,
                {
                    date:
                        today,

                    reminders
                }
            );

            return;
        }

        /* =================================================
           MEDICINE TAKEN
        ================================================= */

        if (
            method === 'POST' &&
            pathname ===
                '/api/patient/medicines/taken'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            const body =
                await readBody(
                    request
                );

            const medicine =
                db.medicines.find(
                    item =>
                        item.id ===
                            cleanString(
                                body.medicineId,
                                200
                            ) &&
                        item.patientId ===
                            user.id
                );

            if (!medicine) {
                failure(
                    response,
                    404,
                    'Medicine not found.'
                );

                return;
            }

            const event =
                medicineEvent(
                    db,
                    user,
                    medicine,
                    'taken'
                );

            saveDb(db);

            success(
                response,
                201,
                {
                    event
                }
            );

            return;
        }

        /* =================================================
           MEDICINE MISSED
        ================================================= */

        if (
            method === 'POST' &&
            pathname ===
                '/api/patient/medicines/missed'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            const body =
                await readBody(
                    request
                );

            const medicine =
                db.medicines.find(
                    item =>
                        item.id ===
                            cleanString(
                                body.medicineId,
                                200
                            ) &&
                        item.patientId ===
                            user.id
                );

            if (!medicine) {
                failure(
                    response,
                    404,
                    'Medicine not found.'
                );

                return;
            }

            const event =
                medicineEvent(
                    db,
                    user,
                    medicine,
                    'missed'
                );

            notifyCaregivers(
                db,
                user.id,
                'Medicine missed',
                `${medicine.name} was marked as missed.`,
                {
                    medicineId:
                        medicine.id
                }
            );

            saveDb(db);

            success(
                response,
                201,
                {
                    event
                }
            );

            return;
        }

        /* =================================================
           MEDICINE HISTORY
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/patient/medicines/events'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            success(
                response,
                200,
                {
                    events:
                        db.medicineEvents.filter(
                            event =>
                                event.patientId ===
                                user.id
                        )
                }
            );

            return;
        }

        /* =================================================
           CAREGIVERS
        ================================================= */

        if (
            pathname ===
                '/api/patient/caregivers'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            if (
                method === 'GET'
            ) {
                success(
                    response,
                    200,
                    {
                        caregivers:
                            db.caregiverContacts.filter(
                                item =>
                                    item.patientId ===
                                    user.id
                            )
                    }
                );

                return;
            }

            if (
                method === 'POST'
            ) {
                const body =
                    await readBody(
                        request
                    );

                const caregiver = {
                    id:
                        makeId(
                            'care'
                        ),

                    patientId:
                        user.id,

                    name:
                        cleanString(
                            body.name,
                            120
                        ),

                    contact:
                        cleanString(
                            body.contact,
                            200
                        ),

                    relation:
                        cleanString(
                            body.relation,
                            80
                        ),

                    userId:
                        cleanString(
                            body.userId,
                            200
                        ),

                    active:
                        body.active !==
                        false,

                    createdAt:
                        now()
                };

                if (
                    !caregiver.name ||
                    !caregiver.contact
                ) {
                    failure(
                        response,
                        400,
                        'Caregiver name and contact are required.'
                    );

                    return;
                }

                db.caregiverContacts.push(
                    caregiver
                );

                saveDb(db);

                success(
                    response,
                    201,
                    {
                        caregiver
                    }
                );

                return;
            }
        }

        /* =================================================
           NOTIFICATIONS
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/notifications'
        ) {
            success(
                response,
                200,
                {
                    notifications:
                        db.notifications.filter(
                            item =>
                                item.userId ===
                                user.id
                        )
                }
            );

            return;
        }

        if (
            method === 'POST' &&
            pathname ===
                '/api/notifications/read'
        ) {
            const body =
                await readBody(
                    request
                );

            const notification =
                db.notifications.find(
                    item =>
                        item.id ===
                            cleanString(
                                body.notificationId,
                                200
                            ) &&
                        item.userId ===
                            user.id
                );

            if (!notification) {
                failure(
                    response,
                    404,
                    'Notification not found.'
                );

                return;
            }

            notification.read =
                true;

            saveDb(db);

            success(
                response,
                200,
                {
                    notification
                }
            );

            return;
        }

        /* =================================================
           HEALTH GET
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/health'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            success(
                response,
                200,
                {
                    records:
                        db.healthRecords.filter(
                            item =>
                                item.patientId ===
                                user.id
                        )
                }
            );

            return;
        }

        /* =================================================
           HEALTH POST
        ================================================= */

        if (
            method === 'POST' &&
            pathname ===
                '/api/health'
        ) {
            if (
                !requireRole(
                    response,
                    user,
                    'patient'
                )
            ) {
                return;
            }

            const body =
                await readBody(
                    request
                );

            const record = {
                id:
                    makeId(
                        'health'
                    ),

                patientId:
                    user.id,

                bloodPressure:
                    cleanString(
                        body.bloodPressure,
                        100
                    ),

                systolic:
                    numberValue(
                        body.systolic
                    ),

                diastolic:
                    numberValue(
                        body.diastolic
                    ),

                spo2:
                    numberValue(
                        body.spo2
                    ),

                pulse:
                    numberValue(
                        body.pulse
                    ),

                temperature:
                    numberValue(
                        body.temperature
                    ),

                weight:
                    numberValue(
                        body.weight
                    ),

                notes:
                    cleanString(
                        body.notes,
                        2000
                    ),

                recordedAt:
                    cleanString(
                        body.recordedAt,
                        100
                    ) ||
                    now(),

                createdAt:
                    now()
            };

            db.healthRecords.push(
                record
            );

            saveDb(db);

            success(
                response,
                201,
                {
                    record
                }
            );

            return;
        }

        /* =================================================
           PATIENT BY ID
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/patient/by-id'
        ) {
            const requestedId =
                cleanString(
                    query.get('id'),
                    200
                );

            if (
                !requestedId
            ) {
                failure(
                    response,
                    400,
                    'Patient id is required.'
                );

                return;
            }

            if (
                user.role ===
                    'patient' &&
                requestedId !==
                    user.id
            ) {
                failure(
                    response,
                    403,
                    'You can only view your own patient profile.'
                );

                return;
            }

            if (
                user.role ===
                    'doctor' &&
                !requireVerifiedDoctor(
                    response,
                    user
                )
            ) {
                return;
            }

            const patient =
                db.users.find(
                    item =>
                        item.id ===
                            requestedId &&
                        item.role ===
                            'patient'
                );

            if (!patient) {
                failure(
                    response,
                    404,
                    'Patient not found.'
                );

                return;
            }

            success(
                response,
                200,
                {
                    user:
                        safeUser(
                            patient
                        ),

                    profile:
                        db.patientProfiles.find(
                            item =>
                                item.userId ===
                                requestedId
                        ) ||
                        null
                }
            );

            return;
        }

        /* =================================================
           DOCTOR HEALTH RECORD
        ================================================= */

        if (
            method === 'GET' &&
            pathname ===
                '/api/doctor/health'
        ) {
            if (
                !requireVerifiedDoctor(
                    response,
                    user
                )
            ) {
                return;
            }

            const patientId =
                cleanString(
                    query.get(
                        'patientId'
                    ),
                    200
                );

            if (!patientId) {
                failure(
                    response,
                    400,
                    'patientId is required.'
                );

                return;
            }

            const patient =
                db.users.find(
                    item =>
                        item.id ===
                            patientId &&
                        item.role ===
                            'patient'
                );

            if (!patient) {
                failure(
                    response,
                    404,
                    'Patient not found.'
                );

                return;
            }

            success(
                response,
                200,
                {
                    patient:
                        safeUser(
                            patient
                        ),

                    records:
                        db.healthRecords.filter(
                            item =>
                                item.patientId ===
                                patientId
                        )
                }
            );

            return;
        }

        /* =================================================
           404
        ================================================= */

        failure(
            response,
            404,
            'API endpoint not found.'
        );

    } catch (error) {
        console.error(
            'Unhandled server error:',
            error
        );

        if (
            !response.headersSent
        ) {
            failure(
                response,
                500,
                'Internal server error.'
            );
        } else {
            response.end();
        }
    }
}

/* =========================================================
   SERVER
========================================================= */

const server =
    http.createServer(
        router
    );

server.on(
    'clientError',
    (error, socket) => {
        console.error(
            'Client error:',
            error
        );

        try {
            socket.end(
                'HTTP/1.1 400 Bad Request\r\n\r\n'
            );
        } catch {}
    }
);

server.listen(
    PORT,
    HOST,
    () => {
        console.log(
            '========================================'
        );

        console.log(
            ' MEDIVOICE BACKEND'
        );

        console.log(
            ' Version:',
            APP_VERSION
        );

        console.log(
            ' Host:',
            HOST
        );

        console.log(
            ' Port:',
            PORT
        );

        console.log(
            ' API prefix:',
            '/medivoice'
        );

        console.log(
            ' Health:',
            '/api/health'
        );

        console.log(
            ' Medicine Reminder:',
            'ENABLED'
        );

        console.log(
            ' User limit:',
            'NO APPLICATION USER CAP'
        );

        console.log(
            '========================================'
        );
    }
);
