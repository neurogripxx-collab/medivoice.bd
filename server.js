'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const ROOT = __dirname;
const DATA = path.join(ROOT, 'medivoice-data');
const DB = path.join(DATA, 'database.json');

const APP_VERSION = '5.0.0';
const SESSION_DAYS = 7;
const MAX_BODY = 2 * 1024 * 1024;

function now() {
    return new Date().toISOString();
}

function id(prefix) {
    return prefix + '-' +
        crypto.randomBytes(8).toString('hex').toUpperCase();
}

function empty() {
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

function ensure() {
    if (!fs.existsSync(DATA)) {
        fs.mkdirSync(DATA, { recursive: true });
    }

    if (!fs.existsSync(DB)) {
        fs.writeFileSync(
            DB,
            JSON.stringify(empty(), null, 2),
            'utf8'
        );
    }
}

ensure();

function read() {
    try {
        return {
            ...empty(),
            ...JSON.parse(
                fs.readFileSync(DB, 'utf8')
            )
        };
    } catch (e) {
        return empty();
    }
}

function write(db) {
    const temp = DB + '.tmp';

    fs.writeFileSync(
        temp,
        JSON.stringify(db, null, 2),
        'utf8'
    );

    fs.renameSync(temp, DB);
}

function send(
    res,
    status,
    data,
    headers = {}
) {
    res.writeHead(
        status,
        {
            'Content-Type':
                'application/json; charset=utf-8',

            'Access-Control-Allow-Origin':
                '*',

            'Access-Control-Allow-Headers':
                'Content-Type, Authorization, X-Admin-Key',

            'Access-Control-Allow-Methods':
                'GET,POST,PUT,PATCH,DELETE,OPTIONS',

            ...headers
        }
    );

    res.end(
        JSON.stringify(data)
    );
}

function ok(
    res,
    data = {}
) {
    send(
        res,
        200,
        {
            success: true,
            ...data
        }
    );
}

function created(
    res,
    data = {}
) {
    send(
        res,
        201,
        {
            success: true,
            ...data
        }
    );
}

function fail(
    res,
    status,
    message
) {
    send(
        res,
        status,
        {
            success: false,
            error: message
        }
    );
}

function body(req) {
    return new Promise(
        (resolve, reject) => {

            let s = '';

            req.on(
                'data',
                chunk => {

                    s += chunk;

                    if (
                        s.length >
                        MAX_BODY
                    ) {
                        reject(
                            new Error(
                                'Request body too large'
                            )
                        );

                        req.destroy();
                    }
                }
            );

            req.on(
                'end',
                () => {

                    if (!s.trim()) {
                        return resolve({});
                    }

                    try {
                        resolve(
                            JSON.parse(s)
                        );
                    } catch (e) {
                        reject(
                            new Error(
                                'Invalid JSON'
                            )
                        );
                    }
                }
            );

            req.on(
                'error',
                reject
            );
        }
    );
}

function hashPass(
    password,
    salt = crypto
        .randomBytes(16)
        .toString('hex')
) {
    return {
        salt,

        hash: crypto
            .pbkdf2Sync(
                String(password),
                salt,
                120000,
                64,
                'sha512'
            )
            .toString('hex')
    };
}

function verify(
    password,
    user
) {
    const hash =
        hashPass(
            password,
            user.passwordSalt
        ).hash;

    const a =
        Buffer.from(
            hash,
            'hex'
        );

    const b =
        Buffer.from(
            user.passwordHash,
            'hex'
        );

    if (
        a.length !==
        b.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        a,
        b
    );
}

function token(req) {
    const authorization =
        req.headers.authorization || '';

    if (
        !authorization.startsWith(
            'Bearer '
        )
    ) {
        return null;
    }

    return authorization
        .slice(7)
        .trim();
}

function auth(req) {
    const t = token(req);

    if (!t) {
        return null;
    }

    const db = read();

    const s =
        db.sessions.find(
            x =>
                x.token === t &&
                new Date(x.expiresAt) >
                new Date()
        );

    if (!s) {
        return null;
    }

    const u =
        db.users.find(
            x =>
                x.id ===
                s.userId
        );

    if (!u) {
        return null;
    }

    return {
        user: u,
        session: s
    };
}

function session(
    db,
    user
) {
    const t =
        crypto
            .randomBytes(48)
            .toString('hex');

    db.sessions.push({
        id: id('SES'),
        token: t,
        userId: user.id,
        role: user.role,
        createdAt: now(),

        expiresAt:
            new Date(
                Date.now() +
                SESSION_DAYS *
                864e5
            ).toISOString()
    });

    return t;
}

function audit(
    db,
    action,
    user,
    target,
    details = ''
) {
    db.auditLogs.push({
        id: id('AUD'),

        action,

        actorId:
            user?.id ||
            null,

        actorRole:
            user?.role ||
            null,

        targetId:
            target ||
            null,

        details,

        createdAt:
            now()
    });

    if (
        db.auditLogs.length >
        5000
    ) {
        db.auditLogs =
            db.auditLogs.slice(-5000);
    }
}

function safe(user) {
    return {
        id: user.id,
        role: user.role,
        name: user.name,
        phone: user.phone,
        status: user.status,
        createdAt: user.createdAt
    };
}

function role(
    user,
    requiredRole
) {
    return (
        user &&
        user.role === requiredRole
    );
}

function parse(req) {
    return new URL(
        req.url,
        'http://localhost'
    );
}

function serve(
    req,
    res,
    url
) {
    let p =
        url.pathname ===
        '/medivoice/'
            ? '/index.html'
            : url.pathname;

    if (p === '/') {
        p = '/index.html';
    }

    if (
        p.startsWith('/api/')
    ) {
        return false;
    }

    if (
        p.startsWith(
            '/medivoice/'
        )
    ) {
        p =
            p.slice(
                '/medivoice'.length
            ) ||
            '/index.html';
    }

    const f =
        path.join(
            ROOT,
            p
        );

    if (
        !f.startsWith(ROOT) ||
        !fs.existsSync(f) ||
        fs.statSync(f).isDirectory()
    ) {
        return false;
    }

    const ext =
        path.extname(f);

    const types = {
        '.html':
            'text/html; charset=utf-8',

        '.js':
            'text/javascript; charset=utf-8',

        '.css':
            'text/css; charset=utf-8',

        '.json':
            'application/json; charset=utf-8',

        '.png':
            'image/png',

        '.jpg':
            'image/jpeg',

        '.jpeg':
            'image/jpeg',

        '.svg':
            'image/svg+xml',

        '.ico':
            'image/x-icon'
    };

    res.writeHead(
        200,
        {
            'Content-Type':
                types[ext] ||
                'application/octet-stream'
        }
    );

    fs.createReadStream(f)
        .pipe(res);

    return true;
}

async function router(
    req,
    res
) {
    const u = parse(req);
    const p = u.pathname;

    const m =
        (
            req.method ||
            'GET'
        ).toUpperCase();

    if (
        m === 'OPTIONS'
    ) {
        return send(
            res,
            204,
            {}
        );
    }

    /*
    =========================================================
    PUBLIC HEALTH
    =========================================================
    */

    if (
        m === 'GET' &&
        (
            p === '/api/health' ||
            p === '/medivoice/api/health'
        )
    ) {
        return ok(
            res,
            {
                app:
                    'Medivoice',

                backend:
                    'online',

                version:
                    APP_VERSION,

                time:
                    now()
            }
        );
    }

    if (
        m === 'GET' &&
        (
            p === '/api/status' ||
            p === '/medivoice/api/status'
        )
    ) {
        return ok(
            res,
            {
                app:
                    'Medivoice',

                version:
                    APP_VERSION,

                status:
                    'online'
            }
        );
    }

    if (
        m === 'GET' &&
        (
            p === '/api/version' ||
            p === '/medivoice/api/version'
        )
    ) {
        return ok(
            res,
            {
                version:
                    APP_VERSION
            }
        );
    }

    /*
    =========================================================
    PHARMACY QR
    =========================================================
    */

    if (
        m === 'GET' &&
        p === '/api/pharmacy/qr'
    ) {
        const ref =
            String(
                u.searchParams.get(
                    'ref'
                ) || ''
            ).trim();

        return ok(
            res,
            {
                ref,

                url:
                    '/medivoice/?ref=' +
                    encodeURIComponent(ref)
            }
        );
    }

    /*
    =========================================================
    REGISTER
    =========================================================
    */

    if (
        m === 'POST' &&
        p === '/api/auth/register'
    ) {
        try {
            const b =
                await body(req);

            const name =
                String(
                    b.name || ''
                ).trim();

            const phone =
                String(
                    b.phone || ''
                ).replace(
                    /\s/g,
                    ''
                );

            const password =
                String(
                    b.password || ''
                );

            const r =
                String(
                    b.role ||
                    'patient'
                ).toLowerCase();

            if (
                !name ||
                !phone ||
                password.length < 8
            ) {
                return fail(
                    res,
                    400,
                    'নাম, মোবাইল ও কমপক্ষে ৮ অক্ষরের password দিন।'
                );
            }

            if (
                ![
                    'patient',
                    'doctor'
                ].includes(r)
            ) {
                return fail(
                    res,
                    400,
                    'Invalid account type.'
                );
            }

            const db =
                read();

            if (
                db.users.some(
                    x =>
                        x.phone ===
                        phone
                )
            ) {
                return fail(
                    res,
                    409,
                    'এই মোবাইল নম্বর দিয়ে account already আছে।'
                );
            }

            const h =
                hashPass(
                    password
                );

            const uid =
                id(
                    r === 'patient'
                        ? 'PAT'
                        : 'DOC'
                );

            const user = {
                id: uid,

                role: r,

                name,

                phone,

                passwordHash:
                    h.hash,

                passwordSalt:
                    h.salt,

                status:
                    r === 'doctor'
                        ? 'pending_verification'
                        : 'active',

                createdAt:
                    now()
            };

            db.users.push(
                user
            );

            if (
                r === 'patient'
            ) {
                db.patients.push({
                    id: uid,

                    userId: uid,

                    name,

                    phone,

                    createdAt:
                        now()
                });
            } else {
                db.doctors.push({
                    id: uid,

                    userId: uid,

                    name,

                    phone,

                    specialty:
                        String(
                            b.specialty ||
                            ''
                        ),

                    bmdcNumber:
                        String(
                            b.bmdcNumber ||
                            ''
                        ),

                    verificationStatus:
                        'pending',

                    createdAt:
                        now()
                });
            }

            const t =
                session(
                    db,
                    user
                );

            audit(
                db,
                'REGISTER',
                user,
                uid,
                r
            );

            write(db);

            return created(
                res,
                {
                    message:
                        r === 'doctor'
                            ? 'Doctor account তৈরি হয়েছে; verification প্রয়োজন।'
                            : 'Patient account তৈরি হয়েছে।',

                    token: t,

                    user:
                        safe(user)
                }
            );

        } catch (e) {
            return fail(
                res,
                400,
                e.message
            );
        }
    }

    /*
    =========================================================
    LOGIN
    =========================================================
    */

    if (
        m === 'POST' &&
        p === '/api/auth/login'
    ) {
        try {
            const b =
                await body(req);

            const phone =
                String(
                    b.phone || ''
                ).replace(
                    /\s/g,
                    ''
                );

            const password =
                String(
                    b.password || ''
                );

            const db =
                read();

            const user =
                db.users.find(
                    x =>
                        x.phone ===
                        phone
                );

            if (
                !user ||
                !verify(
                    password,
                    user
                )
            ) {
                return fail(
                    res,
                    401,
                    'মোবাইল বা password সঠিক নয়।'
                );
            }

            if (
                user.status ===
                'blocked'
            ) {
                return fail(
                    res,
                    403,
                    'Account blocked.'
                );
            }

            const t =
                session(
                    db,
                    user
                );

            audit(
                db,
                'LOGIN',
                user,
                user.id
            );

            write(db);

            return ok(
                res,
                {
                    token: t,

                    user:
                        safe(user)
                }
            );

        } catch (e) {
            return fail(
                res,
                400,
                e.message
            );
        }
    }

    /*
    =========================================================
    LOGOUT
    =========================================================
    */

    if (
        m === 'POST' &&
        p === '/api/auth/logout'
    ) {
        const a =
            auth(req);

        if (a) {
            const db =
                read();

            db.sessions =
                db.sessions.filter(
                    x =>
                        x.token !==
                        token(req)
                );

            audit(
                db,
                'LOGOUT',
                a.user,
                a.user.id
            );

            write(db);
        }

        return ok(res);
    }

    /*
    =========================================================
    PUBLIC PARTNERS
    =========================================================
    */

    if (
        m === 'GET' &&
        p === '/api/partners'
    ) {
        const db =
            read();

        const q =
            String(
                u.searchParams.get(
                    'q'
                ) || ''
            ).toLowerCase();

        const area =
            String(
                u.searchParams.get(
                    'area'
                ) || ''
            ).toLowerCase();

        const list =
            db.partners.filter(
                x =>

                    x.status !==
                    'suspended' &&

                    x.verified &&

                    (
                        !q ||
                        JSON.stringify(x)
                            .toLowerCase()
                            .includes(q)
                    ) &&

                    (
                        !area ||
                        JSON.stringify(x)
                            .toLowerCase()
                            .includes(area)
                    )
            );

        return ok(
            res,
            {
                partners:
                    list.slice(
                        0,
                        100
                    )
            }
        );
    }

    /*
    =========================================================
    PUBLIC PHARMACY REFERRAL
    =========================================================
    */

    if (
        m === 'GET' &&
        p.startsWith(
            '/api/pharmacy/'
        )
    ) {
        const ref =
            p.split('/').pop();

        const db =
            read();

        const pharmacy =
            db.pharmacyReferrals.find(
                x =>
                    x.code === ref &&
                    x.active !== false
            );

        return pharmacy
            ? ok(
                res,
                {
                    pharmacy
                }
            )
            : fail(
                res,
                404,
                'Pharmacy referral not found.'
            );
    }

    /*
    =========================================================
    AUTHENTICATION REQUIRED
    =========================================================
    */

    const a =
        auth(req);

    if (!a) {
        return fail(
            res,
            401,
            'Login required.'
        );
    }

    const user =
        a.user;

    const db =
        read();

    /*
    =========================================================
    ME
    =========================================================
    */

    if (
        m === 'GET' &&
        p === '/api/me'
    ) {
        let profile =
            null;

        if (
            user.role ===
            'patient'
        ) {
            profile =
                db.patients.find(
                    x =>
                        x.userId ===
                        user.id
                ) || null;
        }

        if (
            user.role ===
            'doctor'
        ) {
            profile =
                db.doctors.find(
                    x =>
                        x.userId ===
                        user.id
                ) || null;
        }

        return ok(
            res,
            {
                user:
                    safe(user),

                profile
            }
        );
    }

    /*
    =========================================================
    PATIENT PROFILE
    =========================================================
    */

    if (
        m === 'GET' &&
        p === '/api/patient/profile'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        return ok(
            res,
            {
                patient:
                    db.patients.find(
                        x =>
                            x.userId ===
                            user.id
                    ) || null
            }
        );
    }

    /*
    =========================================================
    PATIENT MEDICINES
    =========================================================
    */

    if (
        m === 'GET' &&
        p === '/api/patient/medicines'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        return ok(
            res,
            {
                medicines:
                    db.medicines
                        .filter(
                            x =>
                                x.patientId ===
                                user.id
                        )
                        .sort(
                            (a, b) =>
                                String(
                                    a.name
                                ).localeCompare(
                                    String(
                                        b.name
                                    )
                                )
                        )
            }
        );
    }

    /*
    =========================================================
    ADD PATIENT MEDICINE
    =========================================================
    */

    if (
        m === 'POST' &&
        p === '/api/patient/medicines'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        const b =
            await body(req);

        if (
            !String(
                b.name || ''
            ).trim()
        ) {
            return fail(
                res,
                400,
                'ওষুধের নাম দিন।'
            );
        }

        const med = {
            id:
                id('MED'),

            patientId:
                user.id,

            name:
                String(
                    b.name
                ).trim(),

            genericName:
                String(
                    b.genericName ||
                    ''
                ),

            dose:
                String(
                    b.dose ||
                    b.dosage ||
                    ''
                ),

            frequency:
                String(
                    b.frequency ||
                    ''
                ),

            times:
                Array.isArray(
                    b.times
                )
                    ? b.times
                    : [],

            mealTiming:
                String(
                    b.mealTiming ||
                    b.meal ||
                    'যেকোনো সময়'
                ),

            startDate:
                String(
                    b.startDate ||
                    ''
                ),

            endDate:
                String(
                    b.endDate ||
                    ''
                ),

            duration:
                String(
                    b.duration ||
                    ''
                ),

            instructions:
                String(
                    b.instructions ||
                    b.notes ||
                    ''
                ),

            prescriptionId:
                b.prescriptionId ||
                null,

            doctorId:
                b.doctorId ||
                null,

            antibiotic:
                !!b.antibiotic,

            special:
                !!b.special,

            active:
                true,

            reminderEnabled:
                b.reminderEnabled !==
                false,

            createdAt:
                now()
        };

        db.medicines.push(
            med
        );

        audit(
            db,
            'ADD_MEDICINE',
            user,
            med.id,
            med.name
        );

        write(db);

        return created(
            res,
            {
                medicine:
                    med
            }
        );
    }

    /*
    =========================================================
    MEDICINE ACTIONS
    =========================================================
    */

    const medMatch =
        p.match(
            /^\/api\/patient\/medicines\/([^/]+)(?:\/(taken|missed))?$/
        );

    if (
        medMatch
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        const mid =
            medMatch[1];

        const action =
            medMatch[2];

        const med =
            db.medicines.find(
                x =>
                    x.id === mid &&
                    x.patientId ===
                    user.id
            );

        if (!med) {
            return fail(
                res,
                404,
                'Medicine not found.'
            );
        }

        if (
            m === 'DELETE' &&
            !action
        ) {
            med.active =
                false;

            med.updatedAt =
                now();

            audit(
                db,
                'DEACTIVATE_MEDICINE',
                user,
                mid
            );

            write(db);

            return ok(
                res,
                {
                    medicine:
                        med
                }
            );
        }

        if (
            m === 'POST' &&
            action
        ) {
            const ev = {
                id:
                    id('MEV'),

                medicineId:
                    mid,

                patientId:
                    user.id,

                type:
                    action,

                createdAt:
                    now(),

                date:
                    new Date()
                        .toISOString()
                        .slice(
                            0,
                            10
                        )
            };

            db.medicineEvents
                .unshift(ev);

            db.notifications
                .unshift({
                    id:
                        id('NOT'),

                    userId:
                        user.id,

                    type:
                        'medicine_' +
                        action,

                    message:
                        action ===
                        'taken'
                            ? med.name +
                              ' — খেয়েছি হিসেবে সংরক্ষিত।'
                            : '⚠️ ' +
                              med.name +
                              ' — খাইনি হিসেবে সংরক্ষিত।',

                    read:
                        false,

                    createdAt:
                        now()
                });

            audit(
                db,

                action ===
                'taken'
                    ? 'MEDICINE_TAKEN'
                    : 'MEDICINE_MISSED',

                user,

                mid
            );

            write(db);

            return ok(
                res,
                {
                    event:
                        ev
                }
            );
        }
    }

    /*
    =========================================================
    MEDICINE HISTORY
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/patient/medicine-events'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        return ok(
            res,
            {
                events:
                    db.medicineEvents
                        .filter(
                            x =>
                                x.patientId ===
                                user.id
                        )
                        .slice(
                            0,
                            200
                        )
            }
        );
    }

    /*
    =========================================================
    PATIENT HEALTH RECORDS
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/patient/health'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        return ok(
            res,
            {
                records:
                    db.healthRecords
                        .filter(
                            x =>
                                x.patientId ===
                                user.id
                        )
                        .sort(
                            (a, b) =>
                                new Date(
                                    b.createdAt
                                ) -
                                new Date(
                                    a.createdAt
                                )
                        )
            }
        );
    }

    /*
    =========================================================
    ADD HEALTH RECORD
    =========================================================
    */

    if (
        m === 'POST' &&
        p ===
        '/api/patient/health'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        const b =
            await body(req);

        if (
            !b.type ||
            !b.value
        ) {
            return fail(
                res,
                400,
                'Type ও value দিন।'
            );
        }

        const record = {
            id:
                id('HLT'),

            patientId:
                user.id,

            type:
                String(
                    b.type
                ),

            value:
                String(
                    b.value
                ),

            unit:
                String(
                    b.unit ||
                    ''
                ),

            createdAt:
                now()
        };

        db.healthRecords.push(
            record
        );

        write(db);

        return created(
            res,
            {
                record
            }
        );
    }

    /*
    =========================================================
    PATIENT PRESCRIPTIONS
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/patient/prescriptions'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        return ok(
            res,
            {
                prescriptions:
                    db.prescriptions
                        .filter(
                            x =>
                                x.patientId ===
                                user.id
                        )
                        .sort(
                            (a, b) =>
                                new Date(
                                    b.createdAt
                                ) -
                                new Date(
                                    a.createdAt
                                )
                        )
            }
        );
    }

    /*
    =========================================================
    CAREGIVERS
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/caregivers'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        return ok(
            res,
            {
                caregivers:
                    db.caregivers.filter(
                        x =>
                            x.patientId ===
                            user.id
                    )
            }
        );
    }

    if (
        m === 'POST' &&
        p ===
        '/api/caregivers'
    ) {
        if (
            !role(
                user,
                'patient'
            )
        ) {
            return fail(
                res,
                403,
                'Patient access only.'
            );
        }

        const b =
            await body(req);

        if (
            !b.name ||
            !b.phone
        ) {
            return fail(
                res,
                400,
                'নাম ও মোবাইল দিন।'
            );
        }

        const caregiver = {
            id:
                id('CG'),

            patientId:
                user.id,

            name:
                String(
                    b.name
                ),

            phone:
                String(
                    b.phone
                ),

            createdAt:
                now()
        };

        db.caregivers.push(
            caregiver
        );

        write(db);

        return created(
            res,
            {
                caregiver
            }
        );
    }

    /*
    =========================================================
    NOTIFICATIONS
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/notifications'
    ) {
        return ok(
            res,
            {
                notifications:
                    db.notifications
                        .filter(
                            x =>
                                x.userId ===
                                user.id
                        )
                        .slice(
                            0,
                            100
                        )
            }
        );
    }

    if (
        m === 'POST' &&
        p ===
        '/api/notifications/read'
    ) {
        db.notifications
            .filter(
                x =>
                    x.userId ===
                    user.id
            )
            .forEach(
                x =>
                    x.read = true
            );

        write(db);

        return ok(res);
    }

    /*
    =========================================================
    PHARMACY REFERRALS
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/pharmacy/my-referrals'
    ) {
        return ok(
            res,
            {
                referrals:
                    db.pharmacyReferrals
                        .filter(
                            x =>
                                x.ownerUserId ===
                                user.id
                        )
            }
        );
    }

    if (
        m === 'POST' &&
        p ===
        '/api/pharmacy/referral'
    ) {
        if (
            ![
                'patient',
                'doctor',
                'pharmacy'
            ].includes(
                user.role
            )
        ) {
            return fail(
                res,
                403,
                'Access denied.'
            );
        }

        const b =
            await body(req);

        const code =
            'MV-PH-' +
            crypto
                .randomBytes(4)
                .toString('hex')
                .toUpperCase();

        const pharmacy = {
            id:
                id('PHR'),

            code,

            name:
                String(
                    b.name ||
                    'MediVoice Pharmacy'
                ),

            phone:
                String(
                    b.phone ||
                    ''
                ),

            address:
                String(
                    b.address ||
                    ''
                ),

            ownerUserId:
                user.id,

            verified:
                false,

            active:
                true,

            createdAt:
                now(),

            oneTimeIncentive:
                10
        };

        db.pharmacyReferrals.push(
            pharmacy
        );

        write(db);

        return created(
            res,
            {
                pharmacy,

                qrUrl:
                    '/medivoice/?ref=' +
                    code
            }
        );
    }

    /*
    =========================================================
    DOCTOR CREATE PRESCRIPTION
    =========================================================
    */

    if (
        m === 'POST' &&
        p ===
        '/api/prescriptions'
    ) {
        if (
            !role(
                user,
                'doctor'
            )
        ) {
            return fail(
                res,
                403,
                'Doctor access only.'
            );
        }

        const doctor =
            db.doctors.find(
                x =>
                    x.userId ===
                    user.id
            );

        if (
            !doctor ||
            doctor.verificationStatus !==
            'verified'
        ) {
            return fail(
                res,
                403,
                'Verified doctor access required.'
            );
        }

        const b =
            await body(req);

        const patient =
            db.patients.find(
                x =>
                    x.id ===
                    b.patientId
            );

        if (!patient) {
            return fail(
                res,
                404,
                'Patient not found.'
            );
        }

        if (
            !Array.isArray(
                b.medicines
            ) ||
            !b.medicines.length
        ) {
            return fail(
                res,
                400,
                'Medicines array required.'
            );
        }

        const rx = {
            id:
                id('RX'),

            doctorId:
                doctor.id,

            patientId:
                patient.id,

            doctorName:
                doctor.name,

            specialty:
                doctor.specialty,

            bmdcNumber:
                doctor.bmdcNumber,

            patientName:
                patient.name,

            medicines:
                b.medicines.map(
                    x => ({
                        ...x
                    })
                ),

            advice:
                String(
                    b.advice ||
                    ''
                ),

            investigation:
                String(
                    b.investigation ||
                    ''
                ),

            followUp:
                String(
                    b.followUp ||
                    ''
                ),

            status:
                'active',

            createdAt:
                now()
        };

        db.prescriptions.push(
            rx
        );

        rx.medicines.forEach(
            x => {

                db.medicines.push({
                    id:
                        id('MED'),

                    patientId:
                        patient.userId,

                    prescriptionId:
                        rx.id,

                    doctorId:
                        doctor.id,

                    name:
                        String(
                            x.name ||
                            ''
                        ),

                    genericName:
                        String(
                            x.genericName ||
                            ''
                        ),

                    dose:
                        String(
                            x.dose ||
                            x.dosage ||
                            ''
                        ),

                    frequency:
                        String(
                            x.frequency ||
                            ''
                        ),

                    times:
                        Array.isArray(
                            x.times
                        )
                            ? x.times
                            : (
                                x.time
                                    ? [x.time]
                                    : []
                            ),

                    mealTiming:
                        String(
                            x.mealTiming ||
                            x.food ||
                            'যেকোনো সময়'
                        ),

                    startDate:
                        String(
                            x.startDate ||
                            ''
                        ),

                    endDate:
                        String(
                            x.endDate ||
                            ''
                        ),

                    duration:
                        String(
                            x.duration ||
                            ''
                        ),

                    instructions:
                        String(
                            x.instructions ||
                            ''
                        ),

                    antibiotic:
                        !!x.antibiotic,

                    special:
                        !!x.special,

                    active:
                        true,

                    reminderEnabled:
                        true,

                    createdAt:
                        now()
                });
            }
        );

        db.notifications.push({
            id:
                id('NOT'),

            userId:
                patient.userId,

            type:
                'prescription',

            message:
                'ডাক্তার নতুন prescription দিয়েছেন।',

            read:
                false,

            createdAt:
                now()
        });

        audit(
            db,
            'CREATE_PRESCRIPTION',
            user,
            rx.id,
            'Prescription created'
        );

        write(db);

        return created(
            res,
            {
                prescription:
                    rx
            }
        );
    }

    /*
    =========================================================
    ADMIN / DOCTOR VERIFICATION
    =========================================================
    */

    if (
        m === 'POST' &&
        p ===
        '/api/doctor/verify'
    ) {
        if (
            process.env.MEDIVOICE_ADMIN_KEY &&
            req.headers[
                'x-admin-key'
            ] !==
            process.env.MEDIVOICE_ADMIN_KEY
        ) {
            return fail(
                res,
                403,
                'Admin key required.'
            );
        }

        const b =
            await body(req);

        const doctor =
            db.doctors.find(
                x =>
                    x.id ===
                    b.doctorId
            );

        if (!doctor) {
            return fail(
                res,
                404,
                'Doctor not found.'
            );
        }

        doctor.verificationStatus =
            b.status ===
            'rejected'
                ? 'rejected'
                : 'verified';

        const u =
            db.users.find(
                x =>
                    x.id ===
                    doctor.userId
            );

        if (u) {
            u.status =
                doctor.verificationStatus ===
                'verified'
                    ? 'active'
                    : 'blocked';
        }

        write(db);

        return ok(
            res,
            {
                doctor
            }
        );
    }

    /*
    =========================================================
    PARTNER CREATE
    =========================================================
    */

    if (
        m === 'POST' &&
        p ===
        '/api/partners'
    ) {
        if (
            process.env.MEDIVOICE_ADMIN_KEY &&
            req.headers[
                'x-admin-key'
            ] !==
            process.env.MEDIVOICE_ADMIN_KEY
        ) {
            return fail(
                res,
                403,
                'Admin key required.'
            );
        }

        const b =
            await body(req);

        if (
            !b.name ||
            !b.type
        ) {
            return fail(
                res,
                400,
                'Partner name/type required.'
            );
        }

        const partner = {
            id:
                id('PAR'),

            type:
                String(
                    b.type
                ),

            name:
                String(
                    b.name
                ),

            legalName:
                String(
                    b.legalName ||
                    ''
                ),

            address:
                String(
                    b.address ||
                    ''
                ),

            district:
                String(
                    b.district ||
                    ''
                ),

            upazila:
                String(
                    b.upazila ||
                    ''
                ),

            phone:
                String(
                    b.phone ||
                    ''
                ),

            website:
                String(
                    b.website ||
                    ''
                ),

            emergency:
                String(
                    b.emergency ||
                    ''
                ),

            hours:
                String(
                    b.hours ||
                    ''
                ),

            verified:
                false,

            status:
                'pending',

            licenseNumber:
                String(
                    b.licenseNumber ||
                    ''
                ),

            licenseType:
                String(
                    b.licenseType ||
                    ''
                ),

            licenseIssueDate:
                String(
                    b.licenseIssueDate ||
                    ''
                ),

            licenseExpiryDate:
                String(
                    b.licenseExpiryDate ||
                    ''
                ),

            licenseVerified:
                false,

            lastUpdatedAt:
                now(),

            partnerDisclosure:
                String(
                    b.partnerDisclosure ||
                    'MediVoice Partner'
                )
        };

        db.partners.push(
            partner
        );

        write(db);

        return created(
            res,
            {
                partner
            }
        );
    }

    /*
    =========================================================
    DOCTOR PATIENT LIST
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/doctor/patients'
    ) {
        if (
            !role(
                user,
                'doctor'
            )
        ) {
            return fail(
                res,
                403,
                'Doctor access only.'
            );
        }

        const doctor =
            db.doctors.find(
                x =>
                    x.userId ===
                    user.id
            );

        if (
            !doctor ||
            doctor.verificationStatus !==
            'verified'
        ) {
            return fail(
                res,
                403,
                'Verified doctor access required.'
            );
        }

        return ok(
            res,
            {
                patients:
                    db.patients.map(
                        x => ({
                            id:
                                x.id,

                            name:
                                x.name,

                            phone:
                                x.phone
                        })
                    )
            }
        );
    }

    /*
    =========================================================
    DOCTOR PRESCRIPTIONS
    =========================================================
    */

    if (
        m === 'GET' &&
        p ===
        '/api/doctor/prescriptions'
    ) {
        if (
            !role(
                user,
                'doctor'
            )
        ) {
            return fail(
                res,
                403,
                'Doctor access only.'
            );
        }

        const doctor =
            db.doctors.find(
                x =>
                    x.userId ===
                    user.id
            );

        if (
            !doctor ||
            doctor.verificationStatus !==
            'verified'
        ) {
            return fail(
                res,
                403,
                'Verified doctor access required.'
            );
        }

        return ok(
            res,
            {
                prescriptions:
                    db.prescriptions.filter(
                        x =>
                            x.doctorId ===
                            doctor.id
                    )
            }
        );
    }

    /*
    =========================================================
    UNKNOWN API
    =========================================================
    */

    return fail(
        res,
        404,
        'API endpoint not found.'
    );
}

const server =
    http.createServer(
        async (
            req,
            res
        ) => {

            try {
                const u =
                    parse(req);

                if (
                    serve(
                        req,
                        res,
                        u
                    )
                ) {
                    return;
                }

                await router(
                    req,
                    res
                );

            } catch (e) {

                console.error(e);

                if (
                    !res.headersSent
                ) {
                    fail(
                        res,
                        500,
                        'Internal server error.'
                    );
                }
            }
        }
    );

server.listen(
    PORT,
    HOST,
    () => {
        console.log(
            `MediVoice V${APP_VERSION} running on ${HOST}:${PORT}`
        );
    }
);
