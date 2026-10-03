/*
===========================================================
 MEDIVOICE BACKEND V3
 Patient + Doctor + Prescription + Health Record API

 Node.js backend
===========================================================

RUN:
    npm install
    npm start

DEFAULT:
    http://localhost:3000

IMPORTANT:
    This backend uses JSON storage for DEVELOPMENT only.
    Do NOT store real patient/NID/medical data in production.
===========================================================
*/

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const url = require("url");

/* =========================================================
CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";

const SESSION_DAYS = 7;

const MAX_BODY_SIZE = 2 * 1024 * 1024;

const DATA_DIR = path.join(
    __dirname,
    "medivoice-data"
);

const DB_FILE = path.join(
    DATA_DIR,
    "database.json"
);


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
        healthRecords: [],
        reports: [],
        sessions: [],
        auditLogs: []
    };

}


function ensureDatabase() {

    if (!fs.existsSync(DATA_DIR)) {

        fs.mkdirSync(
            DATA_DIR,
            {
                recursive: true
            }
        );

    }

    if (!fs.existsSync(DB_FILE)) {

        fs.writeFileSync(
            DB_FILE,
            JSON.stringify(
                emptyDatabase(),
                null,
                2
            ),
            "utf8"
        );

    }

}


ensureDatabase();


function readDB() {

    try {

        const raw =
            fs.readFileSync(
                DB_FILE,
                "utf8"
            );

        const db =
            JSON.parse(raw);

        return {
            ...emptyDatabase(),
            ...db
        };

    }
    catch (err) {

        console.error(
            "Database read error:",
            err.message
        );

        return emptyDatabase();

    }

}


function writeDB(db) {

    const tempFile =
        DB_FILE + ".tmp";

    fs.writeFileSync(
        tempFile,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );

    fs.renameSync(
        tempFile,
        DB_FILE
    );

}


/* =========================================================
GENERAL HELPERS
========================================================= */

function createId(prefix) {

    return (
        prefix +
        "-" +
        crypto
            .randomBytes(10)
            .toString("hex")
            .toUpperCase()
    );

}


function now() {

    return new Date()
        .toISOString();

}


function normalizePhone(phone) {

    return String(
        phone || ""
    )
        .replace(/\s+/g, "")
        .trim();

}


function normalizeNID(nid) {

    return String(
        nid || ""
    )
        .replace(/\s+/g, "")
        .trim();

}


function hashNID(nid) {

    return crypto
        .createHash("sha256")
        .update(
            normalizeNID(nid)
        )
        .digest("hex");

}


/* =========================================================
PASSWORD
========================================================= */

function hashPassword(password) {

    const salt =
        crypto
            .randomBytes(16)
            .toString("hex");

    const hash =
        crypto
            .pbkdf2Sync(
                password,
                salt,
                120000,
                64,
                "sha512"
            )
            .toString("hex");

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
            crypto
                .pbkdf2Sync(
                    password,
                    salt,
                    120000,
                    64,
                    "sha512"
                )
                .toString("hex");

        const a =
            Buffer.from(
                hash,
                "hex"
            );

        const b =
            Buffer.from(
                storedHash,
                "hex"
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
    catch (err) {

        return false;

    }

}


/* =========================================================
HTTP RESPONSE
========================================================= */

function json(
    response,
    status,
    data
) {

    response.writeHead(
        status,
        {
            "Content-Type":
                "application/json; charset=utf-8",

            "Access-Control-Allow-Origin":
                "*",

            "Access-Control-Allow-Headers":
                "Content-Type, Authorization",

            "Access-Control-Allow-Methods":
                "GET,POST,PUT,DELETE,OPTIONS",

            "Cache-Control":
                "no-store"
        }
    );

    response.end(
        JSON.stringify(data)
    );

}


function success(
    response,
    status,
    data = {}
) {

    json(
        response,
        status,
        {
            success: true,
            ...data
        }
    );

}


function error(
    response,
    status,
    message
) {

    json(
        response,
        status,
        {
            success: false,
            error: message
        }
    );

}


/* =========================================================
REQUEST BODY
========================================================= */

function readBody(request) {

    return new Promise(
        (resolve, reject) => {

            let body = "";

            let finished = false;

            request.on(
                "data",
                chunk => {

                    if (finished) {
                        return;
                    }

                    body +=
                        chunk.toString();

                    if (
                        body.length >
                        MAX_BODY_SIZE
                    ) {

                        finished = true;

                        reject(
                            new Error(
                                "Request body too large."
                            )
                        );

                        request.destroy();

                    }

                }
            );

            request.on(
                "end",
                () => {

                    if (finished) {
                        return;
                    }

                    if (
                        !body.trim()
                    ) {

                        resolve({});

                        return;

                    }

                    try {

                        resolve(
                            JSON.parse(body)
                        );

                    }
                    catch (err) {

                        reject(
                            new Error(
                                "Invalid JSON."
                            )
                        );

                    }

                }
            );

            request.on(
                "error",
                err => {

                    if (!finished) {
                        reject(err);
                    }

                }
            );

        }
    );

}


/* =========================================================
SAFE USER
========================================================= */

function safeUser(user) {

    return {

        id: user.id,

        role: user.role,

        name: user.name,

        phone: user.phone,

        status: user.status,

        createdAt: user.createdAt

    };

}


/* =========================================================
SESSION
========================================================= */

function createSession(
    userId,
    role
) {

    const db =
        readDB();

    const token =
        crypto
            .randomBytes(48)
            .toString("hex");

    const expiresAt =
        new Date(
            Date.now() +
            SESSION_DAYS *
            24 *
            60 *
            60 *
            1000
        ).toISOString();

    db.sessions.push({

        id:
            createId("SES"),

        token,

        userId,

        role,

        createdAt:
            now(),

        expiresAt

    });

    writeDB(db);

    return token;

}


function getToken(request) {

    const authorization =
        request.headers.authorization ||
        "";

    if (
        !authorization.startsWith(
            "Bearer "
        )
    ) {

        return null;

    }

    return authorization
        .slice(7)
        .trim();

}


function authenticate(request) {

    const token =
        getToken(request);

    if (!token) {

        return null;

    }

    const db =
        readDB();

    const session =
        db.sessions.find(
            item =>
                item.token === token &&
                new Date(
                    item.expiresAt
                ).getTime() >
                Date.now()
        );

    if (!session) {

        return null;

    }

    const user =
        db.users.find(
            item =>
                item.id ===
                session.userId
        );

    if (!user) {

        return null;

    }

    return {

        user,

        session

    };

}


/* =========================================================
AUDIT
========================================================= */

function audit(
    action,
    actor,
    targetId,
    details = ""
) {

    const db =
        readDB();

    db.auditLogs.push({

        id:
            createId("AUD"),

        action,

        actorId:
            actor
                ? actor.id
                : null,

        actorRole:
            actor
                ? actor.role
                : null,

        targetId:
            targetId ||
            null,

        details,

        createdAt:
            now()

    });

    writeDB(db);

}


/* =========================================================
ROLE CHECK
========================================================= */

function requireRole(
    response,
    user,
    role
) {

    if (
        user.role !== role
    ) {

        error(
            response,
            403,
            `${role} access only.`
        );

        return false;

    }

    return true;

}


/* =========================================================
ROUTER
========================================================= */

async function router(
    request,
    response
) {

    const parsed =
        url.parse(
            request.url,
            true
        );

    const pathname =
        parsed.pathname;

    const method =
        String(
            request.method ||
            "GET"
        ).toUpperCase();


    /* =====================================================
       CORS
    ===================================================== */

    if (
        method === "OPTIONS"
    ) {

        response.writeHead(
            204,
            {
                "Access-Control-Allow-Origin":
                    "*",

                "Access-Control-Allow-Headers":
                    "Content-Type, Authorization",

                "Access-Control-Allow-Methods":
                    "GET,POST,PUT,DELETE,OPTIONS"
            }
        );

        response.end();

        return;

    }


    /* =====================================================
       HEALTH
    ===================================================== */

    if (
        method === "GET" &&
        pathname === "/api/health"
    ) {

        success(
            response,
            200,
            {

                app:
                    "Medivoice",

                backend:
                    "online",

                version:
                    "3.0.0",

                time:
                    now()

            }
        );

        return;

    }


    /* =====================================================
       REGISTER
    ===================================================== */

    if (
        method === "POST" &&
        pathname ===
            "/api/auth/register"
    ) {

        let body;

        try {

            body =
                await readBody(
                    request
                );

        }
        catch (err) {

            error(
                response,
                400,
                err.message
            );

            return;

        }


        const role =
            String(
                body.role ||
                ""
            )
                .trim()
                .toLowerCase();


        if (
            role !== "patient" &&
            role !== "doctor"
        ) {

            error(
                response,
                400,
                "Role must be patient or doctor."
            );

            return;

        }


        const name =
            String(
                body.name ||
                ""
            ).trim();

        const phone =
            normalizePhone(
                body.phone
            );

        const password =
            String(
                body.password ||
                ""
            );


        if (
            !name ||
            !phone ||
            !password
        ) {

            error(
                response,
                400,
                "Name, phone and password are required."
            );

            return;

        }


        if (
            password.length < 8
        ) {

            error(
                response,
                400,
                "Password must be at least 8 characters."
            );

            return;

        }


        const db =
            readDB();


        const existingUser =
            db.users.find(
                user =>
                    user.phone ===
                    phone
            );


        if (existingUser) {

            error(
                response,
                409,
                "এই মোবাইল নম্বর দিয়ে account already আছে।"
            );

            return;

        }


        /* -------------------------------------------------
           PATIENT VALIDATION
        ------------------------------------------------- */

        let nidHash = null;

        if (
            role === "patient"
        ) {

            const nid =
                normalizeNID(
                    body.nid
                );

            if (!nid) {

                error(
                    response,
                    400,
                    "Patient registration-এর জন্য NID required."
                );

                return;

            }

            nidHash =
                hashNID(
                    nid
                );


            const duplicate =
                db.patients.find(
                    patient =>
                        patient.nidHash ===
                        nidHash
                );


            if (duplicate) {

                error(
                    response,
                    409,
                    "এই NID ইতিমধ্যে registered."
                );

                return;

            }

        }


        /* -------------------------------------------------
           PASSWORD
        ------------------------------------------------- */

        const passwordData =
            hashPassword(
                password
            );


        /* -------------------------------------------------
           USER ID
        ------------------------------------------------- */

        const userId =
            role === "patient"
                ? createId("PAT")
                : createId("DOC");


        const user = {

            id:
                userId,

            role,

            name,

            phone,

            passwordHash:
                passwordData.hash,

            passwordSalt:
                passwordData.salt,

            status:
                role === "doctor"
                    ? "pending_verification"
                    : "active",

            createdAt:
                now()

        };


        db.users.push(
            user
        );


        /* -------------------------------------------------
           PATIENT PROFILE
        ------------------------------------------------- */

        if (
            role === "patient"
        ) {

            db.patients.push({

                id:
                    userId,

                userId:
                    userId,

                name,

                phone,

                nidHash,

                photo:
                    null,

                dateOfBirth:
                    body.dateOfBirth ||
                    null,

                gender:
                    body.gender ||
                    null,

                bloodGroup:
                    body.bloodGroup ||
                    null,

                emergencyContact:
                    body.emergencyContact ||
                    null,

                createdAt:
                    now()

            });

        }


        /* -------------------------------------------------
           DOCTOR PROFILE
        ------------------------------------------------- */

        if (
            role === "doctor"
        ) {

            db.doctors.push({

                id:
                    userId,

                userId:
                    userId,

                name,

                phone,

                specialty:
                    String(
                        body.specialty ||
                        ""
                    ).trim(),

                bmdcNumber:
                    String(
                        body.bmdcNumber ||
                        ""
                    ).trim(),

                verificationStatus:
                    "pending",

                createdAt:
                    now()

            });

        }


        writeDB(
            db
        );


        audit(
            "REGISTER",
            user,
            user.id,
            "New " +
            role +
            " account"
        );


        const token =
            createSession(
                user.id,
                user.role
            );


        success(
            response,
            201,
            {

                message:
                    role === "doctor"
                        ? "Doctor account created. Verification required."
                        : "Patient account created.",

                token,

                user:
                    safeUser(
                        user
                    )

            }
        );

        return;

    }


    /* =====================================================
       LOGIN
    ===================================================== */

    if (
        method === "POST" &&
        pathname ===
            "/api/auth/login"
    ) {

        let body;

        try {

            body =
                await readBody(
                    request
                );

        }
        catch (err) {

            error(
                response,
                400,
                err.message
            );

            return;

        }


        const phone =
            normalizePhone(
                body.phone
            );

        const password =
            String(
                body.password ||
                ""
            );


        const db =
            readDB();


        const user =
            db.users.find(
                item =>
                    item.phone ===
                    phone
            );


        if (
            !user ||
            !verifyPassword(
                password,
                user.passwordSalt,
                user.passwordHash
            )
        ) {

            error(
                response,
                401,
                "মোবাইল বা password সঠিক নয়।"
            );

            return;

        }


        if (
            user.status ===
            "blocked"
        ) {

            error(
                response,
                403,
                "Account blocked."
            );

            return;

        }


        const token =
            createSession(
                user.id,
                user.role
            );


        audit(
            "LOGIN",
            user,
            user.id,
            "Successful login"
        );


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


    /* =====================================================
       LOGOUT
    ===================================================== */

    if (
        method === "POST" &&
        pathname ===
            "/api/auth/logout"
    ) {

        const token =
            getToken(
                request
            );

        if (token) {

            const db =
                readDB();

            const session =
                db.sessions.find(
                    item =>
                        item.token ===
                        token
                );


            db.sessions =
                db.sessions.filter(
                    item =>
                        item.token !==
                        token
                );


            writeDB(
                db
            );


            if (session) {

                const user =
                    db.users.find(
                        item =>
                            item.id ===
                            session.userId
                    );


                if (user) {

                    audit(
                        "LOGOUT",
                        user,
                        user.id,
                        "User logout"
                    );

                }

            }

        }


        success(
            response,
            200
        );

        return;

    }


    /* =====================================================
       PRIVATE ROUTES
    ===================================================== */

    const current =
        authenticate(
            request
        );


    if (!current) {

        error(
            response,
            401,
            "Login required."
        );

        return;

    }


    const db =
        readDB();

    const user =
        current.user;


    /* =====================================================
       ME
    ===================================================== */

    if (
        method === "GET" &&
        pathname === "/api/me"
    ) {

        let profile = null;


        if (
            user.role ===
            "patient"
        ) {

            profile =
                db.patients.find(
                    item =>
                        item.userId ===
                        user.id
                ) ||
                null;

        }


        if (
            user.role ===
            "doctor"
        ) {

            profile =
                db.doctors.find(
                    item =>
                        item.userId ===
                        user.id
                ) ||
                null;

        }


        success(
            response,
            200,
            {

                user:
                    safeUser(
                        user
                    ),

                profile

            }
        );

        return;

    }


    /* =====================================================
       PATIENT PROFILE
    ===================================================== */

    if (
        method === "GET" &&
        pathname ===
            "/api/patient/profile"
    ) {

        if (
            !requireRole(
                response,
                user,
                "patient"
            )
        ) {
            return;
        }


        const patient =
            db.patients.find(
                item =>
                    item.userId ===
                    user.id
            );


        success(
            response,
            200,
            {

                patient:
                    patient ||
                    null

            }
        );

        return;

    }


    /* =====================================================
       DOCTOR PROFILE
    ===================================================== */

    if (
        method === "GET" &&
        pathname ===
            "/api/doctor/profile"
    ) {

        if (
            !requireRole(
                response,
                user,
                "doctor"
            )
        ) {
            return;
        }


        const doctor =
            db.doctors.find(
                item =>
                    item.userId ===
                    user.id
            );


        success(
            response,
            200,
            {

                doctor:
                    doctor ||
                    null

            }
        );

        return;

    }


    /* =====================================================
       DOCTOR PATIENT LIST
       VERIFIED DOCTOR ONLY
    ===================================================== */

    if (
        method === "GET" &&
        pathname ===
            "/api/doctor/patients"
    ) {

        if (
            !requireRole(
                response,
                user,
                "doctor"
            )
        ) {
            return;
        }


        const doctor =
            db.doctors.find(
                item =>
                    item.userId ===
                    user.id
            );


        if (
            !doctor ||
            doctor.verificationStatus !==
                "verified"
        ) {

            error(
                response,
                403,
                "Verified doctor access required."
            );

            return;

        }


        const patients =
            db.patients.map(
                patient => ({

                    id:
                        patient.id,

                    name:
                        patient.name,

                    phone:
                        patient.phone,

                    photo:
                        patient.photo,

                    dateOfBirth:
                        patient.dateOfBirth,

                    gender:
                        patient.gender,

                    bloodGroup:
                        patient.bloodGroup,

                    createdAt:
                        patient.createdAt

                })
            );


        success(
            response,
            200,
            {
                patients
            }
        );

        return;

    }


    /* =====================================================
       DOCTOR CREATE PRESCRIPTION
    ===================================================== */

    if (
        method === "POST" &&
        pathname ===
            "/api/prescriptions"
    ) {

        if (
            !requireRole(
                response,
                user,
                "doctor"
            )
        ) {
            return;
        }


        const doctor =
            db.doctors.find(
                item =>
                    item.userId ===
                    user.id
            );


        if (
            !doctor ||
            doctor.verificationStatus !==
                "verified"
        ) {

            error(
                response,
                403,
                "Doctor verification required before prescription."
            );

            return;

        }


        let body;

        try {

            body =
                await readBody(
                    request
                );

        }
        catch (err) {

            error(
                response,
                400,
                err.message
            );

            return;

        }


        const patientId =
            String(
                body.patientId ||
                ""
            ).trim();


        const patient =
            db.patients.find(
                item =>
                    item.id ===
                    patientId
            );


        if (!patient) {

            error(
                response,
                404,
                "Patient not found."
            );

            return;

        }


        if (
            !Array.isArray(
                body.medicines
            )
        ) {

            error(
                response,
                400,
                "Medicines array required."
            );

            return;

        }


        if (
            body.medicines.length === 0
        ) {

            error(
                response,
                400,
                "At least one medicine is required."
            );

            return;

        }


        const medicines =
            body.medicines.map(
                medicine => ({

                    name:
                        String(
                            medicine.name ||
                            ""
                        ).trim(),

                    dose:
                        String(
                            medicine.dose ||
                            ""
                        ).trim(),

                    food:
                        String(
                            medicine.food ||
                            ""
                        ).trim(),

                    time:
                        String(
                            medicine.time ||
                            ""
                        ).trim(),

                    duration:
                        String(
                            medicine.duration ||
                            ""
                        ).trim()

                })
            );


        const prescription = {

            id:
                createId("RX"),

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

            patientPhoto:
                patient.photo,

            symptoms:
                String(
                    body.symptoms ||
                    ""
                ),

            diagnosis:
                String(
                    body.diagnosis ||
                    ""
                ),

            medicines,

            advice:
                String(
                    body.advice ||
                    ""
                ),

            investigation:
                String(
                    body.investigation ||
                    ""
                ),

            followUp:
                String(
                    body.followUp ||
                    ""
                ),

            status:
                "active",

            createdAt:
                now()

        };


        db.prescriptions.push(
            prescription
        );


        medicines.forEach(
            medicine => {

                db.medicines.push({

                    id:
                        createId("MED"),

                    patientId:
                        patient.id,

                    prescriptionId:
                        prescription.id,

                    doctorId:
                        doctor.id,

                    ...medicine,

                    createdAt:
                        now()

                });

            }
        );


        writeDB(
            db
        );


        audit(
            "CREATE_PRESCRIPTION",
            user,
            prescription.id,
            "Prescription created"
        );


        success(
            response,
            201,
            {

                prescription

            }
        );

        return;

    }


    /* =====================================================
       PATIENT PRESCRIPTIONS
    ===================================================== */

    if (
        method === "GET" &&
        pathname ===
            "/api/patient/prescriptions"
    ) {

        if (
            !requireRole(
                response,
                user,
                "patient"
            )
        ) {
            return;
        }


        const patient =
            db.patients.find(
                item =>
                    item.userId ===
                    user.id
            );


        if (!patient) {

            error(
                response,
                404,
                "Patient profile not found."
            );

            return;

        }


        const prescriptions =
            db.prescriptions.filter(
                item =>
                    item.patientId ===
                    patient.id
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


    /* =====================================================
       DOCTOR PRESCRIPTIONS
    ===================================================== */

    if (
        method === "GET" &&
        pathname ===
            "/api/doctor/prescriptions"
    ) {

        if (
            !requireRole(
                response,
                user,
                "doctor"
            )
        ) {
            return;
        }


        const doctor =
            db.doctors.find(
                item =>
                    item.userId ===
                    user.id
            );


        if (
            !doctor ||
            doctor.verificationStatus !==
                "verified"
        ) {

            error(
                response,
                403,
                "Verified doctor access required."
            );

            return;

        }


        const prescriptions =
            db.prescriptions.filter(
                item =>
                    item.doctorId ===
                    user.id
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


    /* =====================================================
       PATIENT MEDICINES
    ===================================================== */

    if (
        method === "GET" &&
        pathname ===
            "/api/patient/medicines"
    ) {

        if (
            !requireRole(
                response,
                user,
                "patient"
            )
        ) {
            return;
        }


        const medicines =
            db.medicines.filter(
                item =>
                    item.patientId ===
                    user.id
            );


        success(
            response,
            200,
            {
                medicines
            }
        );

        return;

    }


    /* =====================================================
       ADD HEALTH RECORD
    ===================================================== */

    if (
        method === "POST" &&
        pathname === "/api/health"
    ) {

        if (
            !requireRole(
                response,
                user,
                "patient"
            )
        ) {
            return;
        }


        let body;

        try {

            body =
                await readBody(
                    request
                );

        }
        catch (err) {

            error(
                response,
                400,
                err.message
            );

            return;

        }


        const type =
            String(
                body.type ||
                ""
            ).trim();

        const value =
            String(
                body.value ||
                ""
            ).trim();

        const unit =
            String(
                body.unit ||
                ""
            ).trim();


        if (
            !type ||
            !value
        ) {

            error(
                response,
                400,
                "type and value required."
            );

            return;

        }


        const record = {

            id:
                createId("HLT"),

            patientId:
                user.id,

            type,

            value,

            unit,

            createdAt:
                now()

        };


        db.healthRecords.push(
            record
        );


        writeDB(
            db
        );


        audit(
            "ADD_HEALTH_RECORD",
            user,
            record.id,
            type
        );


        success(
            response,
            201,
            {
                record
            }
        );

        return;

    }


    /* =====================================================
       GET HEALTH RECORDS
    ===================================================== */

    if (
        method === "GET" &&
        pathname === "/api/health"
    ) {

        if (
            !requireRole(
                response,
                user,
                "patient"
            )
        ) {
            return;
        }


        const records =
            db.healthRecords
                .filter(
                    record =>
                        record.patientId ===
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
                );


        success(
            response,
            200,
            {
                records
            }
        );

        return;

    }


    /* =====================================================
       PATIENT BY ID
    ===================================================== */

    if (
        method === "GET" &&
        pathname ===
            "/api/patient/by-id"
    ) {

        const patientId =
            String(
                parsed.query.id ||
                ""
            ).trim();


        if (!patientId) {

            error(
                response,
                400,
                "Patient ID required."
            );

            return;

        }


        const patient =
            db.patients.find(
                item =>
                    item.id ===
                    patientId
            );


        if (!patient) {

            error(
                response,
                404,
                "Patient not found."
            );

            return;

        }


        /* -----------------------------------------------
           PATIENT CAN VIEW OWN PROFILE
           VERIFIED DOCTOR CAN VIEW PATIENT
        ------------------------------------------------ */

        if (
            user.role ===
            "patient"
        ) {

            if (
                user.id !==
                patient.userId
            ) {

                error(
                    response,
                    403,
                    "Permission denied."
                );

                return;

            }

        }
        else if (
            user.role ===
            "doctor"
        ) {

            const doctor =
                db.doctors.find(
                    item =>
                        item.userId ===
                        user.id
                );


            if (
                !doctor ||
                doctor.verificationStatus !==
                    "verified"
            ) {

                error(
                    response,
                    403,
                    "Verified doctor access required."
                );

                return;

            }

        }
        else {

            error(
                response,
                403,
                "Permission denied."
            );

            return;

        }


        success(
            response,
            200,
            {

                patient: {

                    id:
                        patient.id,

                    name:
                        patient.name,

                    photo:
                        patient.photo,

                    dateOfBirth:
                        patient.dateOfBirth,

                    gender:
                        patient.gender,

                    bloodGroup:
                        patient.bloodGroup

                }

            }
        );

        return;

    }


    /* =====================================================
       404
    ===================================================== */

    error(
        response,
        404,
        "API endpoint not found."
    );

}


/* =========================================================
SERVER
========================================================= */

const server =
    http.createServer(
        async (
            request,
            response
        ) => {

            try {

                await router(
                    request,
                    response
                );

            }
            catch (err) {

                console.error(
                    "SERVER ERROR:",
                    err
                );

                if (
                    response.headersSent
                ) {

                    response.end();

                    return;

                }

                error(
                    response,
                    500,
                    "Internal server error."
                );

            }

        }
    );


server.listen(
    PORT,
    HOST,
    () => {

        console.log(
            "===================================="
        );

        console.log(
            " Medivoice Backend V3"
        );

        console.log(
            ` Server: http://localhost:${PORT}`
        );

        console.log(
            ` API:    http://localhost:${PORT}/api/health`
        );

        console.log(
            "===================================="
        );

    }
);
