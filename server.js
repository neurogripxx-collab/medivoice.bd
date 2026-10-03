/*
========================================================
 MEDIVOICE BACKEND V3.1
 cPanel / Passenger compatible
 API prefix support: /medivoice
========================================================
*/

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

/* ======================================================
   CONFIG
====================================================== */

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";

const APP_NAME = "Medivoice";
const APP_VERSION = "3.1.0";

const DATA_DIR = path.join(__dirname, "medivoice-data");
const DB_FILE = path.join(DATA_DIR, "database.json");

const SESSION_DAYS = 7;

/* ======================================================
   DATABASE
====================================================== */

function defaultDatabase() {
    return {
        users: [],
        patientProfiles: [],
        doctorProfiles: [],
        prescriptions: [],
        medicines: [],
        healthRecords: [],
        auditLogs: []
    };
}

function ensureDatabase() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(
            DB_FILE,
            JSON.stringify(defaultDatabase(), null, 2),
            "utf8"
        );
    }
}

function loadDatabase() {
    ensureDatabase();

    try {
        const raw = fs.readFileSync(DB_FILE, "utf8");

        if (!raw.trim()) {
            const db = defaultDatabase();
            saveDatabase(db);
            return db;
        }

        const db = JSON.parse(raw);

        const base = defaultDatabase();

        for (const key of Object.keys(base)) {
            if (!Array.isArray(db[key])) {
                db[key] = [];
            }
        }

        return db;
    } catch (error) {
        console.error("Database read error:", error);

        const db = defaultDatabase();
        saveDatabase(db);

        return db;
    }
}

function saveDatabase(db) {
    ensureDatabase();

    const tempFile = `${DB_FILE}.tmp`;

    fs.writeFileSync(
        tempFile,
        JSON.stringify(db, null, 2),
        "utf8"
    );

    fs.renameSync(tempFile, DB_FILE);
}

/* ======================================================
   BASIC HELPERS
====================================================== */

function now() {
    return new Date().toISOString();
}

function makeId(prefix) {
    return (
        prefix +
        "_" +
        crypto.randomBytes(12).toString("hex")
    );
}

function cleanString(value, max = 500) {
    if (value === undefined || value === null) {
        return "";
    }

    return String(value).trim().slice(0, max);
}

function normalizeEmail(email) {
    return cleanString(email, 200).toLowerCase();
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* ======================================================
   PASSWORD HASHING
====================================================== */

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");

    const hash = crypto
        .pbkdf2Sync(
            String(password),
            salt,
            100000,
            64,
            "sha512"
        )
        .toString("hex");

    return {
        salt,
        hash
    };
}

function verifyPassword(password, salt, storedHash) {
    const hash = crypto
        .pbkdf2Sync(
            String(password),
            salt,
            100000,
            64,
            "sha512"
        )
        .toString("hex");

    return crypto.timingSafeEqual(
        Buffer.from(hash, "hex"),
        Buffer.from(storedHash, "hex")
    );
}

/* ======================================================
   RESPONSE HELPERS
====================================================== */

function setCommonHeaders(response) {
    response.setHeader(
        "Access-Control-Allow-Origin",
        "*"
    );

    response.setHeader(
        "Access-Control-Allow-Methods",
        "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );

    response.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
    );

    response.setHeader(
        "Content-Type",
        "application/json; charset=utf-8"
    );
}

function send(response, statusCode, payload) {
    setCommonHeaders(response);

    response.writeHead(statusCode);

    response.end(
        JSON.stringify(payload)
    );
}

function success(response, statusCode, data = {}) {
    send(response, statusCode, {
        success: true,
        ...data
    });
}

function failure(response, statusCode, error) {
    send(response, statusCode, {
        success: false,
        error
    });
}

/* ======================================================
   REQUEST BODY
====================================================== */

function readBody(request) {
    return new Promise((resolve, reject) => {
        let body = "";

        request.on("data", chunk => {
            body += chunk.toString();

            if (body.length > 2 * 1024 * 1024) {
                reject(
                    new Error("Request body too large.")
                );

                request.destroy();
            }
        });

        request.on("end", () => {
            if (!body.trim()) {
                resolve({});
                return;
            }

            try {
                resolve(JSON.parse(body));
            } catch (error) {
                reject(
                    new Error("Invalid JSON body.")
                );
            }
        });

        request.on("error", reject);
    });
}

/* ======================================================
   SAFE USER
====================================================== */

function safeUser(user) {
    if (!user) {
        return null;
    }

    return {
        id: user.id,
        role: user.role,
        name: user.name,
        email: user.email,
        phone: user.phone || "",
        verificationStatus:
            user.verificationStatus || null,
        createdAt: user.createdAt
    };
}

/* ======================================================
   SESSIONS
====================================================== */

const sessions = new Map();

function createSession(userId) {
    const token = crypto
        .randomBytes(32)
        .toString("hex");

    sessions.set(token, {
        userId,
        createdAt: Date.now(),
        expiresAt:
            Date.now() +
            SESSION_DAYS * 24 * 60 * 60 * 1000
    });

    return token;
}

function getToken(request) {
    const auth =
        request.headers.authorization || "";

    if (
        auth.startsWith("Bearer ")
    ) {
        return auth.slice(7).trim();
    }

    return null;
}

function getCurrentUser(request, db) {
    const token = getToken(request);

    if (!token) {
        return null;
    }

    const session = sessions.get(token);

    if (!session) {
        return null;
    }

    if (session.expiresAt < Date.now()) {
        sessions.delete(token);
        return null;
    }

    return (
        db.users.find(
            user => user.id === session.userId
        ) || null
    );
}

function requireLogin(request, response, db) {
    const user = getCurrentUser(
        request,
        db
    );

    if (!user) {
        failure(
            response,
            401,
            "Login required."
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
            "Login required."
        );

        return false;
    }

    if (user.role !== role) {
        failure(
            response,
            403,
            "Access denied."
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
            "doctor"
        )
    ) {
        return false;
    }

    if (
        user.verificationStatus !==
        "verified"
    ) {
        failure(
            response,
            403,
            "Doctor account is not verified."
        );

        return false;
    }

    return true;
}

/* ======================================================
   AUDIT
====================================================== */

function audit(
    db,
    userId,
    action,
    details = {}
) {
    db.auditLogs.push({
        id: makeId("audit"),
        userId: userId || null,
        action,
        details,
        createdAt: now()
    });

    if (db.auditLogs.length > 5000) {
        db.auditLogs =
            db.auditLogs.slice(-5000);
    }
}

/* ======================================================
   URL PREFIX NORMALIZATION
======================================================

   cPanel application URL:

       https://gyanverse.xyz/medivoice

   Passenger may send:

       /medivoice/api/health

   But our Node routes are:

       /api/health

   So we remove /medivoice before routing.
====================================================== */

function normalizePathname(pathname) {
    if (!pathname) {
        return "/";
    }

    let cleanPath = pathname;

    if (
        cleanPath === "/medivoice"
    ) {
        return "/";
    }

    if (
        cleanPath.startsWith(
            "/medivoice/"
        )
    ) {
        cleanPath =
            cleanPath.slice(
                "/medivoice".length
            );
    }

    if (!cleanPath.startsWith("/")) {
        cleanPath =
            "/" + cleanPath;
    }

    return cleanPath;
}

/* ======================================================
   ROUTER
====================================================== */

async function router(
    request,
    response
) {
    setCommonHeaders(response);

    if (
        request.method === "OPTIONS"
    ) {
        response.writeHead(204);
        response.end();
        return;
    }

    let parsed;

    try {
        parsed = new URL(
            request.url,
            `http://${request.headers.host || "localhost"}`
        );
    } catch (error) {
        failure(
            response,
            400,
            "Invalid request URL."
        );

        return;
    }

    const method = request.method;

    let pathname =
        normalizePathname(
            parsed.pathname
        );

    const query = parsed.searchParams;

    const db = loadDatabase();

    /* ==================================================
       PUBLIC HEALTH CHECK
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/health"
    ) {
        success(
            response,
            200,
            {
                app: APP_NAME,
                backend: "online",
                version: APP_VERSION,
                time: now()
            }
        );

        return;
    }

    /* ==================================================
       PUBLIC ROOT
    ================================================== */

    if (
        method === "GET" &&
        (
            pathname === "/" ||
            pathname === ""
        )
    ) {
        success(
            response,
            200,
            {
                app: APP_NAME,
                backend: "online",
                version: APP_VERSION,
                message:
                    "MediVoice backend is running."
            }
        );

        return;
    }

    /* ==================================================
       REGISTER
    ================================================== */

    if (
        method === "POST" &&
        pathname === "/api/register"
    ) {
        let body;

        try {
            body = await readBody(request);
        } catch (error) {
            failure(
                response,
                400,
                error.message
            );

            return;
        }

        const name =
            cleanString(body.name, 120);

        const email =
            normalizeEmail(body.email);

        const phone =
            cleanString(body.phone, 50);

        const password =
            String(body.password || "");

        const role =
            cleanString(
                body.role || "patient",
                30
            ).toLowerCase();

        if (!name) {
            failure(
                response,
                400,
                "Name is required."
            );

            return;
        }

        if (
            !email ||
            !isValidEmail(email)
        ) {
            failure(
                response,
                400,
                "Valid email is required."
            );

            return;
        }

        if (
            password.length < 6
        ) {
            failure(
                response,
                400,
                "Password must be at least 6 characters."
            );

            return;
        }

        if (
            role !== "patient" &&
            role !== "doctor"
        ) {
            failure(
                response,
                400,
                "Invalid role."
            );

            return;
        }

        const existing =
            db.users.find(
                user =>
                    user.email === email
            );

        if (existing) {
            failure(
                response,
                409,
                "Email already registered."
            );

            return;
        }

        const passwordData =
            hashPassword(password);

        const user = {
            id: makeId("user"),
            name,
            email,
            phone,
            role,
            passwordHash:
                passwordData.hash,
            passwordSalt:
                passwordData.salt,
            verificationStatus:
                role === "doctor"
                    ? "pending"
                    : "not_required",
            createdAt: now(),
            updatedAt: now()
        };

        db.users.push(user);

        if (role === "patient") {
            db.patientProfiles.push({
                id: user.id,
                userId: user.id,
                name,
                email,
                phone,
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
                createdAt: now(),
                updatedAt: now()
            });
        }

        if (role === "doctor") {
            db.doctorProfiles.push({
                id: user.id,
                userId: user.id,
                name,
                email,
                phone,
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
                createdAt: now(),
                updatedAt: now()
            });
        }

        audit(
            db,
            user.id,
            "REGISTER",
            { role }
        );

        saveDatabase(db);

        success(
            response,
            201,
            {
                user: safeUser(user),
                message:
                    role === "doctor"
                        ? "Doctor registered. Verification is pending."
                        : "Registration successful."
            }
        );

        return;
    }

    /* ==================================================
       LOGIN
    ================================================== */

    if (
        method === "POST" &&
        pathname === "/api/login"
    ) {
        let body;

        try {
            body = await readBody(request);
        } catch (error) {
            failure(
                response,
                400,
                error.message
            );

            return;
        }

        const email =
            normalizeEmail(body.email);

        const password =
            String(body.password || "");

        if (!email || !password) {
            failure(
                response,
                400,
                "Email and password are required."
            );

            return;
        }

        const user =
            db.users.find(
                item =>
                    item.email === email
            );

        if (!user) {
            failure(
                response,
                401,
                "Invalid email or password."
            );

            return;
        }

        let valid = false;

        try {
            valid = verifyPassword(
                password,
                user.passwordSalt,
                user.passwordHash
            );
        } catch (error) {
            valid = false;
        }

        if (!valid) {
            failure(
                response,
                401,
                "Invalid email or password."
            );

            return;
        }

        const token =
            createSession(user.id);

        audit(
            db,
            user.id,
            "LOGIN"
        );

        saveDatabase(db);

        success(
            response,
            200,
            {
                token,
                user: safeUser(user)
            }
        );

        return;
    }

    /* ==================================================
       LOGOUT
    ================================================== */

    if (
        method === "POST" &&
        pathname === "/api/logout"
    ) {
        const token =
            getToken(request);

        const user =
            getCurrentUser(
                request,
                db
            );

        if (token) {
            sessions.delete(token);
        }

        if (user) {
            audit(
                db,
                user.id,
                "LOGOUT"
            );

            saveDatabase(db);
        }

        success(
            response,
            200,
            {
                message:
                    "Logged out successfully."
            }
        );

        return;
    }

    /* ==================================================
       AUTHENTICATED USER
    ================================================== */

    const user =
        requireLogin(
            request,
            response,
            db
        );

    if (!user) {
        return;
    }

    /* ==================================================
       ME
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/me"
    ) {
        let profile = null;

        if (user.role === "patient") {
            profile =
                db.patientProfiles.find(
                    item =>
                        item.userId ===
                        user.id
                );
        }

        if (user.role === "doctor") {
            profile =
                db.doctorProfiles.find(
                    item =>
                        item.userId ===
                        user.id
                );
        }

        success(
            response,
            200,
            {
                user: safeUser(user),
                profile
            }
        );

        return;
    }

    /* ==================================================
       PATIENT PROFILE
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/patient/profile"
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

        const profile =
            db.patientProfiles.find(
                item =>
                    item.userId ===
                    user.id
            );

        success(
            response,
            200,
            {
                profile: profile || null
            }
        );

        return;
    }

    if (
        (
            method === "POST" ||
            method === "PUT" ||
            method === "PATCH"
        ) &&
        pathname === "/api/patient/profile"
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
            body = await readBody(request);
        } catch (error) {
            failure(
                response,
                400,
                error.message
            );

            return;
        }

        let profile =
            db.patientProfiles.find(
                item =>
                    item.userId ===
                    user.id
            );

        if (!profile) {
            profile = {
                id: user.id,
                userId: user.id,
                createdAt: now()
            };

            db.patientProfiles.push(
                profile
            );
        }

        const allowed = [
            "name",
            "phone",
            "dateOfBirth",
            "gender",
            "bloodGroup",
            "address",
            "emergencyContact",
            "nid"
        ];

        for (const key of allowed) {
            if (
                body[key] !== undefined
            ) {
                profile[key] =
                    cleanString(
                        body[key],
                        500
                    );
            }
        }

        profile.updatedAt = now();

        if (profile.name) {
            user.name = profile.name;
        }

        if (profile.phone) {
            user.phone = profile.phone;
        }

        user.updatedAt = now();

        audit(
            db,
            user.id,
            "UPDATE_PATIENT_PROFILE"
        );

        saveDatabase(db);

        success(
            response,
            200,
            {
                profile
            }
        );

        return;
    }

    /* ==================================================
       DOCTOR PROFILE
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/doctor/profile"
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

        const profile =
            db.doctorProfiles.find(
                item =>
                    item.userId ===
                    user.id
            );

        success(
            response,
            200,
            {
                profile:
                    profile || null,
                verificationStatus:
                    user.verificationStatus
            }
        );

        return;
    }

    if (
        (
            method === "POST" ||
            method === "PUT" ||
            method === "PATCH"
        ) &&
        pathname === "/api/doctor/profile"
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

        let body;

        try {
            body = await readBody(request);
        } catch (error) {
            failure(
                response,
                400,
                error.message
            );

            return;
        }

        let profile =
            db.doctorProfiles.find(
                item =>
                    item.userId ===
                    user.id
            );

        if (!profile) {
            profile = {
                id: user.id,
                userId: user.id,
                createdAt: now()
            };

            db.doctorProfiles.push(
                profile
            );
        }

        const allowed = [
            "name",
            "phone",
            "specialization",
            "licenseNumber",
            "chamber",
            "qualification"
        ];

        for (const key of allowed) {
            if (
                body[key] !== undefined
            ) {
                profile[key] =
                    cleanString(
                        body[key],
                        500
                    );
            }
        }

        profile.updatedAt = now();

        if (profile.name) {
            user.name = profile.name;
        }

        if (profile.phone) {
            user.phone = profile.phone;
        }

        user.updatedAt = now();

        audit(
            db,
            user.id,
            "UPDATE_DOCTOR_PROFILE"
        );

        saveDatabase(db);

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

    /* ==================================================
       DOCTOR -> PATIENT LIST
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/doctor/patients"
    ) {
        if (
            !requireVerifiedDoctor(
                response,
                user
            )
        ) {
            return;
        }

        const patients =
            db.patientProfiles.map(
                patient => {
                    const patientUser =
                        db.users.find(
                            item =>
                                item.id ===
                                patient.userId
                        );

                    return {
                        ...patient,
                        user: patientUser
                            ? safeUser(
                                  patientUser
                              )
                            : null
                    };
                }
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

    /* ==================================================
       DOCTOR -> CREATE PRESCRIPTION
    ================================================== */

    if (
        method === "POST" &&
        (
            pathname ===
                "/api/doctor/prescriptions" ||
            pathname ===
                "/api/prescriptions"
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

        let body;

        try {
            body = await readBody(request);
        } catch (error) {
            failure(
                response,
                400,
                error.message
            );

            return;
        }

        const patientId =
            cleanString(
                body.patientId,
                200
            );

        if (!patientId) {
            failure(
                response,
                400,
                "patientId is required."
            );

            return;
        }

        const patient =
            db.users.find(
                item =>
                    item.id ===
                    patientId &&
                    item.role ===
                        "patient"
            );

        if (!patient) {
            failure(
                response,
                404,
                "Patient not found."
            );

            return;
        }

        let medicines =
            body.medicines;

        if (
            typeof medicines ===
            "string"
        ) {
            try {
                medicines =
                    JSON.parse(
                        medicines
                    );
            } catch {
                medicines = [
                    {
                        name: medicines
                    }
                ];
            }
        }

        if (
            !Array.isArray(
                medicines
            )
        ) {
            medicines = [];
        }

        const prescription = {
            id: makeId("rx"),
            doctorId: user.id,
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
                    item => ({
                        name:
                            cleanString(
                                item.name,
                                200
                            ),
                        dosage:
                            cleanString(
                                item.dosage,
                                200
                            ),
                        frequency:
                            cleanString(
                                item.frequency,
                                200
                            ),
                        duration:
                            cleanString(
                                item.duration,
                                200
                            ),
                        instructions:
                            cleanString(
                                item.instructions,
                                500
                            )
                    })
                ),
            createdAt: now(),
            updatedAt: now()
        };

        db.prescriptions.push(
            prescription
        );

        audit(
            db,
            user.id,
            "CREATE_PRESCRIPTION",
            {
                prescriptionId:
                    prescription.id,
                patientId
            }
        );

        saveDatabase(db);

        success(
            response,
            201,
            {
                prescription
            }
        );

        return;
    }

    /* ==================================================
       PATIENT -> PRESCRIPTIONS
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/patient/prescriptions"
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

        const prescriptions =
            db.prescriptions
                .filter(
                    item =>
                        item.patientId ===
                        user.id
                )
                .map(item => {
                    const doctor =
                        db.users.find(
                            doctorUser =>
                                doctorUser.id ===
                                item.doctorId
                        );

                    return {
                        ...item,
                        doctor:
                            doctor
                                ? safeUser(
                                      doctor
                                  )
                                : null
                    };
                });

        success(
            response,
            200,
            {
                prescriptions
            }
        );

        return;
    }

    /* ==================================================
       DOCTOR -> OWN PRESCRIPTIONS
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/doctor/prescriptions"
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

    /* ==================================================
       PATIENT -> MEDICINES
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/patient/medicines"
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

    if (
        method === "POST" &&
        pathname === "/api/patient/medicines"
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
            body = await readBody(request);
        } catch (error) {
            failure(
                response,
                400,
                error.message
            );

            return;
        }

        const medicine = {
            id: makeId("medicine"),
            patientId: user.id,
            name:
                cleanString(
                    body.name,
                    200
                ),
            dosage:
                cleanString(
                    body.dosage,
                    200
                ),
            frequency:
                cleanString(
                    body.frequency,
                    200
                ),
            time:
                cleanString(
                    body.time,
                    100
                ),
            startDate:
                cleanString(
                    body.startDate,
                    50
                ),
            endDate:
                cleanString(
                    body.endDate,
                    50
                ),
            notes:
                cleanString(
                    body.notes,
                    1000
                ),
            active:
                body.active !== false,
            createdAt: now(),
            updatedAt: now()
        };

        if (!medicine.name) {
            failure(
                response,
                400,
                "Medicine name is required."
            );

            return;
        }

        db.medicines.push(
            medicine
        );

        audit(
            db,
            user.id,
            "ADD_MEDICINE",
            {
                medicineId:
                    medicine.id
            }
        );

        saveDatabase(db);

        success(
            response,
            201,
            {
                medicine
            }
        );

        return;
    }

    /* ==================================================
       HEALTH RECORD - GET
    ================================================== */

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
            db.healthRecords.filter(
                item =>
                    item.patientId ===
                    user.id
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

    /* ==================================================
       HEALTH RECORD - POST
    ================================================== */

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
            body = await readBody(request);
        } catch (error) {
            failure(
                response,
                400,
                error.message
            );

            return;
        }

        const record = {
            id: makeId("health"),
            patientId: user.id,

            bloodPressure:
                cleanString(
                    body.bloodPressure,
                    100
                ),

            systolic:
                body.systolic !==
                undefined
                    ? Number(
                          body.systolic
                      )
                    : null,

            diastolic:
                body.diastolic !==
                undefined
                    ? Number(
                          body.diastolic
                      )
                    : null,

            spo2:
                body.spo2 !==
                undefined
                    ? Number(
                          body.spo2
                      )
                    : null,

            pulse:
                body.pulse !==
                undefined
                    ? Number(
                          body.pulse
                      )
                    : null,

            temperature:
                body.temperature !==
                undefined
                    ? Number(
                          body.temperature
                      )
                    : null,

            weight:
                body.weight !==
                undefined
                    ? Number(
                          body.weight
                      )
                    : null,

            notes:
                cleanString(
                    body.notes,
                    2000
                ),

            recordedAt:
                cleanString(
                    body.recordedAt,
                    100
                ) || now(),

            createdAt: now()
        };

        db.healthRecords.push(
            record
        );

        audit(
            db,
            user.id,
            "ADD_HEALTH_RECORD",
            {
                recordId:
                    record.id
            }
        );

        saveDatabase(db);

        success(
            response,
            201,
            {
                record
            }
        );

        return;
    }

    /* ==================================================
       PATIENT BY ID
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/patient/by-id"
    ) {
        const requestedId =
            cleanString(
                query.get("id"),
                200
            );

        if (!requestedId) {
            failure(
                response,
                400,
                "Patient id is required."
            );

            return;
        }

        if (
            user.role === "patient"
        ) {
            if (
                requestedId !==
                user.id
            ) {
                failure(
                    response,
                    403,
                    "You can only view your own patient profile."
                );

                return;
            }
        } else if (
            user.role === "doctor"
        ) {
            if (
                user.verificationStatus !==
                "verified"
            ) {
                failure(
                    response,
                    403,
                    "Doctor account is not verified."
                );

                return;
            }
        } else {
            failure(
                response,
                403,
                "Access denied."
            );

            return;
        }

        const patientUser =
            db.users.find(
                item =>
                    item.id ===
                    requestedId &&
                    item.role ===
                        "patient"
            );

        if (!patientUser) {
            failure(
                response,
                404,
                "Patient not found."
            );

            return;
        }

        const profile =
            db.patientProfiles.find(
                item =>
                    item.userId ===
                    requestedId
            );

        success(
            response,
            200,
            {
                user:
                    safeUser(
                        patientUser
                    ),
                profile:
                    profile || null
            }
        );

        return;
    }

    /* ==================================================
       DOCTOR -> PATIENT HEALTH RECORDS
    ================================================== */

    if (
        method === "GET" &&
        pathname === "/api/doctor/health"
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
                query.get("patientId"),
                200
            );

        if (!patientId) {
            failure(
                response,
                400,
                "patientId is required."
            );

            return;
        }

        const patient =
            db.users.find(
                item =>
                    item.id ===
                    patientId &&
                    item.role ===
                        "patient"
            );

        if (!patient) {
            failure(
                response,
                404,
                "Patient not found."
            );

            return;
        }

        const records =
            db.healthRecords.filter(
                item =>
                    item.patientId ===
                    patientId
            );

        success(
            response,
            200,
            {
                patient:
                    safeUser(
                        patient
                    ),
                records
            }
        );

        return;
    }

    /* ==================================================
       404
    ================================================== */

    failure(
        response,
        404,
        "API endpoint not found."
    );
}

/* ======================================================
   SERVER
====================================================== */

const server = http.createServer(
    async (request, response) => {
        try {
            await router(
                request,
                response
            );
        } catch (error) {
            console.error(
                "Unhandled server error:",
                error
            );

            if (!response.headersSent) {
                failure(
                    response,
                    500,
                    "Internal server error."
                );
            } else {
                response.end();
            }
        }
    }
);

server.on(
    "clientError",
    (error, socket) => {
        console.error(
            "Client error:",
            error
        );

        try {
            socket.end(
                "HTTP/1.1 400 Bad Request\r\n\r\n"
            );
        } catch {}
    }
);

server.listen(
    PORT,
    HOST,
    () => {
        console.log(
            "================================================"
        );

        console.log(
            " MEDIVOICE BACKEND"
        );

        console.log(
            " Version:",
            APP_VERSION
        );

        console.log(
            " Host:",
            HOST
        );

        console.log(
            " Port:",
            PORT
        );

        console.log(
            " API prefix:",
            "/medivoice"
        );

        console.log(
            " Health:",
            "/api/health"
        );

        console.log(
            "================================================"
        );
    }
);
