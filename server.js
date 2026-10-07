'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'medivoice-data');
const DB_FILE = path.join(DATA_DIR, 'database.json');

const APP_VERSION = '6.1.0';
const SESSION_DAYS = 7;
const MAX_BODY = 2 * 1024 * 1024;
const MAX_REPORT_TEXT = 200000;

const ADMIN_KEY = process.env.MEDIVOICE_ADMIN_KEY || '';

const COLLECTIONS = [
  'users',
  'patients',
  'doctors',
  'prescriptions',
  'medicines',
  'medicineEvents',
  'caregivers',
  'healthRecords',
  'reports',
  'partners',
  'partnerDoctors',
  'partnerTests',
  'partnerCommercials',
  'partnerBookings',
  'pharmacyReferrals',
  'sessions',
  'notifications',
  'auditLogs'
];

function emptyDB() {
  const db = {};

  for (const collection of COLLECTIONS) {
    db[collection] = [];
  }

  return db;
}

function ensureDB() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(emptyDB(), null, 2),
      'utf8'
    );
  }
}

function loadDB() {
  ensureDB();

  try {
    const parsed = JSON.parse(
      fs.readFileSync(DB_FILE, 'utf8')
    );

    const db = emptyDB();

    for (const collection of COLLECTIONS) {
      db[collection] = Array.isArray(parsed[collection])
        ? parsed[collection]
        : [];
    }

    return db;
  } catch (error) {
    throw new Error(
      'Database file is invalid: ' + error.message
    );
  }
}

let db = loadDB();

let saveChain = Promise.resolve();

function saveDB() {
  const snapshot = JSON.stringify(db, null, 2);

  saveChain = saveChain.then(async () => {
    const tempFile = DB_FILE + '.tmp';

    await fs.promises.writeFile(
      tempFile,
      snapshot,
      'utf8'
    );

    await fs.promises.rename(
      tempFile,
      DB_FILE
    );
  });

  return saveChain;
}

/* =========================
   BASIC HELPERS
========================= */

function id(prefix = 'id') {
  return (
    prefix +
    '_' +
    crypto.randomBytes(12).toString('hex')
  );
}

function nowISO() {
  return new Date().toISOString();
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

function normalizePhone(value) {
  return cleanString(value, 30)
    .replace(/[^0-9+]/g, '');
}

function validPassword(value) {
  return (
    typeof value === 'string' &&
    value.length >= 6 &&
    value.length <= 128
  );
}

function validRole(value) {
  return [
    'patient',
    'doctor'
  ].includes(value);
}

function findBy(collection, field, value) {
  return db[collection].find(
    item => item[field] === value
  );
}

function getPatientByUser(userId) {
  return findBy(
    'patients',
    'userId',
    userId
  );
}

function getDoctorByUser(userId) {
  return findBy(
    'doctors',
    'userId',
    userId
  );
}

/* =========================
   PASSWORD
========================= */

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString('hex')
) {
  return new Promise(
    (resolve, reject) => {
      crypto.pbkdf2(
        password,
        salt,
        120000,
        64,
        'sha512',
        (error, key) => {
          if (error) {
            reject(error);
            return;
          }

          resolve({
            salt,
            hash: key.toString('hex')
          });
        }
      );
    }
  );
}

function verifyPassword(
  password,
  salt,
  expected
) {
  return new Promise(
    (resolve, reject) => {
      crypto.pbkdf2(
        password,
        salt,
        120000,
        64,
        'sha512',
        (error, key) => {
          if (error) {
            reject(error);
            return;
          }

          const actual =
            Buffer.from(
              key.toString('hex'),
              'utf8'
            );

          const expectedBuffer =
            Buffer.from(
              String(expected),
              'utf8'
            );

          resolve(
            actual.length ===
              expectedBuffer.length &&
            crypto.timingSafeEqual(
              actual,
              expectedBuffer
            )
          );
        }
      );
    }
  );
}

/* =========================
   SESSION
========================= */

function tokenHash(token) {
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
}

function newToken() {
  return crypto
    .randomBytes(48)
    .toString('hex');
}

function createSession(userId) {
  const rawToken = newToken();

  db.sessions = db.sessions.filter(
    session =>
      new Date(session.expiresAt).getTime() >
      Date.now()
  );

  db.sessions.push({
    id: id('sess'),
    userId,
    tokenHash: tokenHash(rawToken),
    createdAt: nowISO(),
    expiresAt:
      new Date(
        Date.now() +
          SESSION_DAYS * 86400000
      ).toISOString()
  });

  return rawToken;
}

function auth(req) {
  const authorization =
    req.headers.authorization || '';

  if (
    !/^Bearer\s+/i.test(
      authorization
    )
  ) {
    return null;
  }

  const rawToken =
    authorization
      .replace(/^Bearer\s+/i, '')
      .trim();

  if (!rawToken) {
    return null;
  }

  const session =
    db.sessions.find(
      item =>
        item.tokenHash ===
        tokenHash(rawToken)
    );

  if (!session) {
    return null;
  }

  if (
    new Date(session.expiresAt)
      .getTime() <= Date.now()
  ) {
    return null;
  }

  return findBy(
    'users',
    'id',
    session.userId
  );
}

/* =========================
   SECURITY
========================= */

const rateMap = new Map();

function rateLimit(
  ip,
  limit = 120,
  windowMs = 60000
) {
  const now = Date.now();

  const item = rateMap.get(ip);

  if (
    !item ||
    now - item.start > windowMs
  ) {
    rateMap.set(ip, {
      start: now,
      count: 1
    });

    return true;
  }

  item.count++;

  return item.count <= limit;
}

setInterval(() => {
  const cutoff =
    Date.now() -
    10 * 60 * 1000;

  for (
    const [key, value]
    of rateMap
  ) {
    if (
      value.start < cutoff
    ) {
      rateMap.delete(key);
    }
  }
}, 10 * 60 * 1000).unref();

function securityHeaders() {
  return {
    'X-Content-Type-Options':
      'nosniff',

    'X-Frame-Options':
      'DENY',

    'Referrer-Policy':
      'strict-origin-when-cross-origin',

    'Permissions-Policy':
      'camera=(self), microphone=(self), geolocation=()',

    'Content-Security-Policy':
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: blob:; " +
      "connect-src 'self' https://cdn.jsdelivr.net; " +
      "worker-src 'self' blob:; " +
      "font-src 'self' data: https://cdn.jsdelivr.net; " +
      "object-src 'none'; " +
      "base-uri 'self'; " +
      "form-action 'self';"
  };
}

function originHeaders(req) {
  const origin =
    req.headers.origin;

  const allowed =
    (process.env.ALLOWED_ORIGINS || '')
      .split(',')
      .map(value => value.trim())
      .filter(Boolean);

  if (
    origin &&
    allowed.includes(origin)
  ) {
    return {
      'Access-Control-Allow-Origin':
        origin,

      'Access-Control-Allow-Credentials':
        'true'
    };
  }

  return {};
}

/* =========================
   RESPONSE
========================= */

function send(
  res,
  status,
  payload,
  extraHeaders = {}
) {
  const body =
    JSON.stringify(payload);

  res.writeHead(
    status,
    {
      'Content-Type':
        'application/json; charset=utf-8',

      'Content-Length':
        Buffer.byteLength(body),

      ...extraHeaders
    }
  );

  res.end(body);
}

function ok(
  res,
  data = {}
) {
  send(
    res,
    200,
    {
      ok: true,
      ...data
    }
  );
}

function sendError(
  res,
  status,
  message,
  code = 'ERROR'
) {
  send(
    res,
    status,
    {
      ok: false,
      error: message,
      code
    }
  );
}

/* =========================
   REQUEST BODY
========================= */

function parseJSON(req) {
  return new Promise(
    (resolve, reject) => {
      let data = '';

      req.on(
        'data',
        chunk => {
          data += chunk;

          if (
            Buffer.byteLength(data) >
            MAX_BODY
          ) {
            reject(
              Object.assign(
                new Error(
                  'Request body too large'
                ),
                { status: 413 }
              )
            );

            req.destroy();
          }
        }
      );

      req.on(
        'end',
        () => {
          if (!data) {
            resolve({});
            return;
          }

          try {
            resolve(
              JSON.parse(data)
            );
          } catch {
            reject(
              Object.assign(
                new Error(
                  'Invalid JSON'
                ),
                { status: 400 }
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

/* =========================
   AUTH GUARD
========================= */

function requireAuth(
  req,
  res,
  roles
) {
  const user = auth(req);

  if (!user) {
    sendError(
      res,
      401,
      'Login required',
      'AUTH_REQUIRED'
    );

    return null;
  }

  if (
    roles &&
    !roles.includes(user.role)
  ) {
    sendError(
      res,
      403,
      'Access denied',
      'FORBIDDEN'
    );

    return null;
  }

  return user;
}

/* =========================
   PUBLIC USER
========================= */

function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    role: user.role,
    status: user.status,
    createdAt: user.createdAt
  };
}

/* =========================
   AUDIT
========================= */

function audit(
  action,
  actorId,
  meta = {}
) {
  db.auditLogs.push({
    id: id('audit'),
    action,
    actorId:
      actorId || null,
    meta,
    createdAt: nowISO()
  });

  if (
    db.auditLogs.length >
    5000
  ) {
    db.auditLogs.splice(
      0,
      db.auditLogs.length - 5000
    );
  }
}

/* =========================
   DOCTOR ACCESS
========================= */

function doctorCanAccessPatient(
  doctorUserId,
  patientId
) {
  const patient =
    findBy(
      'patients',
      'id',
      patientId
    );

  if (!patient) {
    return false;
  }

  return db.prescriptions.some(
    prescription =>
      prescription.doctorUserId ===
        doctorUserId &&
      prescription.patientId ===
        patientId
  );
}

/* =========================
   MAIN ROUTER
========================= */

async function route(
  req,
  res
) {
  const headers = {
    ...securityHeaders(),
    ...originHeaders(req)
  };

  if (
    !rateLimit(
      req.socket.remoteAddress ||
        'unknown'
    )
  ) {
    send(
      res,
      429,
      {
        ok: false,
        error:
          'Too many requests'
      },
      headers
    );

    return;
  }

  if (
    req.method === 'OPTIONS'
  ) {
    res.writeHead(
      204,
      {
        ...headers,

        'Access-Control-Allow-Methods':
          'GET,POST,PUT,PATCH,DELETE,OPTIONS',

        'Access-Control-Allow-Headers':
          'Content-Type, Authorization, X-Admin-Key'
      }
    );

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

  const method =
    req.method;

  try {
    /* =====================
       PUBLIC
    ===================== */

    if (
      method === 'GET' &&
      pathname ===
        '/api/health'
    ) {
      return ok(
        res,
        {
          status: 'healthy',
          version:
            APP_VERSION,
          time: nowISO()
        }
      );
    }

    if (
      method === 'GET' &&
      pathname ===
        '/api/status'
    ) {
      return ok(
        res,
        {
          app:
            'AZAD Health',
          version:
            APP_VERSION,
          storage:
            'json-prototype',
          security:
            'prototype'
        }
      );
    }

    if (
      method === 'GET' &&
      pathname ===
        '/api/version'
    ) {
      return ok(
        res,
        {
          name:
            'AZAD Health',
          version:
            APP_VERSION
        }
      );
    }

    if (
      method === 'GET' &&
      pathname ===
        '/api/partners'
    ) {
      return ok(
        res,
        {
          partners:
            db.partners
        }
      );
    }

    /* =====================
       REGISTER
    ===================== */

    if (
      method === 'POST' &&
      pathname ===
        '/api/auth/register'
    ) {
      const body =
        await parseJSON(req);

      const name =
        cleanString(
          body.name,
          120
        );

      const phone =
        normalizePhone(
          body.phone
        );

      const password =
        body.password;

      const role =
        body.role;

      if (
        !name ||
        phone.length < 6 ||
        !validPassword(password) ||
        !validRole(role)
      ) {
        return sendError(
          res,
          400,
          'Name, valid phone, password (6+) and role are required'
        );
      }

      if (
        findBy(
          'users',
          'phone',
          phone
        )
      ) {
        return sendError(
          res,
          409,
          'Phone already registered'
        );
      }

      const passwordData =
        await hashPassword(
          password
        );

      const user = {
        id: id('usr'),
        name,
        phone,
        role,

        status:
          role === 'doctor'
            ? 'pending_verification'
            : 'active',

        passwordHash:
          passwordData.hash,

        passwordSalt:
          passwordData.salt,

        createdAt:
          nowISO()
      };

      db.users.push(user);

      if (
        role === 'patient'
      ) {
        db.patients.push({
          id: id('pat'),
          userId:
            user.id,
          name,
          phone,
          createdAt:
            nowISO(),
          profile: {}
        });
      } else {
        db.doctors.push({
          id: id('doc'),
          userId:
            user.id,
          name,
          phone,

          verificationStatus:
            'pending_verification',

          specialty: '',
          licenseNumber: '',
          createdAt:
            nowISO()
        });
      }

      audit(
        'auth.register',
        user.id,
        { role }
      );

      await saveDB();

      const token =
        createSession(
          user.id
        );

      await saveDB();

      return ok(
        res,
        {
          user:
            publicUser(
              user
            ),
          token
        }
      );
    }

    /* =====================
       LOGIN
    ===================== */

    if (
      method === 'POST' &&
      pathname ===
        '/api/auth/login'
    ) {
      const body =
        await parseJSON(req);

      const phone =
        normalizePhone(
          body.phone
        );

      const password =
        body.password;

      const user =
        findBy(
          'users',
          'phone',
          phone
        );

      if (
        !user ||
        !validPassword(
          password
        )
      ) {
        return sendError(
          res,
          401,
          'Invalid phone or password',
          'LOGIN_FAILED'
        );
      }

      const valid =
        await verifyPassword(
          password,
          user.passwordSalt,
          user.passwordHash
        );

      if (!valid) {
        return sendError(
          res,
          401,
          'Invalid phone or password',
          'LOGIN_FAILED'
        );
      }

      const token =
        createSession(
          user.id
        );

      audit(
        'auth.login',
        user.id
      );

      await saveDB();

      return ok(
        res,
        {
          user:
            publicUser(
              user
            ),
          token
        }
      );
    }

    /* =====================
       LOGOUT
    ===================== */

    if (
      method === 'POST' &&
      pathname ===
        '/api/auth/logout'
    ) {
      const user =
        auth(req);

      if (user) {
        const rawToken =
          (
            req.headers
              .authorization ||
            ''
          )
            .replace(
              /^Bearer\s+/i,
              ''
            )
            .trim();

        db.sessions =
          db.sessions.filter(
            session =>
              session.tokenHash !==
              tokenHash(
                rawToken
              )
          );

        audit(
          'auth.logout',
          user.id
        );

        await saveDB();
      }

      return ok(res);
    }

    /* =====================
       ME
    ===================== */

    if (
      method === 'GET' &&
      pathname ===
        '/api/me'
    ) {
      const user =
        requireAuth(
          req,
          res
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          user:
            publicUser(
              user
            )
        }
      );
    }

    /* =====================
       PATIENT PROFILE
    ===================== */

    if (
      pathname ===
        '/api/patient/profile' &&
      ['GET', 'PUT', 'PATCH']
        .includes(method)
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const patient =
        getPatientByUser(
          user.id
        );

      if (!patient) {
        return sendError(
          res,
          404,
          'Patient profile not found'
        );
      }

      if (
        method === 'GET'
      ) {
        return ok(
          res,
          {
            profile: {
              ...patient.profile,
              id:
                patient.id,
              name:
                patient.name,
              phone:
                patient.phone
            }
          }
        );
      }

      const body =
        await parseJSON(req);

      patient.name =
        cleanString(
          body.name ||
            patient.name,
          120
        );

      patient.profile = {
        ...patient.profile,

        dob:
          cleanString(
            body.dob,
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
          )
      };

      user.name =
        patient.name;

      audit(
        'patient.profile.update',
        user.id
      );

      await saveDB();

      return ok(
        res,
        {
          profile: {
            ...patient.profile,
            id:
              patient.id,
            name:
              patient.name,
            phone:
              patient.phone
          }
        }
      );
    }

    /* =====================
       PATIENT MEDICINES
    ===================== */

    if (
      pathname ===
        '/api/patient/medicines' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          medicines:
            db.medicines.filter(
              medicine =>
                medicine.patientUserId ===
                user.id
            )
        }
      );
    }

    if (
      pathname ===
        '/api/patient/medicines' &&
      method === 'POST'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const body =
        await parseJSON(req);

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

      if (
        !name ||
        !dose ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(
          time
        )
      ) {
        return sendError(
          res,
          400,
          'Medicine name, dose and valid time are required'
        );
      }

      const medicine = {
        id: id('med'),
        patientUserId:
          user.id,
        name,
        dose,
        time,

        foodRule:
          cleanString(
            body.foodRule,
            60
          ),

        startDate:
          cleanString(
            body.startDate,
            20
          ),

        endDate:
          cleanString(
            body.endDate,
            20
          ),

        source:
          'patient',

        createdAt:
          nowISO()
      };

      db.medicines.push(
        medicine
      );

      audit(
        'medicine.create',
        user.id,
        {
          medicineId:
            medicine.id
        }
      );

      await saveDB();

      return ok(
        res,
        {
          medicine
        }
      );
    }

    const medicineAction =
      pathname.match(
        /^\/api\/patient\/medicines\/([^/]+)\/(taken|missed)$/
      );

    if (
      medicineAction &&
      method === 'POST'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const medicine =
        findBy(
          'medicines',
          'id',
          medicineAction[1]
        );

      if (
        !medicine ||
        medicine.patientUserId !==
          user.id
      ) {
        return sendError(
          res,
          404,
          'Medicine not found'
        );
      }

      const event = {
        id: id('mev'),

        medicineId:
          medicine.id,

        patientUserId:
          user.id,

        status:
          medicineAction[2],

        at: nowISO()
      };

      db.medicineEvents.push(
        event
      );

      await saveDB();

      return ok(
        res,
        {
          event
        }
      );
    }

    const medicineDelete =
      pathname.match(
        /^\/api\/patient\/medicines\/([^/]+)$/
      );

    if (
      medicineDelete &&
      method === 'DELETE'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const index =
        db.medicines.findIndex(
          medicine =>
            medicine.id ===
              medicineDelete[1] &&
            medicine.patientUserId ===
              user.id
        );

      if (index < 0) {
        return sendError(
          res,
          404,
          'Medicine not found'
        );
      }

      db.medicines.splice(
        index,
        1
      );

      audit(
        'medicine.delete',
        user.id,
        {
          medicineId:
            medicineDelete[1]
        }
      );

      await saveDB();

      return ok(res);
    }

    if (
      pathname ===
        '/api/patient/medicine-events' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          events:
            db.medicineEvents
              .filter(
                event =>
                  event.patientUserId ===
                  user.id
              )
              .sort(
                (a, b) =>
                  b.at.localeCompare(
                    a.at
                  )
              )
        }
      );
    }

    /* =====================
       PATIENT HEALTH
    ===================== */

    if (
      pathname ===
        '/api/patient/health' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          records:
            db.healthRecords
              .filter(
                record =>
                  record.patientUserId ===
                  user.id
              )
              .sort(
                (a, b) =>
                  b.createdAt.localeCompare(
                    a.createdAt
                  )
              )
        }
      );
    }

    if (
      pathname ===
        '/api/patient/health' &&
      method === 'POST'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const body =
        await parseJSON(req);

      const type =
        cleanString(
          body.type,
          40
        );

      const value =
        cleanString(
          body.value,
          100
        );

      const unit =
        cleanString(
          body.unit,
          30
        );

      if (
        !type ||
        !value
      ) {
        return sendError(
          res,
          400,
          'Health type and value are required'
        );
      }

      const record = {
        id: id('hr'),

        patientUserId:
          user.id,

        type,
        value,
        unit,

        note:
          cleanString(
            body.note,
            300
          ),

        createdAt:
          nowISO()
      };

      db.healthRecords.push(
        record
      );

      audit(
        'health.create',
        user.id,
        { type }
      );

      await saveDB();

      return ok(
        res,
        {
          record
        }
      );
    }

    /* =====================
       PATIENT PRESCRIPTIONS
    ===================== */

    if (
      pathname ===
        '/api/patient/prescriptions' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          prescriptions:
            db.prescriptions
              .filter(
                prescription =>
                  prescription.patientUserId ===
                  user.id
              )
              .sort(
                (a, b) =>
                  b.createdAt.localeCompare(
                    a.createdAt
                  )
              )
        }
      );
    }

    /* =====================
       PATIENT REPORTS
    ===================== */

    if (
      pathname ===
        '/api/patient/reports' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          reports:
            db.reports
              .filter(
                report =>
                  report.patientUserId ===
                  user.id
              )
              .sort(
                (a, b) =>
                  b.createdAt.localeCompare(
                    a.createdAt
                  )
              )
        }
      );
    }

    if (
      pathname ===
        '/api/patient/reports' &&
      method === 'POST'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const body =
        await parseJSON(req);

      const text =
        cleanString(
          body.text,
          MAX_REPORT_TEXT
        );

      if (!text) {
        return sendError(
          res,
          400,
          'Report text is required'
        );
      }

      const report = {
        id: id('rpt'),

        patientUserId:
          user.id,

        text,

        source:
          cleanString(
            body.source,
            40
          ) || 'ocr',

        createdAt:
          nowISO()
      };

      db.reports.push(
        report
      );

      audit(
        'report.create',
        user.id,
        {
          reportId:
            report.id
        }
      );

      await saveDB();

      return ok(
        res,
        {
          report
        }
      );
    }

    /* =====================
       CAREGIVERS
    ===================== */

    if (
      pathname ===
        '/api/caregivers' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          caregivers:
            db.caregivers.filter(
              item =>
                item.patientUserId ===
                user.id
            )
        }
      );
    }

    if (
      pathname ===
        '/api/caregivers' &&
      method === 'POST'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const body =
        await parseJSON(req);

      const caregiver = {
        id: id('cg'),

        patientUserId:
          user.id,

        name:
          cleanString(
            body.name,
            120
          ),

        phone:
          normalizePhone(
            body.phone
          ),

        relationship:
          cleanString(
            body.relationship,
            60
          ),

        createdAt:
          nowISO()
      };

      if (
        !caregiver.name ||
        caregiver.phone.length < 6
      ) {
        return sendError(
          res,
          400,
          'Caregiver name and phone are required'
        );
      }

      db.caregivers.push(
        caregiver
      );

      await saveDB();

      return ok(
        res,
        {
          caregiver
        }
      );
    }

    /* =====================
       NOTIFICATIONS
    ===================== */

    if (
      pathname ===
        '/api/notifications' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          notifications:
            db.notifications
              .filter(
                item =>
                  item.userId ===
                  user.id
              )
              .sort(
                (a, b) =>
                  b.createdAt.localeCompare(
                    a.createdAt
                  )
              )
        }
      );
    }

    if (
      pathname ===
        '/api/notifications' &&
      method === 'POST'
    ) {
      const user =
        requireAuth(
          req,
          res
        );

      if (!user) {
        return;
      }

      const body =
        await parseJSON(req);

      const notification = {
        id: id('noti'),

        userId:
          user.id,

        title:
          cleanString(
            body.title,
            160
          ),

        message:
          cleanString(
            body.message,
            500
          ),

        read: false,

        createdAt:
          nowISO()
      };

      db.notifications.push(
        notification
      );

      await saveDB();

      return ok(
        res,
        {
          notification
        }
      );
    }

    /* =====================
       PHARMACY REFERRALS
    ===================== */

    if (
      pathname ===
        '/api/pharmacy/referrals' &&
      method === 'GET'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      return ok(
        res,
        {
          referrals:
            db.pharmacyReferrals.filter(
              item =>
                item.patientUserId ===
                user.id
            )
        }
      );
    }

    if (
      pathname ===
        '/api/pharmacy/referrals' &&
      method === 'POST'
    ) {
      const user =
        requireAuth(
          req,
          res,
          ['patient']
        );

      if (!user) {
        return;
      }

      const body =
        await parseJSON(req);

      const referral = {
        id: id('ref'),

        patientUserId:
          user.id,

        pharmacy:
          cleanString(
            body.pharmacy,
            160
          ),

        medicineIds:
          Array.isArray(
            body.medicineIds
          )
            ? body.medicineIds.slice(
                0,
                50
              )
            : [],

        status:
          'requested',

        createdAt:
          nowISO()
      };

      db.pharmacyReferrals.push(
        referral
      );

      await saveDB();

      return ok(
        res,
        {
          referral
        }
      );
    }

    /* =====================
       DOCTOR CREATE RX
    ===================== */

    if (
      pathname ===
        '/api/prescriptions' &&
      method === 'POST'
    ) {
      const doctor =
        requireAuth(
          req,
          res,
          ['doctor']
        );

      if (!doctor) {
        return;
      }

      if (
        doctor.status !==
        'active'
      ) {
        return sendError(
          res,
          403,
          'Doctor account is not active yet',
          'DOCTOR_NOT_VERIFIED'
        );
      }

      const doctorProfile =
        getDoctorByUser(
          doctor.id
        );

      const body =
        await parseJSON(req);

      const patientUserId =
        cleanString(
          body.patientUserId,
          100
        );

      const patient =
        getPatientByUser(
          patientUserId
        );

      if (!patient) {
        return sendError(
          res,
          404,
          'Patient not found'
        );
      }

      const medicines =
        Array.isArray(
          body.medicines
        )
          ? body.medicines.slice(
              0,
              30
            )
          : [];

      if (
        !medicines.length
      ) {
        return sendError(
          res,
          400,
          'At least one medicine is required'
        );
      }

      const prescription = {
        id: id('rx'),

        patientId:
          patient.id,

        patientUserId,

        doctorUserId:
          doctor.id,

        doctorId:
          doctorProfile
            ? doctorProfile.id
            : null,

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

        createdAt:
          nowISO()
      };

      db.prescriptions.push(
        prescription
      );

      for (
        const item
        of medicines
      ) {
        const medicine = {
          id: id('med'),

          patientUserId,

          name:
            cleanString(
              item.name,
              150
            ),

          dose:
            cleanString(
              item.dose,
              100
            ),

          time:
            cleanString(
              item.time,
              20
            ),

          foodRule:
            cleanString(
              item.foodRule,
              60
            ),

          startDate:
            cleanString(
              item.startDate,
              20
            ),

          endDate:
            cleanString(
              item.endDate,
              20
            ),

          source:
            'doctor',

          prescriptionId:
            prescription.id,

          doctorUserId:
            doctor.id,

          createdAt:
            nowISO()
        };

        if (
          medicine.name &&
          medicine.dose &&
          /^([01]\d|2[0-3]):[0-5]\d$/.test(
            medicine.time
          )
        ) {
          db.medicines.push(
            medicine
          );
        }
      }

      db.notifications.push({
        id: id('noti'),

        userId:
          patientUserId,

        title:
          'নতুন প্রেসক্রিপশন',

        message:
          'আপনার জন্য একজন চিকিৎসক নতুন prescription দিয়েছেন।',

        read: false,

        createdAt:
          nowISO()
      });

      audit(
        'prescription.create',
        doctor.id,
        {
          prescriptionId:
            prescription.id,

          patientUserId
        }
      );

      await saveDB();

      return ok(
        res,
        {
          prescription
        }
      );
    }

    /* =====================
       DOCTOR PATIENTS
    ===================== */

    if (
      pathname ===
        '/api/doctor/patients' &&
      method === 'GET'
    ) {
      const doctor =
        requireAuth(
          req,
          res,
          ['doctor']
        );

      if (!doctor) {
        return;
      }

      const patientUserIds =
        [
          ...new Set(
            db.prescriptions
              .filter(
                prescription =>
                  prescription.doctorUserId ===
                  doctor.id
              )
              .map(
                prescription =>
                  prescription.patientUserId
              )
          )
        ];

      const patients =
        patientUserIds
          .map(
            userId => {
              const user =
                findBy(
                  'users',
                  'id',
                  userId
                );

              const patient =
                getPatientByUser(
                  userId
                );

              if (
                !user ||
                !patient
              ) {
                return null;
              }

              return {
                id:
                  patient.id,

                userId,

                name:
                  user.name,

                phone:
                  user.phone,

                profile:
                  patient.profile
              };
            }
          )
          .filter(Boolean);

      return ok(
        res,
        {
          patients
        }
      );
    }

    /* =====================
       DOCTOR PRESCRIPTIONS
    ===================== */

    if (
      pathname ===
        '/api/doctor/prescriptions' &&
      method === 'GET'
    ) {
      const doctor =
        requireAuth(
          req,
          res,
          ['doctor']
        );

      if (!doctor) {
        return;
      }

      return ok(
        res,
        {
          prescriptions:
            db.prescriptions
              .filter(
                prescription =>
                  prescription.doctorUserId ===
                  doctor.id
              )
              .sort(
                (a, b) =>
                  b.createdAt.localeCompare(
                    a.createdAt
                  )
              )
        }
      );
    }

    /* =====================
       DOCTOR SINGLE PATIENT
    ===================== */

    const doctorPatient =
      pathname.match(
        /^\/api\/doctor\/patients\/([^/]+)$/
      );

    if (
      doctorPatient &&
      method === 'GET'
    ) {
      const doctor =
        requireAuth(
          req,
          res,
          ['doctor']
        );

      if (!doctor) {
        return;
      }

      const patientId =
        doctorPatient[1];

      if (
        !doctorCanAccessPatient(
          doctor.id,
          patientId
        )
      ) {
        return sendError(
          res,
          403,
          'Patient relationship not established'
        );
      }

      const patient =
        findBy(
          'patients',
          'id',
          patientId
        );

      const user =
        findBy(
          'users',
          'id',
          patient.userId
        );

      return ok(
        res,
        {
          patient: {
            id:
              patient.id,

            userId:
              patient.userId,

            name:
              user?.name ||
              patient.name,

            phone:
              user?.phone ||
              patient.phone,

            profile:
              patient.profile
          },

          health:
            db.healthRecords
              .filter(
                record =>
                  record.patientUserId ===
                  patient.userId
              )
              .sort(
                (a, b) =>
                  b.createdAt.localeCompare(
                    a.createdAt
                  )
              ),

          reports:
            db.reports
              .filter(
                report =>
                  report.patientUserId ===
                  patient.userId
              )
              .sort(
                (a, b) =>
                  b.createdAt.localeCompare(
                    a.createdAt
                  )
              ),

          prescriptions:
            db.prescriptions.filter(
              prescription =>
                prescription.patientUserId ===
                  patient.userId &&
                prescription.doctorUserId ===
                  doctor.id
            ),

          medicines:
            db.medicines.filter(
              medicine =>
                medicine.patientUserId ===
                patient.userId
            )
        }
      );
    }

    /* =====================
       ADMIN DOCTOR VERIFY
    ===================== */

    if (
      pathname ===
        '/api/doctor/verify' &&
      method === 'POST'
    ) {
      const adminKey =
        req.headers[
          'x-admin-key'
        ] || '';

      if (
        !ADMIN_KEY ||
        adminKey !==
          ADMIN_KEY
      ) {
        return sendError(
          res,
          403,
          'Valid admin key required',
          'ADMIN_REQUIRED'
        );
      }

      const body =
        await parseJSON(req);

      const user =
        findBy(
          'users',
          'id',
          cleanString(
            body.userId,
            100
          )
        );

      if (
        !user ||
        user.role !==
          'doctor'
      ) {
        return sendError(
          res,
          404,
          'Doctor not found'
        );
      }

      user.status =
        'active';

      const doctor =
        getDoctorByUser(
          user.id
        );

      if (doctor) {
        doctor.verificationStatus =
          'verified';

        doctor.verifiedAt =
          nowISO();
      }

      audit(
        'doctor.verify',
        'admin',
        {
          userId:
            user.id
        }
      );

      await saveDB();

      return ok(
        res,
        {
          user:
            publicUser(
              user
            )
        }
      );
    }

    return sendError(
      res,
      404,
      'Route not found',
      'NOT_FOUND'
    );
  } catch (error) {
    console.error(error);

    return sendError(
      res,
      error.status || 500,
      error.message ||
        'Internal server error',
      'SERVER_ERROR'
    );
  }
}

/* =========================
   SERVER
========================= */

const server =
  http.createServer(
    (req, res) => {
      const headers = {
        ...securityHeaders(),
        ...originHeaders(req)
      };

      /*
       * Header set before routing.
       */
      for (
        const [key, value]
        of Object.entries(headers)
      ) {
        res.setHeader(
          key,
          value
        );
      }

      route(req, res);
    }
  );

server.listen(
  PORT,
  HOST,
  () => {
    console.log(
      `AZAD Health V${APP_VERSION} running on http://${HOST}:${PORT}`
    );
  }
);
