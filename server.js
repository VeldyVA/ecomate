import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifySession from "@fastify/session";
import jwt from "@fastify/jwt";
import nodemailer from "nodemailer";
import axios from "axios";
import dotenv from "dotenv";
import fs from "fs";
import { ConfidentialClientApplication } from "@azure/msal-node";

dotenv.config();

const fastify = Fastify({ logger: true });

// Register JWT plugin
if (!process.env.JWT_SECRET) {
  fastify.log.error("FATAL: JWT_SECRET environment variable is not set.");
  process.exit(1);
}
fastify.register(jwt, {
  secret: process.env.JWT_SECRET,
});

fastify.register(fastifyCookie);
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET || "a-super-secret-for-sessions-that-is-long",
  cookie: { secure: false }, // true kalau pakai https di prod
});

// ==============================
// 🔹 Konfigurasi
// ==============================
const dataverseBaseUrl = process.env.DATAVERSE_URL; // ex: https://ecomindo365.crm5.dynamics.com
const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const ADMIN_EMAILS = process.env.ADMIN_EMAILS.split(","); // ex: admin1@company.com,admin2@company.com

// ==============================
// 🔹 Konfigurasi MSAL dengan Delegated
// ==============================
const msalConfig = {
  auth: {
    clientId: process.env.AZURE_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}`,
  },
  system: {
    loggerOptions: {
      loggerCallback(loglevel, message) {
        console.log(message);
      },
      piiLoggingEnabled: false,
      logLevel: 3,
    },
  },
};

const cca = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.AZURE_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}`,
    clientSecret: process.env.AZURE_CLIENT_SECRET, // wajib
  }
});

// Redirect user ke login Azure
fastify.get("/login", async (req, reply) => {
  const authCodeUrlParameters = {
    scopes: [`${dataverseBaseUrl}/.default`, "offline_access"], // scope untuk Dataverse + refresh token
    redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
  };

  const authUrl = await cca.getAuthCodeUrl(authCodeUrlParameters);
  reply.redirect(authUrl);
});

// ==============================
// 🔹 OTP In-Memory Stores
// ==============================
const otpStore = {}; // For email-based OTPs: { email: { otp, expiresAt } }
const tokenOtpStore = {}; // For token exchange: { otp: { jwt, expiresAt } }

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ==============================
// 🔹 Callback setelah login user (diubah untuk alur OTP)
// ==============================
fastify.get("/auth/callback", async (req, reply) => {
  const code = req.query.code;
  if (!code) {
    return reply.status(400).send({ error: "No authorization code received." });
  }

  try {
    const tokenResponse = await cca.acquireTokenByCode({
      code: req.query.code,
      scopes: [`${dataverseBaseUrl}/.default`, "offline_access"],
      redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
    });

    // Simpan access token di session untuk direct API calls dari browser
    req.session.accessToken = tokenResponse.accessToken;

    const userEmail = tokenResponse.account.username;

    // Dapatkan detail user dari Dataverse untuk disimpan di JWT
    const res = await axios.get(`${dataverseBaseUrl}/api/data/v9.2/ecom_employeepersonalinformations`, {
      headers: {
        Authorization: `Bearer ${tokenResponse.accessToken}`,
        Accept: "application/json"
      },
      params: {
        $filter: `ecom_workemail eq '${userEmail}'`,
        $select: "_ecom_fullname_value"
      }
    });
    const userData = res.data;

    if (!userData.value || userData.value.length === 0 || !userData.value[0]._ecom_fullname_value) {
      throw new Error(`Employee GUID (_ecom_fullname_value) not found for email ${userEmail}`);
    }
    
    const employeeId = userData.value[0]._ecom_fullname_value;
    const userRole = isAdmin(userEmail) ? "admin" : "employee";
    
    // Simpan info penting di session
    req.session.employee_id = employeeId;
    req.session.email = userEmail;
    req.session.role = userRole;

    // Buat JWT jangka panjang (API Key)
    const userPayload = { employeeId, email: userEmail, role: userRole };
    fastify.jwt.sign(userPayload, { expiresIn: '90d' }, (err, longLivedJwt) => {
      if (err) {
        console.error("❌ Error signing JWT:", err);
        return reply.status(500).send({ error: "Failed to sign JWT." });
      }

      // Buat OTP untuk ditukar dengan JWT
      const otp = generateOTP();
      const expiresAt = new Date(new Date().getTime() + 5 * 60000); // 5 menit
      tokenOtpStore[otp] = { jwt: longLivedJwt, expiresAt };
      console.log('OTP generated and stored:', tokenOtpStore);

      // Tampilkan halaman HTML dengan OTP
      reply.type('text/html').send(`
        <html>
          <head>
            <title>Login Success</title>
            <style>
              body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f4f4f9; margin: 0; }
              .container { text-align: center; padding: 40px; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
              h1 { color: #333; }
              p { color: #555; }
              .otp { font-size: 2.5em; font-weight: bold; color: #007bff; letter-spacing: 5px; margin: 20px 0; padding: 10px; background-color: #eef; border-radius: 4px; }
              .expiry { font-size: 0.9em; color: #999; }
            </style>
          </head>
          <body>
            <div class="container">
              <h1>Authentication Successful!</h1>
              <p>Enter this one-time code in your Pusaka agent:</p>
              <div class="otp">${otp.slice(0,3)}-${otp.slice(3,6)}</div>
              <p class="expiry">This code will expire in 5 minutes.</p>
            </div>
          </body>
        </html>
      `);
    });

  } catch (err) {
    console.error("❌ Authentication callback error:", err);
    reply.status(500).send({
      error: "Authentication failed",
      details: err.errorMessage || err.message,
    });
  }
});

// ==============================
// 🔹 Endpoint Baru: Tukar OTP dengan API Key
// ==============================
fastify.post("/exchange-otp", async (req, reply) => {
  console.log('Request to /exchange-otp. tokenOtpStore:', tokenOtpStore);
  let { otp } = req.body;
  if (!otp) {
    return reply.code(400).send({ error: "OTP is required." });
  }

  // Handle OTP with or without hyphen
  otp = otp.replace(/-/g, "");

  const stored = tokenOtpStore[otp];

  if (!stored || new Date() > stored.expiresAt) {
    // Hapus OTP yang sudah expired
    if (stored) delete tokenOtpStore[otp];
    return reply.code(404).send({ error: "OTP not found or has expired." });
  }

  const apiKey = stored.jwt;

  // Hapus OTP setelah berhasil digunakan
  delete tokenOtpStore[otp];

  reply.send({ apiKey });
});


// ==============================
// 🔹 Dataverse App-Level Token Management
// ==============================
let appTokenCache = {
  token: null,
  expiresOn: 0
};

async function getAppLevelDataverseToken() {
  fastify.log.info("Acquiring new application-level Dataverse token...");
  const tokenRequest = {
    scopes: [`${dataverseBaseUrl}/.default`],
  };
  try {
    const response = await cca.acquireTokenByClientCredential(tokenRequest);
    fastify.log.info("Successfully acquired application-level Dataverse token.");
    return response.accessToken;
  } catch (error) {
    fastify.log.error("Failed to acquire application-level token", error.message);
    fastify.log.error("Full error object:", error);
    throw new Error("Could not acquire application-level token for Dataverse.");
  }
}

// ==============================
// 🔹 Helper: Request ke Dataverse (Refactored)
// ==============================
async function dataverseRequest(req, method, entitySet, options = {}) {
  let token;
  // Prioritaskan token user dari session jika ada (untuk alur login via browser)
  if (req.session && req.session.accessToken) {
    fastify.log.info("Using user-delegated token from session.");
    token = req.session.accessToken;
  } else {
    // Jika tidak ada session (misal: request via API Key), gunakan token aplikasi
    fastify.log.info("No user session token found, falling back to application-level token.");
    token = await getAppLevelDataverseToken();
  }

  const res = await axios({
    method,
    url: `${dataverseBaseUrl}/api/data/v9.2/${entitySet}`,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    data: options.data || undefined,
    params: options.params || undefined,
  });

  return res.data;
}

// ==============================
// 🔹 Nodemailer (SMTP Office 365/Gmail)
// ==============================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// ==============================
// 🔹 Role Guard
// ==============================
function isAdmin(email) {
  return ADMIN_EMAILS.includes(email.toLowerCase());
}

// ==============================
// 🔹 Middleware Auth (diperbarui untuk JWT)
// ==============================
fastify.decorate("authenticate", async (req, reply) => {
  // Prioritaskan otentikasi via API Key (JWT) dari header
  if (req.headers.authorization) {
    const [type, token] = req.headers.authorization.split(' ') || [];
    if (type === 'Bearer' && token) {
      try {
        const decoded = fastify.jwt.verify(token);
        req.user = decoded; // payload JWT kita berisi: { employeeId, email, role }
        return; // Sukses, lanjut ke handler
      } catch (err) {
        return reply.code(401).send({ error: "Invalid API Key." });
      }
    }
  }

  // Fallback ke otentikasi via session cookie (untuk browser)
  if (req.session && req.session.accessToken && req.session.employee_id) {
    req.user = {
      employeeId: req.session.employee_id,
      email: req.session.email,
      role: req.session.role
    };
    return; // Sukses, lanjut ke handler
  }

  // Jika keduanya gagal
  return reply.code(401).send({ error: "Not authenticated. Please login or provide an API Key." });
});


// ==============================
// 🔹 Endpoint
// ==============================

fastify.get("/whoami", { preValidation: [fastify.authenticate] }, async (request, reply) => {
  // Setelah middleware authenticate, req.user sudah pasti ada.
  return request.user;
});

// ... (sisa endpoint tidak perlu diubah karena bergantung pada middleware 'authenticate') ...

// ==============================
// 🔹 Admin: Search and Get Employee Profile
// ==============================
fastify.get("/admin/profile/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  console.log("Request received at /admin/profile/search"); // New log
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { id, code, email, name } = req.query;

  let filter = "";
  if (id) {
    filter = `ecom_employeepersonalinformationid eq '${id}'`;
  } else if (code) {
    filter = `ecom_employeeid eq '${code}'`;
  } else if (email) {
    filter = `ecom_workemail eq '${email}'`;
  } else if (name) {
    filter = `ecom_employeename eq '${name}'`;
  } else {
    return reply.code(400).send({ message: "Setidaknya satu dari 'id', 'code', 'email', atau 'name' harus diberikan." });
  }

  try {
    const personalInfoData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
      params: {
        $filter: filter,
        $select: [
          "ecom_employeepersonalinformationid", "ecom_employeeid", "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
          "ecom_phonenumber", "ecom_status", "ecom_startwork",
          "ecom_workexperience",
          "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
          "ecom_emergencycontactrelationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
          "ecom_profilepicture", "ecom_notes", "ecom_bankaccountnumber", "ecom_bpjsnumber",
          "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
          "ecom_religion", "ecom_bankname", "ecom_personalemail", "ecom_workemail"
        ].join(",")
      }
    });

    if (!personalInfoData.value || personalInfoData.value.length === 0) {
      return reply.code(404).send({ message: "Personal information record not found for the provided criteria." });
    }

    return personalInfoData.value;

  } catch (err) {
    console.error("❌ Error searching employee profile:", err.response ? JSON.stringify(err.response.data, null, 2) : err.message);
    reply.status(500).send({
      error: "Failed to search employee profile",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});


// 5. PATCH update profile (Admin only)
fastify.patch("/profile/:employeeId", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { employeeId } = req.params; 

  try {
    const personalInfoData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
      params: {
        $filter: `_ecom_fullname_value eq ${employeeId}`,
        $select: "ecom_employeepersonalinformationid"
      }
    });

    if (!personalInfoData.value || personalInfoData.value.length === 0) {
      return reply.code(404).send({ message: "Personal information record not found for this employee." });
    }
    const personalInfoId = personalInfoData.value[0].ecom_employeepersonalinformationid;

    const allowedFields = [
      "ecom_gender", "ecom_dateofbirth", "ecom_phonenumber", "ecom_emergencycontactname",
      "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber", "ecom_emergencycontactrelationship",
      "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber", "ecom_notes", "ecom_bankaccountnumber",
      "ecom_bpjsnumber", "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent",
      "ecom_placeofbirth", "ecom_religion", "ecom_bankname", "ecom_personalemail", "ecom_workexperience"
    ];

    const updates = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }

    if (Object.keys(updates).length === 0) {
        return reply.code(400).send({ message: "No valid fields to update were provided." });
    }

    await dataverseRequest(req, "patch", `ecom_employeepersonalinformations(${personalInfoId})`, { data: updates });

    return { message: "Profile updated successfully." };

  } catch (err) {
    console.error("❌ Error updating profile:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to update profile",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});



console.log("JWT_SECRET:", process.env.JWT_SECRET ? "Loaded" : "Not Found - Using Default");
console.log("ADMIN_EMAILS:", process.env.ADMIN_EMAILS);

// ==============================
// 🔹 Start server
// ==============================
fastify.listen({ port: process.env.PORT || 3000, host: "0.0.0.0" }, (err, address) => {
  if (err) throw err;
  fastify.log.info(`🚀 Server running at ${address}`);
});

fastify.get("/healthz", async (req, reply) => {
  return { status: "ok" };
});

// ==============================
// 🔹 Leave Helper (Refactored)
// ==============================

// Daftar hari libur nasional (dapat diperbarui atau dipindahkan ke database)
// Format: YYYY-MM-DD
const PUBLIC_HOLIDAYS = new Set([
  "2024-01-01", "2024-02-08", "2024-02-09", "2024-02-10", "2024-03-11", 
  "2024-03-12", "2024-03-29", "2024-03-31", "2024-04-08", "2024-04-09", 
  "2024-04-10", "2024-04-11", "2024-04-12", "2024-04-15", "2024-05-01", 
  "2024-05-09", "2024-05-10", "2024-05-23", "2024-05-24", "2024-06-01", 
  "2024-06-17", "2024-06-18", "2024-07-07", "2024-08-17", "2024-09-16", 
  "2024-12-25", "2024-12-26",
  // 2025 (contoh)
  "2025-01-01", "2025-01-29", "2025-03-03", "2025-03-21", "2025-03-31",
  "2025-04-01", "2025-04-18", "2025-05-01", "2025-05-12", "2025-05-29",
  "2025-06-01", "2025-06-06", "2025-08-17", "2025-09-05", "2025-12-25"
]);

function parseDateUTC(str) {
  const [y, m, d] = str.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d));
}

function formatDateUTC(date) {
  const pad = n => (n < 10 ? "0" + n : n);
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

function isWorkday(date) {
  const dow = date.getUTCDay();
  const dateStr = formatDateUTC(date);
  // Bukan Sabtu (6) atau Minggu (0) dan tidak ada di daftar hari libur
  return dow !== 0 && dow !== 6 && !PUBLIC_HOLIDAYS.has(dateStr);
}

function calculateEndDate(startDateStr, days) {
  const start = parseDateUTC(startDateStr);
  let workDaysCounted = 0;
  const current = new Date(start);

  // Jika hari pertama adalah hari kerja, hitung sebagai hari pertama
  if (isWorkday(current)) {
    workDaysCounted = 1;
  }

  // Cari sisa hari cuti
  while (workDaysCounted < days) {
    current.setUTCDate(current.getUTCDate() + 1);
    if (isWorkday(current)) {
      workDaysCounted++;
    }
  }
  return formatDateUTC(current);
}

// ==============================
// 🔹 Cuti: Get Saldo Cuti User
// ==============================
fastify.get("/leave/balance", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { period } = req.query;
  if (!period) {
    return reply.code(400).send({ message: "Parameter 'period' (tahun) wajib diisi." });
  }

  const employeeId = req.user.employeeId;

  try {
    const filter = `ecom_Employee/_ecom_fullname_value eq ${employeeId} and ecom_period eq '${period}'`;

    const balanceData = await dataverseRequest(req, "get", "ecom_leaveusages", {
      params: {
        $filter: filter,
        $select: "ecom_balance,_ecom_leavetype_value,ecom_name,ecom_period,ecom_enddate"
      }
    });

    if (!balanceData.value || balanceData.value.length === 0) {
      return reply.code(404).send({ message: `No leave balance records found for this employee for the period ${period}.` });
    }

    const leaveTypeIds = balanceData.value.map(i => i._ecom_leavetype_value);

    const leaveTypePromises = leaveTypeIds.map(id =>
      dataverseRequest(req, "get", `ecom_leavetypes(${id})`, {
        params: { $select: "ecom_name,ecom_quota" }
      })
    );
    const leaveTypes = await Promise.all(leaveTypePromises);

    const balances = balanceData.value.map((item, i) => ({
      leave_type_id: leaveTypeIds[i],
      leave_type_name: leaveTypes[i]?.ecom_name || "(unknown)",
      quota: leaveTypes[i]?.ecom_quota || 0,
      balance: item.ecom_balance,
      end_date: item.ecom_enddate
    }));

    return balances;

  } catch (err) {
    console.error("❌ Error fetching leave balance:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch leave balance",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Admin: Search for employee's leave balance
// ==============================
fastify.get("/admin/leave-balance/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { employeeId, email, name, period } = req.query;

  if (!period) {
    return reply.code(400).send({ message: "Parameter 'period' (tahun) wajib diisi." });
  }

  if (!employeeId && !email && !name) {
    return reply.code(400).send({ message: "Either employeeId, email or name must be provided." });
  }

  let employeeFilter;
  if (employeeId) {
    employeeFilter = `ecom_Employee/_ecom_fullname_value eq ${employeeId}`;
  } else {
    let personalInfoFilter;
    if (email) {
      personalInfoFilter = `ecom_workemail eq '${email}'`;
    } else { // name
      personalInfoFilter = `ecom_employeename eq '${name}'`;
    }

    try {
      fastify.log.info(`Searching for employee with filter: ${personalInfoFilter}`);
      const userData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
        params: {
          $filter: personalInfoFilter,
          $select: "_ecom_fullname_value"
        }
      });

      if (!userData.value || userData.value.length === 0 || !userData.value[0]._ecom_fullname_value) {
        fastify.log.warn({ msg: "Employee lookup failed", filter: personalInfoFilter, result: userData.value });
        return reply.code(404).send({ message: `Employee not found for the provided criteria.` });
      }
      const foundEmployeeId = userData.value[0]._ecom_fullname_value;
      employeeFilter = `ecom_Employee/_ecom_fullname_value eq ${foundEmployeeId}`;
    } catch (err) {
      console.error("❌ Error fetching employee by email/name:", err.response?.data || err.message);
      return reply.status(500).send({
        error: "Failed to fetch employee by email/name",
        details: err.response?.data?.error?.message || err.message,
      });
    }
  }

  try {
    const filter = `${employeeFilter} and ecom_period eq '${period}'`;

    const balanceData = await dataverseRequest(req, "get", "ecom_leaveusages", {
      params: {
        $filter: filter,
        $select: "ecom_balance,_ecom_leavetype_value,ecom_name,ecom_period,ecom_enddate"
      }
    });

    const leaveTypeIds = balanceData.value.map(i => i._ecom_leavetype_value);

    const leaveTypePromises = leaveTypeIds.map(id =>
      dataverseRequest(req, "get", `ecom_leavetypes(${id})`, {
        params: { $select: "ecom_name,ecom_quota" }
      })
    );
    const leaveTypes = await Promise.all(leaveTypePromises);
    
    if (!balanceData.value || balanceData.value.length === 0) {
      return reply.code(404).send({ message: `No leave balance records found for this employee for the period ${period}.` });
    }

    const balances = balanceData.value.map((item, i) => ({
      leave_type_id: leaveTypeIds[i],
      leave_type_name: leaveTypes[i]?.ecom_name || "(unknown)",
      quota: leaveTypes[i]?.ecom_quota || 0,
      balance: item.ecom_balance,
      end_date: item.ecom_enddate
    }));

    return balances;

  } catch (err) {
    console.error("❌ Error fetching leave balance:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch leave balance",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Cuti: Get All Leave Types
// ==============================
fastify.get("/leave/types", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  try {
    const leaveTypesData = await dataverseRequest(req, "get", "ecom_leavetypes", {
      params: {
        $filter: "statecode eq 0",
        $select: "ecom_leavetypeid,ecom_name,ecom_quota"
      }
    });

    return leaveTypesData.value || [];

  } catch (err) {
    console.error("❌ Error fetching leave types:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch leave types",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Cuti: Get User's Leave Requests
// ==============================
fastify.get("/leave/requests", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const employeeId = req.user.employeeId; // Diubah dari req.session.employee_id

  try {
    const requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeId}`,
        $expand: "ecom_LeaveType($select=ecom_name)",
        $select: "ecom_name,ecom_startdate,ecom_enddate,ecom_numberofdays,ecom_reason,ecom_leavestatus,ecom_pmsmapprovalstatus,ecom_pmsmnote,ecom_hrapprovalstatus,ecom_hrnote",
        $orderby: "createdon desc"
      }
    });

    return requestsData.value || [];

  } catch (err) {
    console.error("❌ Error fetching user leave requests:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch leave requests",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Cuti: Apply for Leave (Refactored)
// ==============================
fastify.post("/leave/requests", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  // Match incoming snake_case from client and rename to camelCase for internal use
  const { leave_typeid: leaveTypeId, start_date: startDate, days, reason } = req.body;
  const employeeId = req.user.employeeId;

  // 1. Validasi input dasar
  if (!leaveTypeId || !startDate || !days) {
    const errorMessage = "leaveTypeId, startDate, and days are required.";
    fastify.log.warn({ reqId: req.id, error: errorMessage, body: req.body });
    return reply.code(400).send({ message: errorMessage });
  }
  if (!Number.isInteger(days) || days <= 0) {
    const errorMessage = "'days' must be a positive integer.";
    fastify.log.warn({ reqId: req.id, error: errorMessage, days });
    return reply.code(400).send({ message: errorMessage });
  }

  // 2. Validasi tanggal mulai
  let start;
  try {
    start = parseDateUTC(startDate);
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    if (start < today) {
      const errorMessage = "Start date cannot be in the past.";
      fastify.log.warn({ reqId: req.id, error: errorMessage, startDate });
      return reply.code(400).send({ message: errorMessage });
    }
    if (!isWorkday(start)) {
      const dayOfWeek = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][start.getUTCDay()];
      const errorMessage = `Start date ${startDate} is a ${dayOfWeek}, which is not a working day.`
      fastify.log.warn({ reqId: req.id, error: errorMessage, startDate });
      return reply.code(400).send({ message: errorMessage });
    }
  } catch (e) {
    const errorMessage = "Invalid startDate format. Use YYYY-MM-DD.";
    fastify.log.warn({ reqId: req.id, error: errorMessage, startDate });
    return reply.code(400).send({ message: errorMessage });
  }

  try {
    // 3. Ambil saldo (DIPERBAIKI: Mencari ID karyawan yang tepat terlebih dahulu)
    const leaveYear = start.getUTCFullYear().toString();

    // Langkah 3a: Dapatkan ID karyawan utama dari ID personal information
    // Ini diperlukan karena tabel leaveusages menggunakan GUID dari tabel employee, bukan personalinformation
    const personalInfoId = req.user.employeeId; // Ini adalah GUID dari ecom_employeepersonalinformations
    const employeeData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
        params: {
            $filter: `_ecom_fullname_value eq ${personalInfoId}`,
            $select: "ecom_employeeid"
        }
    });

    if (!employeeData.value || employeeData.value.length === 0) {
        return reply.code(404).send({ message: "Could not find main employee record linked to your user profile." });
    }
    const mainEmployeeId = employeeData.value[0].employeeid;

    // Langkah 3b: Gunakan ID karyawan utama untuk mencari saldo cuti
    const filter = `_ecom_employee_value eq ${mainEmployeeId} and _ecom_leavetype_value eq ${leaveTypeId} and ecom_period eq '${leaveYear}'`;

    fastify.log.info({ reqId: req.id, msg: "Fetching leave balance with main employee ID", filter });

    const balanceData = await dataverseRequest(req, "get", "ecom_leaveusages", {
      params: { $filter: filter, $select: "ecom_balance,_ecom_leavetype_value" }
    });

    const usage = balanceData.value?.[0];
    if (!usage) {
      const errorMessage = `No leave balance record found for the specified leave type for the year ${leaveYear}.`;
      fastify.log.warn({ reqId: req.id, error: errorMessage, leaveTypeId, year: leaveYear });
      return reply.code(404).send({ message: errorMessage });
    }

    // Ambil detail Tipe Cuti secara terpisah
    const leaveTypeData = await dataverseRequest(req, "get", `ecom_leavetypes(${leaveTypeId})`, {
        params: { $select: "ecom_name" }
    });

    const currentBalance = usage.ecom_balance;
    const leaveTypeName = leaveTypeData?.ecom_name || "Unknown Leave";

    // 4. Validasi saldo cuti
    if (currentBalance < days) {
      const errorMessage = `Insufficient leave balance for '${leaveTypeName}'. Available: ${currentBalance}, Requested: ${days}.`;
      fastify.log.warn({ reqId: req.id, error: errorMessage, currentBalance, requestedDays: days });
      return reply.code(400).send({ 
        message: errorMessage 
      });
    }

    // 5. Hitung tanggal selesai & buat request
    const endDate = calculateEndDate(startDate, days);
    const leaveRequestName = `Leave Request - ${employeeId} - ${startDate}`;

    const newLeaveRequest = {
      "ecom_Employee@odata.bind": `/employees(${employeeId})`,
      "ecom_LeaveType@odata.bind": `/ecom_leavetypes(${leaveTypeId})`,
      ecom_name: leaveRequestName,
      ecom_startdate: startDate,
      ecom_enddate: endDate,
      ecom_numberofdays: days,
      ecom_reason: reason || null,
      ecom_leavestatus: 1, // Pending
      ecom_pmsmapprovalstatus: 1, // Pending
      ecom_hrapprovalstatus: 1 // Pending
    };

    const inserted = await dataverseRequest(req, "post", "ecom_employeeleaves", { data: newLeaveRequest });

    return reply.code(201).send({ 
      message: "Leave request submitted successfully.", 
      data: inserted 
    });

  } catch (err) {
    console.error("❌ Error applying for leave:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to apply for leave",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Cuti: Cancel a Leave Request (Refactored with Retry)
// ==============================
fastify.post("/leave/requests/:leaveId/cancel", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { leaveId } = req.params;
  const employeeId = req.user.employeeId;

  const MAX_RETRIES = 3;
  const RETRY_DELAY_MS = 500;
  let leaveRequest = null;

  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      fastify.log.info(`[Attempt ${attempt}/${MAX_RETRIES}] Fetching leave request ${leaveId} for cancellation.`);
      leaveRequest = await dataverseRequest(req, "get", `ecom_employeeleaves(${leaveId})`, {
        params: { $select: "ecom_leavestatus,_ecom_employee_value" }
      });
      if (leaveRequest) break; // Success, exit loop
    } catch (err) {
      if (err.response && err.response.status === 404 && attempt < MAX_RETRIES) {
        fastify.log.warn(`Leave request ${leaveId} not found. Retrying in ${RETRY_DELAY_MS}ms...`);
        await sleep(RETRY_DELAY_MS);
      } else {
        // For non-404 errors or on the last attempt, fail permanently
        fastify.log.error(`❌ Failed to fetch leave request ${leaveId}:`, err.response?.data || err.message);
        const statusCode = err.response?.status === 404 ? 404 : 500;
        const message = err.response?.status === 404 ? `Leave request with ID ${leaveId} not found.` : "Failed to cancel leave request";
        return reply.code(statusCode).send({ 
          error: message,
          details: err.response?.data?.error?.message || err.message 
        });
      }
    }
  }

  try {
    // Validasi kepemilikan (kecuali untuk admin)
    if (req.user.role !== 'admin' && leaveRequest._ecom_employee_value !== employeeId) {
      return reply.code(403).send({ message: "You can only cancel your own leave requests." });
    }

    // Validasi status (hanya yang pending yang bisa dibatalkan)
    if (leaveRequest.ecom_leavestatus !== 1) { // 1 = Pending
      return reply.code(400).send({ message: `Only requests with 'Pending' status can be cancelled. Current status: ${leaveRequest.ecom_leavestatus}` });
    }

    const updates = {
      statecode: 1,       // Deactivate the record
      statuscode: 2,      // Inactive
      ecom_leavestatus: 3 // 3 = Cancelled
    };

    await dataverseRequest("patch", `ecom_employeeleaves(${leaveId})`, { data: updates });

    fastify.log.info(`Leave request ${leaveId} has been cancelled successfully.`);
    return { message: `Leave request ${leaveId} has been cancelled.` };

  } catch (err) {
    fastify.log.error("❌ Error during leave cancellation logic (validation/update):", err.response?.data || err.message);
    reply.status(500).send({
      error: "An unexpected error occurred during the cancellation process.",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Admin: List all leave requests
// ==============================
fastify.get("/admin/leave-requests", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  try {
    const requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", {
      params: {
        $expand: "ecom_LeaveType($select=ecom_name),ecom_employee($select=ecom_employeename)",
        $select: "ecom_name,ecom_startdate,ecom_enddate,ecom_numberofdays,ecom_leavestatus,ecom_pmsmapprovalstatus,ecom_hrapprovalstatus",
        $orderby: "createdon desc"
      }
    });

    return requestsData.value || [];

  } catch (err) {
    console.error("❌ Error fetching all leave requests:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch all leave requests",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Admin: Search for employee's leave requests
// ==============================
fastify.get("/admin/leave-requests/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { employeeId, email, name } = req.query;

  if (!employeeId && !email && !name) {
    return reply.code(400).send({ message: "Either employeeId, email or name must be provided." });
  }

  let employeeFilter;
  if (employeeId) {
    employeeFilter = `_ecom_employee_value eq ${employeeId}`;
  } else {
    let personalInfoFilter;
    if (email) {
      personalInfoFilter = `ecom_workemail eq '${email}'`;
    } else { // name
      personalInfoFilter = `ecom_employeename eq '${name}'`;
    }

    try {
      const userData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
        params: {
          $filter: personalInfoFilter,
          $select: "_ecom_fullname_value"
        }
      });

      if (!userData.value || userData.value.length === 0 || !userData.value[0]._ecom_fullname_value) {
        return reply.code(404).send({ message: `Employee not found for the provided criteria.` });
      }
      const foundEmployeeId = userData.value[0]._ecom_fullname_value;
      employeeFilter = `_ecom_employee_value eq ${foundEmployeeId}`;
    } catch (err) {
      console.error("❌ Error fetching employee by email/name:", err.response?.data || err.message);
      return reply.status(500).send({
        error: "Failed to fetch employee by email/name",
        details: err.response?.data?.error?.message || err.message,
      });
    }
  }

  try {
    const requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", {
      params: {
        $filter: employeeFilter,
        $expand: "ecom_LeaveType($select=ecom_name)",
        $select: "ecom_name,ecom_startdate,ecom_enddate,ecom_numberofdays,ecom_reason,ecom_leavestatus,ecom_pmsmapprovalstatus,ecom_pmsmnote,ecom_hrapprovalstatus,ecom_hrnote",
        $orderby: "createdon desc"
      }
    });

    return requestsData.value || [];

  } catch (err) {
    console.error("❌ Error fetching user leave requests:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch leave requests",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// 5. Get Own Profile
fastify.get("/profile/personal-info", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const employeeId = req.user.employeeId;

  try {
    const data = await dataverseRequest(
      req,
      "get",
      "ecom_employeepersonalinformations",
      {
        params: {
          $filter: `_ecom_fullname_value eq ${employeeId}`,
          $select: [
            "ecom_employeeid", "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
            "ecom_phonenumber", "ecom_status", "ecom_startwork", "ecom_workexperience",
            "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
            "ecom_emergencycontactrelationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
            "ecom_profilepicture", "ecom_notes", "ecom_bankaccountnumber", "ecom_bpjsnumber",
            "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
            "ecom_religion", "ecom_bankname", "ecom_personalemail", "ecom_insurancenumber"
          ].join(",")
        }
      }
    );

    if (!data.value || data.value.length === 0) {
      fastify.log.warn(`Profile not found for employeeId: ${employeeId}`);
      return reply.code(404).send({ message: "Personal information record not found for your user." });
    }

    // Return the single record object, not the array
    return data.value[0];

  } catch (err) {
    console.error("❌ Error fetching own profile:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch profile",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// 🔹 User: Get own non-annual leave history
// ==============================
fastify.get("/leave/history", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  try {
    const { year, type } = req.query;
    const employeeId = req.user.employeeId; // This is already the GUID

    // 🔹 Bangun filter dinamis
    let filter = `_ecom_employeeid_value eq '${employeeId}'`;

    if (year) {
      filter += ` and (startswith(ecom_startdate,'${year}') or startswith(ecom_enddate,'${year}'))`;
    }
    if (type) {
      filter += ` and ecom_LeaveType/ecom_name eq '${type}'`;
    }

    // 🔹 Query ke Dataverse
    const historyData = await dataverseRequest(req, "get", "ecom_leaves", {
      params: {
        $filter: filter,
        $select: "ecom_startdate,ecom_enddate,ecom_numberofdays",
        $expand: "ecom_LeaveType($select=ecom_name)"
      }
    });

    const data = historyData.value?.map((item) => ({
      leaveType: item.ecom_LeaveType?.ecom_name || null,
      startDate: item.ecom_startdate,
      endDate: item.ecom_enddate,
      numberOfDays: item.ecom_numberofdays
    })) || [];

    return reply.send(data);
    
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ message: "Failed to retrieve leave history", error: error.message });
  }
});

// ==============================
// // 🔹 Admin: Search for employee's non-annual leave history
// ==============================
// 🔹 Admin: Search for employee's non-annual leave history
// ==============================
fastify.get("/admin/leave-history/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { employeeId, email, name, year, type } = req.query;

  if (!employeeId && !email && !name) {
    return reply.code(400).send({ message: "Either employeeId, email or name must be provided." });
  }

  try {
    let resolvedEmployeeId;

    // 🔸 Langsung pakai employeeId kalau sudah dikirim
    if (employeeId) {
      resolvedEmployeeId = employeeId;
    } else {
      // 🔸 Build filter untuk cari di ecom_personalinformation
      let personalInfoFilter;
      if (email) {
        personalInfoFilter = `ecom_workemail eq '${email}'`;
      } else {
        personalInfoFilter = `ecom_employeename eq '${name}'`;
      }

      // 🔸 Lookup personal info (ambil GUID dari ecom_personalinformation)
      const personalInfoResult = await dataverseRequest(req, "get", "ecom_personalinformations", {
        params: {
          $filter: personalInfoFilter,
          $select: "ecom_personalinformationid,ecom_workemail,ecom_employeename"
        }
      });

      if (!personalInfoResult.value?.length) {
        fastify.log.warn({ msg: "Employee lookup failed", filter: personalInfoFilter });
        return reply.code(404).send({ message: `Employee not found for the provided criteria.` });
      }

      resolvedEmployeeId = personalInfoResult.value[0].ecom_personalinformationid;
      fastify.log.info(`✅ Resolved employee personal information ID: ${resolvedEmployeeId}`);
    }

    // 🔹 Build dynamic filter
    let filter = `_ecom_employeeid_value eq '${resolvedEmployeeId}'`; // ✅ perbaikan: pakai resolvedEmployeeId

    if (year) {
      // Filter berdasar tahun dari startdate atau enddate
      filter += ` and (startswith(ecom_startdate,'${year}') or startswith(ecom_enddate,'${year}'))`;
    }

    if (type) {
      // Escape tanda kutip tunggal di nama cuti agar aman di query OData
      const safeType = type.replace(/'/g, "''");
      filter += ` and ecom_LeaveType/ecom_name eq '${safeType}'`;
    }

    fastify.log.info(`🧩 Dataverse filter: ${filter}`);

    // 🔸 Fetch leave history by resolved employee GUID
    const historyData = await dataverseRequest(req, "get", "ecom_leaves", {
      params: {
        $filter: filter,
        $select: "ecom_startdate,ecom_enddate,ecom_numberofdays",
        $expand: "ecom_LeaveType($select=ecom_name)"
      }
    });

    if (!historyData.value?.length) {
      return reply.send([]); // ✅ Jangan 404, cukup kosong
    }

    // 🔸 Transform hasil
    const history = historyData.value.map(item => ({
      leave_type_name: item.ecom_LeaveType?.ecom_name || "(unknown)",
      start_date: item.ecom_startdate,
      end_date: item.ecom_enddate,
      number_of_days: item.ecom_numberofdays
    }));

    return reply.send(history);

  } catch (err) {
    fastify.log.error("❌ Error fetching leave history:", err.response?.data || err.message);
    return reply.status(500).send({
      error: "Failed to fetch leave history",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});