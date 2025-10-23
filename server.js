import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifySession from "@fastify/session";
import jwt from "@fastify/jwt";
import nodemailer from "nodemailer";
import axios from "axios";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { ConfidentialClientApplication } from "@azure/msal-node";

dotenv.config();

const fastify = Fastify({ logger: true });

// Create OTP directory if it doesn't exist
const otpDir = 'otps';
if (!fs.existsSync(otpDir)) {
  fs.mkdirSync(otpDir, { recursive: true });
  fastify.log.info(`Created directory for OTPs: ${otpDir}`);
}

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
// Note: In-memory OTP stores were replaced with a file-based store to support multi-instance deployments.

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
      const otpFilePath = path.join(otpDir, `${otp}.json`);
      const otpData = JSON.stringify({ jwt: longLivedJwt, expiresAt: expiresAt.toISOString() });

      try {
        fs.writeFileSync(otpFilePath, otpData);
        fastify.log.info(`OTP ${otp} stored in file.`);
      } catch (writeErr) {
        fastify.log.error("❌ Error writing OTP file:", writeErr);
        return reply.status(500).send({ error: "Failed to store authentication session." });
      }

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
  let { otp } = req.body;
  if (!otp) {
    return reply.code(400).send({ error: "OTP is required." });
  }

  // Handle OTP with or without hyphen
  otp = otp.replace(/-/g, "");

  const otpFilePath = path.join(otpDir, `${otp}.json`);

  if (!fs.existsSync(otpFilePath)) {
    return reply.code(404).send({ error: "OTP not found or has expired." });
  }

  try {
    const otpData = JSON.parse(fs.readFileSync(otpFilePath, 'utf8'));
    const expiresAt = new Date(otpData.expiresAt);

    if (new Date() > expiresAt) {
      fs.unlinkSync(otpFilePath); // Clean up expired OTP
      return reply.code(404).send({ error: "OTP not found or has expired." });
    }

    const apiKey = otpData.jwt;

    // Hapus file OTP setelah berhasil digunakan
    fs.unlinkSync(otpFilePath);

    reply.send({ apiKey });
  } catch (err) {
    fastify.log.error(`❌ Error processing OTP ${otp}:`, err);
    // Defensively try to delete the file if it still exists, as it might be corrupt
    if (fs.existsSync(otpFilePath)) {
      try {
        fs.unlinkSync(otpFilePath);
      } catch (unlinkErr) {
        fastify.log.error(`❌ Failed to delete corrupt OTP file ${otpFilePath}:`, unlinkErr);
      }
    }
    return reply.code(500).send({ error: "Failed to process OTP. The code may be invalid or already used." });
  }
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

  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
    "Content-Type": "application/json",
  };

  // Add Prefer header for POST requests to get the created record back
  if (method.toLowerCase() === 'post') {
    headers['Prefer'] = 'return=representation';
  }

  const res = await axios({
    method,
    url: `${dataverseBaseUrl}/api/data/v9.2/${entitySet}`,
    headers: headers,
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
    fastify.log.info("Authentication: Authorization header found.");
    const [type, token] = req.headers.authorization.split(' ') || [];
    if (type === 'Bearer' && token) {
      try {
        const decoded = fastify.jwt.verify(token);
        req.user = decoded; // payload JWT kita berisi: { employeeId, email, role }
        fastify.log.info(`Authentication: JWT verified for user ${decoded.email} with role ${decoded.role}.`);
        return; // Sukses, lanjut ke handler
      } catch (err) {
        fastify.log.warn(`Authentication: JWT verification failed: ${err.message}`);
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

  // Fallback ke otentikasi via App Token
  if (req.headers['x-app-token']) {
    try {
      const appToken = await getAppLevelDataverseToken();
      if (req.headers['x-app-token'] === appToken) {
        req.user = { role: 'admin' }; // Atau role yang sesuai
        return; // Sukses, lanjut ke handler
      }
    } catch (error) {
      return reply.code(500).send({ error: "Failed to validate app token" });
    }
  }

  // Jika keduanya gagal
  return reply.code(401).send({ error: "Not authenticated. Please login or provide an API Key." });
});


// ==============================
// 🔹 Endpoint
// ==============================

fastify.get("/app-token", async (req, reply) => {
  try {
    const token = await getAppLevelDataverseToken();
    reply.send({ token });
  } catch (error) {
    reply.status(500).send({ error: "Failed to get app-level token" });
  }
});

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
    const personalInfoData = await dataverseRequest(req, "get", "ecom_personalinformations", {
      params: {
        $filter: filter,
        $select: [
          "ecom_personalinformationid", "ecom_nik", "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
          "ecom_phonenumber", "statecode", "ecom_startwork", "ecom_jobtitle",
          "ecom_workexperience", "ecom_dateofemployment",
          "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
          "ecom_relationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
          "ecom_profilepicture", "ecom_bankaccountnumber", "ecom_bpjsnumber", "ecom_insurancenumber",
          "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
          "ecom_religion", "ecom_bankname", "ecom_accountname", "ecom_personalemail", "ecom_workemail"
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

  const { employeeId } = req.params; // This is the personalinformationid (GUID)
  fastify.log.info(`PATCH /profile/${employeeId} - req.body: ${JSON.stringify(req.body)}, Content-Type: ${req.headers['content-type']}`);

  try {
    const allowedFields = [
      "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
      "ecom_phonenumber", "statecode", "ecom_startwork", "ecom_jobtitle",
      "ecom_workexperience", "ecom_dateofemployment",
      "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
      "ecom_relationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
      "ecom_profilepicture", "ecom_bankaccountnumber", "ecom_bpjsnumber", "ecom_insurancenumber",
      "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
      "ecom_religion", "ecom_bankname", "ecom_accountname", "ecom_personalemail", "ecom_workemail"
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

    // Directly use the employeeId from the URL for the PATCH request
    await dataverseRequest(req, "patch", `ecom_personalinformations(${employeeId})`, { data: updates });

    return { message: "Profile updated successfully." };

  } catch (err) {
    // Add a check for 404 error, in case the ID is not found
    if (err.response && err.response.status === 404) {
      return reply.code(404).send({ message: `Personal information record with ID ${employeeId} not found.` });
    }
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
// 🔹 Leave Status Mapping (global di file ini)
// ==============================
const LeaveStatus = {
  273700000: { en: "Waiting for PM/SM/SPV Approval", id: "Menunggu Persetujuan Atasan" },
  273700001: { en: "Waiting for HR Manager Approval", id: "Menunggu Persetujuan HR" },
  273700002: { en: "Approved", id: "Disetujui" },
  273700003: { en: "Rejected", id: "Ditolak" },
  273700004: { en: "Cancelled", id: "Dibatalkan" },
  273700005: { en: "Draft", id: "Draf" },
};

// ==============================
// 🔹 Approval Status Mapping (PM/SM dan HR)
// ==============================
const PMSMApprovalStatus = {
  273700000: { en: "Waiting for Approval", id: "Menunggu Persetujuan" },
  273700001: { en: "Approved", id: "Disetujui" },
  273700002: { en: "Rejected", id: "Ditolak" },
  273700003: { en: "Draft", id: "Draf" },
  273700004: { en: "Rejected by Others", id: "Ditolak oleh Pihak Lain" },
  273700005: { en: "Waiting for Final Result", id: "Menunggu Hasil Akhir" },
  273700006: { en: "Passed", id: "Lulus" },
  273700007: { en: "Failed", id: "Gagal" },
};

const HRApprovalStatus = {
  273700000: { en: "Waiting for Approval", id: "Menunggu Persetujuan" },
  273700001: { en: "Approved", id: "Disetujui" },
  273700002: { en: "Rejected", id: "Ditolak" },
  273700003: { en: "Draft", id: "Draf" },
  273700004: { en: "Rejected by Others", id: "Ditolak oleh Pihak Lain" },
  273700005: { en: "Waiting for Final Result", id: "Menunggu Hasil Akhir" },
  273700006: { en: "Passed", id: "Lulus" },
  273700007: { en: "Failed", id: "Gagal" },
};

// ==============================
// 🔹 Cuti: Get User's Leave Requests
// ==============================

fastify.get("/leave/requests", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const employeeId = req.user.employeeId; // GUID from ecom_employees

  try {
    // Ambil personalInfoId dari user yang sedang login
    const employeeEmail = req.user.email; // Get email from authenticated user
    const personalInfoRes = await dataverseRequest(req, "get", "ecom_personalinformations", {
      params: {
        $filter: `ecom_workemail eq '${employeeEmail}'`,
        $select: "ecom_personalinformationid",
      },
    });

    if (!personalInfoRes.value?.length) {
      return reply.code(404).send({ message: `Personal information not found for current user.` });
    }
    const currentUserPersonalInfoId = personalInfoRes.value[0].ecom_personalinformationid;

    const requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", {
      params: {
        $filter: `_ecom_employee_value eq ${currentUserPersonalInfoId}`,
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
// Leave: Apply for Leave (Final - By Email → Employee GUID)
// ==============================
fastify.post("/leave/requests", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { leave_typeid: leaveTypeId, start_date: startDate, days, reason } = req.body;
  const employeeEmail = req.user.email;

  // === 1. Validasi input dasar ===
  if (!leaveTypeId || !startDate || !days) {
    return reply.code(400).send({ message: "leaveTypeId, startDate, and days are required." });
  }

  if (!Number.isInteger(days) || days <= 0) {
    return reply.code(400).send({ message: "'days' must be a positive integer." });
  }

  // === 2. Validasi tanggal mulai ===
  let start;
  try {
    start = new Date(startDate);
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    if (start < today) return reply.code(400).send({ message: "Start date cannot be in the past." });

    const dayOfWeek = start.getUTCDay();
    if (dayOfWeek === 0 || dayOfWeek === 6) {
      return reply.code(400).send({ message: `Start date ${startDate} falls on a weekend.` });
    }
  } catch {
    return reply.code(400).send({ message: "Invalid startDate format. Use YYYY-MM-DD." });
  }

  try {
    const leaveYear = start.getUTCFullYear().toString();

    // === 3. Ambil GUID karyawan dari email ===
    const personalInfoRes = await dataverseRequest(req, "get", "ecom_personalinformations", {
      params: {
        $filter: `ecom_workemail eq '${employeeEmail}'`,
        $select: "ecom_personalinformationid,ecom_workemail,ecom_employeename,ecom_nik",
      },
    });

    if (!personalInfoRes.value?.length) {
      return reply.code(404).send({ message: `No personal record found for ${employeeEmail}.` });
    }

    // Cari record personal info paling baru (misalnya tahun tertinggi di ecom_employeename)
    const sortedPersonal = personalInfoRes.value.sort((a, b) =>
      (b.ecom_employeename || "").localeCompare(a.ecom_employeename || "")
    );
    const employeeInfo = sortedPersonal[0];
    const employeeGuid = employeeInfo.ecom_personalinformationid; // GUID dari personal info record

    // === 4. Ambil saldo cuti dari ecom_leaveusages ===
    const balancesRes = await dataverseRequest(req, "get", "ecom_leaveusages", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${leaveYear}'`,
        $select: "ecom_balance,_ecom_leavetype_value,ecom_period,ecom_name",
      },
    });

    if (!balancesRes.value?.length) {
      return reply.code(404).send({
        message: `No leave balance found for ${employeeEmail} in year ${leaveYear}.`,
      });
    }

    const usage = balancesRes.value.find(u => u._ecom_leavetype_value === leaveTypeId);
    if (!usage) {
      return reply.code(404).send({
        message: `No leave balance record found for leave type ${leaveTypeId} in ${leaveYear}.`,
      });
    }

    const currentBalance = usage.ecom_balance;

    // === 5. Validasi saldo ===
    if (currentBalance < days) {
      return reply.code(400).send({
        message: `Insufficient balance. Available: ${currentBalance}, Requested: ${days}.`,
      });
    }

    // === 6. Hitung end date ===
    const endDate = new Date(start);
    let daysAdded = 0;
    while (daysAdded < days - 1) {
      endDate.setUTCDate(endDate.getUTCDate() + 1);
      const d = endDate.getUTCDay();
      if (d !== 0 && d !== 6) daysAdded++;
    }
    const endDateStr = endDate.toISOString().split("T")[0];

    // === 7. Insert ke ecom_employeeleaves ===
    const newLeaveRequest = {
      // Gunakan navigation property 'ecom_employee' dan bind ke entitas 'ecom_personalinformations'
      "ecom_Employee@odata.bind": `/ecom_personalinformations(${employeeGuid})`,
      "ecom_LeaveType@odata.bind": `/ecom_leavetypes(${leaveTypeId})`,
      // Format ecom_name sesuai contoh Anda
      ecom_name: `${employeeInfo.ecom_nik} - ${employeeInfo.ecom_employeename} - Leave request`,
      ecom_startdate: startDate,
      ecom_enddate: endDateStr,
      ecom_numberofdays: days,
      ecom_reason: reason || null,
      ecom_leavestatus: 273700005, // Draft
      ecom_pmsmapprovalstatus: null,
      ecom_hrapprovalstatus: null,
    };

    const inserted = await dataverseRequest(req, "post", "ecom_employeeleaves", { data: newLeaveRequest });

    // === 8. Ambil systemuserid dari systemuser (berdasarkan email user) ===
const userRes = await dataverseRequest(req, "get", "systemusers", {
  params: {
    $select: "systemuserid,internalemailaddress",
    $filter: `internalemailaddress eq '${employeeEmail}'`,
  },
});

if (!userRes.value?.length) {
  fastify.log.warn(`⚠️ No systemuser found for ${employeeEmail}`);
} else {
  const systemUserId = userRes.value[0].systemuserid;
  const leaveId = inserted.ecom_employeeleaveid; // ID dari record cuti baru

  // === 9. Trigger Power Automate Flow ===
  try {
    const flowUrl = process.env.POWERAPPS_FLOW_URL;

    if (!flowUrl) {
      fastify.log.error("❌ Configuration Error: POWERAPPS_FLOW_URL is not set in the environment. Skipping flow trigger.");
    } else {
      await fetch(flowUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
        recordId: leaveId,
        leaveId: leaveId,
        systemuserid: systemUserId,
      }),
      });

      fastify.log.info(`✅ Flow triggered successfully for ${employeeEmail}`);
    }
  } catch (flowErr) {
    fastify.log.error({
      msg: "❌ Failed to trigger Power Automate Flow",
      error: flowErr.message,
    });
  }
}

// === 10. Response sukses ===
return reply.code(201).send({
  message: `Leave request submitted successfully.`,
  balance_remaining: currentBalance - days,
  data: inserted,
});

  } catch (err) {
    fastify.log.error({
      msg: "❌ Failed to apply leave",
      error: err.response?.data || err.message,
    });
    reply.code(500).send({
      error: "Failed to apply for leave",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Cuti: Cancel a Leave Request (Final Version - Clean & Safe)
// ==============================
fastify.post("/leave/requests/:leaveId/cancel", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { leaveId } = req.params;

  const MAX_RETRIES = 3;
  const RETRY_DELAY_MS = 500;
  let leaveRequest = null;

  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  // === Step 1: Ambil data cuti yang ingin dibatalkan ===
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      leaveRequest = await dataverseRequest(req, "get", `ecom_employeeleaves(${leaveId})`, {
        params: { $select: "ecom_leavestatus,_ecom_employee_value" }
      });
      if (leaveRequest) break;
    } catch (err) {
      if (err.response?.status === 404 && attempt < MAX_RETRIES) {
        await sleep(RETRY_DELAY_MS);
      } else {
        const statusCode = err.response?.status === 404 ? 404 : 500;
        const message = err.response?.status === 404
          ? `Leave request with ID ${leaveId} not found.`
          : "Failed to fetch leave request.";
        return reply.code(statusCode).send({
          error: message,
          details: err.response?.data?.error?.message || err.message
        });
      }
    }
  }

  try {
    // === Step 2: Ambil personal info ID dari user login ===
    const employeeEmail = req.user.email;
    const personalInfoRes = await dataverseRequest(req, "get", "ecom_personalinformations", {
      params: {
        $filter: `ecom_workemail eq '${employeeEmail}'`,
        $select: "ecom_personalinformationid"
      }
    });

    if (!personalInfoRes.value?.length) {
      return reply.code(404).send({ message: "Personal information not found for current user." });
    }

    const currentUserPersonalInfoId = personalInfoRes.value[0].ecom_personalinformationid;

    // === Step 3: Validasi kepemilikan (kecuali admin) ===
    if (req.user.role !== "admin" && leaveRequest._ecom_employee_value !== currentUserPersonalInfoId) {
      return reply.code(403).send({ message: "You can only cancel your own leave requests." });
    }

    // === Step 4: Validasi status cuti yang boleh dibatalkan ===
    const cancellableStatuses = [273700000, 273700001, 273700005]; 
    // Waiting for PM/SM/SPV approval, Waiting for HR Manager Approval, Draft

    if (!cancellableStatuses.includes(leaveRequest.ecom_leavestatus)) {
      return reply.code(400).send({
        message: `You cannot cancel this leave because its current status (${leaveRequest.ecom_leavestatus}) is not eligible for cancellation.`
      });
    }

    // === Step 5: Update status ke "Cancelled" ===
    await dataverseRequest(req, "patch", `ecom_employeeleaves(${leaveId})`, {
      data: { ecom_leavestatus: 273700004 } // ✅ Official code for Cancelled
    });

    return reply.code(200).send({
      message: `Leave request ${leaveId} has been cancelled successfully.`,
      new_status: 273700004
    });

  } catch (err) {
    const status = err.response?.status || 500;
    const message = err.response?.data?.error?.message || err.message;

    return reply.code(status).send({
      error: "An unexpected error occurred during the cancellation process.",
      message
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
      const userData = await dataverseRequest(req, "get", "ecom_personalinformations", {
        params: {
          $filter: personalInfoFilter,
          $select: "ecom_personalinformationid"
        }
      });

      if (!userData.value || userData.value.length === 0 || !userData.value[0].ecom_personalinformationid) {
        return reply.code(404).send({ message: `Employee not found for the provided criteria.` });
      }
      const foundEmployeeId = userData.value[0].ecom_personalinformationid;
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
      "ecom_personalinformations",
      {
        params: {
          $filter: `_ecom_fullname_value eq ${employeeId}`,
          $select: [
          "ecom_personalinformationid", "ecom_nik", "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
          "ecom_phonenumber", "statecode", "ecom_startwork",
          "ecom_workexperience", "ecom_dateofemployment", "ecom_jobtitle",
          "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
          "ecom_relationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
          "ecom_profilepicture", "ecom_bankaccountnumber", "ecom_bpjsnumber",
          "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
          "ecom_religion", "ecom_bankname", "ecom_accountname", "ecom_personalemail", "ecom_workemail", "ecom_insurancenumber"
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