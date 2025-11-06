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
import fastifyCors from "@fastify/cors";

dotenv.config();

const fastify = Fastify({ logger: true });

fastify.register(fastifyCors, {
  origin: true, // or specify a specific origin
  credentials: true,
  methods: ['GET', 'PUT', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
});

// Custom JSON parser to allow empty body for PATCH requests
fastify.addContentTypeParser('application/json', { parseAs: 'string' }, function (req, body, done) {
  if (!body || body.trim() === '') {
    if (req.method === 'PATCH') {
      return done(null, {});
    }
    const err = new Error("Body cannot be empty when content-type is set to 'application/json'");
    err.statusCode = 400;
    return done(err, undefined);
  }
  try {
    const json = JSON.parse(body);
    done(null, json);
  } catch (e) {
    const err = new Error('Invalid JSON: ' + e.message);
    err.statusCode = 400;
    done(err, undefined);
  }
});

// Workaround for clients that do not send Content-Type
fastify.addHook('preParsing', (req, reply, payload, done) => {
  if (!req.headers['content-type'] && (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT')) {
    req.headers['content-type'] = 'application/json';
  }
  done(null, payload);
});

// Create OTP directory if it doesn't exist
const otpDir = path.join('/tmp', 'otps');
if (!fs.existsSync(otpDir)) {
  fs.mkdirSync(otpDir, { recursive: true });
  fastify.log.info(`Created directory for OTPs: ${otpDir}`);
}

// Configuration Validation
let isConfigValid = true;
const missingEnvVars = [];
const requiredEnvVars = [
  'JWT_SECRET',
  'REDIRECT_URI',
  'SESSION_SECRET',
  'DATAVERSE_URL',
  'AZURE_TENANT_ID',
  'AZURE_CLIENT_ID',
  'AZURE_CLIENT_SECRET',
  'ADMIN_EMAILS',
  'SMTP_HOST',
  'SMTP_USER',
  'SMTP_PASS',
  'POWERAPPS_FLOW_URL'
];

for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    missingEnvVars.push(varName);
    isConfigValid = false;
  }
}

if (!isConfigValid) {
  fastify.log.error({
    msg: "FATAL: Application starting with missing environment variables. Service will be in a degraded state.",
    missing: missingEnvVars
  });
} else {
  fastify.log.info("All required environment variables are loaded successfully.");
}

// Register JWT plugin
fastify.register(jwt, {
  secret: process.env.JWT_SECRET,
});

// Temporary log for debugging JWT_SECRET
const loadedSecret = process.env.JWT_SECRET || "";
fastify.log.info(`JWT_SECRET check -> Starts: [${loadedSecret.substring(0, 8)}], Ends: [${loadedSecret.slice(-8)}]`);

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
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "").split(",");
const CO_ADMIN_EMAILS = (process.env.CO_ADMIN_EMAILS || "").split(",");

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

// Redirect root to /login
fastify.get("/", async (req, reply) => {
  reply.redirect("/login");
});

// Redirect user ke login Azure
fastify.get("/login", async (req, reply) => {
  if (!isConfigValid) {
    return reply.code(503).type('text/html').send(`
      <html>
        <head>
          <title>Service Error</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; margin: 0; }
            .container { text-align: center; padding: 40px; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-top: 5px solid #ffc107; max-width: 500px; }
            h1 { color: #343a40; margin-bottom: 20px; }
            p { color: #343a40; font-size: 1.1em; line-height: 1.6; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Terdapat Kesalahan</h1>
            <p>Silakan ulangi proses login dengan me-refresh halaman Agent ecomate.</p>
          </div>
        </body>
      </html>
    `);
  }

  const authCodeUrlParameters = {
    scopes: [`${dataverseBaseUrl}/.default`, "offline_access"],
    redirectUri: process.env.REDIRECT_URI,
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
  // Log the full request query to debug missing code issues
  fastify.log.info({
    msg: "Received request at /auth/callback",
    query: req.query,
    url: req.raw.url // log raw url
  });

  const code = req.query.code;
  if (!code) {
    fastify.log.error("FATAL: /auth/callback was called without an authorization code.");
    return reply.status(400).send({ error: "No authorization code received." });
  }

  // Prevent code from being used twice
  if (req.session.processedCode && req.session.processedCode === code) {
    fastify.log.warn(`Authorization code ${code} has already been processed. Redirecting to OTP page.`);
    return reply.redirect('/show-otp');
  }

  try {
    const tokenResponse = await cca.acquireTokenByCode({
      code: req.query.code,
      scopes: [`${dataverseBaseUrl}/.default`, "offline_access"],
      redirectUri: process.env.REDIRECT_URI,
    });

    // Mark code as processed in the session
    req.session.processedCode = code;

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
    let userRole = "employee";
    if (isAdmin(userEmail)) {
      userRole = "admin";
    } else if (isCoAdmin(userEmail)) {
      userRole = "co_admin";
    }
    
    // Simpan info penting di session
    req.session.employee_id = employeeId;
    req.session.email = userEmail;
    req.session.role = userRole;

    // Buat JWT jangka panjang (API Key)
    const userPayload = { employeeId, email: userEmail, role: userRole };
    const longLivedJwt = await fastify.jwt.sign(userPayload, { expiresIn: '90d' });

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

    // Simpan OTP di session dan redirect ke halaman baru untuk menampilkannya
    req.session.otp = otp;
    reply.redirect('/show-otp');

  } catch (err) {
    fastify.log.error({ msg: "❌ Authentication callback error", err: err.message, stack: err.stack });

    let userEmail = null;
    const errorMessage = err.message || "";
    
    // Try to extract email from the specific error message
    const match = errorMessage.match(/not found for email (\S+)/);
    if (match && match[1]) {
      userEmail = match[1];
    }

    let title = "Login Gagal";
    let message;

    if (userEmail) {
      message = `<p>Alamat email Anda <strong style="color: #333;">${userEmail}</strong> berhasil diautentikasi, tetapi tidak ditemukan di sistem HR Ecomate.</p><p style="font-size: 0.9em; color: #777;">Mohon hubungi departemen HR untuk pendaftaran atau jika Anda merasa ini adalah sebuah kesalahan.</p>`;
    } else {
      message = `<p>Terjadi kesalahan teknis saat memproses autentikasi Anda.</p><p style="font-size: 0.9em; color: #777;">Silakan coba lagi, atau hubungi administrator jika masalah berlanjut.</p>`;
    }

    reply.code(500).type('text/html').send(`
      <html>
        <head>
          <title>${title}</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; margin: 0; }
            .container { text-align: center; padding: 40px; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-top: 5px solid #dc3545; max-width: 500px; }
            h1 { color: #dc3545; margin-bottom: 20px; }
            p { color: #343a40; font-size: 1.1em; line-height: 1.6; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>${title}</h1>
            ${message}
          </div>
        </body>
      </html>
    `);
  }
});

// ==============================
// 🔹 Endpoint Baru: Tampilkan OTP setelah login sukses
// ==============================
fastify.get("/show-otp", (req, reply) => {
  const otp = req.session.otp;

  if (!otp) {
    // Jika tidak ada OTP di session, mungkin user refresh halaman /show-otp atau akses langsung.
    // Redirect ke halaman login untuk memulai alur baru.
    return reply.redirect('/login');
  }

  // Hapus OTP dari session agar hanya bisa ditampilkan sekali.
  delete req.session.otp;
  // Hapus juga processedCode agar alur login bisa diulang dari awal jika perlu.
  delete req.session.processedCode;

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

function isCoAdmin(email) {
  return CO_ADMIN_EMAILS.includes(email.toLowerCase());
}

// ==============================
// 🔹 Middleware Auth (diperbarui untuk JWT)
// ==============================
fastify.decorate("authenticate", async (req, reply) => {
  fastify.log.info({ headers: req.headers }, "DEBUG: Incoming headers for authentication");

  // Prioritaskan otentikasi via API Key (JWT) dari header
  if (req.headers.authorization) {
    fastify.log.info("Authentication: Authorization header found.");
    const parts = req.headers.authorization.split(' ');
    let token;

    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    } else if (parts.length === 1) {
      token = parts[0]; // Assume the whole header is the token
    }

    if (token) {
      try {
        const decoded = fastify.jwt.verify(token);
        req.user = decoded; // payload JWT kita berisi: { employeeId, email, role }
        fastify.log.info(`Authentication: JWT verified for user ${decoded.email} with role ${decoded.role}.`);
        return; // Sukses, lanjut ke handler
      } catch (err) {
        // Log detail error dan token yang bermasalah
        fastify.log.warn({
          msg: `Authentication: JWT verification failed: ${err.message}`,
          token: token,
          error_details: { name: err.name, message: err.message, stack: err.stack }
        });
        return reply.code(401).send({ error: "Invalid API Key." });
      }
    } else {
      // Jika format header bukan 'Bearer <token>' dan token tidak bisa diekstrak
      fastify.log.warn({
        msg: "Authentication: Malformed Authorization header received or token could not be extracted.",
        header: req.headers.authorization
      });
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

  // Jika semua gagal
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

fastify.get('/favicon.ico', (request, reply) => {
  reply.code(204).send();
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

function calculateReturnDate(endDateStr) {
  let returnDate = parseDateUTC(endDateStr);
  returnDate.setUTCDate(returnDate.getUTCDate() + 1); // Start with the day after end date

  while (!isWorkday(returnDate)) {
    returnDate.setUTCDate(returnDate.getUTCDate() + 1);
  }
  return formatDateUTC(returnDate);
}

async function checkForOverlappingLeave(req, employeeGuid, newStartDate, newEndDate) {
    const newStart = new Date(newStartDate);
    const newEnd = new Date(newEndDate);

    // Defines statuses that block new leave requests.
    // This check intentionally allows new requests to overlap with 'Rejected' (273700003) and 'Cancelled' (273700004) leaves.
    const blockingStatuses = [
        273700000, // Waiting for PM/SM/SPV Approval
        273700001, // Waiting for HR Manager Approval
        273700002, // Approved
        273700005  // Draft
    ];
    const statusFilter = blockingStatuses.map(s => `ecom_leavestatus eq ${s}`).join(' or ');

    const existingLeaves = await dataverseRequest(req, "get", "ecom_employeeleaves", {
        params: {
            $filter: `_ecom_employee_value eq ${employeeGuid} and (${statusFilter})`,
            $select: "ecom_startdate,ecom_enddate"
        }
    });

    if (!existingLeaves.value || existingLeaves.value.length === 0) {
        return null; // No active leaves, no overlap
    }

    for (const leave of existingLeaves.value) {
        const existingStart = new Date(leave.ecom_startdate);
        const existingEnd = new Date(leave.ecom_enddate);

        // Check for overlap: (StartA <= EndB) and (EndA >= StartB)
        if (newStart <= existingEnd && newEnd >= existingStart) {
            return `Overlaps with existing leave from ${leave.ecom_startdate} to ${leave.ecom_enddate}.`;
        }
    }

    return null; // No overlap found
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
        $select: "ecom_leaveusageid,ecom_balance,_ecom_leavetype_value,ecom_name,ecom_period,ecom_startdate,ecom_enddate"
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
        $select: "ecom_leaveusageid,ecom_balance,_ecom_leavetype_value,ecom_name,ecom_period,ecom_startdate,ecom_enddate"
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
        $select: "ecom_personalinformationid,ecom_workemail,ecom_employeename,ecom_nik,ecom_dateofemployment",
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
    const returnDateStr = calculateReturnDate(endDateStr);

    // === 6.5 Validasi Tumpang Tindih (Overlap) ===
    const overlapError = await checkForOverlappingLeave(req, employeeGuid, startDate, endDateStr);
    if (overlapError) {
        return reply.code(400).send({ message: "The requested leave dates overlap with an existing leave request.", details: overlapError });
    }

    // === 7. Insert ke ecom_employeeleaves ===
    const newLeaveRequest = {
      // Gunakan navigation property 'ecom_employee' dan bind ke entitas 'ecom_personalinformations'
      "ecom_Employee@odata.bind": `/ecom_personalinformations(${employeeGuid})`,
      "ecom_LeaveType@odata.bind": `/ecom_leavetypes(${leaveTypeId})`,
      // Format ecom_name sesuai contoh Anda
      ecom_name: `${employeeInfo.ecom_nik} - ${employeeInfo.com_employeename} - Leave request`,
      ecom_startdate: startDate,
      ecom_enddate: endDateStr,
      ecom_returndate: returnDateStr, // Add return date
      ecom_numberofdays: days,
      ecom_reason: reason || null
    };;

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

  // === 8.5. Hubungkan leave request ke leave balance ===
try {
  const leaveYear = start.getUTCFullYear().toString();

  const [balanceThis, balanceNext] = await Promise.all([
    dataverseRequest(req, "get", "ecom_leaveusages", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${leaveYear}'`,
        $select: "ecom_leaveusageid",
      },
    }),
    dataverseRequest(req, "get", "ecom_leaveusages", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${parseInt(leaveYear) + 1}'`,
        $select: "ecom_leaveusageid",
      },
    }),
  ]);

  const thisBalanceId = balanceThis.value?.[0]?.ecom_leaveusageid;
  const nextBalanceId = balanceNext.value?.[0]?.ecom_leaveusageid;

  if (thisBalanceId || nextBalanceId) {
    await dataverseRequest(req, "patch", `ecom_employeeleaves(${inserted.ecom_employeeleaveid})`, {
      data: {
        ...(thisBalanceId && {
          "ecom_LeaveBalanceThisPeriod@odata.bind": `/ecom_leaveusages(${thisBalanceId})`,
        }),
        ...(nextBalanceId && {
          "ecom_LeaveBalanceNextPeriod@odata.bind": `/ecom_leaveusages(${nextBalanceId})`,
        }),
      },
    });
    fastify.log.info(
      `✅ Linked leave request ${inserted.ecom_employeeleaveid} to balance(s): ${thisBalanceId || "-"} / ${nextBalanceId || "-"}`
    );
  } else {
    fastify.log.warn(
      `⚠️ No leave balance records found for ${employeeGuid} (${leaveYear}/${parseInt(leaveYear) + 1}). Flow may fail.`
    );
  }
} catch (err) {
  fastify.log.error("❌ Failed to link leave balances:", err.message);
}

  // === 8.6. Tambahan untuk pastikan nilai numerik tidak null ===
try {
  // Pastikan field total days tidak null
  await dataverseRequest(req, "patch", `ecom_employeeleaves(${inserted.ecom_employeeleaveid})`, {
    data: {
      ecom_totaldaysthisperiod: days, // misal default isi semua ke periode ini
      ecom_totaldaysnextperiod: 0
    },
  });
  fastify.log.info(`🧮 Set totaldaysthisperiod=${days}, totaldaysnextperiod=0 for ${inserted.ecom_employeeleaveid}`);
} catch (numErr) {
  fastify.log.error("❌ Failed to set totalday fields:", numErr.message);
}

  // === 9. Trigger Power Automate Flow ===
  try {
    const flowUrl = process.env.POWERAPPS_FLOW_URL;

    if (!flowUrl) {
      fastify.log.error("❌ Configuration Error: POWERAPPS_FLOW_URL is not set in the environment. Skipping flow trigger.");
    } else {

    // Delay 1 detik
    await new Promise(resolve => setTimeout(resolve, 1000));

      await fetch(flowUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
        leaveId: leaveId,
        userId: systemUserId,
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
// 🔹 Cuti: Apply for Special Leave (Quota-based, no balance check)
// ==============================
fastify.post("/leave/requests/special", { preValidation: [fastify.authenticate] }, async (req, reply) => {
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
    // === 3. Ambil info karyawan & tipe cuti ===
    const personalInfoRes = await dataverseRequest(req, "get", "ecom_personalinformations", {
      params: {
        $filter: `ecom_workemail eq '${employeeEmail}'`,
        $select: "ecom_personalinformationid,ecom_workemail,ecom_employeename,ecom_nik,ecom_dateofemployment",
      },
    });

    if (!personalInfoRes.value?.length) {
      return reply.code(404).send({ message: `No personal record found for ${employeeEmail}.` });
    }

    const employeeInfo = personalInfoRes.value.sort((a, b) => (b.ecom_employeename || "").localeCompare(a.ecom_employeename || ""))[0];
    const employeeGuid = employeeInfo.ecom_personalinformationid;

    const leaveTypeInfo = await dataverseRequest(req, "get", `ecom_leavetypes(${leaveTypeId})`, {
        params: { $select: "ecom_quota,ecom_name" }
    });

    // === 4. LOGIKA INTI: Cuti Panjang vs Cuti Khusus Lainnya ===
    const isLongLeave = leaveTypeInfo.ecom_name.trim().toLowerCase().startsWith('cuti panjang');
    fastify.log.info({ leaveTypeName: leaveTypeInfo.ecom_name, isLongLeave }, "DEBUG: Checking leave type");

    if (isLongLeave) {
        // --- VALIDASI CUTI PANJANG ---
        fastify.log.info({ requestedDays: days }, "DEBUG: Applying Long Leave validation logic.");

        // Aturan 1: Maks 10 hari per pengambilan
        if (days > 10) {
            fastify.log.warn("DEBUG: Failed rule - days > 10");
            return reply.code(400).send({ message: "Long leave can only be taken for a maximum of 10 days per request." });
        }

        const employmentDate = new Date(employeeInfo.ecom_dateofemployment);
        if (isNaN(employmentDate.getTime())) {
            fastify.log.error("DEBUG: Failed rule - employment date is invalid");
            return reply.code(404).send({ message: "Employee employment date is not set or invalid." });
        }

        const today = new Date();
        const tenureInYears = (today.getTime() - employmentDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
        fastify.log.info({ tenureInYears }, "DEBUG: Calculated tenure");

        // Aturan 2: Masa kerja minimal 5 tahun
        if (tenureInYears < 5) {
            fastify.log.warn("DEBUG: Failed rule - tenure < 5 years");
            return reply.code(403).send({ message: `Not eligible for long leave. Minimum 5 years of service required. Your tenure: ${tenureInYears.toFixed(1)} years.` });
        }

        const currentTier = Math.floor(tenureInYears / 5) * 5;
        const eligibilityStartDate = new Date(employmentDate);
        eligibilityStartDate.setFullYear(eligibilityStartDate.getFullYear() + currentTier);
        const expirationDate = new Date(eligibilityStartDate);
        expirationDate.setFullYear(expirationDate.getFullYear() + 3);
        fastify.log.info({ currentTier, eligibilityStartDate: eligibilityStartDate.toISOString(), expirationDate: expirationDate.toISOString() }, "DEBUG: Calculated tier and dates");

        // Aturan 3: Cek masa hangus
        if (today > expirationDate) {
            fastify.log.warn("DEBUG: Failed rule - expired window");
            return reply.code(403).send({ message: `Long leave for the ${currentTier}-year service period has expired on ${expirationDate.toISOString().split('T')[0]}.` });
        }
        
        // Aturan 4: Cek kuota & cicilan dalam jendela kelayakan
        const windowStartFilter = eligibilityStartDate.toISOString();
        const pastLongLeavesInWindow = await dataverseRequest(req, "get", "ecom_employeeleaves", {
            params: {
                $filter: `_ecom_employee_value eq ${employeeGuid} and _ecom_leavetype_value eq ${leaveTypeId} and createdon ge ${windowStartFilter} and (ecom_leavestatus ne 273700003 and ecom_leavestatus ne 273700004)`,
                $select: "ecom_numberofdays"
            }
        });

        const daysTakenInWindow = pastLongLeavesInWindow.value.reduce((sum, leave) => sum + leave.ecom_numberofdays, 0);
        fastify.log.info({ daysTakenInWindow, requested: days }, "DEBUG: Checking window quota");

        if ((daysTakenInWindow + days) > 20) {
            fastify.log.warn("DEBUG: Failed rule - quota exceeded");
            return reply.code(400).send({
                message: "Request exceeds the 20-day total quota for the current eligibility window.",
                total_quota: 20,
                taken_in_window: daysTakenInWindow,
                requested: days
            });
        }

    } else {
        // --- VALIDASI CUTI KHUSUS LAINNYA ---
        fastify.log.info("DEBUG: Applying simple quota validation logic for non-long-leave.");
        if (leaveTypeInfo.ecom_quota == null) {
            return reply.code(400).send({ message: `Leave type '${leaveTypeInfo.ecom_name}' does not use a quota system.` });
        }
        const quota = leaveTypeInfo.ecom_quota;
        const leaveYear = start.getUTCFullYear().toString();

        const pastLeaves = await dataverseRequest(req, "get", "ecom_employeeleaves", {
            params: {
                $filter: `_ecom_employee_value eq ${employeeGuid} and _ecom_leavetype_value eq ${leaveTypeId} and createdon ge ${leaveYear}-01-01T00:00:00Z and createdon le ${leaveYear}-12-31T23:59:59Z and (ecom_leavestatus ne 273700003 and ecom_leavestatus ne 273700004)`,
                $select: "ecom_numberofdays"
            }
        });
        const daysAlreadyTaken = pastLeaves.value.reduce((sum, leave) => sum + leave.ecom_numberofdays, 0);

        if ((daysAlreadyTaken + days) > quota) {
            return reply.code(400).send({
                message: `Request exceeds quota for '${leaveTypeInfo.ecom_name}'.`,
                quota: quota,
                already_taken: daysAlreadyTaken,
                requested: days
            });
        }
    }

    // === 5. Hitung end date ===
    const endDate = new Date(start);
    let daysAdded = 0;
    while (daysAdded < days - 1) {
      endDate.setUTCDate(endDate.getUTCDate() + 1);
      const d = endDate.getUTCDay();
      if (d !== 0 && d !== 6) daysAdded++;
    }
    const endDateStr = endDate.toISOString().split("T")[0];
    const returnDateStr = calculateReturnDate(endDateStr);

    // === 5.5 Validasi Tumpang Tindih (Overlap) [BUG FIX] ===
    const overlapError = await checkForOverlappingLeave(req, employeeGuid, startDate, endDateStr);
    if (overlapError) {
        return reply.code(400).send({ message: "The requested leave dates overlap with an existing leave request.", details: overlapError });
    }

    // === 6. Insert ke ecom_employeeleaves ===
    const newLeaveRequest = {
      "ecom_Employee@odata.bind": `/ecom_personalinformations(${employeeGuid})`,
      "ecom_LeaveType@odata.bind": `/ecom_leavetypes(${leaveTypeId})`,
      ecom_name: `${employeeInfo.ecom_nik} - ${employeeInfo.ecom_employeename} - Leave request`,
      ecom_startdate: startDate,
      ecom_enddate: endDateStr,
      ecom_returndate: returnDateStr,
      ecom_numberofdays: days,
      ecom_reason: reason || null
    };

    const inserted = await dataverseRequest(req, "post", "ecom_employeeleaves", { data: newLeaveRequest });

    // === 7. Trigger Power Automate ===
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
        const leaveId = inserted.ecom_employeeleaveid;

        try {
            const leaveYear = start.getUTCFullYear().toString();
            const [balanceThis, balanceNext] = await Promise.all([
                dataverseRequest(req, "get", "ecom_leaveusages", { params: { $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${leaveYear}'`, $select: "ecom_leaveusageid" } }),
                dataverseRequest(req, "get", "ecom_leaveusages", { params: { $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${parseInt(leaveYear) + 1}'`, $select: "ecom_leaveusageid" } })
            ]);
            const thisBalanceId = balanceThis.value?.[0]?.ecom_leaveusageid;
            const nextBalanceId = balanceNext.value?.[0]?.ecom_leaveusageid;
            if (thisBalanceId || nextBalanceId) {
                await dataverseRequest(req, "patch", `ecom_employeeleaves(${inserted.ecom_employeeleaveid})`, {
                    data: {
                        ...(thisBalanceId && { "ecom_LeaveBalanceThisPeriod@odata.bind": `/ecom_leaveusages(${thisBalanceId})` }),
                        ...(nextBalanceId && { "ecom_LeaveBalanceNextPeriod@odata.bind": `/ecom_leaveusages(${nextBalanceId})` })
                    }
                });
                fastify.log.info(`✅ Linked leave request ${inserted.ecom_employeeleaveid} to balance records.`);
            }
        } catch (err) {
            fastify.log.error("❌ Failed to link leave to balances:", err.message);
        }

        try {
            await dataverseRequest(req, "patch", `ecom_employeeleaves(${inserted.ecom_employeeleaveid})`, {
                data: { ecom_totaldaysthisperiod: days, ecom_totaldaysnextperiod: 0 }
            });
            fastify.log.info(`🧮 Set totaldaysthisperiod=${days} for leave ${inserted.ecom_employeeleaveid}`);
        } catch (numErr) {
            fastify.log.error("❌ Failed to set totalday fields:", numErr.message);
        }

        try {
            const flowUrl = process.env.POWERAPPS_FLOW_URL;
            if (!flowUrl) {
                fastify.log.error("❌ POWERAPPS_FLOW_URL is not set. Skipping flow trigger.");
            } else {
                await new Promise(resolve => setTimeout(resolve, 1000));
                await fetch(flowUrl, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ leaveId: leaveId, userId: systemUserId })
                });
                fastify.log.info(`✅ Flow triggered successfully for ${employeeEmail}`);
            }
        } catch (flowErr) {
            fastify.log.error({ msg: "❌ Failed to trigger Power Automate Flow", error: flowErr.message });
        }
    }

    // === 8. Response sukses ===
    return reply.code(201).send({
        message: `Leave request submitted successfully.`,
        data: inserted,
    });

  } catch (err) {
    fastify.log.error({ msg: "❌ Failed to apply for special leave", error: err.response?.data || err.message });
    reply.code(500).send({
      error: "Failed to apply for special leave",
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
  if (!["admin", "co_admin"].includes(req.user.role)) {
    return reply.code(403).send({ message: "Admin access required." });
  }

  try {
    const { startDate, endDate, month, year } = req.query;
    const filters = [];

    let finalStartDate = startDate;
    let finalEndDate = endDate;

    // Handle month and year parameters if explicit date range isn't provided
    if (!finalStartDate && !finalEndDate) {
      if (month) { // e.g., month=2025-12
        const [y, m] = month.split('-').map(Number);
        if (y && m && m >= 1 && m <= 12) {
          finalStartDate = `${y}-${String(m).padStart(2, '0')}-01`;
          const lastDay = new Date(y, m, 0).getDate();
          finalEndDate = `${y}-${String(m).padStart(2, '0')}-${String(lastDay).padStart(2, '0')}`;
        }
      } else if (year) { // e.g., year=2025
        const y = Number(year);
        if (y) {
          finalStartDate = `${y}-01-01`;
          finalEndDate = `${y}-12-31`;
        }
      }
    }

    // Build the OData filter for overlap
    if (finalStartDate) {
      // Leaves that end on or after the start of the period
      filters.push(`ecom_enddate ge ${finalStartDate}`);
    }
    if (finalEndDate) {
      // Leaves that start on or before the end of the period
      filters.push(`ecom_startdate le ${finalEndDate}`);
    }

    const params = {
      $expand: "ecom_LeaveType($select=ecom_name),ecom_Employee($select=ecom_employeename)",
      $select: "ecom_name,ecom_startdate,ecom_enddate,ecom_numberofdays,ecom_leavestatus,ecom_pmsmapprovalstatus,ecom_hrapprovalstatus",
      $orderby: "createdon desc"
    };

    if (filters.length > 0) {
      params.$filter = filters.join(' and ');
    }

    fastify.log.info({ msg: "Fetching admin leave requests with params", params });

    const requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", { params });

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
  if (!["admin", "co_admin"].includes(req.user.role)) {
    return reply.code(403).send({ message: "Admin access required." });
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

// ==============================
// 🔹 Development History Mappings
// ==============================
const DEVELOPMENT_TYPE_MAP = {
  273700000: 'Project',
  273700001: 'Training',
  273700002: 'Certification',
  273700003: 'Onboarding',
};

// Helper to transform development records
const transformDevelopmentRecord = (record) => ({
  id: record.ecom_developmentid,
  title: record.ecom_title,
  type_code: record.ecom_type,
  type_label: DEVELOPMENT_TYPE_MAP[record.ecom_type] || 'Unknown',
  start_date: record.ecom_date,
  end_date: record.ecom_enddate,
  involvement_percentage: record.ecom_description,
  client_name: record.ecom_Client?.name || null,
  project_manager_name: record.ecom_ProjectManager?.fullname || null,
  created_by_name: record.lk_ecom_development_createdby?.fullname || null,
  last_updated_on: record.ecom_updatedon,
});

// ==============================
// 🔹 Development History: Get Own History
// ==============================
fastify.get("/developments", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const employeeGuid = req.user.employeeId;

  try {
    const historyData = await dataverseRequest(req, "get", "ecom_developments", {
      params: {
        $filter: `_ecom_employeeid_value eq ${employeeGuid}`,
        $select: "ecom_developmentid,ecom_title,ecom_date,ecom_enddate,ecom_description,ecom_type,ecom_updatedon",
        $expand: "ecom_Client($select=name),ecom_ProjectManager($select=fullname)",
        $orderby: "ecom_date desc",
      }
    });

    if (!historyData.value || historyData.value.length === 0) {
      return [];
    }

    const transformedData = historyData.value.map(transformDevelopmentRecord);
    return transformedData;

  } catch (err) {
    fastify.log.error({ msg: "❌ Error fetching own development history", error: err.response?.data || err.message });
    reply.status(500).send({
      error: "Failed to fetch development history",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Development History: Admin Search
// ==============================
fastify.get("/admin/developments/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (!["admin", "co_admin"].includes(req.user.role)) {
    return reply.code(403).send({ message: "Admin access required." });
  }

  const { email, name } = req.query;
  if (!email && !name) {
    return reply.code(400).send({ message: "Either email or name query parameter is required." });
  }

  try {
    let employeeGuid;

    // Find employee GUID from email or name
    let personalInfoFilter;
    if (email) {
      personalInfoFilter = `ecom_workemail eq '${email}'`;
    } else { // name
      personalInfoFilter = `ecom_employeename eq '${name}'`;
    }

    const personalInfoRes = await dataverseRequest(req, "get", "ecom_personalinformations", {
      params: { $filter: personalInfoFilter, $select: "ecom_personalinformationid" },
    });

    if (!personalInfoRes.value || personalInfoRes.value.length === 0) {
      return reply.code(404).send({ message: `Employee not found with the provided ${email ? 'email' : 'name'}.` });
    }
    employeeGuid = personalInfoRes.value[0].ecom_personalinformationid;

    // Fetch development history for the found employee
    const historyData = await dataverseRequest(req, "get", "ecom_developments", {
      params: {
        $filter: `_ecom_employeeid_value eq ${employeeGuid}`,
        $select: "ecom_developmentid,ecom_title,ecom_date,ecom_enddate,ecom_description,ecom_type,ecom_updatedon",
        $expand: "ecom_Client($select=name),ecom_ProjectManager($select=fullname)",
        $orderby: "ecom_date desc",
      }
    });

    if (!historyData.value || historyData.value.length === 0) {
      return [];
    }

    const transformedData = historyData.value.map(transformDevelopmentRecord);
    return transformedData;

  } catch (err) {
    fastify.log.error({ msg: "❌ Error in admin development history search", error: err.response?.data || err.message });
    reply.status(500).send({
      error: "Failed to search development history",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Summary Peer Review: Get Own Reviews
// ==============================
fastify.get("/summary-peer-review", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  // Assuming req.user.employeeId is the systemuserid
  const employeeId = req.user.employeeId;

  try {
    const summaryData = await dataverseRequest(req, "get", "ecom_summarypeerreviews", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeId}`,
        $select: "ecom_startdate,ecom_enddate,ecom_totalpeerreview,ecom_averagerating",
        $expand: "ecom_Project($select=ecom_projectname),ecom_Employee($select=fullname)",
      }
    });

    if (!summaryData.value || summaryData.value.length === 0) {
      return [];
    }

    const transformedData = summaryData.value.map(item => ({
      project_name: item.ecom_Project?.ecom_projectname || null,
      employee_name: item.ecom_Employee?.fullname || null,
      project_start_date: item.ecom_startdate,
      project_end_date: item.ecom_enddate,
      total_peer_review: item.ecom_totalpeerreview,
      average_rating: item.ecom_averagerating,
    }));

    return transformedData;

  } catch (err) {
    fastify.log.error({ msg: "❌ Error fetching own summary peer review", error: err.response?.data || err.message });
    reply.status(500).send({
      error: "Failed to fetch own summary peer review",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Admin: Search Summary Peer Reviews
// ==============================
fastify.get("/admin/summary-peer-review/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin access only." });
  }

  const { employeeId, email, name } = req.query;

  if (!employeeId && !email && !name) {
    return reply.code(400).send({ message: "Either employeeId, email or name must be provided to search." });
  }

  try {
    let userIdToSearch;

    if (employeeId) {
      userIdToSearch = employeeId;
    } else {
      let userFilter;
      if (email) {
        userFilter = `internalemailaddress eq '${email}'`;
      } else { // name
        userFilter = `fullname eq '${name}'`;
      }

      const userRes = await dataverseRequest(req, "get", "systemusers", {
        params: {
          $filter: userFilter,
          $select: "systemuserid"
        },
      });

      if (!userRes.value || userRes.value.length === 0) {
        // Return empty array if user not found, to match the "success 200 but no data" behavior
        return [];
      }
      userIdToSearch = userRes.value[0].systemuserid;
    }

    const summaryData = await dataverseRequest(req, "get", "ecom_summarypeerreviews", {
      params: {
        $filter: `_ecom_employee_value eq ${userIdToSearch}`,
        $select: "ecom_startdate,ecom_enddate,ecom_totalpeerreview,ecom_averagerating",
        $expand: "ecom_Project($select=ecom_projectname),ecom_Employee($select=fullname)",
      }
    });

    if (!summaryData.value || summaryData.value.length === 0) {
      return [];
    }

    const transformedData = summaryData.value.map(item => ({
      project_name: item.ecom_Project?.ecom_projectname || null,
      employee_name: item.ecom_Employee?.fullname || null,
      project_start_date: item.ecom_startdate,
      project_end_date: item.ecom_enddate,
      total_peer_review: item.ecom_totalpeerreview,
      average_rating: item.ecom_averagerating,
    }));

    return transformedData;

  } catch (err) {
    fastify.log.error({ msg: "❌ Error in admin summary peer review search", error: err.response?.data || err.message });
    reply.status(500).send({
      error: "Failed to search summary peer review",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});
