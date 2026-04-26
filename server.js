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
import { Redis } from "@upstash/redis";

import crypto from "crypto";

dotenv.config();

// Initialize Redis client with Upstash credentials
// Use KV_REST_API1_* format from Upstash
const kvUrl = process.env.KV_REST_API1_KV_REST_API_URL;
const kvToken = process.env.KV_REST_API1_KV_REST_API_TOKEN;

if (!kvUrl || !kvToken) {
  console.error("❌ FATAL: Redis credentials not found!");
  console.error("Required environment variables:");
  console.error("  - KV_REST_API1_KV_REST_API_URL");
  console.error("  - KV_REST_API1_KV_REST_API_TOKEN");
  console.error("\nSet these in Vercel Environment Variables:");
  console.error("  KV_REST_API1_KV_REST_API_URL=https://hip-lacewing-95640.upstash.io");
  console.error("  KV_REST_API1_KV_REST_API_TOKEN=gQAAAAAAAXWYAAIncDJkMzVmYzc0MjkxMzg0NDkyYmQ0MjJmY2NmMmUyMjM2YnAyOTU2NDA");
  process.exit(1);
}

const kv = new Redis({
  url: kvUrl,
  token: kvToken,
});

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
    if (req.method === 'PATCH' || (req.method === 'POST' && req.url.includes('/cancel'))) {
      return done(null, {});
    }
    const err = new Error("Body cannot be empty when content-type is set to 'application/json'");
    err.statusCode = 400;
    return done(err, undefined);
  }
  try {
    // Preserve raw body string for webhook signature verification
    try { req.rawBody = body; } catch (e) { /* ignore if unable to set */ }
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
    req.session.permission = userRole;

    // Buat JWT jangka panjang (API Key)
    const userPayload = { employeeId, email: userEmail, permission: userRole };

    // Log the payload right before signing
    fastify.log.info({ msg: "JWT_PAYLOAD_CHECK", payload: userPayload });

    const longLivedJwt = await fastify.jwt.sign(userPayload, { expiresIn: '90d' });

    // 🔥 Log terstruktur baru untuk debugging secret mismatch
    const loadedSecretForSigning = process.env.JWT_SECRET || "Not Set!";
    fastify.log.info({
        msg: "JWT_SIGNING_CHECK",
        secret_check: `Secret used for SIGNING starts with [${loadedSecretForSigning.substring(0, 4)}] and ends with [${loadedSecretForSigning.slice(-4)}]`
    });

    // Buat OTP untuk ditukar dengan JWT
    const otp = generateOTP();
    
    try {
      // Simpan JWT di Vercel KV dengan OTP sebagai key, berlaku selama 5 menit (300 detik)
      await kv.set(otp, longLivedJwt, { ex: 300 });
      fastify.log.info(`OTP ${otp} and JWT stored in Vercel KV.`);
    } catch (kvErr) {
      fastify.log.error({
        msg: "❌ Error saving OTP to Vercel KV",
        error: kvErr.message,
        stack: kvErr.stack,
        kvUrlStartsWith: kvUrl?.substring(0, 20),
        kvUrlLength: kvUrl?.length || 0,
        kvTokenStartsWith: kvToken?.substring(0, 20),
        kvTokenLength: kvToken?.length || 0
      });
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
          .otp { font-size: 2.5em; font-weight: bold; color: #007bff; letter-spacing: 5px; margin: 20px 0; padding: 10px; background-color: #eef; border-radius: 4px; cursor: pointer; user-select: none; }
          .expiry { font-size: 0.9em; color: #999; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Authentication Successful!</h1>
          <p>Enter this one-time code in your ecomate agent:</p>
          <div id="otp-display" class="otp" title="Click to copy">${otp}</div>
          <p class="expiry">This code will expire in 5 minutes.</p>
        </div>
        <script>
          const otpElement = document.getElementById('otp-display');
          otpElement.addEventListener('click', () => {
            const otpValue = otpElement.innerText;
            navigator.clipboard.writeText(otpValue).then(() => {
              const originalText = otpElement.innerText;
              otpElement.innerText = 'Copied!';
              setTimeout(() => {
                otpElement.innerText = originalText;
              }, 1500);
            }).catch(err => {
              console.error('Failed to copy OTP: ', err);
            });
          });
        </script>
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

  try {
    // Ambil JWT dari Vercel KV menggunakan OTP sebagai key
    const apiKey = await kv.get(otp);
    // Do not log the actual API key to avoid leaking credentials
    fastify.log.info({ msg: "KV_RETRIEVED_API_KEY_CHECK" });

    if (!apiKey) {
      // Jika tidak ada, berarti OTP salah, sudah digunakan, atau expired
      return reply.code(404).send({ error: "OTP not found, has expired, or was already used." });
    }

    // Hapus OTP dari KV setelah berhasil digunakan untuk mencegah reuse
    await kv.del(otp);

    reply.send({ apiKey });
  } catch (err) {
    fastify.log.error(`❌ Error processing OTP ${otp} from Vercel KV:`, err);
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

  if (options.headers && typeof options.headers === 'object') {
    for (const [k, v] of Object.entries(options.headers)) {
      if (k.toLowerCase() === 'prefer' && headers['Prefer']) {
        headers['Prefer'] = `${headers['Prefer']},${v}`;
      } else {
        headers[k] = v;
      }
    }
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

const DATAVERSE_FORMATTED_VALUE_HEADERS = {
  Prefer: 'odata.include-annotations="OData.Community.Display.V1.FormattedValue"'
};

// ==============================
// 🔹 Nodemailer (SMTP Office 365/Gmail)
// ==============================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// New Gmail Transporter
const gmailTransporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com', // Explicitly set Gmail SMTP host
  port: 587,             // Explicitly set Gmail SMTP port (for STARTTLS)
  secure: false,         // Use STARTTLS, not SSL/TLS directly on port 587
  auth: {
    user: process.env.GMAIL_SMTP_USER,
    pass: process.env.GMAIL_SMTP_PASS,
  },
});

// Helper function to send leave request email
async function sendLeaveRequestEmail(fastifyInstance, leaveRequestId, recipientEmail) {
  fastifyInstance.log.info(`Attempting to send leave request email for ID: ${leaveRequestId} to ${recipientEmail}`);
  try {
    const mailOptions = {
      from: process.env.GMAIL_SMTP_USER,
      to: recipientEmail,
      subject: `New Leave Request Notification`,
      html: `
        <p>Dear Admin,</p>
        <p>A new leave request has been submitted. Please click the button below to view the details and take action:</p>
        <p style="text-align: center;">
          <a href="https://ecomate-dashboard.lovable.app/admin" style="
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            border-radius: 5px;
            font-weight: bold;
          ">Click Here</a>
        </p>
        <p>Thank you.</p>
        <br>
        <p>Regards,</p>
        <p>Ecomate HR System</p>
      `,
    };

    await gmailTransporter.sendMail(mailOptions);
    fastifyInstance.log.info(`Email notification for new leave request successfully sent to ${recipientEmail} for leave ID ${leaveRequestId}`);
  } catch (error) {
    fastifyInstance.log.error({ msg: `Failed to send new leave request email for ID ${leaveRequestId}:`, error: error.message, stack: error.stack });
  }
}

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
  const authHeader = req.headers.authorization;

  // Prioritaskan otentikasi via API Key (JWT) dari header
  if (authHeader) {
    const parts = authHeader.split(" ");
    let token = parts.length === 2 && parts[0] === "Bearer" ? parts[1].trim() : authHeader.trim();

    // Validasi awal: pastikan token ada dan memiliki struktur JWT (x.y.z)
    if (token && token.split(".").length === 3) {
      try {
        const decoded = fastify.jwt.verify(token);
        req.user = decoded; // payload JWT kita berisi: { employeeId, email, permission }
        fastify.log.info(`Authentication: JWT verified for user ${decoded.email} with permission ${decoded.permission}.`);
        return; // Sukses, lanjut ke handler
      } catch (err) {
        // Gagal verifikasi (signature salah, expired, dll)
        fastify.log.error({
          msg: "JWT verification failed",
          token: token, // Log token yang gagal
          error: err.message
        });
        return reply.code(401).send({ error: "Token tidak valid atau expired", relogin: true });
      }
    } else {
      // Format token salah atau tidak ada token setelah parsing
      fastify.log.warn({ header: authHeader }, "Malformed Authorization header or empty token.");
      return reply.code(401).send({ error: "Format token salah" });
    }
  }

  // Fallback ke otentikasi via session cookie (untuk browser)
  if (req.session && req.session.accessToken && req.session.employee_id) {
    req.user = {
      employeeId: req.session.employee_id,
      email: req.session.email,
      permission: req.session.permission
    };
    fastify.log.info(`Authentication: Session cookie verified for user ${req.user.email}.`);
    return; // Sukses, lanjut ke handler
  }

  // Fallback ke otentikasi via App Token
  if (req.headers['x-app-token']) {
    try {
      const appToken = await getAppLevelDataverseToken();
      if (req.headers['x-app-token'] === appToken) {
        req.user = { role: 'admin' }; // Atau role yang sesuai
        fastify.log.info("Authentication: App token verified.");
        return; // Sukses, lanjut ke handler
      }
    } catch (error) {
      fastify.log.error("Failed to validate app token", error);
      return reply.code(500).send({ error: "Failed to validate app token" });
    }
  }

  // Jika semua metode otentikasi gagal
  fastify.log.warn("Authentication: No valid authentication method found.");
  return reply.code(401).send({ error: "Autentikasi diperlukan. Silakan login.", relogin: true });
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

fastify.get("/whoami", {
  preValidation: [fastify.authenticate],
  schema: {
    summary: 'Get Current User Identity',
    description: 'Mengambil informasi identitas user yang sedang login, baik via Cookie maupun API Key.',
    tags: ['Authentication'],
    response: {
      200: {
        type: 'object',
        properties: {
          employeeId: { type: 'string', format: 'uuid' },
          email: { type: 'string', format: 'email' },
          permission: { type: 'string' }
        }
      }
    },
    security: [
      { Bearer: [] }
    ]
  }
}, async (request, reply) => {
  // Setelah middleware authenticate, req.user sudah pasti ada.
  return request.user;
});

// ... (sisa endpoint tidak perlu diubah karena bergantung pada middleware 'authenticate') ...

// ==============================
// 🔹 Admin: Search and Get Employee Profile
// ==============================
fastify.get("/admin/profile/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  console.log("Request received at /admin/profile/search"); // New log
  if (req.user.permission !== "admin") {
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
    filter = `contains(ecom_employeename, '${name}')`;
  } else {
    return reply.code(400).send({ message: "Setidaknya satu dari 'id', 'code', 'email', atau 'name' harus diberikan." });
  }

  try {
    const personalInfoData = await dataverseRequest(req, "get", "ecom_personalinformations", {
      params: {
        $filter: filter,
        $select: [
          "ecom_personalinformationid", "ecom_nik", "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
          "ecom_phonenumber", "statecode", "ecom_startwork",
          "ecom_workexperience", "ecom_dateofemployment",
          "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
          "ecom_relationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
          "ecom_profilepicture", "ecom_bankaccountnumber", "ecom_bpjsnumber",
          "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
          "ecom_religion", "ecom_bankname", "ecom_accountname", "ecom_personalemail", "ecom_workemail", "ecom_insurancenumber"
        ].join(",")
      }
    });

    if (!personalInfoData.value || personalInfoData.value.length === 0) {
      return reply.code(404).send({ message: "Personal information record not found for the provided criteria." });
    }

    const profile = personalInfoData.value[0]; // Admin search returns at most one profile

    // Fetch the latest job title from ecom_employeepositions
    try {
      const latestPositionData = await dataverseRequest(req, "get", "ecom_employeepositions", {
        params: {
          $filter: `_ecom_personalinformation_value eq ${profile.ecom_personalinformationid} and statecode eq 0`,
          $select: "ecom_startdate", // Only need a field to expand
          $expand: "ecom_JobTitle($select=ecom_jobtitle)",
          $orderby: "ecom_startdate desc",
          $top: 1
        }
      });

      if (latestPositionData.value && latestPositionData.value.length > 0) {
        const latestPosition = latestPositionData.value[0];
        if (latestPosition.ecom_JobTitle && latestPosition.ecom_JobTitle.ecom_jobtitle) {
          profile.ecom_jobtitle = latestPosition.ecom_JobTitle.ecom_jobtitle;
        } else {
          profile.ecom_jobtitle = null;
        }
      } else {
        profile.ecom_jobtitle = null; // No active position found
      }
    } catch (positionErr) {
      fastify.log.error(`Error fetching latest position for ${profile.ecom_personalinformationid}: ${positionErr.message}`);
      profile.ecom_jobtitle = null; // Fallback in case of error
    }

    return profile; // Return single profile

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
  fastify.log.info(req.body, "DEBUG: Received body for PATCH profile");
  if (req.user.permission !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { employeeId } = req.params; // This is the personalinformationid (GUID)
  fastify.log.info(`PATCH /profile/${employeeId} - req.body: ${JSON.stringify(req.body)}, Content-Type: ${req.headers['content-type']}`);

  try {
    const allowedFields = [
      "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
      "ecom_phonenumber", "statecode", "ecom_startwork",
      "ecom_workexperience", "ecom_dateofemployment",
      "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
      "ecom_relationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
      "ecom_profilepicture", "ecom_bankaccountnumber", "ecom_bpjsnumber", "ecom_insurancenumber",
      "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
      "ecom_religion", "ecom_bankname", "ecom_accountname", "ecom_personalemail", "ecom_workemail"
    ];

    let potentialUpdates = {};
    if (req.body && typeof req.body.data_update_json === 'string' && req.body.data_update_json.trim() !== '') {
      try {
        potentialUpdates = JSON.parse(req.body.data_update_json);
        fastify.log.info(potentialUpdates, "DEBUG: Parsed updates from data_update_json field");
      } catch (e) {
        fastify.log.error(e, "DEBUG: Failed to parse data_update_json string, falling back to use raw body.");
        potentialUpdates = req.body;
      }
    } else {
      potentialUpdates = req.body;
    }

    const updates = {};
    for (const field of allowedFields) {
      if (potentialUpdates[field] !== undefined) {
        updates[field] = potentialUpdates[field];
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

// ==============================
// 🔹 INSTAGRAM WEBHOOK HELPERS & ENDPOINTS
// Inserted by Copilot: handles verification, intent parsing, dataverse calls via existing helpers
// ==============================

function verifyInstagramSignature(payload, signature, appSecret) {
  if (!signature) return false;
  try {
    const expected = crypto.createHmac('sha1', appSecret).update(payload, 'utf8').digest('hex');
    const parts = signature.split('=');
    return parts.length === 2 && parts[0] === 'sha1' && parts[1] === expected;
  } catch (e) {
    fastify.log.error({ msg: 'verifyInstagramSignature failed', error: e.message });
    return false;
  }
}

function extractPeriodFromText(text) {
  const m = String(text || '').match(/\b(20\d{2})\b/);
  return m ? m[1] : null;
}

function parseIntent(messageText) {
  const text = (messageText || '').toLowerCase().trim();
  if (!text) return { intent: 'unknown', params: {} };
  if (text.startsWith('admin ')) {
    return { intent: 'admin_query', params: parseAdminCommand(messageText) };
  }
  if (text.startsWith('pilih cuti')) return { intent: 'submit_leave', params: { raw_message: messageText } };
  if (text === 'help' || text === 'bantuan' || text === 'menu') return { intent: 'help', params: {} };
  if (text.includes('login') || text.includes('masuk')) return { intent: 'login', params: {} };
  if (text.includes('jenis cuti') || text.includes('tipe cuti') || text.includes('leave type')) return { intent: 'get_leave_types', params: {} };
  if (text.includes('cek cuti') || text.includes('saldo') || text.includes('cuti berapa')) {
    return { intent: 'check_leave_balance', params: { period: extractPeriodFromText(text) } };
  }
  if (text.includes('ajukan') || text.includes('apply') || text.includes('request')) return { intent: 'submit_leave', params: { raw_message: messageText } };
  if (text.includes('data') || text.includes('profil') || text.includes('info')) return { intent: 'get_profile', params: {} };
  if (text.includes('posisi') || text.includes('jabatan') || text.includes('grade')) return { intent: 'get_position', params: {} };
  if (text.includes('development') || text.includes('pengembangan') || text.includes('project')) return { intent: 'get_developments', params: {} };
  if (text.includes('peer review') || text.includes('review') || text.includes('penilaian')) return { intent: 'get_peer_review_summary', params: {} };
  if (text.includes('riwayat') || text.includes('history') || text.includes('daftar cuti')) return { intent: 'get_leave_requests', params: {} };
  return { intent: 'unknown', params: { raw_message: messageText } };
}

function parseAdminCommand(messageText) {
  const raw = (messageText || '').trim();

  const withCriteria = /^admin\s+(profile|saldo|position|developments?|review|peer\s*review)\s+(.+)$/i.exec(raw);
  if (withCriteria) {
    const action = withCriteria[1].toLowerCase().replace(/\s+/g, '_');
    const value = (withCriteria[2] || '').trim();
    return { action, by: 'name', value };
  }

  const leaveCmd = /^admin\s+(cuti|leave)(?:\s+(.+))?$/i.exec(raw);
  if (leaveCmd) {
    const arg = (leaveCmd[2] || '').trim();
    if (!arg) return { action: 'leave_requests' };

    const monthMap = {
      januari: '01', january: '01', jan: '01',
      februari: '02', february: '02', feb: '02',
      maret: '03', march: '03', mar: '03',
      april: '04', apr: '04',
      mei: '05', may: '05',
      juni: '06', june: '06', jun: '06',
      juli: '07', july: '07', jul: '07',
      agustus: '08', august: '08', agu: '08', aug: '08',
      september: '09', sep: '09', sept: '09',
      oktober: '10', october: '10', okt: '10', oct: '10',
      november: '11', nov: '11',
      desember: '12', december: '12', des: '12', dec: '12'
    };

    let period = null;
    let name = arg;

    const monthYearMatch = arg.match(/\b([a-zA-Z]+)\s+(20\d{2})\b/i);
    if (monthYearMatch) {
      const month = monthMap[monthYearMatch[1].toLowerCase()];
      if (month) {
        period = `${monthYearMatch[2]}-${month}`;
        name = name.replace(monthYearMatch[0], ' ');
      }
    }

    if (!period) {
      const ymMatch = arg.match(/\b(20\d{2})-(\d{1,2})\b/);
      if (ymMatch) {
        const mm = Number(ymMatch[2]);
        if (mm >= 1 && mm <= 12) {
          period = `${ymMatch[1]}-${String(mm).padStart(2, '0')}`;
          name = name.replace(ymMatch[0], ' ');
        }
      }
    }

    if (!period) {
      const yearMatch = arg.match(/\b(20\d{2})\b/);
      if (yearMatch) {
        period = yearMatch[1];
        name = name.replace(yearMatch[0], ' ');
      }
    }

    name = name.replace(/\b(period|periode|tahun|month|bulan|di|pada)\b/gi, ' ').replace(/\s+/g, ' ').trim();
    if (!name || /^(all|semua)$/i.test(name)) name = null;

    return { action: 'leave_requests', name, period };
  }

  return { action: 'unknown', raw };
}

function splitInstagramMessage(messageText, maxLen = 1000) {
  const text = String(messageText || '');
  if (!text || text.length <= maxLen) return [text];

  const lines = text.split('\n');
  const chunks = [];
  let current = '';

  const flush = () => {
    if (current) {
      chunks.push(current);
      current = '';
    }
  };

  for (const line of lines) {
    const candidate = current ? `${current}\n${line}` : line;
    if (candidate.length <= maxLen) {
      current = candidate;
      continue;
    }

    flush();

    if (line.length <= maxLen) {
      current = line;
      continue;
    }

    // Handle a single very long line by slicing it into safe chunks.
    let remaining = line;
    while (remaining.length > maxLen) {
      chunks.push(remaining.slice(0, maxLen));
      remaining = remaining.slice(maxLen);
    }
    current = remaining;
  }

  flush();
  return chunks.length ? chunks : [text];
}

async function sendInstagramMessageChunk(recipientId, messageText, token) {
  const endpoint = 'https://graph.instagram.com/v25.0/me/messages';
  const payload = {
    recipient: { id: String(recipientId) },
    message: { text: String(messageText || '') }
  };

  try {
    fastify.log.info({
      msg: 'Sending Instagram message via Graph API',
      endpoint,
      recipientId: String(recipientId),
      messagePreview: String(messageText || '').substring(0, 50),
      tokenPrefix: token.substring(0, 6),
      messageLength: String(messageText || '').length
    });

    // Primary request format: Authorization Bearer header (same as tested curl).
    const res = await axios.post(endpoint, payload, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });

    fastify.log.info({
      msg: 'Instagram message sent successfully',
      recipientId: String(recipientId),
      responseData: res.data
    });
    return res.data;
  } catch (err) {
    // Fallback for environments that still expect access_token query param.
    try {
      const fallbackRes = await axios.post(endpoint, payload, {
        params: { access_token: token },
        headers: { 'Content-Type': 'application/json' },
        timeout: 10000
      });
      fastify.log.info({
        msg: 'Instagram message sent successfully via fallback query token',
        recipientId: String(recipientId),
        responseData: fallbackRes.data
      });
      return fallbackRes.data;
    } catch (fallbackErr) {
      fastify.log.error({
        msg: 'Failed to send Instagram message',
        recipientId: String(recipientId),
        error: fallbackErr.message,
        status: fallbackErr.response?.status,
        responseData: fallbackErr.response?.data
      });
      throw fallbackErr;
    }
  }
}

async function sendInstagramMessage(recipientId, messageText, accessToken) {
  const token = (accessToken || process.env.INSTAGRAM_ACCESS_TOKEN || '').trim();
  if (!token) {
    fastify.log.error({ msg: 'INSTAGRAM_ACCESS_TOKEN is missing. Cannot send message.' });
    return null;
  }

  const chunks = splitInstagramMessage(messageText, 1000);
  if (chunks.length > 1) {
    fastify.log.info({
      msg: 'Splitting Instagram message into chunks',
      recipientId: String(recipientId),
      chunkCount: chunks.length,
      originalLength: String(messageText || '').length
    });
  }

  const responses = [];
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    fastify.log.info({
      msg: 'Sending Instagram message chunk',
      recipientId: String(recipientId),
      chunkIndex: i + 1,
      chunkCount: chunks.length,
      chunkLength: chunk.length
    });
    const res = await sendInstagramMessageChunk(recipientId, chunk, token);
    responses.push(res);
  }
  return responses[responses.length - 1] || null;
}

const LOGIN_URL = 'https://ecomate-phi.vercel.app/login';

async function sendInstagramButtonTemplate(recipientId, accessToken, text, buttons) {
  const token = (accessToken || process.env.INSTAGRAM_ACCESS_TOKEN || '').trim();
  if (!token) return null;
  if (!Array.isArray(buttons) || !buttons.length) return null;

  const endpoint = 'https://graph.instagram.com/v25.0/me/messages';
  const payload = {
    recipient: { id: String(recipientId) },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'button',
          text,
          buttons
        }
      }
    }
  };

  try {
    return await axios.post(endpoint, payload, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
  } catch (err) {
    fastify.log.warn({ msg: 'sendInstagramButtonTemplate failed', error: err.message, status: err.response?.status, responseData: err.response?.data });
    return null;
  }
}

async function sendInstagramLoginButton(recipientId, accessToken) {
  return sendInstagramButtonTemplate(recipientId, accessToken, 'Klik tombol di bawah untuk login:', [
    {
      type: 'web_url',
      title: 'Login ecomate',
      url: LOGIN_URL
    }
  ]);
}

async function sendInstagramServiceButtons(recipientId, accessToken) {
  return sendInstagramButtonTemplate(recipientId, accessToken, 'Layanan HR lebih lengkap:', [
    {
      type: 'web_url',
      title: 'Whatsapp Agent ecomate (AI)',
      url: 'https://wa.me/6281280393537'
    },
    {
      type: 'web_url',
      title: 'Web Agent ecomate (AI)',
      url: 'https://app.qlar.ai/ecomate'
    },
    {
      type: 'web_url',
      title: 'ecomate Dashboard',
      url: 'https://ecomate-dashboard.lovable.app'
    }
  ]);
}

function getDataverseFormattedValue(record, fieldName) {
  if (!record || !fieldName) return null;
  const key = `${fieldName}@OData.Community.Display.V1.FormattedValue`;
  const val = record[key];
  if (val === null || val === undefined) return null;
  const txt = String(val).trim();
  return txt || null;
}

function toProfileDisplayValue(record, fieldName) {
  return getDataverseFormattedValue(record, fieldName) || record?.[fieldName];
}

function toLeaveStatusLabel(record) {
  if (!record) return '-';
  const formatted = getDataverseFormattedValue(record, 'ecom_leavestatus');
  if (formatted) return formatted;
  const mapped = LeaveStatus?.[record.ecom_leavestatus]?.id;
  return mapped || record.ecom_leavestatus || '-';
}

function formatInstagramResponse(data, intent) {
  const normalizeDateText = (input) => {
    let text = String(input || '');

    // Convert ISO datetime like 2026-07-02T00:00:00Z -> 02-07-2026
    text = text.replace(/\b(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b/g, (_, y, m, d) => `${d}-${m}-${y}`);

    // Convert plain date like 2026-07-02 -> 02-07-2026
    text = text.replace(/\b(\d{4})-(\d{2})-(\d{2})\b/g, (_, y, m, d) => `${d}-${m}-${y}`);

    return text;
  };

  let response = '';
  switch (intent) {
    case 'help':
      response = [
        '📌 Perintah yang tersedia:',
        '- login',
        '- data / profil',
        '- posisi / jabatan',
        '- cek cuti / saldo',
        '- tipe cuti',
        '- ajukan cuti <tanggal>',
        '- ajukan cuti khusus <tanggal>',
        '- pilih cuti <nomor> <jumlah_hari> <alasan(optional)>',
        '- pilih cuti khusus <nomor> <jumlah_hari> <alasan(optional)>',
        '- riwayat cuti',
        '- development (riwayat project)',
        '- peer review',
        '',
        '🔎 Contoh tanggal: 27 april 2026',
        '',
        '🔒 Perintah admin (butuh role admin/co_admin):',
        '- admin profile <nama>',
        '- admin saldo <nama>',
        '- admin position <nama>',
        '- admin development <nama>',
        '- admin review <nama>',
        '- admin cuti <bulan> <tahun>',
        '- admin cuti <nama> <bulan> <tahun>',
        '- admin cuti <nama> <tahun>'
      ].join('\n');
      break;
    case 'login':
      response = '🔐 Login diminta\n\nKlik tombol Login di bawah, lalu salin OTP dari browser dan kirim ke sini.';
      break;
    case 'get_leave_types':
      if (data.leaveTypes && data.leaveTypes.length) {
        response = '🗂️ Jenis Cuti Aktif:\n';
        data.leaveTypes.slice(0, 10).forEach(t => {
          const quota = t.ecom_quota == null ? '-' : t.ecom_quota;
          const name = String(t.ecom_name || '').toLowerCase();
          const routeHint = name.startsWith('cuti panjang') ? 'khusus' : 'reguler/khusus (tergantung rule)';
          response += `- ${t.ecom_name} (kuota: ${quota}, jalur: ${routeHint})\n`;
        });
        response += '\nℹ️ Pembeda jalur:';
        response += '\n- /leave/requests: untuk cuti reguler berbasis saldo periode.';
        response += '\n- /leave/requests/special: untuk cuti khusus berbasis kuota/aturan khusus (termasuk Cuti Panjang).';
      } else {
        response = '❌ Data jenis cuti tidak ditemukan.';
      }
      break;
    case 'check_leave_balance':
      if (data.action === 'select_period') {
        const periods = data.periods || [];
        if (!periods.length) {
          response = '❌ Tidak ada data periode saldo cuti yang tersedia.';
        } else {
          response = [
            '📅 Mau cek saldo cuti tahun berapa?',
            `Periode tersedia: ${periods.join(', ')}`,
            'Contoh: cek cuti 2026'
          ].join('\n');
        }
      } else if (data.balances && data.balances.length) {
        const periodLabel = data.period || '-';
        response = `📅 Saldo Cuti Anda (Periode ${periodLabel})\n`;
        data.balances.forEach(b => {
          const start = b.start_date || '-';
          const end = b.end_date || '-';
          response += `${b.leave_type_name || b.ecom_name}: ${b.balance || b.ecom_balance} hari\n`;
          response += `  periode tanggal: ${start} s/d ${end}\n`;
        });
      } else {
        const periodLabel = data.period || 'tahun yang dipilih';
        response = `❌ Tidak ada data saldo cuti untuk periode ${periodLabel}.`;
      }
      break;
    case 'get_profile':
      if (data.profile) {
        const profile = data.profile;
        const fields = [
          ['Nama', profile.ecom_employeename],
          ['Email Kerja', profile.ecom_workemail],
          ['Email Personal', profile.ecom_personalemail],
          ['NIK', profile.ecom_nik],
          ['No HP', profile.ecom_phonenumber],
          ['Gender', toProfileDisplayValue(profile, 'ecom_gender')],
          ['Tanggal Lahir', profile.ecom_dateofbirth],
          ['Tempat Lahir', profile.ecom_placeofbirth],
          ['Agama', toProfileDisplayValue(profile, 'ecom_religion')],
          ['Status Menikah', toProfileDisplayValue(profile, 'ecom_maritalstatus')],
          ['Jumlah Tanggungan', profile.ecom_numberofdependent],
          ['Alamat', profile.ecom_address],
          ['Jabatan', profile.ecom_jobtitle],
          ['Tanggal Join', profile.ecom_dateofemployment],
          ['Bank', profile.ecom_bankname],
          ['No Rekening', profile.ecom_bankaccountnumber],
          ['NPWP', profile.ecom_npwpnumber],
          ['BPJS Kesehatan', profile.ecom_bpjsnumber],
          ['BPJS TK', profile.ecom_bpjstknumber],
          ['Kontak Darurat', profile.ecom_emergencycontactname],
          ['Telp Darurat', profile.ecom_emergencycontractphonenumber],
          ['Hubungan Darurat', profile.ecom_relationship]
        ].filter(([, v]) => v !== null && v !== undefined && String(v).trim() !== '');

        response = `👤 Profil Lengkap Anda\n${fields.map(([k, v]) => `${k}: ${v}`).join('\n')}`;
      } else {
        response = '❌ Profil tidak ditemukan.';
      }
      break;
    case 'admin_query':
      response = data.adminText || '❌ Perintah admin gagal diproses.';
      break;
    case 'get_position':
      if (data.position_name || data.grade_label) {
        response = [
          '🧭 Posisi Saat Ini:',
          `Posisi: ${data.position_name || '-'}`,
          `Grade: ${data.grade_label || '-'}`,
          `Status: ${data.status_label || '-'}`,
          `Mulai: ${data.start_date || '-'}`
        ].join('\n');
      } else {
        response = '❌ Data posisi tidak ditemukan.';
      }
      break;
    case 'get_leave_requests':
      if (data.requests && data.requests.length) {
        response = '📋 Riwayat Cuti:\n';
        data.requests.slice(0,5).forEach(r => { response += `${r.leave_type}: ${r.start_date} → ${r.end_date} [${r.status_label || r.status}]\n`; });
      } else response = '✅ Tidak ada riwayat cuti.';
      break;
    case 'get_developments':
      if (data.items && data.items.length) {
        response = '🚀 Development Terbaru:\n';
        data.items.slice(0, 5).forEach((d) => {
          response += `${d.title || '-'} (${d.type_label || '-'}) ${d.start_date || '-'}\n`;
        });
      } else {
        response = '✅ Belum ada data development.';
      }
      break;
    case 'get_peer_review_summary':
      if (data.items && data.items.length) {
        response = '⭐ Summary Peer Review:\n';
        data.items.slice(0, 5).forEach((r) => {
          response += `${r.project_name || '-'} | avg: ${r.average_rating ?? '-'} | total: ${r.total_peer_review ?? '-'}\n`;
        });
      } else {
        response = '✅ Belum ada data peer review.';
      }
      break;
    case 'submit_leave':
      if (data.action === 'select_leave_type') {
        const items = Array.isArray(data.leaveTypes) ? data.leaveTypes : [];
        if (!items.length) {
          response = '❌ Jenis cuti tidak ditemukan saat ini. Coba lagi nanti.';
          break;
        }
        const isSpecial = data.submissionKind === 'special';
        const chooseCmd = isSpecial ? 'pilih cuti khusus' : 'pilih cuti';
        response = [
          `📝 Tanggal mulai cuti: ${data.startDate || '-'}`,
          'Pilih jenis cuti dengan balas:',
          `${chooseCmd} <nomor> <jumlah_hari> <alasan(optional)>`,
          '',
          `Contoh: ${chooseCmd} 1 2 urusan keluarga`,
          '',
          'Daftar jenis cuti:'
        ].join('\n');

        items.slice(0, 12).forEach((t, i) => {
          const quota = t.ecom_quota == null ? '-' : t.ecom_quota;
          response += `\n${i + 1}. ${t.ecom_name} (kuota: ${quota})`;
        });
      } else if (data.ok) {
        response = [
          '✅ Pengajuan cuti berhasil dibuat.',
          `Leave ID: ${data.leaveId || '-'}`,
          `Tipe Cuti: ${data.leaveTypeName || '-'}`,
          `Periode: ${data.startDate || '-'} s/d ${data.endDate || '-'}`,
          `Masuk Kerja: ${data.returnDate || '-'}`,
          `Jumlah Hari: ${data.days || 0}`,
          `Sisa Saldo: ${data.balanceRemaining ?? '-'}`
        ].join('\n');
      } else {
        response = `❌ Gagal ajukan cuti. ${data.message || ''}`.trim();
      }
      break;
    default:
      response = '❓ Perintah tidak dipahami. Ketik bantuan untuk lihat daftar perintah.';
  }
  response = normalizeDateText(response);
  const maxResponseLength = (intent === 'get_profile' || intent === 'admin_query') ? 1800 : 900;
  if (response.length > maxResponseLength) response = response.substring(0, maxResponseLength - 3) + '...';
  return response;
}

function getPermissionByEmail(email) {
  if (!email) return 'employee';
  if (isAdmin(email)) return 'admin';
  if (isCoAdmin(email)) return 'co_admin';
  return 'employee';
}

async function getPSIDUserMapping(psid) {
  try {
    const data = await kv.get(`instagram:psid:${psid}`);
    if (!data) return null;
    if (typeof data === 'string') {
      return {
        email: data,
        permission: getPermissionByEmail(data),
      };
    }
    return data;
  } catch (e) {
    fastify.log.error({ msg: 'kv.get failed', e: e.message });
    return null;
  }
}

async function setPSIDUserMapping(psid, userData, ttl = 2592000) { // 30 days
  try {
    await kv.setex(`instagram:psid:${psid}`, ttl, userData);
  } catch (e) {
    fastify.log.error({ msg: 'kv.setex failed', e: e.message });
  }
}

async function getLeaveDraft(psid) {
  try {
    return await kv.get(`instagram:leave-draft:${psid}`);
  } catch (e) {
    fastify.log.error({ msg: 'getLeaveDraft failed', e: e.message });
    return null;
  }
}

async function setLeaveDraft(psid, draft, ttl = 3600) { // 1 hour
  try {
    await kv.setex(`instagram:leave-draft:${psid}`, ttl, draft);
  } catch (e) {
    fastify.log.error({ msg: 'setLeaveDraft failed', e: e.message });
  }
}

async function clearLeaveDraft(psid) {
  try {
    await kv.del(`instagram:leave-draft:${psid}`);
  } catch (e) {
    fastify.log.error({ msg: 'clearLeaveDraft failed', e: e.message });
  }
}

// Helper functions for data fetching (shared with endpoints)
async function getLeaveBalance(email, period = null) {
  try {
    const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() }, user: { email } };
    const personal = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', { params: { $filter: `ecom_workemail eq '${email}'`, $select: 'ecom_personalinformationid' } });
    if (!personal.value?.length) return { error: 'Personal info not found' };
    const employeeId = personal.value[0].ecom_personalinformationid;

    if (!period) {
      const periodsRes = await dataverseRequest(minReq, 'get', 'ecom_leaveusages', {
        params: {
          $filter: `_ecom_employee_value eq ${employeeId}`,
          $select: 'ecom_period',
          $orderby: 'ecom_period desc',
          $top: 20
        }
      });
      const periods = Array.from(new Set((periodsRes.value || [])
        .map(i => String(i.ecom_period || '').trim())
        .filter(Boolean)))
        .sort((a, b) => b.localeCompare(a));
      return { action: 'select_period', periods };
    }

    const balancesRes = await dataverseRequest(minReq, 'get', 'ecom_leaveusages', {
      params: {
        $filter: `_ecom_employee_value eq ${employeeId} and ecom_period eq '${period}'`,
        $select: 'ecom_balance,_ecom_leavetype_value,ecom_name,ecom_period,ecom_startdate,ecom_enddate'
      }
    });
    const balances = (balancesRes.value || []).map(b => ({
      leave_type_name: b.ecom_name,
      balance: b.ecom_balance,
      period: b.ecom_period,
      start_date: b.ecom_startdate,
      end_date: b.ecom_enddate
    }));
    return { period: String(period), balances };
  } catch (e) {
    fastify.log.error({ msg: 'getLeaveBalance failed', e: e.message });
    return { error: 'Failed to fetch balance' };
  }
}

async function getProfile(email) {
  try {
    const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() }, user: { email } };
    const personalInfoRes = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', {
      headers: DATAVERSE_FORMATTED_VALUE_HEADERS,
      params: {
        $filter: `ecom_workemail eq '${email}'`,
        $select: [
          'ecom_personalinformationid', 'ecom_nik', 'ecom_employeename', 'ecom_gender', 'ecom_dateofbirth',
          'ecom_phonenumber', 'statecode', 'ecom_startwork', 'ecom_workexperience', 'ecom_dateofemployment',
          'ecom_emergencycontactname', 'ecom_emergencycontactaddress', 'ecom_emergencycontractphonenumber',
          'ecom_relationship', 'ecom_address', 'ecom_ktpnumber', 'ecom_npwpnumber', 'ecom_profilepicture',
          'ecom_bankaccountnumber', 'ecom_bpjsnumber', 'ecom_bpjstknumber', 'ecom_maritalstatus',
          'ecom_numberofdependent', 'ecom_placeofbirth', 'ecom_religion', 'ecom_bankname', 'ecom_accountname',
          'ecom_personalemail', 'ecom_workemail', 'ecom_insurancenumber'
        ].join(',')
      }
    });

    if (personalInfoRes.value?.length) {
      const profile = personalInfoRes.value[0];

      try {
        const latestPositionData = await dataverseRequest(minReq, 'get', 'ecom_employeepositions', {
          params: {
            $filter: `_ecom_personalinformation_value eq ${profile.ecom_personalinformationid} and statecode eq 0`,
            $select: 'ecom_startdate',
            $expand: 'ecom_JobTitle($select=ecom_jobtitle)',
            $orderby: 'ecom_startdate desc',
            $top: 1
          }
        });
        profile.ecom_jobtitle = latestPositionData.value?.[0]?.ecom_JobTitle?.ecom_jobtitle || null;
      } catch (positionErr) {
        fastify.log.error({ msg: 'getProfile position lookup failed', e: positionErr.message });
        profile.ecom_jobtitle = null;
      }

      return { profile };
    }

    return { error: 'Profile not found' };
  } catch (e) {
    fastify.log.error({ msg: 'getProfile failed', e: e.message });
    return { error: 'Failed to fetch profile' };
  }
}

async function resolveEmployeeIdForAdmin(minReq, by, value) {
  if (by === 'id') return value;
  const filter = by === 'email'
    ? `ecom_workemail eq '${value}'`
    : `contains(ecom_employeename, '${value}')`;

  const userData = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', {
    params: {
      $filter: filter,
      $select: 'ecom_personalinformationid'
    }
  });

  return userData.value?.[0]?.ecom_personalinformationid || null;
}

async function handleAdminQuery(userMapping, params) {
  const permission = userMapping?.permission || 'employee';
  if (!['admin', 'co_admin'].includes(permission)) {
    return { adminText: '⛔ Fitur ini hanya untuk admin/co_admin.' };
  }

  const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() }, user: { email: userMapping.email, permission } };
  const action = params?.action;
  const by = params?.by;
  const value = params?.value;

  try {
    if (action === 'profile') {
      if (!value) return { adminText: 'Gunakan: admin profile <nama>' };
      const employeeId = await resolveEmployeeIdForAdmin(minReq, 'name', value);
      if (!employeeId) return { adminText: '❌ Karyawan tidak ditemukan.' };

      const profileRes = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', {
        headers: DATAVERSE_FORMATTED_VALUE_HEADERS,
        params: {
          $filter: `ecom_personalinformationid eq ${employeeId}`,
          $select: [
            'ecom_personalinformationid', 'ecom_nik', 'ecom_employeename', 'ecom_gender', 'ecom_dateofbirth',
            'ecom_phonenumber', 'statecode', 'ecom_startwork', 'ecom_workexperience', 'ecom_dateofemployment',
            'ecom_emergencycontactname', 'ecom_emergencycontactaddress', 'ecom_emergencycontractphonenumber',
            'ecom_relationship', 'ecom_address', 'ecom_ktpnumber', 'ecom_npwpnumber', 'ecom_profilepicture',
            'ecom_bankaccountnumber', 'ecom_bpjsnumber', 'ecom_bpjstknumber', 'ecom_maritalstatus',
            'ecom_numberofdependent', 'ecom_placeofbirth', 'ecom_religion', 'ecom_bankname', 'ecom_accountname',
            'ecom_personalemail', 'ecom_workemail', 'ecom_insurancenumber'
          ].join(',')
        }
      });
      const p = profileRes.value?.[0];
      if (!p) return { adminText: '❌ Profil karyawan tidak ditemukan.' };

      try {
        const latestPositionData = await dataverseRequest(minReq, 'get', 'ecom_employeepositions', {
          params: {
            $filter: `_ecom_personalinformation_value eq ${p.ecom_personalinformationid} and statecode eq 0`,
            $select: 'ecom_startdate',
            $expand: 'ecom_JobTitle($select=ecom_jobtitle)',
            $orderby: 'ecom_startdate desc',
            $top: 1
          }
        });
        p.ecom_jobtitle = latestPositionData.value?.[0]?.ecom_JobTitle?.ecom_jobtitle || null;
      } catch (positionErr) {
        fastify.log.error({ msg: 'admin profile: position lookup failed', e: positionErr.message });
        p.ecom_jobtitle = null;
      }

      const fields = [
        ['Nama', p.ecom_employeename],
        ['Email Kerja', p.ecom_workemail],
        ['Email Personal', p.ecom_personalemail],
        ['NIK', p.ecom_nik],
        ['No HP', p.ecom_phonenumber],
        ['Gender', toProfileDisplayValue(p, 'ecom_gender')],
        ['Tanggal Lahir', p.ecom_dateofbirth],
        ['Tempat Lahir', p.ecom_placeofbirth],
        ['Agama', toProfileDisplayValue(p, 'ecom_religion')],
        ['Status Menikah', toProfileDisplayValue(p, 'ecom_maritalstatus')],
        ['Jumlah Tanggungan', p.ecom_numberofdependent],
        ['Alamat', p.ecom_address],
        ['Jabatan', p.ecom_jobtitle],
        ['Tanggal Join', p.ecom_dateofemployment],
        ['Bank', p.ecom_bankname],
        ['No Rekening', p.ecom_bankaccountnumber],
        ['NPWP', p.ecom_npwpnumber],
        ['No KTP', p.ecom_ktpnumber],
        ['BPJS Kesehatan', p.ecom_bpjsnumber],
        ['BPJS TK', p.ecom_bpjstknumber],
        ['No Asuransi', p.ecom_insurancenumber],
        ['Kontak Darurat', p.ecom_emergencycontactname],
        ['Alamat Darurat', p.ecom_emergencycontactaddress],
        ['Telp Darurat', p.ecom_emergencycontractphonenumber],
        ['Hubungan Darurat', p.ecom_relationship]
      ].filter(([, v]) => v !== null && v !== undefined && String(v).trim() !== '');

      return {
        adminText: `🧾 Profil Karyawan Lengkap\n${fields.map(([k, v]) => `${k}: ${v}`).join('\n')}`
      };
    }

    if (action === 'saldo') {
      if (!value) return { adminText: 'Gunakan: admin saldo <nama>' };
      const employeeId = await resolveEmployeeIdForAdmin(minReq, 'name', value);
      if (!employeeId) return { adminText: '❌ Karyawan tidak ditemukan.' };

      const period = String(new Date().getFullYear());
      const balanceData = await dataverseRequest(minReq, 'get', 'ecom_leaveusages', {
        params: {
          $filter: `_ecom_employee_value eq ${employeeId} and ecom_period eq '${period}'`,
          $select: 'ecom_balance,ecom_name'
        }
      });
      const items = balanceData.value || [];
      if (!items.length) return { adminText: `❌ Tidak ada saldo cuti periode ${period}.` };
      return { adminText: `📊 Saldo Cuti (${period})\n${items.map((i) => `- ${i.ecom_name || '-'}: ${i.ecom_balance || 0} hari`).join('\n')}` };
    }

    if (action === 'position') {
      if (!value) return { adminText: 'Gunakan: admin position <nama>' };
      const employeeId = await resolveEmployeeIdForAdmin(minReq, 'name', value);
      if (!employeeId) return { adminText: '❌ Karyawan tidak ditemukan.' };

      const positionData = await dataverseRequest(minReq, 'get', 'ecom_employeepositions', {
        params: {
          $filter: `_ecom_personalinformation_value eq ${employeeId}`,
          $select: 'ecom_startdate,ecom_grading,statecode',
          $expand: 'ecom_JobTitle($select=ecom_jobtitle),ecom_PersonalInformation($select=ecom_employeename)',
          $orderby: 'ecom_startdate desc',
          $top: 5
        }
      });
      const rows = positionData.value || [];
      if (!rows.length) return { adminText: '❌ Data posisi tidak ditemukan.' };
      return {
        adminText: `🧭 Riwayat Posisi\n${rows.map((r) => `- ${r.ecom_PersonalInformation?.ecom_employeename || '-'} | ${r.ecom_JobTitle?.ecom_jobtitle || '-'} | ${GRADE_MAP[r.ecom_grading] || 'Unknown'} | ${r.ecom_startdate || '-'}`).join('\n')}`
      };
    }

    if (action === 'development' || action === 'developments') {
      if (!value) return { adminText: 'Gunakan: admin development <nama>' };
      const employeeId = await resolveEmployeeIdForAdmin(minReq, 'name', value);
      if (!employeeId) return { adminText: '❌ Karyawan tidak ditemukan.' };

      const historyData = await dataverseRequest(minReq, 'get', 'ecom_developments', {
        params: {
          $filter: `_ecom_employeeid_value eq ${employeeId}`,
          $select: 'ecom_title,ecom_date,ecom_type',
          $orderby: 'ecom_date desc',
          $top: 5
        }
      });
      const rows = historyData.value || [];
      if (!rows.length) return { adminText: '✅ Tidak ada data development.' };
      return { adminText: `🚀 Development Karyawan\n${rows.map((r) => `- ${r.ecom_title || '-'} (${DEVELOPMENT_TYPE_MAP[r.ecom_type] || 'Unknown'}) ${r.ecom_date || '-'}`).join('\n')}` };
    }

    if (action === 'review' || action === 'peer_review') {
      if (!value) return { adminText: 'Gunakan: admin review <nama>' };

      let userIdToSearch = null;
      const userFilter = `contains(fullname, '${value}')`;
      const userRes = await dataverseRequest(minReq, 'get', 'systemusers', {
        params: {
          $filter: userFilter,
          $select: 'systemuserid'
        }
      });
      userIdToSearch = userRes.value?.[0]?.systemuserid || null;

      if (!userIdToSearch) return { adminText: '❌ User system tidak ditemukan.' };

      const summaryData = await dataverseRequest(minReq, 'get', 'ecom_summarypeerreviews', {
        params: {
          $filter: `_ecom_employee_value eq ${userIdToSearch}`,
          $select: 'ecom_totalpeerreview,ecom_averagerating',
          $expand: 'ecom_Project($select=ecom_projectname)',
          $top: 5
        }
      });
      const rows = summaryData.value || [];
      if (!rows.length) return { adminText: '✅ Tidak ada data peer review.' };
      return { adminText: `⭐ Summary Peer Review\n${rows.map((r) => `- ${r.ecom_Project?.ecom_projectname || '-'} | avg ${r.ecom_averagerating ?? '-'} | total ${r.ecom_totalpeerreview ?? '-'}`).join('\n')}` };
    }

    if (action === 'leave_requests') {
      const filters = [];
      const descriptor = [];

      if (params?.name) {
        const employeeId = await resolveEmployeeIdForAdmin(minReq, 'name', params.name);
        if (!employeeId) return { adminText: '❌ Karyawan tidak ditemukan untuk pencarian cuti.' };
        filters.push(`_ecom_employee_value eq ${employeeId}`);
        descriptor.push(`nama: ${params.name}`);
      }

      if (params?.period) {
        const p = String(params.period).trim();
        if (/^20\d{2}$/.test(p)) {
          filters.push(`ecom_enddate ge ${p}-01-01`);
          filters.push(`ecom_startdate le ${p}-12-31`);
          descriptor.push(`periode: ${p}`);
        } else if (/^20\d{2}-\d{2}$/.test(p)) {
          const [yy, mm] = p.split('-').map(Number);
          const last = new Date(yy, mm, 0).getDate();
          const start = `${yy}-${String(mm).padStart(2, '0')}-01`;
          const end = `${yy}-${String(mm).padStart(2, '0')}-${String(last).padStart(2, '0')}`;
          filters.push(`ecom_enddate ge ${start}`);
          filters.push(`ecom_startdate le ${end}`);
          const monthNames = ['januari', 'februari', 'maret', 'april', 'mei', 'juni', 'juli', 'agustus', 'september', 'oktober', 'november', 'desember'];
          descriptor.push(`periode: ${monthNames[mm - 1]} ${yy}`);
        }
      }

      const query = {
        $select: 'ecom_name,ecom_startdate,ecom_enddate,ecom_leavestatus,createdon',
        $expand: 'ecom_Employee($select=ecom_employeename),ecom_LeaveType($select=ecom_name)',
        $orderby: 'createdon desc',
        $top: 50
      };
      if (filters.length) query.$filter = filters.join(' and ');

      const list = await dataverseRequest(minReq, 'get', 'ecom_employeeleaves', {
        headers: DATAVERSE_FORMATTED_VALUE_HEADERS,
        params: query
      });
      const rows = list.value || [];
      if (!rows.length) return { adminText: '✅ Tidak ada data cuti.' };
      const titleFilter = descriptor.length ? ` (${descriptor.join(', ')})` : ' (terbaru)';
      return {
        adminText: `📋 Leave Requests${titleFilter}\n${rows.map((r) => `- ${r.ecom_Employee?.ecom_employeename || '-'} | ${r.ecom_LeaveType?.ecom_name || r.ecom_name || '-'} | ${r.ecom_startdate || '-'} s/d ${r.ecom_enddate || '-'} | status ${toLeaveStatusLabel(r)}`).join('\n')}`
      };
    }

    return { adminText: '❓ Perintah admin belum dikenali. Ketik bantuan untuk contoh command.' };
  } catch (e) {
    fastify.log.error({ msg: 'handleAdminQuery failed', e: e.message, params });
    return { adminText: `❌ Admin query gagal: ${e.message}` };
  }
}

async function getLeaveRequests(email) {
  try {
    const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() }, user: { email } };
    const personal = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', { params: { $filter: `ecom_workemail eq '${email}'`, $select: 'ecom_personalinformationid' } });
    if (!personal.value?.length) return { error: 'Personal info not found' };
    const employeeId = personal.value[0].ecom_personalinformationid;
    const requestsRes = await dataverseRequest(minReq, 'get', 'ecom_employeeleaves', {
      headers: DATAVERSE_FORMATTED_VALUE_HEADERS,
      params: {
        $filter: `_ecom_employee_value eq ${employeeId}`,
        $select: 'ecom_name,ecom_startdate,ecom_enddate,ecom_leavestatus',
        $orderby: 'createdon desc',
        $top: 10
      }
    });
    const requests = (requestsRes.value || []).map(r => ({
      leave_type: r.ecom_name,
      start_date: r.ecom_startdate,
      end_date: r.ecom_enddate,
      status: r.ecom_leavestatus,
      status_label: toLeaveStatusLabel(r)
    }));
    return { requests };
  } catch (e) {
    fastify.log.error({ msg: 'getLeaveRequests failed', e: e.message });
    return { error: 'Failed to fetch requests' };
  }
}

async function getLeaveTypes() {
  try {
    const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() } };
    const leaveTypesData = await dataverseRequest(minReq, 'get', 'ecom_leavetypes', {
      params: {
        $filter: 'statecode eq 0',
        $select: 'ecom_leavetypeid,ecom_name,ecom_quota',
        $orderby: 'ecom_name asc'
      }
    });
    return { leaveTypes: leaveTypesData.value || [] };
  } catch (e) {
    fastify.log.error({ msg: 'getLeaveTypes failed', e: e.message });
    return { error: 'Failed to fetch leave types' };
  }
}

async function getPosition(email) {
  try {
    const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() }, user: { email } };
    const userData = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', {
      params: {
        $filter: `ecom_workemail eq '${email}'`,
        $select: 'ecom_personalinformationid'
      }
    });
    if (!userData.value?.length) return { error: 'Personal info not found' };

    const personalInformationId = userData.value[0].ecom_personalinformationid;
    const positionData = await dataverseRequest(minReq, 'get', 'ecom_employeepositions', {
      params: {
        $filter: `_ecom_personalinformation_value eq ${personalInformationId} and statecode eq 0`,
        $select: 'ecom_startdate,ecom_grading,statecode',
        $expand: 'ecom_JobTitle($select=ecom_jobtitle),ecom_UpdatedBy($select=fullname),ecom_PersonalInformation($select=ecom_employeename)',
        $orderby: 'ecom_startdate desc',
        $top: 1
      }
    });
    if (!positionData.value?.length) return { error: 'No active position record found' };

    const row = positionData.value[0];
    return {
      position_name: row.ecom_JobTitle?.ecom_jobtitle || null,
      grade_code: row.ecom_grading,
      grade_label: GRADE_MAP[row.ecom_grading] || 'Unknown',
      status_code: row.statecode,
      status_label: STATUS_MAP[row.statecode] || 'Unknown',
      start_date: row.ecom_startdate
    };
  } catch (e) {
    fastify.log.error({ msg: 'getPosition failed', e: e.message });
    return { error: 'Failed to fetch position information' };
  }
}

async function getDevelopments(email) {
  try {
    const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() }, user: { email } };
    const personalInfoRes = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', {
      params: {
        $filter: `ecom_workemail eq '${email}'`,
        $select: 'ecom_personalinformationid'
      }
    });
    if (!personalInfoRes.value?.length) return { error: 'Personal info not found' };

    const employeeGuid = personalInfoRes.value[0].ecom_personalinformationid;
    const historyData = await dataverseRequest(minReq, 'get', 'ecom_developments', {
      params: {
        $filter: `_ecom_employeeid_value eq ${employeeGuid}`,
        $select: 'ecom_developmentid,ecom_title,ecom_date,ecom_enddate,ecom_description,ecom_type,ecom_updatedon',
        $expand: 'ecom_Client($select=name),ecom_ProjectManager($select=fullname)',
        $orderby: 'ecom_date desc',
        $top: 10
      }
    });

    const items = (historyData.value || []).map((record) => ({
      id: record.ecom_developmentid,
      title: record.ecom_title,
      type_code: record.ecom_type,
      type_label: DEVELOPMENT_TYPE_MAP[record.ecom_type] || 'Unknown',
      start_date: record.ecom_date,
      end_date: record.ecom_enddate
    }));
    return { items };
  } catch (e) {
    fastify.log.error({ msg: 'getDevelopments failed', e: e.message });
    return { error: 'Failed to fetch development history' };
  }
}

async function getPeerReviewSummary(email) {
  try {
    const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() }, user: { email } };
    const userRes = await dataverseRequest(minReq, 'get', 'systemusers', {
      params: {
        $filter: `internalemailaddress eq '${email}'`,
        $select: 'systemuserid'
      }
    });
    if (!userRes.value?.length) return { error: 'User not found' };

    const userId = userRes.value[0].systemuserid;
    const summaryData = await dataverseRequest(minReq, 'get', 'ecom_summarypeerreviews', {
      params: {
        $filter: `_ecom_employee_value eq ${userId}`,
        $select: 'ecom_startdate,ecom_enddate,ecom_totalpeerreview,ecom_averagerating',
        $expand: 'ecom_Project($select=ecom_projectname),ecom_Employee($select=fullname)'
      }
    });

    const items = (summaryData.value || []).map((item) => ({
      project_name: item.ecom_Project?.ecom_projectname || null,
      employee_name: item.ecom_Employee?.fullname || null,
      project_start_date: item.ecom_startdate,
      project_end_date: item.ecom_enddate,
      total_peer_review: item.ecom_totalpeerreview,
      average_rating: item.ecom_averagerating
    }));
    return { items };
  } catch (e) {
    fastify.log.error({ msg: 'getPeerReviewSummary failed', e: e.message });
    return { error: 'Failed to fetch summary peer review' };
  }
}

function toIsoDate(y, m, d) {
  const yy = Number(y);
  const mm = Number(m);
  const dd = Number(d);
  if (!Number.isInteger(yy) || !Number.isInteger(mm) || !Number.isInteger(dd)) return null;
  if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return null;
  const date = new Date(Date.UTC(yy, mm - 1, dd));
  if (date.getUTCFullYear() !== yy || date.getUTCMonth() + 1 !== mm || date.getUTCDate() !== dd) return null;
  return `${yy}-${String(mm).padStart(2, '0')}-${String(dd).padStart(2, '0')}`;
}

function parseFlexibleDateFromText(text) {
  const raw = String(text || '').trim().toLowerCase();

  let m = raw.match(/\b(\d{4})[\-\/.](\d{1,2})[\-\/.](\d{1,2})\b/);
  if (m) return toIsoDate(m[1], m[2], m[3]);

  m = raw.match(/\b(\d{1,2})[\-\/.](\d{1,2})[\-\/.](\d{4})\b/);
  if (m) return toIsoDate(m[3], m[2], m[1]);

  const monthMap = {
    januari: 1, january: 1,
    februari: 2, february: 2, feb: 2,
    maret: 3, march: 3,
    april: 4,
    mei: 5, may: 5,
    juni: 6, june: 6,
    juli: 7, july: 7,
    agustus: 8, august: 8,
    september: 9,
    oktober: 10, october: 10,
    november: 11,
    desember: 12, december: 12
  };

  m = raw.match(/\b(\d{1,2})\s+([a-zA-Z]+)\s+(\d{4})\b/);
  if (m) {
    const month = monthMap[m[2]];
    if (!month) return null;
    return toIsoDate(m[3], month, m[1]);
  }

  return null;
}

function parseSubmitLeaveCommand(rawMessage) {
  const raw = String(rawMessage || '').trim();

  // Step 2 flow: choose special leave type by option number
  let m = raw.match(/^pilih\s+cuti\s+khusus\s+(\d+)(?:\s+(\d+))?(?:\s+(.+))?$/i);
  if (m) {
    return {
      mode: 'select_type',
      submissionKind: 'special',
      optionIndex: Number(m[1]),
      days: Number(m[2] || 1),
      reason: (m[3] || '').trim() || null,
    };
  }

  // Step 2 flow: choose leave type by option number
  m = raw.match(/^pilih\s+cuti\s+(\d+)(?:\s+(\d+))?(?:\s+(.+))?$/i);
  if (m) {
    return {
      mode: 'select_type',
      submissionKind: 'regular',
      optionIndex: Number(m[1]),
      days: Number(m[2] || 1),
      reason: (m[3] || '').trim() || null,
    };
  }

  // Legacy full command (backward compatible)
  m = raw.match(/^ajukan\s+cuti\s+([0-9a-fA-F-]{36})\s+(\d{4}-\d{2}-\d{2})\s+(\d+)(?:\s+(.+))?$/i);
  if (m) {
    return {
      mode: 'legacy_full',
      submissionKind: 'regular',
      leaveTypeId: m[1],
      startDate: m[2],
      days: Number(m[3]),
      reason: (m[4] || '').trim() || null,
    };
  }

  // Simplified command (special): user only sends start date
  if (/^ajukan\s+cuti\s+khusus\b/i.test(raw)) {
    const startDate = parseFlexibleDateFromText(raw);
    if (!startDate) return null;
    return { mode: 'need_type', submissionKind: 'special', startDate };
  }

  // Simplified command: user only sends start date
  if (/^ajukan\s+cuti\b/i.test(raw)) {
    const startDate = parseFlexibleDateFromText(raw);
    if (!startDate) return null;
    return { mode: 'need_type', submissionKind: 'regular', startDate };
  }

  return null;
}

async function submitLeaveRequestViaDm(email, rawMessage, senderId = null) {
  const parsed = parseSubmitLeaveCommand(rawMessage);
  if (!parsed) {
    return {
      ok: false,
      error: 'format',
      message: 'Gunakan format sederhana: ajukan cuti <tanggal>. Contoh: ajukan cuti 27 april 2026'
    };
  }

  let leaveTypeId;
  let startDate;
  let days;
  let reason;
  let submissionKind = parsed.submissionKind || 'regular';

  if (parsed.mode === 'need_type') {
    const leaveTypeData = await getLeaveTypes();
    let leaveTypes = leaveTypeData.leaveTypes || [];
    if (!leaveTypes.length) {
      return { ok: false, message: 'Jenis cuti tidak ditemukan saat ini.' };
    }

    if (submissionKind === 'special') {
      try {
        const minReq = {
          headers: {},
          session: { accessToken: await getAppLevelDataverseToken() },
          user: { email, permission: getPermissionByEmail(email) }
        };

        const leaveYear = new Date(parsed.startDate).getUTCFullYear().toString();
        const personalInfoRes = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', {
          params: {
            $filter: `ecom_workemail eq '${email}'`,
            $select: 'ecom_personalinformationid'
          }
        });

        const employeeGuid = personalInfoRes.value?.[0]?.ecom_personalinformationid;
        if (employeeGuid) {
          const usageRes = await dataverseRequest(minReq, 'get', 'ecom_leaveusages', {
            params: {
              $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${leaveYear}'`,
              $select: '_ecom_leavetype_value'
            }
          });

          const regularLeaveTypeIds = new Set((usageRes.value || [])
            .map((u) => u._ecom_leavetype_value)
            .filter(Boolean));

          // Special leave candidates are types not tied to yearly regular balance records.
          leaveTypes = leaveTypes.filter((t) => !regularLeaveTypeIds.has(t.ecom_leavetypeid));
        }
      } catch (e) {
        fastify.log.error({ msg: 'special leave type filtering failed', e: e.message });
      }

      // Fallback heuristic if filtering still returns empty.
      if (!leaveTypes.length) {
        const specialNameRegex = /(panjang|khusus|special|menikah|duka|melahirkan|haid|berkabung|ibadah)/i;
        leaveTypes = (leaveTypeData.leaveTypes || []).filter((t) => specialNameRegex.test(String(t.ecom_name || '')));
      }
    }

    if (!leaveTypes.length) {
      return { ok: false, message: submissionKind === 'special' ? 'Jenis cuti khusus tidak ditemukan untuk dipilih.' : 'Jenis cuti tidak ditemukan saat ini.' };
    }

    if (senderId) {
      await setLeaveDraft(senderId, {
        email,
        submissionKind,
        startDate: parsed.startDate,
        options: leaveTypes.map((t) => ({
          leaveTypeId: t.ecom_leavetypeid,
          ecom_name: t.ecom_name,
          ecom_quota: t.ecom_quota
        }))
      });
    }

    return {
      ok: false,
      action: 'select_leave_type',
      submissionKind,
      startDate: parsed.startDate,
      leaveTypes
    };
  }

  if (parsed.mode === 'select_type') {
    if (!senderId) {
      return { ok: false, message: 'Ketik dulu: ajukan cuti <tanggal>.' };
    }
    const draft = await getLeaveDraft(senderId);
    if (!draft || !Array.isArray(draft.options) || !draft.options.length) {
      return { ok: false, message: 'Sesi pengajuan tidak ditemukan. Ulangi: ajukan cuti <tanggal>.' };
    }

    submissionKind = draft.submissionKind || submissionKind;
    const idx = parsed.optionIndex - 1;
    if (idx < 0 || idx >= draft.options.length) {
      return { ok: false, message: `Nomor jenis cuti tidak valid. Pilih 1 sampai ${draft.options.length}.` };
    }

    leaveTypeId = draft.options[idx].leaveTypeId;
    startDate = draft.startDate;
    days = parsed.days;
    reason = parsed.reason;
  } else {
    leaveTypeId = parsed.leaveTypeId;
    startDate = parsed.startDate;
    days = parsed.days;
    reason = parsed.reason;
    submissionKind = parsed.submissionKind || submissionKind;
  }

  if (!leaveTypeId || !startDate || !days) {
    return { ok: false, message: 'leaveTypeId, startDate, dan days wajib diisi.' };
  }

  if (!Number.isInteger(days) || days <= 0) {
    return { ok: false, message: 'Jumlah hari harus bilangan bulat positif.' };
  }

  let start;
  try {
    start = new Date(startDate);
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    if (start < today) return { ok: false, message: 'Start date tidak boleh di masa lalu.' };

    const dayOfWeek = start.getUTCDay();
    if (dayOfWeek === 0 || dayOfWeek === 6) {
      return { ok: false, message: `Start date ${startDate} jatuh di weekend.` };
    }
  } catch {
    return { ok: false, message: 'Format tanggal tidak valid. Gunakan YYYY-MM-DD.' };
  }

  try {
    const minReq = {
      headers: {},
      session: { accessToken: await getAppLevelDataverseToken() },
      user: { email, permission: getPermissionByEmail(email) }
    };

    const leaveYear = start.getUTCFullYear().toString();
    const personalInfoRes = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', {
      params: {
        $filter: `ecom_workemail eq '${email}'`,
        $select: 'ecom_personalinformationid,ecom_workemail,ecom_employeename,ecom_nik,ecom_dateofemployment'
      }
    });

    if (!personalInfoRes.value?.length) {
      return { ok: false, message: `Data personal tidak ditemukan untuk ${email}.` };
    }

    const employeeInfo = personalInfoRes.value.sort((a, b) =>
      (b.ecom_employeename || '').localeCompare(a.ecom_employeename || '')
    )[0];
    const employeeGuid = employeeInfo.ecom_personalinformationid;

    if (submissionKind === 'special') {
      const leaveTypeInfo = await dataverseRequest(minReq, 'get', `ecom_leavetypes(${leaveTypeId})`, {
        params: { $select: 'ecom_quota,ecom_name' }
      });

      const isLongLeave = String(leaveTypeInfo.ecom_name || '').trim().toLowerCase().startsWith('cuti panjang');
      if (isLongLeave) {
        if (days > 10) return { ok: false, message: 'Cuti panjang maksimal 10 hari per pengajuan.' };

        const employmentDate = new Date(employeeInfo.ecom_dateofemployment);
        if (isNaN(employmentDate.getTime())) return { ok: false, message: 'Tanggal mulai kerja tidak valid.' };

        const today = new Date();
        const tenureInYears = (today.getTime() - employmentDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
        if (tenureInYears < 5) {
          return { ok: false, message: `Belum eligible cuti panjang. Minimal 5 tahun masa kerja (Anda: ${tenureInYears.toFixed(1)} tahun).` };
        }

        const currentTier = Math.floor(tenureInYears / 5) * 5;
        const eligibilityStartDate = new Date(employmentDate);
        eligibilityStartDate.setFullYear(eligibilityStartDate.getFullYear() + currentTier);
        const expirationDate = new Date(eligibilityStartDate);
        expirationDate.setFullYear(expirationDate.getFullYear() + 3);
        if (today > expirationDate) {
          return { ok: false, message: `Jendela cuti panjang periode ${currentTier} tahun sudah kedaluwarsa.` };
        }

        const pastLongLeaves = await dataverseRequest(minReq, 'get', 'ecom_employeeleaves', {
          params: {
            $filter: `_ecom_employee_value eq ${employeeGuid} and _ecom_leavetype_value eq ${leaveTypeId} and createdon ge ${eligibilityStartDate.toISOString()} and (ecom_leavestatus ne 273700003 and ecom_leavestatus ne 273700004)`,
            $select: 'ecom_numberofdays'
          }
        });
        const taken = (pastLongLeaves.value || []).reduce((sum, leave) => sum + (leave.ecom_numberofdays || 0), 0);
        if ((taken + days) > 20) {
          return { ok: false, message: `Melebihi kuota cuti panjang 20 hari (sudah diambil: ${taken}, diminta: ${days}).` };
        }
      } else {
        if (leaveTypeInfo.ecom_quota == null) {
          return { ok: false, message: `Tipe cuti '${leaveTypeInfo.ecom_name}' tidak menggunakan kuota special.` };
        }
        const quota = leaveTypeInfo.ecom_quota;
        const pastLeaves = await dataverseRequest(minReq, 'get', 'ecom_employeeleaves', {
          params: {
            $filter: `_ecom_employee_value eq ${employeeGuid} and _ecom_leavetype_value eq ${leaveTypeId} and createdon ge ${leaveYear}-01-01T00:00:00Z and createdon le ${leaveYear}-12-31T23:59:59Z and (ecom_leavestatus ne 273700003 and ecom_leavestatus ne 273700004)`,
            $select: 'ecom_numberofdays'
          }
        });
        const taken = (pastLeaves.value || []).reduce((sum, leave) => sum + (leave.ecom_numberofdays || 0), 0);
        if ((taken + days) > quota) {
          return { ok: false, message: `Melebihi kuota '${leaveTypeInfo.ecom_name}' (quota: ${quota}, sudah: ${taken}, diminta: ${days}).` };
        }
      }

      const endDate = new Date(start);
      let daysAdded = 0;
      while (daysAdded < days - 1) {
        endDate.setUTCDate(endDate.getUTCDate() + 1);
        const d = endDate.getUTCDay();
        if (d !== 0 && d !== 6) daysAdded++;
      }
      const endDateStr = endDate.toISOString().split('T')[0];
      const returnDateStr = calculateReturnDate(endDateStr);

      const overlapError = await checkForOverlappingLeave(minReq, employeeGuid, startDate, endDateStr);
      if (overlapError) return { ok: false, message: `Tanggal cuti bentrok. ${overlapError}` };

      const newLeaveRequest = {
        'ecom_Employee@odata.bind': `/ecom_personalinformations(${employeeGuid})`,
        'ecom_LeaveType@odata.bind': `/ecom_leavetypes(${leaveTypeId})`,
        ecom_name: `${employeeInfo.ecom_nik} - ${employeeInfo.ecom_employeename} - Leave request`,
        ecom_startdate: startDate,
        ecom_enddate: endDateStr,
        ecom_returndate: returnDateStr,
        ecom_numberofdays: days,
        ecom_reason: reason || null
      };

      const inserted = await dataverseRequest(minReq, 'post', 'ecom_employeeleaves', { data: newLeaveRequest });
      const leaveId = inserted.ecom_employeeleaveid || inserted.ecom_leaverequestid;

      return {
        ok: true,
        leaveId,
        leaveTypeName: leaveTypeInfo.ecom_name || 'Unknown',
        startDate,
        endDate: endDateStr,
        returnDate: returnDateStr,
        days,
        balanceRemaining: '-',
        submissionKind: 'special'
      };
    }

    const balancesRes = await dataverseRequest(minReq, 'get', 'ecom_leaveusages', {
      params: {
        $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${leaveYear}'`,
        $select: 'ecom_balance,_ecom_leavetype_value,ecom_period,ecom_name'
      }
    });

    if (!balancesRes.value?.length) {
      return { ok: false, message: `Saldo cuti ${leaveYear} tidak ditemukan.` };
    }

    const usage = balancesRes.value.find((u) => u._ecom_leavetype_value === leaveTypeId);
    if (!usage) {
      return { ok: false, message: `Leave type ${leaveTypeId} tidak tersedia di saldo ${leaveYear}.` };
    }

    const currentBalance = usage.ecom_balance || 0;
    if (currentBalance < days) {
      return { ok: false, message: `Saldo tidak cukup. Available: ${currentBalance}, requested: ${days}.` };
    }

    const endDate = new Date(start);
    let daysAdded = 0;
    while (daysAdded < days - 1) {
      endDate.setUTCDate(endDate.getUTCDate() + 1);
      const d = endDate.getUTCDay();
      if (d !== 0 && d !== 6) daysAdded++;
    }
    const endDateStr = endDate.toISOString().split('T')[0];
    const returnDateStr = calculateReturnDate(endDateStr);

    const overlapError = await checkForOverlappingLeave(minReq, employeeGuid, startDate, endDateStr);
    if (overlapError) {
      return { ok: false, message: `Tanggal cuti bentrok. ${overlapError}` };
    }

    const newLeaveRequest = {
      'ecom_Employee@odata.bind': `/ecom_personalinformations(${employeeGuid})`,
      'ecom_LeaveType@odata.bind': `/ecom_leavetypes(${leaveTypeId})`,
      ecom_name: `${employeeInfo.ecom_nik} - ${employeeInfo.ecom_employeename} - Leave request`,
      ecom_startdate: startDate,
      ecom_enddate: endDateStr,
      ecom_returndate: returnDateStr,
      ecom_numberofdays: days,
      ecom_reason: reason || null
    };

    const inserted = await dataverseRequest(minReq, 'post', 'ecom_employeeleaves', { data: newLeaveRequest });
    const leaveId = inserted.ecom_employeeleaveid || inserted.ecom_leaverequestid;

    try {
      const [balanceThis, balanceNext] = await Promise.all([
        dataverseRequest(minReq, 'get', 'ecom_leaveusages', {
          params: {
            $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${leaveYear}'`,
            $select: 'ecom_leaveusageid'
          }
        }),
        dataverseRequest(minReq, 'get', 'ecom_leaveusages', {
          params: {
            $filter: `_ecom_employee_value eq ${employeeGuid} and ecom_period eq '${parseInt(leaveYear, 10) + 1}'`,
            $select: 'ecom_leaveusageid'
          }
        })
      ]);

      const thisBalanceId = balanceThis.value?.[0]?.ecom_leaveusageid;
      const nextBalanceId = balanceNext.value?.[0]?.ecom_leaveusageid;
      if (leaveId && (thisBalanceId || nextBalanceId)) {
        await dataverseRequest(minReq, 'patch', `ecom_employeeleaves(${leaveId})`, {
          data: {
            ...(thisBalanceId && { 'ecom_LeaveBalanceThisPeriod@odata.bind': `/ecom_leaveusages(${thisBalanceId})` }),
            ...(nextBalanceId && { 'ecom_LeaveBalanceNextPeriod@odata.bind': `/ecom_leaveusages(${nextBalanceId})` })
          }
        });
      }
    } catch (linkErr) {
      fastify.log.error({ msg: 'DM leave: failed to link balances', e: linkErr.message });
    }

    try {
      if (leaveId) {
        await dataverseRequest(minReq, 'patch', `ecom_employeeleaves(${leaveId})`, {
          data: {
            ecom_totaldaysthisperiod: days,
            ecom_totaldaysnextperiod: 0
          }
        });
      }
    } catch (numErr) {
      fastify.log.error({ msg: 'DM leave: failed to set totalday fields', e: numErr.message });
    }

    try {
      const userRes = await dataverseRequest(minReq, 'get', 'systemusers', {
        params: {
          $select: 'systemuserid,internalemailaddress',
          $filter: `internalemailaddress eq '${email}'`
        }
      });

      const systemUserId = userRes.value?.[0]?.systemuserid;
      const flowUrl = process.env.POWERAPPS_FLOW_URL;
      if (flowUrl && leaveId && systemUserId) {
        await fetch(flowUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ leaveId, userId: systemUserId })
        });
      }
    } catch (flowErr) {
      fastify.log.error({ msg: 'DM leave: flow trigger failed', e: flowErr.message });
    }

    return {
      ok: true,
      leaveId,
      leaveTypeName: usage.ecom_name || 'Unknown',
      startDate,
      endDate: endDateStr,
      returnDate: returnDateStr,
      days,
      balanceRemaining: currentBalance - days
    };
  } catch (e) {
    fastify.log.error({ msg: 'submitLeaveRequestViaDm failed', e: e.message, email, rawMessage });
    return { ok: false, message: e.message || 'Gagal mengajukan cuti via DM.' };
  } finally {
    if (senderId && parsed.mode === 'select_type') {
      await clearLeaveDraft(senderId);
    }
  }
}

// Verification endpoint (GET) for Facebook/Instagram webhook setup
fastify.get('/instagram/webhook', async (req, reply) => {
  const verifyToken = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  fastify.log.info({ msg: 'instagram webhook verify', ok: !!verifyToken, tokenMatch: verifyToken === process.env.INSTAGRAM_VERIFY_TOKEN });
  if (verifyToken === process.env.INSTAGRAM_VERIFY_TOKEN) {
    // Return plain text challenge per webhook verification requirements
    return reply.type('text/plain').code(200).send(String(challenge || ''));
  }
  return reply.code(403).send({ error: 'Verification token invalid' });
});

// Message receiver (POST)
fastify.post('/instagram/webhook', async (req, reply) => {
  fastify.log.info({ msg: 'instagram webhook post', hasSignature: !!req.headers['x-hub-signature'] });
  try {
    const signature = req.headers['x-hub-signature'];
    const appSecret = process.env.INSTAGRAM_APP_SECRET;
    if (!signature || !appSecret) return reply.code(400).send({ error: 'Missing signature or secret' });
    // Use the raw body (preserved by our content-type parser) for HMAC verification
    const payload = req.rawBody || JSON.stringify(req.body || {});
    if (!verifyInstagramSignature(payload, signature, appSecret)) {
      fastify.log.error({ msg: 'Instagram signature verification failed' });
      return reply.code(401).send({ error: 'Signature verification failed' });
    }
    fastify.log.info({ msg: 'Instagram signature verified successfully' });

    const { entry } = req.body;
    if (!entry || !Array.isArray(entry)) {
      fastify.log.error({ msg: 'Invalid Instagram payload: no entry or not array', entry: entry });
      return reply.code(400).send({ error: 'Invalid payload' });
    }
    fastify.log.info({ msg: 'Instagram payload parsed', entryCount: entry.length });

    for (const evt of entry) {

  // ✅ INSTAGRAM (changes format)
  if (evt.changes && Array.isArray(evt.changes)) {
    fastify.log.info({ msg: 'Processing IG changes', count: evt.changes.length });

    for (const change of evt.changes) {
      if (change.field === 'messages') {
        const messages = change.value?.messages;

        if (Array.isArray(messages)) {
          for (const msg of messages) {
            const senderId = msg.from?.id;
            const messageText = msg.text || '[non-text message]';

            if (!senderId) continue;

            fastify.log.info({
              msg: 'IG message received',
              senderId,
              messageText
            });

            await handleInstagramMessage(senderId, messageText)
              .catch(err => fastify.log.error({
                msg: 'handleInstagramMessage failed',
                err: err.message
              }));
          }
        }
      }
    }
  }

  // ✅ FALLBACK (Messenger-style / legacy)
  else if (evt.messaging && Array.isArray(evt.messaging)) {
    fastify.log.info({ msg: 'Processing messaging events', eventCount: evt.messaging.length });

    for (const msg of evt.messaging) {
      if (!msg.message) continue;

      const senderId = msg.sender?.id;
      const messageText = msg.message?.text || '[non-text message]';

      if (!senderId) continue;

      fastify.log.info({
        msg: 'Messenger message received',
        senderId,
        messageText
      });

      await handleInstagramMessage(senderId, messageText)
        .catch(err => fastify.log.error({
          msg: 'handleInstagramMessage failed',
          err: err.message
        }));
    }
  }
    
  // ❗ Unknown format
  else {
    fastify.log.warn({
      msg: 'Unknown event format',
      evt
    });
  }
}
  
return reply.code(200).send({ status: 'received' });
} catch (e) {
  fastify.log.error({ msg: 'instagram webhook error', e: e.message });
  return reply.code(500).send({ error: 'Internal error' });
}
});

async function handleInstagramMessage(senderId, messageText) {
  let responseText = '⏳ Sedang memproses permintaan Anda...'; // Initial response
  let shouldSendLoginButton = false;
  let shouldSendServiceButtons = false;

  try {
    fastify.log.info({ msg: 'handleInstagramMessage started', senderId, messageText });
    fastify.log.info({ msg: 'DEBUG: before getPSIDUserMapping' });
    let userMapping = await getPSIDUserMapping(senderId);
    let userEmail = userMapping?.email || null;
    fastify.log.info({ msg: 'DEBUG: after getPSIDUserMapping', userMapping });
    const { intent, params } = parseIntent(messageText);
    fastify.log.info({ msg: 'DEBUG: after parseIntent', intent, params });
    fastify.log.info({ msg: 'intent parsed', intent, senderId, mapped: !!userEmail });

    // User's requested logic for initial responseText update
    if (!userEmail) {
      responseText = 'Silakan login dulu...';
    } else {
      responseText = 'Data Anda sedang diproses...';
    }

    // --- Start of original logic, now modifying responseText instead of sending directly ---

    // If sensitive actions require mapping/email, prompt user
    if ((
      intent === 'submit_leave' ||
      intent === 'check_leave_balance' ||
      intent === 'get_profile' ||
      intent === 'get_leave_requests' ||
      intent === 'get_position' ||
      intent === 'get_developments' ||
      intent === 'get_peer_review_summary' ||
      intent === 'admin_query'
    ) && !userEmail) {
      responseText = 'ℹ️ Untuk akses data, silakan login dulu. Klik tombol Login di bawah, lalu salin OTP dari browser dan kirim ke sini.';
      shouldSendLoginButton = true;
      shouldSendServiceButtons = true;
      // No return here, will send at the end
    }
    // If user sends OTP (6 digits)
    else if (messageText.match(/^\d{6}$/)) { // Use else if to prevent multiple branches from executing
      const otp = messageText;
      try {
        const jwt = await kv.get(otp);
        if (jwt) {
          const decoded = fastify.jwt.verify(jwt);
          const mappedUser = {
            email: decoded.email,
            permission: decoded.permission || getPermissionByEmail(decoded.email),
            employeeId: decoded.employeeId || null
          };
          await setPSIDUserMapping(senderId, mappedUser);
          const email = mappedUser.email;
          responseText = `✅ Login berhasil! Email: ${email}\n\nSekarang coba: ajukan cuti, cek cuti, riwayat cuti, profil, development (riwayat project), peer review, atau ketik bantuan.`;
        } else {
          responseText = '❌ OTP tidak valid atau sudah expired. Coba login lagi.';
        }
      } catch (e) {
        fastify.log.error({ msg: 'OTP validation failed', e: e.message });
        responseText = '❌ Terjadi kesalahan saat validasi OTP.';
      }
    }
    // If user sends an email to map (fallback, but now prefer OTP)
    else if (intent === 'unknown' && messageText.includes('@') && messageText.includes('.')) { // Use else if
      const potentialEmail = messageText.trim();
      try {
        const minReq = { headers: {}, session: { accessToken: await getAppLevelDataverseToken() } };
        const res = await dataverseRequest(minReq, 'get', 'ecom_personalinformations', { params: { $filter: `ecom_workemail eq '${potentialEmail}'`, $select: 'ecom_personalinformationid,ecom_employeename' } });
        if (res.value && res.value.length) {
          await setPSIDUserMapping(senderId, {
            email: potentialEmail,
            permission: getPermissionByEmail(potentialEmail),
            employeeId: res.value[0].ecom_personalinformationid || null
          });
          responseText = `✅ Email terverifikasi: ${potentialEmail}\n\nSekarang coba: ajukan cuti, cek cuti, riwayat cuti, profil, development (riwayat project), peer review, atau ketik bantuan.`;
        } else {
          responseText = '❌ Email tidak ditemukan di sistem. Pastikan email kerja Anda.';
        }
      } catch (e) {
        fastify.log.error({ msg: 'validate email failed', e: e.message });
        responseText = '❌ Email tidak ditemukan di sistem. Pastikan email kerja Anda.'; // Fallback for error
      }
    }
    // Handle other intents
    else {
      let responseData = {};
      switch (intent) {
        case 'help':
          responseData = { action: 'help' };
          shouldSendServiceButtons = true;
          break;
        case 'login':
          responseData = { action: 'login' };
          shouldSendLoginButton = true;
          shouldSendServiceButtons = true;
          break;
        case 'submit_leave':
          if (userEmail) {
            responseData = await submitLeaveRequestViaDm(userEmail, messageText, senderId);
          } else {
            responseData = {
              ok: false,
              message: 'Silakan login dulu sebelum mengajukan cuti.'
            };
          }
          break;
        case 'get_leave_types':
          responseData = await getLeaveTypes();
          break;
        case 'check_leave_balance':
          if (userEmail) responseData = await getLeaveBalance(userEmail, params.period || null);
          break;
        case 'get_profile':
          if (userEmail) responseData = await getProfile(userEmail);
          break;
        case 'get_position':
          if (userEmail) responseData = await getPosition(userEmail);
          break;
        case 'get_leave_requests':
          if (userEmail) responseData = await getLeaveRequests(userEmail);
          break;
        case 'get_developments':
          if (userEmail) responseData = await getDevelopments(userEmail);
          break;
        case 'get_peer_review_summary':
          if (userEmail) responseData = await getPeerReviewSummary(userEmail);
          break;
        case 'admin_query':
          responseData = await handleAdminQuery(userMapping, params);
          break;
        default:
          responseData = { action: 'unknown' };
      }
      responseText = formatInstagramResponse(responseData, intent);
    }

    fastify.log.info({ msg: 'instagram reply prepared', senderId, intent });

  } catch (e) {
    fastify.log.error({ msg: 'handleInstagramMessage unexpected', e: e.message });
    responseText = '❌ Terjadi error internal.';
  }

  fastify.log.info({ msg: 'Final Instagram message prepared', senderId, responseText: responseText.substring(0, 50) + '...' });
  // Send the final responseText
  await sendInstagramMessage(senderId, responseText, process.env.INSTAGRAM_ACCESS_TOKEN);

  if (shouldSendLoginButton) {
    await sendInstagramLoginButton(senderId, process.env.INSTAGRAM_ACCESS_TOKEN);
  }

  if (shouldSendServiceButtons) {
    await sendInstagramServiceButtons(senderId, process.env.INSTAGRAM_ACCESS_TOKEN);
  }
}

const EmojiMap = {
  help: '📌',
  login: '🔐',
  get_leave_types: '🗂️',
  check_leave_balance: '📅',
  get_profile: '👤',
  get_position: '🧭',
  get_leave_requests: '📋',
  get_developments: '🚀',
  get_peer_review_summary: '⭐'
};

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

fastify.get('/apple-touch-icon-precomposed.png', (request, reply) => {
  reply.code(204).send();
});

fastify.get('/apple-touch-icon.png', (request, reply) => {
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
      start_date: item.ecom_startdate,
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
  if (req.user.permission !== "admin") {
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
      personalInfoFilter = `contains(ecom_employeename, '${name}')`;
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
      start_date: item.ecom_startdate,
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

    // Try to fetch user leave requests, retrying with legacy ID name if necessary
    const userParams = {
      $filter: `_ecom_employee_value eq ${currentUserPersonalInfoId}`,
      $expand: "ecom_LeaveType($select=ecom_name)",
      $select: "ecom_leaverequestid,ecom_name,ecom_startdate,ecom_enddate,ecom_numberofdays,ecom_reason,ecom_leavestatus,ecom_pmsmapprovalstatus,ecom_pmsmnote,ecom_hrapprovalstatus,createdon",
      $orderby: "createdon desc"
    };

    let requestsData;
    try {
      requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", { params: userParams });
    } catch (err) {
      const msg = err.response?.data?.error?.message || '';
      if (msg.includes('ecom_leaverequestid') || msg.includes('Could not find a property')) {
        fastify.log.warn({ msg: 'ecom_leaverequestid not present for user query; retrying with ecom_employeeleaveid' });
        userParams.$select = userParams.$select.replace(/ecom_leaverequestid/g, 'ecom_employeeleaveid');
        requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", { params: userParams });
      } else {
        throw err;
      }
    }

    // Normalize to ecom_leaverequestid when legacy field is used
    const rows = (requestsData.value || []).map(item => {
      if (!item.ecom_leaverequestid && item.ecom_employeeleaveid) {
        item.ecom_leaverequestid = item.ecom_employeeleaveid;
      }
      // Ensure date is in ISO format
      if (item.createdon) {
        item.createdon = new Date(item.createdon).toISOString();
      }
      return item;
    });

    return rows;

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
    };

    fastify.log.info({ msg: "REGULAR LEAVE: Creating leave request with data", data: newLeaveRequest });
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
      // === SEND EMAIL NOTIFICATION AFTER FLOW ===
      await sendLeaveRequestEmail(fastify, leaveId, "veldy.verdiyansyah@ecomindo.com");
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

    fastify.log.info({ msg: "SPECIAL LEAVE: Creating leave request with data", data: newLeaveRequest });
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

        // === SEND EMAIL NOTIFICATION ===
        await sendLeaveRequestEmail(fastify, leaveId, "veldy.verdiyansyah@ecomindo.com");

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
            } else {
                fastify.log.warn(
                    `⚠️ No leave balance records found for ${employeeGuid} (${leaveYear}/${parseInt(leaveYear) + 1}). Flow may fail.`
                );
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
                // === SEND EMAIL NOTIFICATION AFTER FLOW ===
                await sendLeaveRequestEmail(fastify, leaveId, "veldy.verdiyansyah@ecomindo.com");
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
    if (req.user.permission !== "admin" && leaveRequest._ecom_employee_value !== currentUserPersonalInfoId) {
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
  if (!["admin", "co_admin"].includes(req.user.permission)) {
    return reply.code(403).send({ message: "Admin access required." });
  }

  try {
    const {
      startDate,
      endDate,
      month,
      year,
      employeeId,
      email,
      name,
      "for": forWho // "ai" | undefined
    } = req.query;

    const filters = [];

    // ==============================
    //  Employee filtering (AMAN)
    // ==============================
    if (employeeId || (email && email.trim()) || (name && name.trim())) {
      let employeeFilter;

      if (employeeId) {
        employeeFilter = `_ecom_employee_value eq ${employeeId}`;
      } else {
        const personalInfoFilter = email
          ? `ecom_workemail eq '${email}'`
          : `contains(ecom_employeename, '${name}')`;

        const userData = await dataverseRequest(req, "get", "ecom_personalinformations", {
          params: {
            $filter: personalInfoFilter,
            $select: "ecom_personalinformationid"
          }
        });

        if (!userData.value?.length) return [];

        employeeFilter = `_ecom_employee_value eq ${userData.value[0].ecom_personalinformationid}`;
      }

      filters.push(employeeFilter);
    }

    // ==============================
    //  Date filtering (AMAN)
    // ==============================
    let finalStartDate = startDate;
    let finalEndDate = endDate;

    if (!finalStartDate && !finalEndDate) {
      if (month) {
        const monthString = String(month);
        // Case 1: month is in "YYYY-MM" format
        if (monthString.includes('-')) {
          const [y, m] = monthString.split("-").map(Number);
          if (!isNaN(y) && !isNaN(m)) {
            const lastDay = new Date(y, m, 0).getDate();
            finalStartDate = `${y}-${String(m).padStart(2, "0")}-01`;
            finalEndDate = `${y}-${String(m).padStart(2, "0")}-${lastDay}`;
          }
        }
        // Case 2: month is a name (e.g., "February") and year is provided
        else if (year) {
          const monthNames = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
          const monthNumber = monthNames.indexOf(monthString.toLowerCase()) + 1;
          const yearNumber = parseInt(year, 10);

          if (monthNumber > 0 && !isNaN(yearNumber)) {
            const lastDay = new Date(yearNumber, monthNumber, 0).getDate();
            finalStartDate = `${yearNumber}-${String(monthNumber).padStart(2, "0")}-01`;
            finalEndDate = `${yearNumber}-${String(monthNumber).padStart(2, "0")}-${lastDay}`;
          }
        }
      } else if (year) {
        const yearNumber = parseInt(year, 10);
        if (!isNaN(yearNumber)) {
            finalStartDate = `${yearNumber}-01-01`;
            finalEndDate = `${yearNumber}-12-31`;
        }
      }
    }

    if (finalStartDate) filters.push(`ecom_enddate ge ${finalStartDate}`);
    if (finalEndDate) filters.push(`ecom_startdate le ${finalEndDate}`);

    // Determine if a specific employee is being filtered
    const isSpecificEmployeeFilterPresent = employeeId || (email && email.trim()) || (name && name.trim());

    // ==============================
    //  Dataverse query (DIPERKETAT)
    // ==============================
    const params = {
      $orderby: "createdon desc"
    };

    //  SELECT DAN EXPAND BERBEDA UNTUK AI
    if (forWho === "ai") {
      let aiSelectFields = "ecom_startdate,ecom_enddate,ecom_leavestatus";
      if (isSpecificEmployeeFilterPresent) {
        // If filtering for a specific employee, include the ID for potential cancellation
        aiSelectFields = "ecom_leaverequestid," + aiSelectFields;
      }
      params.$select = aiSelectFields;
      // Re-add expand for AI, but keep it minimal
      params.$expand = "ecom_LeaveType($select=ecom_name),ecom_Employee($select=ecom_employeename)";
      params.$top = 20; // HARD LIMIT
    } else {
      // Existing logic for non-AI
      params.$expand = "ecom_LeaveType($select=ecom_name),ecom_Employee($select=ecom_employeename),createdby($select=fullname)";
      // Ensure we include the primary key so admin clients can act on items (e.g., cancel)
      params.$select = `
        ecom_leaverequestid,
        ecom_name,
        ecom_startdate,
        ecom_enddate,
        ecom_numberofdays,
        ecom_leavestatus,
        ecom_pmsmapprovalstatus,
        ecom_hrapprovalstatus,
        createdon
      `;
    }

    if (filters.length) params.$filter = filters.join(" and ");

    // Fetch leave rows with a fallback for environments that use a legacy PK name
    let requestsData;
    try {
      requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", { params });
    } catch (err) {
      const msg = err.response?.data?.error?.message || '';
      // If Dataverse complains about missing property, retry with legacy field name
      if (msg.includes('ecom_leaverequestid') || msg.includes('Could not find a property')) {
        fastify.log.warn({ msg: 'ecom_leaverequestid not present in schema; retrying with ecom_employeeleaveid' });
        // Replace occurrences in the select clause
        if (params.$select) {
          params.$select = params.$select.replace(/ecom_leaverequestid/g, 'ecom_employeeleaveid');
        }
        requestsData = await dataverseRequest(req, "get", "ecom_employeeleaves", { params });
      } else {
        throw err; // rethrow and let outer catch handle
      }
    }

    // Normalize ID field for backward compatibility (some environments use ecom_employeeleaveid)
    const rows = (requestsData.value || []).map(item => {
      if (!item.ecom_leaverequestid && item.ecom_employeeleaveid) {
        item.ecom_leaverequestid = item.ecom_employeeleaveid;
      }
      // Ensure date is in ISO format
      if (item.ecom_updatedon) {
        item.ecom_updatedon = new Date(item.ecom_updatedon).toISOString();
      }
      return item;
    });

    // ==============================
    //  AI-FRIENDLY RESPONSE
    // ==============================
    if (forWho === "ai") {
      return rows.map(item => ({
        employee: item.ecom_Employee?.ecom_employeename,
        leaveType: item.ecom_LeaveType?.ecom_name,
        startDate: item.ecom_startdate,
        endDate: item.ecom_enddate,
        status: item.ecom_leavestatus,
        ecom_leaverequestid: item.ecom_leaverequestid,
        createdon: item.createdon
      }));
    }

    return rows;

  } catch (err) {
    fastify.log.error({
      msg: "❌ Failed to fetch leave requests",
      error: err.response?.data || err.message,
      stack: err.stack
    });

    return reply.code(500).send({
      error: "Failed to fetch leave requests",
      details: err.response?.data?.error?.message || err.message
    });
  }
});

// 5. Get Own Profile
fastify.get("/profile/personal-info", {
  preValidation: [fastify.authenticate],
  schema: {
    summary: 'Get Own Profile',
    description: 'Mengambil data personal lengkap milik user yang sedang login.',
    tags: ['Profile'],
    response: {
      200: {
        type: 'object',
        properties: {
          ecom_personalinformationid: { type: 'string', format: 'uuid' },
          ecom_nik: { type: 'string' },
          ecom_employeename: { type: 'string' },
          ecom_gender: { type: 'integer' },
          ecom_dateofbirth: { type: 'string', format: 'date' },
          ecom_phonenumber: { type: 'string' },
          statecode: { type: 'integer' },
          ecom_startwork: { type: 'string', format: 'date' },
          ecom_workexperience: { type: 'string' },
          ecom_dateofemployment: { type: 'string', format: 'date' },
          ecom_jobtitle: { type: 'string' },
          ecom_emergencycontactname: { type: 'string' },
          ecom_emergencycontactaddress: { type: 'string' },
          ecom_emergencycontractphonenumber: { type: 'string' },
          ecom_relationship: { type: 'string' },
          ecom_address: { type: 'string' },
          ecom_ktpnumber: { type: 'string' },
          ecom_npwpnumber: { type: 'string' },
          ecom_profilepicture: { type: 'string', format: 'uri' },
          ecom_bankaccountnumber: { type: 'string' },
          ecom_bpjsnumber: { type: 'string' },
          ecom_bpjstknumber: { type: 'string' },
          ecom_maritalstatus: { type: 'integer' },
          ecom_numberofdependent: { type: 'integer' },
          ecom_placeofbirth: { type: 'string' },
          ecom_religion: { type: 'string' },
          ecom_bankname: { type: 'string' },
          ecom_accountname: { type: 'string' },
          ecom_personalemail: { type: 'string', format: 'email' },
          ecom_workemail: { type: 'string', format: 'email' },
          ecom_insurancenumber: { type: 'string' }
        }
      },
      401: {
        type: 'object',
        properties: {
          message: { type: 'string' }
        }
      },
      404: {
        type: 'object',
        properties: {
          message: { type: 'string' }
        }
      },
      500: {
        type: 'object',
        properties: {
          error: { type: 'string' },
          details: { type: 'string' }
        }
      }
    },
    security: [
      { Bearer: [] }
    ]
  }
}, async (req, reply) => {
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
          "ecom_workexperience", "ecom_dateofemployment",
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
      return reply.code(404).send({ message: "Profile not found." });
    }

    const profile = data.value[0];

    // Fetch the latest job title from ecom_employeepositions
    try {
      const latestPositionData = await dataverseRequest(req, "get", "ecom_employeepositions", {
        params: {
          $filter: `_ecom_personalinformation_value eq ${profile.ecom_personalinformationid} and statecode eq 0`,
          $select: "ecom_startdate", // Only need a field to expand
          $expand: "ecom_JobTitle($select=ecom_jobtitle)",
          $orderby: "ecom_startdate desc",
          $top: 1
        }
      });

      if (latestPositionData.value && latestPositionData.value.length > 0) {
        const latestPosition = latestPositionData.value[0];
        if (latestPosition.ecom_JobTitle && latestPosition.ecom_JobTitle.ecom_jobtitle) {
          profile.ecom_jobtitle = latestPosition.ecom_JobTitle.ecom_jobtitle;
        } else {
          profile.ecom_jobtitle = null;
        }
      } else {
        profile.ecom_jobtitle = null; // No active position found
      }
    } catch (positionErr) {
      fastify.log.error(`Error fetching latest position for ${profile.ecom_personalinformationid}: ${positionErr.message}`);
      profile.ecom_jobtitle = null; // Fallback in case of error
    }

    return profile;

  } catch (err) {
    console.error("❌ Error fetching own profile:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch profile",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// ==============================
// 🔹 Position/Grade Mappings & Endpoints
// ==============================
const GRADE_MAP = {
  273700000: "Junior",
  273700001: "Middle",
  273700002: "Senior",
  273700003: "Associate 1",
  273700004: "Associate 2",
  273700005: "Consultant",
  273700006: "Solution Architect",
  273700007: "Strategic",
};

const STATUS_MAP = {
  0: "Active",
  1: "Inactive",
};

const transformPositionRecord = (record) => ({
  employee_name: record.ecom_PersonalInformation?.ecom_employeename || null,
  start_date: record.ecom_startdate,
  position_name: record.ecom_JobTitle?.ecom_jobtitle || null,
  grade_code: record.ecom_grading,
  grade_label: GRADE_MAP[record.ecom_grading] || 'Unknown',
  status_code: record.statecode,
  status_label: STATUS_MAP[record.statecode] || 'Unknown',
  updated_by: record.ecom_UpdatedBy?.fullname || null,
});

// Get own current position
fastify.get("/profile/position", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  try {
    // First, get the personalinformationid from the user's email
    const userEmail = req.user.email;
    const userData = await dataverseRequest(req, "get", "ecom_personalinformations", {
        params: {
            $filter: `ecom_workemail eq '${userEmail}'`,
            $select: "ecom_personalinformationid"
        }
    });

    if (!userData.value || userData.value.length === 0) {
        return reply.code(404).send({ message: "Personal information record not found for your user." });
    }
    const personalInformationId = userData.value[0].ecom_personalinformationid;

    // Now, query the position with the correct ID
    const positionData = await dataverseRequest(req, "get", "ecom_employeepositions", {
      params: {
        $filter: `_ecom_personalinformation_value eq ${personalInformationId} and statecode eq 0`,
        $select: "ecom_startdate,ecom_grading,statecode",
        $expand: "ecom_JobTitle($select=ecom_jobtitle),ecom_UpdatedBy($select=fullname),ecom_PersonalInformation($select=ecom_employeename)",
        $orderby: "ecom_startdate desc",
        $top: 1
      }
    });

    if (!positionData.value || positionData.value.length === 0) {
      return reply.code(404).send({ message: "No active position record found for your user." });
    }

    const transformedData = transformPositionRecord(positionData.value[0]);
    return transformedData;

  } catch (err) {
    fastify.log.error({ msg: "❌ Error fetching own position info", error: err.response?.data || err.message });
    reply.status(500).send({
      error: "Failed to fetch position information",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// Admin search for employee position history
fastify.get("/admin/position/search", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (!["admin", "co_admin"].includes(req.user.permission)) {
    return reply.code(403).send({ message: "Admin access required." });
  }

  const { employeeId, email, name } = req.query;
  if (!employeeId && !email && !name) {
    return reply.code(400).send({ message: "Either employeeId, email, or name must be provided." });
  }

  try {
    let targetEmployeeId;

    if (employeeId) {
      targetEmployeeId = employeeId;
    } else {
      const personalInfoFilter = email ? `ecom_workemail eq '${email}'` : `contains(ecom_employeename, '${name}')`;
      const userData = await dataverseRequest(req, "get", "ecom_personalinformations", {
        params: { $filter: personalInfoFilter, $select: "ecom_personalinformationid" }
      });

      if (!userData.value || userData.value.length === 0) {
        return reply.code(404).send({ message: "Employee not found for the provided criteria." });
      }
      targetEmployeeId = userData.value[0].ecom_personalinformationid;
    }

    const positionData = await dataverseRequest(req, "get", "ecom_employeepositions", {
      params: {
        $filter: `_ecom_personalinformation_value eq ${targetEmployeeId}`,
        $select: "ecom_startdate,ecom_grading,statecode",
        $expand: "ecom_JobTitle($select=ecom_jobtitle),ecom_UpdatedBy($select=fullname),ecom_PersonalInformation($select=ecom_employeename)",
        $orderby: "ecom_startdate desc",
      }
    });

    if (!positionData.value || positionData.value.length === 0) {
      return [];
    }

    const transformedData = positionData.value.map(transformPositionRecord);
    return transformedData;

  } catch (err) {
    fastify.log.error({ msg: "❌ Error in admin position search", error: err.response?.data || err.message });
    reply.status(500).send({
      error: "Failed to search position information",
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
  if (!["admin", "co_admin"].includes(req.user.permission)) {
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
      personalInfoFilter = `contains(ecom_employeename, '${name}')`;
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
  if (req.user.permission !== "admin") {
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
        userFilter = `contains(fullname, '${name}')`;
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
})