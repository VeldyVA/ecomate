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
fastify.register(jwt, {
  secret: process.env.JWT_SECRET || "a-very-strong-and-long-secret-for-jwt",
});

fastify.register(fastifyCookie);
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET || "a-super-secret-for-sessions-that-is-long",
  cookie: { secure: false }, // true kalau pakai https di prod
});

// ==============================
// 🔹 Konfigurasi
// ==============================
const dataverseBaseUrl = process.env.DATAVERSE_URL;
const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const ADMIN_EMAILS = process.env.ADMIN_EMAILS.split(",");

const cca = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.AZURE_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}`,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
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
  const now = Date.now();
  // Refresh token if it's expired or will expire in the next 5 minutes
  if (!appTokenCache.token || now >= appTokenCache.expiresOn - 300000) {
    fastify.log.info("Acquiring new application-level Dataverse token...");
    const tokenRequest = {
      scopes: [`${dataverseBaseUrl}/.default`],
    };
    try {
      const response = await cca.acquireTokenByClientCredential(tokenRequest);
      appTokenCache = {
        token: response.accessToken,
        // MSAL gives expiresOn in seconds, convert to milliseconds
        expiresOn: response.expiresOn * 1000 
      };
      fastify.log.info("Successfully acquired new application-level token.");
    } catch (error) {
      fastify.log.error("Failed to acquire application-level token", error);
      throw new Error("Could not acquire application-level token for Dataverse.");
    }
  }
  return appTokenCache.token;
}

// ==============================
// 🔹 Helper: Request ke Dataverse (Refactored)
// ==============================
async function dataverseRequest(method, entitySet, options = {}, delegatedToken = null) {
  let token;
  if (delegatedToken) {
    // Gunakan token delegasi dari pengguna jika disediakan (hanya saat login callback)
    token = delegatedToken;
  } else {
    // Untuk semua request lain, gunakan token level aplikasi
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

// Redirect user ke login Azure
fastify.get("/login", async (req, reply) => {
  const authCodeUrlParameters = {
    scopes: [`${dataverseBaseUrl}/.default`, "offline_access"],
    redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
  };
  const authUrl = await cca.getAuthCodeUrl(authCodeUrlParameters);
  reply.redirect(authUrl);
});

// ==============================
// 🔹 OTP In-Memory Stores
// ==============================
const otpStore = {};
const tokenOtpStore = {};

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ==============================
// 🔹 Callback setelah login user
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

    req.session.accessToken = tokenResponse.accessToken; // Simpan untuk panggilan dari browser jika diperlukan
    const userEmail = tokenResponse.account.username;

    // Gunakan delegated token yang baru didapat untuk mencari detail user
    const userData = await dataverseRequest("get", "ecom_employeepersonalinformations", {
      params: {
        $filter: `ecom_workemail eq '${userEmail}'`,
        $select: "_ecom_fullname_value"
      }
    }, tokenResponse.accessToken);

    if (!userData.value || userData.value.length === 0 || !userData.value[0]._ecom_fullname_value) {
      throw new Error(`Employee GUID not found for email ${userEmail}`);
    }
    
    const employeeId = userData.value[0]._ecom_fullname_value;
    const userRole = isAdmin(userEmail) ? "admin" : "employee";
    
    req.session.employee_id = employeeId;
    req.session.email = userEmail;
    req.session.role = userRole;

    const userPayload = { employeeId, email: userEmail, role: userRole };
    const longLivedJwt = fastify.jwt.sign(userPayload, { expiresIn: '90d' });

    const otp = generateOTP();
    const expiresAt = new Date(new Date().getTime() + 5 * 60000);
    tokenOtpStore[otp] = { jwt: longLivedJwt, expiresAt };

    reply.type('text/html').send(`
      <html>
        <head><title>Login Success</title></head>
        <body><h1>Authentication Successful!</h1><p>Enter this one-time code in your Pusaka agent:</p><h2>${otp}</h2></body>
      </html>
    `);

  } catch (err) {
    console.error("❌ Authentication callback error:", err);
    reply.status(500).send({ error: "Authentication failed", details: err.message });
  }
});

// ==============================
// 🔹 Endpoint Baru: Tukar OTP dengan API Key
// ==============================
fastify.post("/exchange-otp", async (req, reply) => {
  const { otp } = req.body;
  if (!otp) {
    return reply.code(400).send({ error: "OTP is required." });
  }
  const stored = tokenOtpStore[otp];
  if (!stored || new Date() > stored.expiresAt) {
    if (stored) delete tokenOtpStore[otp];
    return reply.code(404).send({ error: "OTP not found or has expired." });
  }
  const apiKey = stored.jwt;
  delete tokenOtpStore[otp];
  reply.send({ apiKey });
});

// ==============================
// 🔹 Role Guard & Middleware Auth
// ==============================
function isAdmin(email) {
  return ADMIN_EMAILS.includes(email.toLowerCase());
}

fastify.decorate("authenticate", async (req, reply) => {
  if (req.headers.authorization) {
    const [type, token] = req.headers.authorization.split(' ') || [];
    if (type === 'Bearer' && token) {
      try {
        req.user = fastify.jwt.verify(token);
        return;
      } catch (err) {
        return reply.code(401).send({ error: "Invalid API Key." });
      }
    }
  }

  if (req.session && req.session.employee_id) {
    req.user = { employeeId: req.session.employee_id, email: req.session.email, role: req.session.role };
    return;
  }

  return reply.code(401).send({ error: "Not authenticated." });
});


// ==============================
// 🔹 Endpoint (Contoh)
// ==============================

fastify.get("/whoami", { preValidation: [fastify.authenticate] }, async (request, reply) => {
  return request.user;
});

// ==============================
// 🔹 Cuti: Get Saldo Cuti User
// ==============================
fastify.get("/leave/balance", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const employeeId = req.user.employeeId;
  try {
    const balanceData = await dataverseRequest("get", "ecom_leaveusages", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeId}`,
        $expand: "ecom_LeaveType($select=ecom_leavetypeid,ecom_name,ecom_quota)",
        $select: "ecom_balance,ecom_usage"
      }
    });

    if (!balanceData.value || balanceData.value.length === 0) {
      return reply.code(404).send({ message: "No leave balance records found." });
    }
    const balances = balanceData.value.map(item => ({
      leave_type_id: item.ecom_LeaveType.ecom_leavetypeid,
      leave_type_name: item.ecom_LeaveType.ecom_name,
      quota: item.ecom_LeaveType.ecom_quota,
      balance: item.ecom_balance,
      used: item.ecom_usage
    }));
    return balances;
  } catch (err) {
    console.error("❌ Error fetching leave balance:", err.response?.data || err.message);
    reply.status(500).send({ error: "Failed to fetch leave balance", details: err.message });
  }
});

// ... (Endpoint lainnya akan menggunakan dataverseRequest yang sudah direfaktor secara otomatis)

console.log("JWT_SECRET:", process.env.JWT_SECRET ? "Loaded" : "Not Found - Using Default");
console.log("ADMIN_EMAILS:", process.env.ADMIN_EMAILS);

fastify.listen({ port: process.env.PORT || 3000, host: "0.0.0.0" }, (err, address) => {
  if (err) throw err;
  fastify.log.info(`🚀 Server running at ${address}`);
});

// ... (sisa file bisa dihapus jika tidak relevan atau disesuaikan)

