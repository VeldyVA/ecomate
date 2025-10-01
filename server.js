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
    const userData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
      params: {
        $filter: `ecom_workemail eq '${userEmail}'`,
        $select: "_ecom_fullname_value"
      }
    });

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
    const longLivedJwt = fastify.jwt.sign(userPayload, { expiresIn: '90d' });

    // Buat OTP untuk ditukar dengan JWT
    const otp = generateOTP();
    const expiresAt = new Date(new Date().getTime() + 5 * 60000); // 5 menit
    tokenOtpStore[otp] = { jwt: longLivedJwt, expiresAt };
    console.log('OTP generated and stored:', tokenOtpStore); // New log

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
  const { otp } = req.body;
  if (!otp) {
    return reply.code(400).send({ error: "OTP is required." });
  }

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
    return response.accessToken;
  } catch (error) {
    fastify.log.error("Failed to acquire application-level token", error);
    throw new Error("Could not acquire application-level token for Dataverse.");
  }
}

// ==============================
// 🔹 Helper: Request ke Dataverse (Refactored)
// ==============================
async function dataverseRequest(req, method, entitySet, options = {}) {
  // Logic ini diubah untuk selalu menggunakan App-level token (Client Credentials)
  // agar bisa dipanggil dari mana saja (baik browser session maupun API Key) tanpa bergantung pada session user.
  const token = await getAppLevelDataverseToken();

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
// 🔹 Leave Helper
// ==============================
function parseDateUTC(str) {
  const [y, m, d] = str.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d));
}

function formatDateUTC(date) {
  const pad = n => (n < 10 ? "0" + n : n);
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth()+1)}-${pad(date.getUTCDate())}`;
}

function calculateEndDate(startDateStr, days) {
  const start = parseDateUTC(startDateStr);
  let remainingDays = days;
  const current = new Date(start);
  while (remainingDays > 0) {
    const dow = current.getUTCDay();
    if (dow !== 0 && dow !== 6) {
      remainingDays--;
    }
    if (remainingDays > 0) {
      current.setUTCDate(current.getUTCDate() + 1);
    }
  }
  return formatDateUTC(current);
}

// ==============================
// 🔹 Leave Preview
// ==============================
fastify.post("/leave-preview", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { start_date, days } = req.body;
  if (!start_date || !days) return reply.code(400).send({ message: "start_date & days required" });

  const start = parseDateUTC(start_date);
  const dow = start.getUTCDay();
  if (dow === 0 || dow === 6) return reply.code(400).send({ message: "Start date cannot fall on Saturday or Sunday" });

  const today = new Date(); today.setUTCHours(0,0,0,0);
  if (start < today) return reply.code(400).send({ message: "Start date cannot be in the past" });

  const end_date = calculateEndDate(start_date, days);
  return { start_date, end_date, days, message: "Preview calculated successfully" };
});

// ==============================
// 🔹 Cuti: Get Saldo Cuti User
// ==============================
fastify.get("/leave/balance", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const employeeId = req.user.employeeId; // Diubah dari req.session.employee_id

  try {
    const balanceData = await dataverseRequest(req, "get", "ecom_leaveusages", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeId}`,
        $expand: "ecom_LeaveType($select=ecom_leavetypeid,ecom_name,ecom_quota)",
        $select: "ecom_balance,ecom_usage"
      }
    });

    if (!balanceData.value || balanceData.value.length === 0) {
      return reply.code(404).send({ message: "No leave balance records found for this employee." });
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
// 🔹 Cuti: Apply for Leave
// ==============================
fastify.post("/leave/requests", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { leaveTypeId, startDate, reason } = req.body;
  const days = req.body.days || req.body.ecom_days;
  const employeeId = req.user.employeeId; // Diubah dari req.session.employee_id

  if (!leaveTypeId || !startDate || !days) {
    return reply.code(400).send({ message: "leaveTypeId, startDate, and days are required." });
  }

  try {
    const balanceData = await dataverseRequest(req, "get", "ecom_leaveusages", {
      params: {
        $filter: `_ecom_employee_value eq ${employeeId} and _ecom_leavetype_value eq ${leaveTypeId}`,
        $select: "ecom_balance"
      }
    });

    const currentBalance = balanceData.value?.[0]?.ecom_balance;

    if (currentBalance === undefined) {
      return reply.code(404).send({ message: `No leave balance found for leave type ${leaveTypeId}.` });
    }

    if (currentBalance < days) {
      return reply.code(400).send({ message: `Insufficient leave balance. Available: ${currentBalance}, Requested: ${days}.` });
    }

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
      ecom_leavestatus: 1, 
      ecom_pmsmapprovalstatus: 1,
      ecom_hrapprovalstatus: 1
    };

    const inserted = await dataverseRequest("post", "ecom_employeeleaves", { data: newLeaveRequest });

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
// 🔹 Cuti: Cancel a Leave Request
// ==============================
fastify.post("/leave/requests/:leaveId/cancel", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { leaveId } = req.params;
  const employeeId = req.user.employeeId; // Diubah

  try {
    const leaveRequest = await dataverseRequest(req, "get", `ecom_employeeleaves(${leaveId})`, {
      params: {
        $select: "ecom_leavestatus,_ecom_employee_value"
      }
    });

    if (req.user.role !== 'admin' && leaveRequest._ecom_employee_value !== employeeId) {
      return reply.code(403).send({ message: "You can only cancel your own leave requests." });
    }

    if (leaveRequest.ecom_leavestatus !== 1) {
      return reply.code(400).send({ message: "Only requests with 'Pending' status can be cancelled." });
    }

    const updates = {
      statecode: 1, 
      statuscode: 2, 
      ecom_leavestatus: 3
    };

    await dataverseRequest("patch", `ecom_employeeleaves(${leaveId})`, { data: updates });

    return { message: `Leave request ${leaveId} has been cancelled.` };

  } catch (err) {
    console.error("❌ Error cancelling leave request:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to cancel leave request",
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
        $expand: "ecom_LeaveType($select=ecom_name),ecom_Employee($select=ecom_employeename)",
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