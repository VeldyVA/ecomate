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

fastify.register(fastifyCookie);
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET || "supersecret",
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
    redirectUri: "http://localhost:3000/auth/callback",
  };

  const authUrl = await cca.getAuthCodeUrl(authCodeUrlParameters);
  reply.redirect(authUrl);
});

// Callback setelah login user
// ==============================
// 🔹 Callback setelah login user (debug)
// ==============================
fastify.get("/auth/callback", async (req, reply) => {
  console.log("===== /auth/callback =====");
  console.log("Query params received:", req.query);

  const code = req.query.code;
  if (!code) {
    console.error("❌ No authorization code received!");
    return reply
      .status(400)
      .send({
        error: "No authorization code received. Check redirect URI & login flow.",
      });
  }

  const tokenRequest = {
    code,
    scopes: [`${dataverseBaseUrl}/.default`],
    redirectUri: "http://localhost:3000/auth/callback", // HARUS sama persis dengan App Registration
  };

  try {
    const tokenResponse = await cca.acquireTokenByCode({
      code: req.query.code,
      scopes: [`${dataverseBaseUrl}/.default`, "offline_access"],
      redirectUri: "http://localhost:3000/auth/callback",
    });

    // simpan di session
    req.session.accessToken = tokenResponse.accessToken;

    reply.send({
      message: "Login sukses, token tersimpan di session!",
      accessToken: tokenResponse.accessToken,
      expiresOn: tokenResponse.expiresOn,
    });
  } catch (err) {
    console.error("❌ Acquire token error:", err);

    // Jika error dari MSAL
    if (err.errorMessage) {
      console.error("MSAL error message:", err.errorMessage);
    }

    reply.status(500).send({
      error: "Token acquisition failed",
      details: err.errorMessage || err.message || err,
    });
  }
});

async function getAccessToken(req) {
  if (!req.session.accessToken) throw new Error("User not logged in");
  return req.session.accessToken;
}

// ==============================
// 🔹 Helper: Request ke Dataverse
// ==============================
async function dataverseRequest(req, method, entitySet, options = {}) {
  const token = await getAccessToken(req);

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
// 🔹 OTP In-Memory
// ==============================
const otpStore = {}; // { email: { otp, expiresAt } }

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ==============================
// 🔹 Role Guard
// ==============================
function isAdmin(email) {
  return ADMIN_EMAILS.includes(email.toLowerCase());
}

function canAccess(request, employeeId) {
  return request.user.role === "admin" || request.user.employeeId === employeeId;
}

// ==============================
// 🔹 Middleware JWT Auth
// ==============================
fastify.decorate("authenticate", async (req, reply) => {
  try {
    await req.jwtVerify();
  } catch (err) {
    reply.code(401).send({ error: "Invalid or missing token" });
  }
});

// ==============================
// 🔹 Endpoint
// ==============================

fastify.get("/whoami", async (request, reply) => {
  const token = request.session.accessToken;
  if (!token) {
    return reply.code(401).send({ error: "No access token in session, please login first." });
  }

  try {
    const response = await axios.get(
      "https://ecomindo365.crm5.dynamics.com/api/data/v9.2/WhoAmI",
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    return reply.send(response.data);
  } catch (err) {
    console.error("Error calling Dataverse:", err.response?.data || err.message);
    return reply.code(500).send({
      error: "Failed to call Dataverse",
      details: err.response?.data || err.message
    });
  }
});

// 1. Request OTP
fastify.post("/auth/request-otp", async (req, reply) => {
  const { email } = req.body;
  if (!email) return reply.code(400).send({ message: "Email required" });

  const employees = await dataverseRequest("get", "employees", {
    params: {
      $select: "employeeid,email,fullname",
      $filter: `email eq '${email}'`,
    },
  });

  if (!employees.value.length) return reply.code(404).send({ message: "Employee not found" });

  const employee = employees.value[0];
  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 5 * 60000); // 5 menit

  otpStore[email.toLowerCase()] = { otp, expiresAt };

  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Kode OTP Anda adalah ${otp}. Berlaku 5 menit.`,
  });

  return { message: "OTP sent" };
});

// 2. Verify OTP & Issue JWT
fastify.post("/auth/verify-otp", async (req, reply) => {
  const { email, otp } = req.body;
  if (!email || !otp) return reply.code(400).send({ message: "Email & OTP required" });

  const record = otpStore[email.toLowerCase()];
  if (!record || record.otp !== otp || new Date() > record.expiresAt) {
    return reply.code(400).send({ message: "Invalid or expired OTP" });
  }

  // Ambil data employee dari Dataverse
  const employees = await dataverseRequest("get", "employees", {
    params: { $select: "employeeid,email,fullname", $filter: `email eq '${email}'` },
  });

  if (!employees.value.length) return reply.code(404).send({ message: "Employee not found" });
  const employee = employees.value[0];

  const token = req.session.accessToken;({
    employeeId: employee.employeeid,
    email: employee.email,
    role: isAdmin(employee.email) ? "admin" : "employee",
  });

  delete otpStore[email.toLowerCase()]; // OTP sudah dipakai

  return { token };
});

// 3. GET own profile
fastify.get("/profile", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { employeeId } = req.user;

  const employee = await dataverseRequest("get", `employees(${employeeId})`, {
    params: { $select: "employeeid,fullname,email,department,position,contract_type,start_date,probation_end,status" },
  });

  return employee || { message: "Employee not found" };
});

// 4. GET profile by ID (Admin)
fastify.get("/admin/profile/:employeeId", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") return reply.code(403).send({ message: "Admin only" });

  const { employeeId } = req.params;

  const employee = await dataverseRequest("get", `employees(${employeeId})`, {
    params: { $select: "employeeid,fullname,email,department,position,contract_type,start_date,probation_end,status" },
  });

  return employee || { message: "Employee not found" };
});

// 5. PATCH update profile (Admin only)
fastify.patch("/profile/:employeeId", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") return reply.code(403).send({ message: "Admin only" });

  const { employeeId } = req.params;
  const allowedFields = [
    "fullname","email","position","department",
    "start_date","probation_end","contract_type","status"
  ];
  const updates = {};
  for (const field of allowedFields) if (field in req.body) updates[field] = req.body[field];

  const updated = await dataverseRequest("patch", `employees(${employeeId})`, { data: updates });
  return updated;
});

// 6. POST new employee (Admin only)
fastify.post("/profile", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") return reply.code(403).send({ message: "Admin only" });

  const newEmployee = req.body;
  if (!newEmployee.email || !newEmployee.fullname) return reply.code(400).send({ message: "fullname & email required" });

  const toInsert = {
    fullname: newEmployee.fullname,
    email: newEmployee.email,
    position: newEmployee.position || null,
    department: newEmployee.department || null,
    start_date: newEmployee.start_date || null,
    probation_end: newEmployee.probation_end || null,
    contract_type: newEmployee.contract_type || null,
    status: newEmployee.status || "active"
  };

  const inserted = await dataverseRequest("post", "employees", { data: toInsert });
  return inserted;
});

console.log("JWT_SECRET:", process.env.JWT_SECRET);
console.log("ADMIN_EMAILS:", process.env.ADMIN_EMAILS);

// ==============================
// 🔹 Start server
// ==============================
fastify.listen({ port: 3000, host: "0.0.0.0" }, (err, address) => {
  if (err) throw err;
  fastify.log.info(`🚀 Server running at ${address}`);
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
  let workDays = 0;
  const current = new Date(start);
  while (workDays < days) {
    const dow = current.getUTCDay();
    if (dow !== 0 && dow !== 6) workDays++;
    if (workDays < days) current.setUTCDate(current.getUTCDate() + 1);
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
// 🔹 Apply Leave
// ==============================
fastify.post("/leave/apply", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { leave_type, start_date, days } = req.body;
  const employeeId = req.user.employeeId;
  if (!leave_type || !start_date || !days) return reply.code(400).send({ message: "leave_type, start_date, days required" });

  const end_date = calculateEndDate(start_date, days);

  // Ambil employee leave balance
  const empData = await dataverseRequest("get", `employees(${employeeId})`, {
    params: { $select: "annual_leave_balance,personal_leave_balance,wellbeing_day_balance" }
  });

  if (!empData) return reply.code(404).send({ message: "Employee not found" });

  let balanceField = "";
  let currentBalance = 0;
  const type = leave_type.toLowerCase().replace(/\s+/g, "_");

  if (type.includes("annual")) { balanceField = "annual_leave_balance"; currentBalance = empData.annual_leave_balance; }
  else if (type.includes("personal")) { balanceField = "personal_leave_balance"; currentBalance = empData.personal_leave_balance; }
  else if (type.includes("wellbeing")) { balanceField = "wellbeing_day_balance"; currentBalance = empData.wellbeing_day_balance; }
  else return reply.code(400).send({ message: "Invalid leave_type" });

  if (currentBalance < days) return reply.code(400).send({ message: "Insufficient leave balance" });

  // Insert leave request ke Dataverse
  const toInsert = {
    employee_id: employeeId,
    leave_type,
    start_date,
    end_date,
    days,
    status: "pending",
    requested_at: new Date().toISOString()
  };

  const inserted = await dataverseRequest("post", "leave_requests", { data: toInsert });

  // Update employee balance
  const updates = {}; updates[balanceField] = currentBalance - days;
  await dataverseRequest("patch", `employees(${employeeId})`, { data: updates });

  return { message: "Leave request applied", start_date, end_date, days, remaining_balance: currentBalance - days };
});

// ==============================
// 🔹 Cancel Leave
// ==============================
fastify.post("/leave/cancel", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const { leave_id } = req.body;
  if (!leave_id) return reply.code(400).send({ message: "leave_id required" });

  const leave = await dataverseRequest("get", `leave_requests(${leave_id})`);
  if (!leave) return reply.code(404).send({ message: "Leave request not found" });

  // Employee hanya bisa cancel miliknya
  if (req.user.role !== "admin" && leave.employee_id !== req.user.employeeId) {
    return reply.code(403).send({ message: "Access denied" });
  }

  if (leave.status !== "pending") return reply.code(400).send({ message: "Only pending leaves can be canceled" });

  // Kembalikan balance
  const emp = await dataverseRequest("get", `employees(${leave.employee_id})`, {
    params: { $select: "annual_leave_balance,personal_leave_balance,wellbeing_day_balance" }
  });

  const type = leave.leave_type.toLowerCase().replace(/\s+/g, "_");
  let balanceField = "", updatedBalance = 0;
  if (type.includes("annual")) { balanceField = "annual_leave_balance"; updatedBalance = emp.annual_leave_balance + leave.days; }
  else if (type.includes("personal")) { balanceField = "personal_leave_balance"; updatedBalance = emp.personal_leave_balance + leave.days; }
  else if (type.includes("wellbeing")) { balanceField = "wellbeing_day_balance"; updatedBalance = emp.wellbeing_day_balance + leave.days; }

  await dataverseRequest("patch", `employees(${leave.employee_id})`, { data: { [balanceField]: updatedBalance } });
  await dataverseRequest("delete", `leave_requests(${leave_id})`);

  return { message: "Leave canceled", returned_days: leave.days, new_balance: updatedBalance };
});

// ==============================
// 🔹 Admin: List all leave requests
// ==============================
fastify.get("/admin/leave", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") return reply.code(403).send({ message: "Admin only" });

  const leaves = await dataverseRequest("get", "leave_requests");
  return leaves.value || [];
});