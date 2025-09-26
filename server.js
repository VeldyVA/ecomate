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
    redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
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
    redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback", // HARUS sama persis dengan App Registration
  };

  try {
    const tokenResponse = await cca.acquireTokenByCode({
      code: req.query.code,
      scopes: [`${dataverseBaseUrl}/.default`, "offline_access"],
      redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
    });

    // simpan di session
    req.session.accessToken = tokenResponse.accessToken;

    // simpan di session
req.session.accessToken = tokenResponse.accessToken;

const userEmail = tokenResponse.account.username;

// cari employee_id di Dataverse
const userData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
  params: {
    $filter: `ecom_workemail eq '${userEmail}'`,
    $select: "_ecom_fullname_value"
  }
});

    if (userData.value.length > 0 && userData.value[0]._ecom_fullname_value) {
      // Store the Employee's GUID in the session
      req.session.employee_id = userData.value[0]._ecom_fullname_value;

      // Check for admin role and store email and role in session
      const userEmail = tokenResponse.account.username;
      const userRole = isAdmin(userEmail) ? "admin" : "employee";
      req.session.email = userEmail;
      req.session.role = userRole;

    } else {
  throw new Error(`Employee GUID (_ecom_fullname_value) not found for email ${userEmail}`);
}

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
    
    // Log detail error dari Dataverse/Axios
    if (err.response?.data) {
      console.error("Dataverse error details:", err.response.data);
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
  if (!req.session || !req.session.accessToken) {
    return reply.code(401).send({ error: "Not logged in or session expired" });
  }

  // Optional: inject user info ke req.user
  req.user = {
    employeeId: req.session.employeeId,
    email: req.session.email,
    role: req.session.role
  };
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



// 4. GET profile by ID (Admin) - UPGRADED
fastify.get("/admin/profile/:employeeId", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { employeeId } = req.params; // This is the Employee GUID

  try {
    // Find the personal_information record for the given employee GUID
  let filter;
  if (employeeId.match(/^[0-9a-fA-F-]{36}$/)) {
    // kalau format GUID
    filter = `ecom_employeeid eq '${employeeId}'`;
  } else {
    // kalau kode karyawan
    filter = `ecom_employeeid eq '${employeeId}'`;
  }
    const personalInfoData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
      params: {
        $filter: filter,
        $select: [
          "ecom_employeeid", "ecom_employeename", "ecom_gender", "ecom_dateofbirth",
          "ecom_phonenumber", "ecom_status", "ecom_startwork",
          "ecom_emergencycontactname", "ecom_emergencycontactaddress", "ecom_emergencycontractphonenumber",
          "ecom_emergencycontactrelationship", "ecom_address", "ecom_ktpnumber", "ecom_npwpnumber",
          "ecom_profilepicture", "ecom_notes", "ecom_bankaccountnumber", "ecom_bpjsnumber",
          "ecom_bpjstknumber", "ecom_maritalstatus", "ecom_numberofdependent", "ecom_placeofbirth",
          "ecom_religion", "ecom_bankname"
        ].join(",")
      }
    });

    const record = personalInfoData.value?.[0];
    if (!record) {
      return reply.code(404).send({ message: "Personal information record not found for this employee." });
    }

    return record;

  } catch (err) {
    console.error("❌ Error fetching profile by ID:", err.response?.data || err.message);
    reply.status(500).send({
      error: "Failed to fetch profile by ID",
      details: err.response?.data?.error?.message || err.message,
    });
  }
});

// 5. PATCH update profile (Admin only)
fastify.patch("/profile/:employeeId", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  // Per user request, this remains admin-only
  if (req.user.role !== "admin") {
    return reply.code(403).send({ message: "Admin only" });
  }

  const { employeeId } = req.params; // This is the Employee GUID to be updated

  try {
    // 1. Find the personal_information record ID for the target employee
    const personalInfoData = await dataverseRequest(req, "get", "ecom_employeepersonalinformations", {
      params: {
        // Use the GUID of the employee to find their personal info record
        $filter: `_ecom_fullname_value eq ${employeeId}`,
        $select: "ecom_employeepersonalinformationid"
      }
    });

    if (!personalInfoData.value || personalInfoData.value.length === 0) {
      return reply.code(404).send({ message: "Personal information record not found for this employee." });
    }
    const personalInfoId = personalInfoData.value[0].ecom_employeepersonalinformationid;

    // 2. Define allowed fields and build the update object
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

    // 3. Perform the PATCH request on the personal information record
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



console.log("JWT_SECRET:", process.env.JWT_SECRET);
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
// 🔹 Cuti: Get Saldo Cuti User
// ==============================
fastify.get("/leave/balance", { preValidation: [fastify.authenticate] }, async (req, reply) => {
  const employeeId = req.session.employee_id;

  // NOTE: Assuming 'ecom_leaveusages' is linked to an employee via '_ecom_employee_value'
  // and to a leave type via '_ecom_leavetype_value'. Please verify these field names.

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

    // Format the response
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
        $filter: "statecode eq 0", // Only fetch active leave types
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
  const employeeId = req.session.employee_id;

  // NOTE: Assuming 'ecom_employeeleaves' is linked to an employee via '_ecom_employee_value'.
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
  const { leaveTypeId, startDate, days, reason } = req.body;
  const employeeId = req.session.employee_id;

  if (!leaveTypeId || !startDate || !days) {
    return reply.code(400).send({ message: "leaveTypeId, startDate, and days are required." });
  }

  // NOTE: Assumptions about lookup fields. Please verify.
  // - 'ecom_leaveusages' is linked to employee via '_ecom_employee_value'
  // - 'ecom_leaveusages' is linked to leave type via '_ecom_leavetype_value'
  // - 'ecom_employeeleaves' (new request) links to employee via 'ecom_Employee'
  // - 'ecom_employeeleaves' links to leave type via 'ecom_LeaveType'

  try {
    // 1. Get current balance for the specified leave type
    // Assuming leaveTypeId is a GUID and does not need quotes.
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

    // 2. Check if balance is sufficient
    if (currentBalance < days) {
      return reply.code(400).send({ message: `Insufficient leave balance. Available: ${currentBalance}, Requested: ${days}.` });
    }

    // 3. Calculate end date (using existing helper function)
    const endDate = calculateEndDate(startDate, days);

    // 4. Create the leave request record
    // The 'ecom_name' is often a required primary name field in Dataverse.
    // We'll construct a meaningful name for it.
    const leaveRequestName = `Leave Request - ${employeeId} - ${startDate}`;

    const newLeaveRequest = {
      "ecom_Employee@odata.bind": `/employees(${employeeId})`,
      "ecom_LeaveType@odata.bind": `/ecom_leavetypes(${leaveTypeId})`,
      ecom_name: leaveRequestName,
      ecom_startdate: startDate,
      ecom_enddate: endDate,
      ecom_numberofdays: days,
      ecom_reason: reason || null,
      // Set initial status. The value '1' for 'Pending' is a common default.
      // This might need adjustment based on the actual OptionSet values.
      ecom_leavestatus: 1, // Assuming 1 = Pending
      ecom_pmsmapprovalstatus: 1, // Assuming 1 = Pending
      ecom_hrapprovalstatus: 1 // Assuming 1 = Pending
    };

    const inserted = await dataverseRequest("post", "ecom_employeeleaves", { data: newLeaveRequest });

    // IMPORTANT: We do NOT update the balance here. The external system will do that upon approval.

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
  const employeeId = req.session.employee_id;

  // NOTE: Assumptions about lookup fields and status values.
  try {
    // 1. Get the leave request
    const leaveRequest = await dataverseRequest(req, "get", `ecom_employeeleaves(${leaveId})`, {
      params: {
        $select: "ecom_leavestatus,_ecom_employee_value"
      }
    });

    // 2. Verify ownership (non-admins can only cancel their own)
    if (req.user.role !== 'admin' && leaveRequest._ecom_employee_value !== employeeId) {
      return reply.code(403).send({ message: "You can only cancel your own leave requests." });
    }

    // 3. Check if status is 'Pending' (assuming value is 1)
    if (leaveRequest.ecom_leavestatus !== 1) {
      return reply.code(400).send({ message: "Only requests with 'Pending' status can be cancelled." });
    }

    // 4. Update status to 'Cancelled'
    // We deactivate the record and set the status reason to Cancelled.
    // The actual integer values for statecode and statuscode might differ.
    const updates = {
      statecode: 1, // 1 = Inactive
      statuscode: 2, // Assuming 2 = Cancelled
      ecom_leavestatus: 3 // Assuming 3 = Cancelled
    };

    await dataverseRequest("patch", `ecom_employeeleaves(${leaveId})`, { data: updates });

    // IMPORTANT: We do NOT restore the balance here. The external system is responsible for that.

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
        // Admin gets all requests, so no employee filter
        // We expand Employee to show who the request belongs to
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
  // Ambil EmployeeID dari session/user
  const employeeId = req.session.employee_id; // sudah di-set di callback

  // Query ke Dataverse: tabel personal information 
  const data = await dataverseRequest(
    req,
    "get",
    `ecom_employeepersonalinformations`, // perhatikan plural "s"
  {
      params: {
        $filter: `_ecom_fullname_value eq ${employeeId}`,
        $select: [
          "ecom_employeeid",
          "ecom_employeename",
          "ecom_gender",
          "ecom_dateofbirth",
          "ecom_phonenumber",
          "ecom_status",
          "ecom_startwork",
          "ecom_emergencycontactname",
          "ecom_emergencycontactaddress",
          "ecom_emergencycontractphonenumber",
          "ecom_emergencycontactrelationship",
          "ecom_address",
          "ecom_ktpnumber",
          "ecom_npwpnumber",
          "ecom_bankaccountnumber",
          "ecom_bpjsnumber",
          "ecom_bpjstknumber",
          "ecom_maritalstatus",
          "ecom_numberofdependent",
          "ecom_placeofbirth",
          "ecom_religion",
          "ecom_bankname",
          "ecom_personalemail",
          "ecom_workexperience",
          "ecom_insurancenumber",  
          "ecom_profilepicture"  

        ].join(",")
      }
    }
  );

  const record = data.value?.[0];
if (!record) return reply.code(404).send({ message: "Data not found" });

// Return the simplified record for debugging
return record;
});
