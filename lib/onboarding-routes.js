// lib/onboarding-routes.js
//
// Phone-first progressive onboarding, replacing the single monolithic
// POST /api/auth/register call with a resumable, step-by-step flow:
//
//   POST /api/onboarding/phone/start     phone -> OTP sent
//   POST /api/onboarding/phone/resend    phone -> new OTP sent
//   POST /api/onboarding/phone/verify    phone + otp -> onboarding_token
//   POST /api/onboarding/account         (onboarding_token) email/password/passcode -> user+session created
//   POST /api/onboarding/profile         (session) name/dob/address -> saved
//   POST /api/onboarding/kyc             (session) bvn/nin -> saved
//   POST /api/onboarding/face            (session) face captures -> stored, virtual account job enqueued
//   GET  /api/onboarding/status          (session) -> where to resume
//
// The server-side users.onboarding_status column is the single source of
// truth for resuming — the frontend never decides this from localStorage
// alone (register.html just asks this endpoint on load).
//
// Existing /api/auth/register is left untouched for backward
// compatibility; this is a parallel, additive flow.
//
// Virtual-account provisioning itself is NOT reimplemented here — the
// existing lib/virtual-account-worker.js + service-registry.js
// (Flutterwave/Paystack) already work and are reused as-is. This file
// only enqueues the same create_virtual_account job the old register
// route enqueued.

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const { z } = require("zod");

const { authenticate, generateSessionId, getDeviceInfo } = require("../middleware/auth");
const virtualAccountWorker = require("./virtual-account-worker");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const router = express.Router();

// ==================== Helpers ====================

function withDbTimeout(queryBuilder, ms = 8000) {
  return Promise.race([
    queryBuilder,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Database query aborted (timeout)")), ms),
    ),
  ]);
}

async function logSecurityEvent(userId, eventType, details = {}) {
  try {
    await supabase.from("security_logs").insert({
      user_id: userId,
      event_type: eventType,
      details,
      ip_address: details.ip || null,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[ONBOARDING] Security log error:", err);
  }
}

// Normalizes any reasonable Nigerian phone input to +234XXXXXXXXXX.
// Returns null if it can't confidently normalize the input.
function normalizeNigerianPhone(raw) {
  if (!raw || typeof raw !== "string") return null;
  let p = raw.trim().replace(/[\s-]/g, "");
  if (p.startsWith("+234")) {
    p = p;
  } else if (p.startsWith("234")) {
    p = "+" + p;
  } else if (p.startsWith("0")) {
    p = "+234" + p.slice(1);
  } else if (/^\d{10}$/.test(p)) {
    p = "+234" + p;
  } else {
    return null;
  }
  return /^\+234\d{10}$/.test(p) ? p : null;
}

function generateOtp() {
  return String(crypto.randomInt(100000, 1000000)); // 6 digits, no leading-zero bias issue
}

// SMS delivery abstraction. Swap the body of this function for your real
// SMS provider (Termii, Africa's Talking, Twilio, etc.) when one is
// wired up — nothing else in this file needs to change.
//
// In development (or when explicitly allowed), it logs the code instead
// of sending it and returns { simulated: true } so the route can decide
// whether to echo it back in the response. It NEVER does this in
// production — if no provider is configured in production, sending
// fails loudly instead of silently pretending to succeed.
async function sendSms(phone, message) {
  const providerUrl = process.env.SMS_PROVIDER_URL;
  const providerKey = process.env.SMS_PROVIDER_KEY;

  if (providerUrl && providerKey) {
    const axios = require("axios");
    await axios.post(
      providerUrl,
      { to: phone, message },
      { headers: { Authorization: `Bearer ${providerKey}` }, timeout: 10000 },
    );
    return { simulated: false };
  }

  if (process.env.NODE_ENV === "production") {
    throw new Error("SMS provider not configured");
  }

  console.log(`[ONBOARDING][DEV SMS] -> ${phone}: ${message}`);
  return { simulated: true };
}

// Short-lived token proving "this phone number was just OTP-verified",
// issued instead of a real session because no users row exists yet.
function signOnboardingToken(phone) {
  return jwt.sign(
    { purpose: "onboarding_phone_verified", phone },
    process.env.JWT_SECRET,
    { expiresIn: "30m" },
  );
}

function requireOnboardingToken(req, res, next) {
  const authHeader = req.header("Authorization");
  const token = authHeader?.replace("Bearer ", "");
  if (!token) {
    return res.status(401).json({ error: "Phone verification required" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.purpose !== "onboarding_phone_verified" || !decoded.phone) {
      return res.status(401).json({ error: "Phone verification required" });
    }
    req.onboardingPhone = decoded.phone;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Verification expired, please verify your phone again" });
  }
}

// ==================== Rate limiters ====================

const otpSendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many code requests. Please try again later." },
  keyGenerator: (req) => `${req.ip}:${normalizeNigerianPhone(req.body?.phone) || "unknown"}`,
});

const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." },
  keyGenerator: (req) => `${req.ip}:${normalizeNigerianPhone(req.body?.phone) || "unknown"}`,
});

const accountCreateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." },
});

// ==================== Validation ====================

const email = z.string().trim().toLowerCase().email("Invalid email address").max(254);
const password = z
  .string()
  .min(6, "Password must be at least 6 characters")
  .max(128, "Password must be 128 characters or fewer");
const sixDigitPasscode = z.string().regex(/^\d{6}$/, "Passcode must be exactly 6 digits");
const bvnSchema = z.string().regex(/^\d{11}$/, "BVN must be exactly 11 digits");
const ninSchema = z.string().regex(/^\d{11}$/, "NIN must be exactly 11 digits");
const nameField = z
  .string()
  .trim()
  .min(1, "Required")
  .max(100)
  .regex(/^[a-zA-Z\s'-]+$/, "Only letters, spaces, hyphens and apostrophes allowed");

const accountSchema = z.object({
  email,
  password,
  passcode: sixDigitPasscode,
});

const profileSchema = z.object({
  first_name: nameField,
  last_name: nameField,
  middle_name: nameField.optional().or(z.literal("")),
  date_of_birth: z.string().refine((v) => !isNaN(Date.parse(v)), "Invalid date"),
  gender: z.enum(["male", "female"]).optional(),
  country: z.string().trim().min(1).max(100).default("Nigeria"),
  state: z.string().trim().min(1).max(100),
  city: z.string().trim().min(1).max(100),
  address: z.string().trim().min(1).max(255),
  postal_code: z.string().trim().max(20).optional(),
  marital_status: z.string().trim().max(30).optional(),
  occupation: z.string().trim().max(100).optional(),
});

// Either BVN or NIN is accepted — Flutterwave supports both as an
// identity anchor for virtual account creation. Paystack is BVN-only
// (confirmed against their Validate Customer docs, not a gap in this
// codebase), so a NIN-only submission here is routed to Flutterwave
// automatically at provisioning time — see virtual-account-worker.js's
// capability override. Nothing about that routing decision needs to
// happen here; this endpoint just needs to accept either identifier.
const kycSchema = z
  .object({
    bvn: bvnSchema.optional().or(z.literal("")),
    nin: ninSchema.optional().or(z.literal("")),
    security_question_1: z.string().trim().min(1).max(255),
    security_answer_1: z.string().trim().min(1).max(255),
    security_question_2: z.string().trim().min(1).max(255),
    security_answer_2: z.string().trim().min(1).max(255),
  })
  .refine((d) => !!d.bvn || !!d.nin, {
    message: "Enter your BVN or your NIN",
    path: ["bvn"],
  })
  .refine((d) => d.security_question_1 !== d.security_question_2, {
    message: "Security questions must be different",
    path: ["security_question_2"],
  });

function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        error: "Invalid request",
        details: result.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      });
    }
    req.body = result.data;
    next();
  };
}

// ==================== 1. Phone + OTP ====================

async function handleSendOtp(req, res) {
  try {
    const phone = normalizeNigerianPhone(req.body.phone);
    if (!phone) {
      return res.status(400).json({ error: "Enter a valid Nigerian phone number" });
    }

    const { data: existing } = await withDbTimeout(
      supabase
        .from("users")
        .select("id, passcode_hash")
        .eq("phone", phone)
        .is("deleted_at", null)
        .maybeSingle(),
    );

    if (existing) {
      return res.status(409).json({
        error: "An account with this phone number already exists. Please log in instead.",
        code: "PHONE_ALREADY_REGISTERED",
      });
    }

    const { count } = await withDbTimeout(
      supabase
        .from("phone_otps")
        .select("id", { count: "exact", head: true })
        .eq("phone", phone)
        .eq("purpose", "signup")
        .gte("created_at", new Date(Date.now() - 10 * 60 * 1000).toISOString()),
    );
    if ((count || 0) >= 3) {
      return res.status(429).json({ error: "Too many codes requested. Please wait a few minutes." });
    }

    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    const { error: insertErr } = await withDbTimeout(
      supabase.from("phone_otps").insert({
        phone,
        otp_code: otp,
        purpose: "signup",
        ip_address: req.ip || null,
        expires_at: expiresAt.toISOString(),
      }),
    );
    if (insertErr) throw insertErr;

    let devOtp = null;
    try {
      const result = await sendSms(phone, `Your FEECENT verification code is ${otp}. It expires in 10 minutes.`);
      if (result.simulated) devOtp = otp;
    } catch (smsErr) {
      console.error("[ONBOARDING] SMS send failed:", smsErr.message);
      return res.status(503).json({
        error: "We couldn't send a verification code right now. Please try again shortly.",
      });
    }

    const response = { message: "Verification code sent", phone };
    if (devOtp) response.dev_otp = devOtp; // only ever set outside production
    res.json(response);
  } catch (error) {
    console.error("[ONBOARDING] send-otp error:", error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
}

router.post("/phone/start", otpSendLimiter, handleSendOtp);
router.post("/phone/resend", otpSendLimiter, handleSendOtp);

router.post("/phone/verify", otpVerifyLimiter, async (req, res) => {
  try {
    const phone = normalizeNigerianPhone(req.body.phone);
    const otp = (req.body.otp || "").trim();

    if (!phone) return res.status(400).json({ error: "Enter a valid Nigerian phone number" });
    if (!/^\d{6}$/.test(otp)) return res.status(400).json({ error: "Enter the 6-digit code" });

    const { data: row } = await withDbTimeout(
      supabase
        .from("phone_otps")
        .select("*")
        .eq("phone", phone)
        .eq("purpose", "signup")
        .eq("is_used", false)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle(),
    );

    if (!row || new Date(row.expires_at) < new Date()) {
      return res.status(400).json({ error: "Code expired. Please request a new one." });
    }

    if (row.attempts >= 5) {
      return res.status(429).json({ error: "Too many incorrect attempts. Please request a new code." });
    }

    if (row.otp_code !== otp) {
      await supabase.from("phone_otps").update({ attempts: row.attempts + 1 }).eq("id", row.id);
      return res.status(400).json({ error: "Incorrect code. Please try again." });
    }

    await supabase.from("phone_otps").update({ is_used: true }).eq("id", row.id);

    const onboarding_token = signOnboardingToken(phone);
    res.json({ onboarding_token, phone });
  } catch (error) {
    console.error("[ONBOARDING] verify-otp error:", error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ==================== 2. Account creation (email + password + passcode) ====================

router.post(
  "/account",
  accountCreateLimiter,
  requireOnboardingToken,
  validate(accountSchema),
  async (req, res) => {
    try {
      const { email: userEmail, password: userPassword, passcode } = req.body;
      const phone = req.onboardingPhone;

      const { data: existingEmail } = await withDbTimeout(
        supabase.from("users").select("id").eq("email", userEmail).maybeSingle(),
      );
      if (existingEmail) {
        return res.status(400).json({ error: "Email already registered" });
      }

      const { data: existingPhone } = await withDbTimeout(
        supabase.from("users").select("id").eq("phone", phone).is("deleted_at", null).maybeSingle(),
      );
      if (existingPhone) {
        return res.status(409).json({ error: "This phone number is already registered. Please log in." });
      }

      const hashedPassword = await bcrypt.hash(userPassword, 10);
      const hashedPasscode = await bcrypt.hash(passcode, 10);

      const { data: user, error: userErr } = await withDbTimeout(
        supabase
          .from("users")
          .insert({
            email: userEmail,
            password_hash: hashedPassword,
            first_name: "",
            last_name: "",
            phone,
            passcode_hash: hashedPasscode,
            passcode_set_at: new Date().toISOString(),
            role: "user",
            kyc_status: "pending",
            is_active: true,
            is_frozen: false,
            account_tier: 1,
            onboarding_status: "PROFILE_PENDING",
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          })
          .select()
          .single(),
        12000,
      );
      if (userErr) throw userErr;

      // Checking account is created now, same as the legacy register route —
      // account creation never depends on virtual-account provisioning, and
      // provisioning itself waits until KYC (BVN) is captured a few steps
      // from now.
      const { error: accountErr } = await withDbTimeout(
        supabase.from("accounts").insert({
          user_id: user.id,
          account_type: "checking",
          currency: "NGN",
          balance: 0.0,
          available_balance: 0.0,
          status: "active",
          creation_status: "PENDING",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        }),
      );
      if (accountErr) console.error("[ONBOARDING] account row insert error:", accountErr);

      // Session — mirrors the exact pattern used by /api/auth/register and
      // /api/auth/verify-passcode so tokens issued here behave identically
      // everywhere else in the app.
      const deviceInfo = getDeviceInfo(req);
      const sessionVersion = Math.floor(Date.now() / 1000);
      const sessionId = generateSessionId();

      const token = jwt.sign(
        {
          userId: user.id,
          email: user.email,
          role: user.role,
          sessionId,
          sessionVersion,
          issuedAt: Date.now(),
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE || "7d" },
      );

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await withDbTimeout(
        supabase.from("user_sessions").insert({
          user_id: user.id,
          session_token: token,
          session_id: sessionId,
          device_fingerprint: deviceInfo.device_name,
          device_name: deviceInfo.device_name,
          ip_address: deviceInfo.ip_address,
          user_agent: deviceInfo.user_agent,
          expires_at: expiresAt.toISOString(),
          is_active: true,
          is_current: true,
          session_version: sessionVersion,
          created_at: new Date().toISOString(),
          last_activity: new Date().toISOString(),
        }),
      );

      await withDbTimeout(
        supabase
          .from("users")
          .update({
            active_session_id: sessionId,
            last_active_device: deviceInfo.device_name,
            active_session_started_at: new Date().toISOString(),
            last_login: new Date().toISOString(),
            session_version: sessionVersion,
          })
          .eq("id", user.id),
      );

      await logSecurityEvent(user.id, "user_registered", {
        ip: req.ip,
        device: deviceInfo.device_name,
        session_id: sessionId,
        flow: "progressive_onboarding",
      });

      res.status(201).json({
        token,
        onboarding_status: "PROFILE_PENDING",
        user: {
          id: user.id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          role: user.role,
        },
        session: { id: sessionId, device: deviceInfo.device_name, logged_in_at: new Date().toISOString() },
      });
    } catch (error) {
      console.error("[ONBOARDING] account creation error:", error);
      res.status(500).json({ error: "Something went wrong creating your account. Please try again." });
    }
  },
);

// ==================== 3. Profile ====================

router.post("/profile", authenticate, validate(profileSchema), async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      middle_name,
      date_of_birth,
      gender,
      country,
      state,
      city,
      address,
      postal_code,
      marital_status,
      occupation,
    } = req.body;

    const birthDate = new Date(date_of_birth);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) age--;

    if (age < 18) {
      return res.status(400).json({ error: "You must be at least 18 years old to open a FEECENT account" });
    }
    if (birthDate > today) {
      return res.status(400).json({ error: "Date of birth cannot be in the future" });
    }

    const { error } = await withDbTimeout(
      supabase
        .from("users")
        .update({
          first_name,
          last_name,
          middle_name: middle_name || null,
          date_of_birth,
          age,
          gender: gender || null,
          country,
          state,
          city,
          address,
          postal_code: postal_code || null,
          marital_status: marital_status || null,
          occupation: occupation || null,
          onboarding_status: "KYC_PENDING",
          updated_at: new Date().toISOString(),
        })
        .eq("id", req.user.id),
    );
    if (error) throw error;

    res.json({ onboarding_status: "KYC_PENDING" });
  } catch (error) {
    console.error("[ONBOARDING] profile error:", error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ==================== 4. KYC (BVN required, NIN optional) ====================

router.post("/kyc", authenticate, validate(kycSchema), async (req, res) => {
  try {
    const { bvn, nin, security_question_1, security_answer_1, security_question_2, security_answer_2 } = req.body;

    const hashedAnswer1 = await bcrypt.hash(security_answer_1.toLowerCase().trim(), 10);
    const hashedAnswer2 = await bcrypt.hash(security_answer_2.toLowerCase().trim(), 10);

    const { error } = await withDbTimeout(
      supabase
        .from("users")
        .update({
          bvn,
          nin: nin || null,
          security_question_1,
          security_answer_1: hashedAnswer1,
          security_question_2,
          security_answer_2: hashedAnswer2,
          onboarding_status: "FACE_PENDING",
          updated_at: new Date().toISOString(),
        })
        .eq("id", req.user.id),
    );
    if (error) throw error;

    await logSecurityEvent(req.user.id, "kyc_identity_submitted", { ip: req.ip });

    res.json({ onboarding_status: "FACE_PENDING" });
  } catch (error) {
    console.error("[ONBOARDING] kyc error:", error);
    res.status(500).json({ error: "We couldn't verify those details. Please check your information and try again." });
  }
});

// ==================== 5. Face capture + virtual account kickoff ====================

router.post("/face", authenticate, async (req, res) => {
  try {
    const { face_images, face_descriptors, face_quality_scores } = req.body;

    if (!Array.isArray(face_images) || face_images.length === 0) {
      return res.status(400).json({ error: "Face capture is required" });
    }

    const userId = req.user.id;
    const descriptorVectors = face_descriptors || [];
    const qualityScores = face_quality_scores || [];

    // ── Collect valid 128-D vectors (same contract as the legacy register route) ──
    const validFrames = [];
    for (let i = 0; i < face_images.length; i++) {
      const vector = descriptorVectors[i];
      const quality = qualityScores[i] || 0.8;
      if (vector && Array.isArray(vector) && vector.length === 128) {
        validFrames.push({ vector, quality, image: face_images[i], index: i });
      }
    }

    if (validFrames.length === 0) {
      return res.status(400).json({
        error: "We couldn't verify your face clearly. Please retry in good lighting.",
      });
    }

    const avg = new Array(128).fill(0);
    for (const frame of validFrames) {
      for (let j = 0; j < 128; j++) avg[j] += frame.vector[j] / validFrames.length;
    }
    const canonicalVector = avg;
    const bestFrame = validFrames.reduce((a, b) => (b.quality > a.quality ? b : a));

    await supabase.from("face_descriptors").delete().eq("user_id", userId);

    await supabase.from("face_descriptors").insert({
      user_id: userId,
      descriptor: canonicalVector,
      is_primary: true,
      is_active: true,
      quality_score: bestFrame.quality,
      version: 1,
      created_at: new Date().toISOString(),
    });

    for (const frame of validFrames) {
      await supabase.from("face_descriptors").insert({
        user_id: userId,
        descriptor: {
          vector: frame.vector,
          image: frame.image,
          angle: frame.index,
          quality: frame.quality,
          timestamp: new Date().toISOString(),
          is_valid: true,
        },
        is_primary: false,
        is_active: true,
        quality_score: frame.quality,
        version: 1,
        created_at: new Date().toISOString(),
      });
    }

    const { data: user, error: fetchErr } = await withDbTimeout(
      supabase.from("users").select("*").eq("id", userId).single(),
    );
    if (fetchErr || !user) throw fetchErr || new Error("User not found");

    await supabase
      .from("users")
      .update({
        face_embedding: JSON.stringify(canonicalVector),
        face_verified: true,
        face_quality_score: bestFrame.quality,
        face_image: bestFrame.image || null,
        face_verification_date: new Date().toISOString(),
        face_embedding_version: 1,
        onboarding_status: "ONBOARDING_COMPLETE",
        updated_at: new Date().toISOString(),
      })
      .eq("id", userId);

    // ── Kick off virtual account provisioning now that identity (BVN or
    // NIN) + face are in. Either identifier is enough — Flutterwave
    // accepts both; virtual-account-worker.js routes NIN-only jobs to
    // Flutterwave specifically since Paystack has no NIN path. ──
    const { data: account } = await withDbTimeout(
      supabase
        .from("accounts")
        .select("id, creation_status")
        .eq("user_id", userId)
        .eq("account_type", "checking")
        .maybeSingle(),
    );

    let enqueuedJobId = null;
    if (account && account.creation_status !== "ACTIVE" && (user.bvn || user.nin)) {
      const { data: existingJob } = await withDbTimeout(
        supabase
          .from("background_jobs")
          .select("id")
          .eq("job_type", "create_virtual_account")
          .contains("payload", { account_id: account.id })
          .in("status", ["pending", "processing"])
          .maybeSingle(),
      );

      if (!existingJob) {
        const { data: job, error: jobError } = await supabase
          .from("background_jobs")
          .insert({
            job_type: "create_virtual_account",
            payload: {
              user_id: userId,
              account_id: account.id,
              email: user.email,
              bvn: user.bvn || null,
              nin: user.nin || null,
              first_name: user.first_name,
              last_name: user.last_name,
              phone: user.phone,
            },
            status: "pending",
            priority: 100,
          })
          .select()
          .single();

        if (jobError) console.error("[ONBOARDING] Failed to enqueue VA job:", jobError);
        else enqueuedJobId = job.id;
      } else {
        enqueuedJobId = existingJob.id;
      }
    }

    if (enqueuedJobId) {
      try {
        const { waitUntil } = require("@vercel/functions");
        waitUntil(virtualAccountWorker.processOne(enqueuedJobId));
      } catch (waitUntilErr) {
        virtualAccountWorker
          .processOne(enqueuedJobId)
          .catch((e) => console.error("[ONBOARDING] processOne fallback failed:", e));
      }
    }

    await logSecurityEvent(userId, "onboarding_completed", { ip: req.ip });

    res.json({
      onboarding_status: "ONBOARDING_COMPLETE",
      message: "Your FEECENT account is ready",
      virtual_account_status: account ? account.creation_status : "PENDING",
    });
  } catch (error) {
    console.error("[ONBOARDING] face error:", error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// ==================== 6. Resume / status ====================

router.get("/status", authenticate, async (req, res) => {
  try {
    const { data: account } = await supabase
      .from("accounts")
      .select("creation_status, account_number, bank_name")
      .eq("user_id", req.user.id)
      .eq("account_type", "checking")
      .maybeSingle();

    res.json({
      onboarding_status: req.user.onboarding_status || "ONBOARDING_COMPLETE",
      first_name: req.user.first_name,
      has_bvn: !!req.user.bvn,
      has_nin: !!req.user.nin,
      face_verified: !!req.user.face_verified,
      virtual_account: account
        ? {
            status: account.creation_status,
            account_number: account.creation_status === "ACTIVE" ? account.account_number : null,
            bank_name: account.creation_status === "ACTIVE" ? account.bank_name : null,
          }
        : null,
    });
  } catch (error) {
    console.error("[ONBOARDING] status error:", error);
    res.status(500).json({ error: "Something went wrong." });
  }
});

module.exports = router;