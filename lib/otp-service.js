// lib/sms/otp-service.js
//
// The single place OTPs are generated, hashed, stored, and verified.
// Nothing else in the app should touch otp_requests directly — call
// requestOtp()/verifyOtp() from here so every caller gets the same
// idempotency, rate-limiting, and hashing guarantees (spec sections
// 4-11, 31-32).
//
// How "provider retries never duplicate the OTP" (section 3/14) is
// actually achieved: sendOtp() calls requestOtp() to mint the OTP
// exactly ONCE per logical request, renders it into the SMS text, and
// hands that rendered text to sms-service.js, which persists it
// (encrypted at rest — see sms-service.js) as a background_jobs
// payload BEFORE any provider is contacted. Every provider attempt in
// the router's failover chain, and every job-level retry if the whole
// chain fails, re-sends that SAME persisted, already-rendered text —
// nothing downstream of this file ever calls generateOtp() again for
// the same request. A duplicate client POST is caught separately, by
// otp_request_id idempotency below.

const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const { hashPhone } = require("./phone-utils");
const { renderOtpMessage } = require("./templates");
const smsService = require("./sms-service");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const OTP_EXPIRY_SECONDS = parseInt(process.env.OTP_EXPIRY_SECONDS || "300", 10); // 5 min default (section 10)
const OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS || "5", 10); // section 9
const OTP_RESEND_COOLDOWN_SECONDS = parseInt(process.env.OTP_RESEND_COOLDOWN_SECONDS || "45", 10); // section 8
const OTP_MAX_PER_USER_15MIN = parseInt(process.env.OTP_MAX_PER_USER_15MIN || "5", 10);
const OTP_MAX_PER_PHONE_HOUR = parseInt(process.env.OTP_MAX_PER_PHONE_HOUR || "10", 10);

// Section 11: crypto-secure, never Math.random().
function generateOtp() {
  return String(crypto.randomInt(100000, 1000000)); // 6 digits
}

// HMAC rather than a plain hash so a stolen DB dump alone can't be
// brute-forced offline against the 6-digit space — the attacker also
// needs OTP_SECRET, which never leaves the server.
function hashOtp(otp) {
  const secret = process.env.OTP_SECRET;
  if (!secret) throw new Error("OTP_SECRET is not configured");
  return crypto.createHmac("sha256", secret).update(otp).digest("hex");
}

function constantTimeEqual(a, b) {
  const bufA = Buffer.from(a || "", "hex");
  const bufB = Buffer.from(b || "", "hex");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Section 8: layered resend/abuse throttling. Rejects BEFORE
// touching otp_requests so a hostile actor can't use the request path
// itself to run up SMS spend once these limits are hit.
async function checkRateLimits({ userId, phoneHash, ipAddress }) {
  const fifteenMinAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

  const { count: userCount } = await supabase
    .from("otp_requests")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .gte("created_at", fifteenMinAgo);
  if ((userCount || 0) >= OTP_MAX_PER_USER_15MIN) {
    return { allowed: false, reason: "Too many code requests for this account. Please try again later." };
  }

  const { count: phoneCount } = await supabase
    .from("otp_requests")
    .select("id", { count: "exact", head: true })
    .eq("phone_number_hash", phoneHash)
    .gte("created_at", oneHourAgo);
  if ((phoneCount || 0) >= OTP_MAX_PER_PHONE_HOUR) {
    return { allowed: false, reason: "Too many code requests for this phone number. Please try again later." };
  }

  // Per-IP is intentionally coarse here (express-rate-limit already
  // guards the HTTP route itself — see otp-routes.js). This DB-level
  // check exists so the limit also applies to non-HTTP callers
  // (workers, admin-triggered resends) that bypass the route middleware.
  if (ipAddress) {
    const { count: ipCount } = await supabase
      .from("otp_requests")
      .select("id", { count: "exact", head: true })
      .eq("ip_address", ipAddress)
      .gte("created_at", fifteenMinAgo);
    if ((ipCount || 0) >= OTP_MAX_PER_USER_15MIN * 3) {
      return { allowed: false, reason: "Too many code requests from this network. Please try again later." };
    }
  }

  return { allowed: true };
}

// requestOtp() — mints/reuses the DB row. Idempotent on otpRequestId
// (section 4); enforces one-active-per-purpose via request_otp_atomic
// (section 7/31). Only returns plaintext `otp` when this call is the
// one that actually generated it (action CREATED/REPLACED) — for
// IDEMPOTENT_REPLAY/COOLDOWN there is nothing new to send, by design
// (see file header).
async function requestOtp({ userId, phone, purpose, otpRequestId, ipAddress, deviceId }) {
  if (!userId || !phone || !purpose) throw new Error("userId, phone, and purpose are required");

  const phoneHash = hashPhone(phone);
  const rateCheck = await checkRateLimits({ userId, phoneHash, ipAddress });
  if (!rateCheck.allowed) {
    return { ok: false, code: "RATE_LIMITED", message: rateCheck.reason };
  }

  const otp = generateOtp();
  const otpHash = hashOtp(otp);
  const requestId = otpRequestId || crypto.randomUUID();
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_SECONDS * 1000).toISOString();

  const { data, error } = await supabase.rpc("request_otp_atomic", {
    p_user_id: userId,
    p_purpose: purpose,
    p_otp_hash: otpHash,
    p_otp_request_id: requestId,
    p_phone_hash: phoneHash,
    p_expires_at: expiresAt,
    p_max_attempts: OTP_MAX_ATTEMPTS,
    p_resend_cooldown_seconds: OTP_RESEND_COOLDOWN_SECONDS,
    p_ip_address: ipAddress || null,
    p_device_id: deviceId || null,
    p_reuse_within_cooldown: false,
  });

  if (error) throw error;
  const row = data[0];

  const mintedNewOtp = row.out_action === "CREATED" || row.out_action === "REPLACED";

  return {
    ok: true,
    action: row.out_action, // CREATED | REPLACED | REUSED_FOR_PROVIDER_RETRY | IDEMPOTENT_REPLAY | COOLDOWN
    otpId: row.out_id,
    otp: mintedNewOtp ? otp : null, // plaintext, ONLY when freshly generated — never logged, discarded after send
    expiresAt: row.out_expires_at,
    otpRequestId: requestId,
    phoneHash,
  };
}

// sendOtp() — requestOtp() then, only if a NEW code was actually
// minted, dispatches it through sms-service (queue -> worker ->
// router -> provider, with failover). A duplicate client POST
// (same otpRequestId) or a resend inside the cooldown window returns
// the existing status WITHOUT sending a second SMS.
async function sendOtp({ userId, phone, purpose, otpRequestId, ipAddress, deviceId }) {
  const result = await requestOtp({ userId, phone, purpose, otpRequestId, ipAddress, deviceId });
  if (!result.ok) return result;

  if (result.action === "COOLDOWN") {
    return { ok: false, code: "COOLDOWN", message: "Please wait before requesting another code.", otpId: result.otpId };
  }

  if (result.action === "IDEMPOTENT_REPLAY" || result.action === "REUSED_FOR_PROVIDER_RETRY") {
    return { ok: true, action: result.action, otpId: result.otpId, expiresAt: result.expiresAt, resent: false };
  }

  const { templateId, message } = renderOtpMessage(purpose, result.otp);

  const sendResult = await smsService.sendSMS({
    userId, phone, message, templateId, messageType: "otp", purpose, otpId: result.otpId,
  });

  return {
    ok: true, action: result.action, otpId: result.otpId, expiresAt: result.expiresAt,
    resent: true, smsMessageId: sendResult.smsMessageId, smsStatus: sendResult.status,
  };
}

// verifyOtp() — atomic, single source of truth for "was this code
// right, for this user, for this purpose, right now" (section 6, 32).
async function verifyOtp({ userId, purpose, otp }) {
  if (!userId || !purpose || !/^\d{6}$/.test(otp || "")) {
    return { ok: false, code: "INVALID_INPUT", message: "Enter the 6-digit code." };
  }

  const otpHash = hashOtp(otp);
  const { data, error } = await supabase.rpc("verify_and_consume_otp", {
    p_user_id: userId, p_purpose: purpose, p_otp_hash: otpHash,
  });
  if (error) throw error;
  const row = data[0];

  switch (row.out_result) {
    case "VERIFIED":
      return { ok: true, otpId: row.out_otp_id };
    case "NOT_FOUND":
      return { ok: false, code: "NOT_FOUND", message: "Enter the code we sent you, or request a new one." };
    case "EXPIRED":
      return { ok: false, code: "EXPIRED", message: "Code expired. Please request a new one." };
    case "LOCKED":
      return { ok: false, code: "LOCKED", message: "Too many incorrect attempts. Please request a new code." };
    case "INCORRECT":
      return {
        ok: false, code: "INCORRECT", message: "Incorrect code. Please try again.",
        attemptsRemaining: Math.max(0, row.out_max_attempts - row.out_attempt_count),
      };
    default:
      return { ok: false, code: "ERROR", message: "Something went wrong. Please try again." };
  }
}

module.exports = {
  requestOtp,
  sendOtp,
  verifyOtp,
  generateOtp,
  hashOtp,
  constantTimeEqual,
  checkRateLimits,
  OTP_EXPIRY_SECONDS,
  OTP_MAX_ATTEMPTS,
  OTP_RESEND_COOLDOWN_SECONDS,
};
