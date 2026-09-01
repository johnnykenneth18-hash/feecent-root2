// lib/sms/sms-service.js
//
// SMSService — the ONLY entry point the rest of the app (and
// otp-service.js) uses to send an SMS. Everything else (which
// provider, retries, circuit breakers) is invisible from here on out;
// callers get back a queued-message id and, later, delivery status.
//
//   application code -> SMSService.sendSMS() -> background_jobs -> sms-worker.js -> SMSRouter -> provider adapter
//
// This sits alongside the existing NotificationService's
// EmailService/PushService as the SMS channel (spec section 39/1) —
// see INTEGRATION.md for the one-line wiring into notification-service.js.
//
// Message text is encrypted at rest in background_jobs.payload with
// AES-256-GCM (key: SMS_JOB_PAYLOAD_KEY) rather than stored as plain
// JSON text. Necessary because an OTP's rendered SMS text (which
// CONTAINS the plaintext OTP — that's the whole point, the user has to
// read it) has to survive from "enqueue" to "a worker invocation that
// may happen seconds later, and may need to retry" — see
// otp-service.js's file header for why job-payload persistence is what
// makes provider/job retries reuse the same code instead of minting a
// new one. Storing that text in cleartext would violate section 5/11's
// "never store OTP in plaintext" even though this is a working queue,
// not a log — so it's encrypted, and only decrypted transiently inside
// the worker process right before a send attempt (never logged either
// side of that).

const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const { normalizeNigerianPhone, hashPhone } = require("./phone-utils");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function getPayloadKey() {
  const keyHex = process.env.SMS_JOB_PAYLOAD_KEY; // 32-byte key, hex-encoded (64 hex chars)
  if (!keyHex || keyHex.length !== 64) {
    throw new Error("SMS_JOB_PAYLOAD_KEY must be a 64-char hex string (32 bytes) — see INTEGRATION.md");
  }
  return Buffer.from(keyHex, "hex");
}

function encryptMessage(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getPayloadKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { iv: iv.toString("base64"), tag: authTag.toString("base64"), data: encrypted.toString("base64") };
}

function decryptMessage({ iv, tag, data }) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", getPayloadKey(), Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(data, "base64")), decipher.final()]);
  return decrypted.toString("utf8");
}

// messageType -> which service_routing lane the router should use
// (section 26 — never route OTPs through a marketing-only provider).
const MESSAGE_TYPE_TO_SERVICE_CODE = {
  otp: "sms_otp",
  transactional: "sms_transactional",
  marketing: "sms_marketing",
};

// sendSMS() — queues the send; does NOT talk to a provider itself
// (section 19 — API returns immediately, sms-worker.js does the
// actual dispatch). Idempotent on the (userId, templateId, otpId)
// tuple for OTPs so a duplicate caller can't queue two jobs for the
// same OTP row; for non-OTP sends the caller may pass its own
// `idempotencyKey`.
async function sendSMS({ userId, phone, message, templateId, messageType = "transactional", purpose = null, otpId = null, idempotencyKey = null }) {
  const normalized = normalizeNigerianPhone(phone);
  if (!normalized) throw new Error("Invalid phone number");
  if (!MESSAGE_TYPE_TO_SERVICE_CODE[messageType]) throw new Error(`Unknown message type "${messageType}"`);

  const phoneHash = hashPhone(normalized);
  const key = idempotencyKey || (otpId ? `otp:${otpId}` : `sms:${crypto.randomUUID()}`);

  const encryptedMessage = encryptMessage(message);
  const encryptedPhone = encryptMessage(normalized); // the worker needs the real number to actually call the provider

  const { data, error } = await supabase.rpc("create_sms_send_job_atomic", {
    p_user_id: userId,
    p_otp_id: otpId,
    p_purpose: purpose,
    p_phone_hash: phoneHash,
    p_message_template_id: templateId,
    p_message_type: messageType,
    p_idempotency_key: key,
    p_job_payload: {
      service_code: MESSAGE_TYPE_TO_SERVICE_CODE[messageType],
      message_enc: encryptedMessage,
      phone_enc: encryptedPhone,
    },
  });

  if (error) throw error;
  const row = data[0];

  // Fire the just-created job immediately rather than letting it sit
  // until the next cron tick (see sms-worker.js's processOne — this is
  // the exact same waitUntil/fallback pattern onboarding-routes.js
  // already uses for virtual-account-worker.processOne). The cron
  // (sms-worker.cronHandler) stays as the safety net for anything this
  // doesn't get to finish — e.g. the function is torn down before
  // waitUntil resolves.
  try {
    const { waitUntil } = require("@vercel/functions");
    const smsWorker = require("./sms-worker"); // lazy require: sms-worker.js requires this file too
    waitUntil(smsWorker.processOne(row.out_job_id));
  } catch (waitUntilErr) {
    const smsWorker = require("./sms-worker");
    smsWorker.processOne(row.out_job_id).catch((e) => console.error("[SMS_SERVICE] processOne fallback failed:", e));
  }

  return { smsMessageId: row.out_sms_message_id, jobId: row.out_job_id, status: "queued" };
}

async function getStatus(smsMessageId) {
  const { data, error } = await supabase
    .from("sms_messages")
    .select("id, status, selected_provider, provider_message_id, created_at, sent_at, delivered_at, failed_at")
    .eq("id", smsMessageId)
    .maybeSingle();
  if (error) throw error;
  return data;
}

module.exports = {
  sendSMS,
  getStatus,
  encryptMessage,
  decryptMessage,
  MESSAGE_TYPE_TO_SERVICE_CODE,
};
