// lib/sms/phone-utils.js
//
// Same normalization behavior as onboarding-routes.js's
// normalizeNigerianPhone() (kept byte-for-byte compatible on purpose —
// see the note in INTEGRATION.md about optionally pointing that file
// at this one later). Centralized here so every SMS/OTP call site
// normalizes identically instead of five slightly-different regexes
// drifting apart over time.

const crypto = require("crypto");

function normalizeNigerianPhone(raw) {
  if (!raw || typeof raw !== "string") return null;
  let p = raw.trim().replace(/[\s-]/g, "");
  if (p.startsWith("+234")) {
    // already normalized
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

// One-way hash for storage/logging/indexing — never the raw number.
// Pepper is a server-side secret (separate from OTP_SECRET) so the
// hash can't be reproduced by anyone without the deployment's env.
function hashPhone(normalizedPhone) {
  const pepper = process.env.PHONE_HASH_PEPPER;
  if (!pepper) {
    throw new Error("PHONE_HASH_PEPPER is not configured");
  }
  return crypto
    .createHmac("sha256", pepper)
    .update(normalizedPhone)
    .digest("hex");
}

// For display/logs only — never full number, never in structured logs
// that flow to third parties without this masking already applied.
function maskPhone(normalizedPhone) {
  if (!normalizedPhone) return "";
  return normalizedPhone.replace(/^(\+234)(\d{2})\d{6}(\d{2})$/, "$1$2******$3");
}

module.exports = { normalizeNigerianPhone, hashPhone, maskPhone };
