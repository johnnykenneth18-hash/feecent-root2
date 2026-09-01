// lib/sms/otp-routes.js
//
// Internal API (spec section 36). Mount in index.js:
//
//   const otpRoutes = require("../lib/sms/otp-routes");
//   app.use("/api/otp", authenticate, otpRoutes);
//
// Every route reads the acting user from req.user (set by
// authenticate()) — NEVER from a client-supplied userId in the body,
// per section 33 ("do not trust the client"). purpose/phone/otp are
// the only client-supplied fields that matter to a security decision,
// and every one of them is re-validated server-side regardless of
// what the client claims.

const express = require("express");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const otpService = require("./otp-service");
const smsService = require("./sms-service");
const { normalizeNigerianPhone } = require("./phone-utils");

const router = express.Router();

const VALID_PURPOSES = [
  "LOGIN", "REGISTRATION", "TRANSFER", "WITHDRAWAL", "PASSWORD_RESET",
  "CHANGE_PHONE", "CHANGE_EMAIL", "DEVICE_VERIFICATION", "PIN_CHANGE", "SECURITY_ACTION",
];

// HTTP-layer throttle — belt-and-suspenders alongside otp-service.js's
// own DB-backed per-user/per-phone checks (section 8). This one also
// catches non-OTP-DB-row-creating abuse, e.g. hammering /verify.
const requestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." },
  keyGenerator: (req) => `${req.ip}:${req.user?.id || "anon"}`,
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." },
  keyGenerator: (req) => `${req.ip}:${req.user?.id || "anon"}`,
});

// POST /api/otp/request  { phone, purpose, otp_request_id? }
router.post("/request", requestLimiter, async (req, res) => {
  try {
    const purpose = req.body.purpose;
    if (!VALID_PURPOSES.includes(purpose)) {
      return res.status(400).json({ error: `purpose must be one of ${VALID_PURPOSES.join(", ")}` });
    }

    const phone = normalizeNigerianPhone(req.body.phone);
    if (!phone) return res.status(400).json({ error: "Enter a valid Nigerian phone number" });

    let otpRequestId = req.body.otp_request_id;
    if (otpRequestId && !/^[0-9a-f-]{36}$/i.test(otpRequestId)) {
      return res.status(400).json({ error: "otp_request_id must be a UUID" });
    }
    otpRequestId = otpRequestId || crypto.randomUUID();

    const result = await otpService.sendOtp({
      userId: req.user.id,
      phone,
      purpose,
      otpRequestId,
      ipAddress: req.ip,
      deviceId: req.header("x-device-id") || null,
    });

    if (!result.ok) {
      const statusMap = { RATE_LIMITED: 429, COOLDOWN: 429 };
      return res.status(statusMap[result.code] || 400).json({ error: result.message, code: result.code });
    }

    // otp_request_id is returned so the client can retry the exact
    // same POST (network failure, etc.) and land on IDEMPOTENT_REPLAY
    // instead of a second SMS (section 4).
    res.json({ message: "Verification code sent", otp_request_id: otpRequestId, expires_at: result.expiresAt });
  } catch (error) {
    console.error("[OTP_ROUTES] request error:", error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// POST /api/otp/verify  { purpose, otp }
router.post("/verify", verifyLimiter, async (req, res) => {
  try {
    const purpose = req.body.purpose;
    if (!VALID_PURPOSES.includes(purpose)) {
      return res.status(400).json({ error: `purpose must be one of ${VALID_PURPOSES.join(", ")}` });
    }

    const result = await otpService.verifyOtp({ userId: req.user.id, purpose, otp: req.body.otp });

    if (!result.ok) {
      const statusMap = { INVALID_INPUT: 400, NOT_FOUND: 400, EXPIRED: 400, LOCKED: 429, INCORRECT: 400 };
      return res.status(statusMap[result.code] || 400).json({
        error: result.message, code: result.code, attempts_remaining: result.attemptsRemaining,
      });
    }

    // Verification alone does NOT authorize a financial action for
    // TRANSFER/WITHDRAWAL/PIN_CHANGE purposes — section 32 requires
    // that authorization step to be separate and atomic against the
    // actual transaction, which lives in the existing transfer
    // authorization flow (transfer_authorizations table /
    // preventConcurrentTransfer in auth.js), not here. This endpoint
    // only certifies "the code was correct"; the caller (e.g. the
    // transfer route) is responsible for treating otp_id as one-time
    // proof and not re-trusting a stale one.
    res.json({ verified: true, otp_id: result.otpId });
  } catch (error) {
    console.error("[OTP_ROUTES] verify error:", error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// GET /api/otp/status/:otpId — lets a client poll whether its SMS is
// still queued/sent/delivered without exposing the OTP value itself.
router.get("/sms/:smsMessageId/status", async (req, res) => {
  try {
    const status = await smsService.getStatus(req.params.smsMessageId);
    if (!status) return res.status(404).json({ error: "Not found" });
    res.json(status);
  } catch (error) {
    console.error("[OTP_ROUTES] status error:", error);
    res.status(500).json({ error: "Something went wrong." });
  }
});

module.exports = router;
