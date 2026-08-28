// frozyla-webhook-routes.js (FEECENT side)
//
// Receives Frozyla's signed webhook. Same HMAC scheme as everywhere
// else in this integration (frozyla-hmac.js), same shared secret as
// FEECENT's outgoing requests (FEECENT_FROZYLA_HMAC_SECRET) — this is
// bidirectional: one secret signs FEECENT->Frozyla requests AND
// verifies Frozyla->FEECENT webhooks. Idempotency here is the
// frozyla_webhook_logs.event_id UNIQUE constraint (checked inside
// frozyla-webhook-handler.js), not a separate nonce table — a replayed
// webhook hits that unique violation and short-circuits before any
// finalize_bill_transaction call, so a nonce table would be redundant
// for this direction (unlike the Frozyla-side /credit endpoint, where
// nonces matter because idempotency there is keyed on
// reference/idempotency_key, not on a per-request event_id).
//
// Mount in FEECENT's index.js, BEFORE the global express.json() call
// touches this path — same raw-body requirement as
// frozyla-feecent-auth-middleware.js on the Frozyla side, same reason:
// signature verification needs the exact bytes, and a body stream can
// only be consumed once.
//
//   const frozylaWebhookRouter = require("./frozyla-webhook-routes");
//   app.use("/api/webhooks/frozyla", frozylaWebhookRouter);

const express = require("express");
const bodyParser = require("body-parser");
const router = express.Router();
const hmac = require("./frozyla-hmac");
const { processFrozylaWebhookEvent } = require("./frozyla-webhook-handler");

const HMAC_SECRET = process.env.FEECENT_FROZYLA_HMAC_SECRET;

if (!HMAC_SECRET) {
  console.warn(
    "[FROZYLA-WEBHOOK] FEECENT_FROZYLA_HMAC_SECRET not set — every " +
      "incoming Frozyla webhook will be rejected until this is configured.",
  );
}

const rawBodyJson = bodyParser.json({
  limit: "256kb",
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString("utf8");
  },
});

router.post("/", rawBodyJson, async (req, res) => {
  if (!HMAC_SECRET) {
    return res.status(503).json({ success: false, message: "Webhook receiver not configured" });
  }

  const timestamp = req.headers["x-frozyla-timestamp"];
  const nonce = req.headers["x-frozyla-nonce"];
  const signature = req.headers["x-frozyla-signature"];
  const rawBody = req.rawBody || "";

  const { valid, reason } = hmac.verify({
    secret: HMAC_SECRET,
    method: req.method,
    path: req.path,
    timestamp,
    nonce,
    rawBody,
    signature,
  });

  if (!valid) {
    console.warn(`[FROZYLA-WEBHOOK] Rejected: ${reason}`);
    // Generic 401 — never reveal which check failed.
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  try {
    const result = await processFrozylaWebhookEvent(req.body || {});
    // Always 200 once signature-verified and processed without an
    // exception — including "duplicate", "orphan", "already terminal",
    // "amount mismatch" cases. Those are all handled states, not
    // delivery failures; returning non-2xx for them would make
    // Frozyla's webhook sender retry something that doesn't need
    // retrying and won't resolve differently next time.
    res.json({ success: true, ...result });
  } catch (err) {
    if (err.code === "INVALID_PAYLOAD") {
      return res.status(400).json({ success: false, message: err.message });
    }
    console.error("[FROZYLA-WEBHOOK] Processing failed:", err);
    // 500 here IS a legitimate "please retry" signal — this is our own
    // internal error (DB call failed, etc.), not a payload problem.
    res.status(500).json({ success: false, message: "Internal error" });
  }
});

module.exports = router;