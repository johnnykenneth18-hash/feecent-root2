// lib/sms/sms-webhook-routes.js
//
// Delivery-receipt webhooks (section 18). Mount in index.js:
//
//   const smsWebhookRoutes = require("../lib/sms/sms-webhook-routes");
//   app.use("/api/webhooks/sms", smsWebhookRoutes);
//
// Reuses provider_webhook_logs (already exists — see
// provider-webhook-logs usage for Flutterwave/Paystack/Monnify) for
// idempotency: UNIQUE(provider_code, webhook_id) means a redelivered
// webhook is a no-op insert conflict, not a double-processed update
// (section 18's "must not update the same SMS multiple times
// incorrectly").
//
// CONFIRM each provider's actual signature/auth mechanism against
// current docs before trusting these in production — verifySignature()
// below is written defensively (rejects if the env var isn't set) but
// the exact header name/algorithm per provider needs confirming
// against your live account's webhook settings.

const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const router = express.Router();

router.use(express.json({ limit: "256kb" }));

// Maps each provider's own delivery-status vocabulary onto ours.
// CONFIRM these against real webhook payloads from each provider —
// values below reflect commonly-documented status strings, not a
// verified live sample.
const STATUS_MAPS = {
  termii: { DND: "failed", Sent: "sent", Delivered: "delivered", Expired: "failed", Rejected: "failed" },
  africastalking: { Success: "delivered", Sent: "sent", Failed: "failed", Rejected: "failed" },
  bulksmsnigeria: { delivered: "delivered", sent: "sent", failed: "failed" },
  arkesel: { delivered: "delivered", sent: "sent", failed: "failed" },
};

function mapStatus(providerCode, rawStatus) {
  return STATUS_MAPS[providerCode]?.[rawStatus] || "unknown";
}

// CONFIRM: replace with each provider's actual signature scheme once
// confirmed — this generic HMAC check covers providers that sign with
// a shared secret + SHA256 over the raw body, which is common but not
// universal. If a provider instead uses IP allowlisting only, add that
// check here explicitly rather than skipping verification.
function verifySignature(providerCode, req) {
  const secretEnvVar = `${providerCode.toUpperCase()}_WEBHOOK_SECRET`;
  const secret = process.env[secretEnvVar];
  if (!secret) {
    console.warn(`[SMS_WEBHOOK] ${secretEnvVar} not set — rejecting webhook (fail closed)`);
    return false;
  }
  const signatureHeader = req.header("x-webhook-signature") || req.header("x-signature");
  if (!signatureHeader) return false;

  const expected = crypto.createHmac("sha256", secret).update(JSON.stringify(req.body)).digest("hex");
  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function handleDeliveryWebhook(providerCode, req, res) {
  if (!verifySignature(providerCode, req)) {
    return res.status(401).json({ error: "Invalid webhook signature" });
  }

  // Every provider payload should carry SOME unique event/message
  // identifier — required for idempotent processing. If a provider
  // genuinely sends none, fall back to a hash of the raw body (still
  // catches exact redeliveries, though not a provider-issued retry
  // with a fresh id).
  const webhookId =
    req.body.message_id || req.body.messageId || req.body.id ||
    crypto.createHash("sha256").update(JSON.stringify(req.body)).digest("hex");

  const { error: logError } = await supabase.from("provider_webhook_logs").insert({
    provider_code: providerCode,
    webhook_id: String(webhookId),
    event_type: req.body.status || req.body.event || "delivery_report",
    reference: req.body.message_id || req.body.messageId || null,
    payload: req.body,
    ip_address: req.ip,
    processed: false,
  });

  if (logError) {
    // Unique violation on (provider_code, webhook_id) => duplicate delivery, already processed. Ack and stop.
    if (logError.code === "23505") return res.status(200).json({ ok: true, duplicate: true });
    console.error(`[SMS_WEBHOOK] ${providerCode} log insert failed:`, logError);
    return res.status(500).json({ error: "Failed to record webhook" });
  }

  const providerMessageId = req.body.message_id || req.body.messageId || req.body.id;
  const rawStatus = req.body.status || req.body.event;
  const mapped = mapStatus(providerCode, rawStatus);

  if (providerMessageId) {
    const { data: attempt } = await supabase
      .from("sms_delivery_attempts")
      .select("sms_message_id")
      .eq("provider", providerCode)
      .eq("provider_message_id", providerMessageId)
      .maybeSingle();

    if (attempt) {
      // Never downgrade a message we already know was delivered, and
      // never let a webhook mark something 'delivered' if our own send
      // attempt recorded a definite failure (section 18 — API_ACCEPTED
      // is not DELIVERED, and the reverse confusion is just as wrong).
      const { data: current } = await supabase
        .from("sms_messages")
        .select("status")
        .eq("id", attempt.sms_message_id)
        .maybeSingle();

      if (current && current.status !== "delivered") {
        const update = { status: mapped };
        if (mapped === "delivered") update.delivered_at = new Date().toISOString();
        if (mapped === "failed") update.failed_at = new Date().toISOString();
        await supabase.from("sms_messages").update(update).eq("id", attempt.sms_message_id);
      }
    }
  }

  await supabase
    .from("provider_webhook_logs")
    .update({ processed: true, processed_at: new Date().toISOString() })
    .eq("provider_code", providerCode)
    .eq("webhook_id", String(webhookId));

  res.status(200).json({ ok: true });
}

router.post("/termii", (req, res) => handleDeliveryWebhook("termii", req, res));
router.post("/africastalking", (req, res) => handleDeliveryWebhook("africastalking", req, res));
router.post("/bulksmsnigeria", (req, res) => handleDeliveryWebhook("bulksmsnigeria", req, res));
router.post("/arkesel", (req, res) => handleDeliveryWebhook("arkesel", req, res));

module.exports = router;
