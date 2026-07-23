// paystack-webhook-handler.js
// POST /api/webhooks/paystack — Paystack's dedicated webhook URL.
//
// CRITICAL — read before touching this file: this endpoint runs
// INDEPENDENTLY of service_routing / manual override / ServiceRegistry
// priority. Those control which provider gets picked for a NEW virtual
// account or transfer request going forward — they say nothing about
// which provider a given EXISTING user's account or in-flight transfer
// already belongs to. A user whose virtual account was created on
// Paystack last month still gets Paystack deposit webhooks today even
// if Paystack is no longer priority 1 (or has been manually overridden
// off) for new virtual account creation.
//
// Flutterwave (deposit-webhook-service.js), Paystack (this file), and
// Monnify (monnify-webhook-handler.js) each have their own permanently
// -mounted webhook URL, and all three run all the time, simultaneously
// — one provider's webhook traffic is never gated by another's routing
// state, and none of them go through ServiceRegistry.resolve() /
// getProvider() for that reason. This file hardcodes "paystack"
// throughout because that is exactly and only what this URL ever
// receives.
//
// Mount requirement: Paystack signs the RAW request body (HMAC-SHA512),
// which Express's default express.json() does not retain. Mount this
// route with a raw body parser BEFORE any global json() middleware
// reaches it, e.g. in index.js:
//
//   app.post("/api/webhooks/paystack",
//     express.raw({ type: "application/json" }),
//     (req, res) => {
//       req.rawBody = req.body; // Buffer — needed for signature check
//       req.body = JSON.parse(req.body.toString("utf8"));
//       paystackWebhookHandler.handlePaystackWebhook(req, res);
//     });
//
// Dedupe/audit uses provider_webhook_logs (013_multi_provider_webhooks_and_capabilities.sql)
// — a shared table across Paystack/Monnify, keyed by (provider_code, webhook_id),
// mirroring the UNIQUE-constraint dedupe trick flutterwave_webhook_logs
// already uses for Flutterwave.

const { createClient } = require("@supabase/supabase-js");
const paystackService = require("./paystack-service");
const { finalizeVerifiedTransfer } = require("./transfer-finalization");
const { creditDeposit, alertNoMatchingAccount } = require("./deposit-credit-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Paystack DVA deposits don't echo back a caller-supplied reference
// (unlike Flutterwave/Monnify's tx_ref/accountReference convention) —
// the receiving account number is the only reliable match key Paystack
// gives us. See paystack-service.js's verifyTransaction() for where
// receiver_account_number comes from.
async function findAccountForDeposit(verified) {
  if (!verified.receiver_account_number) return null;
  const { data } = await supabase
    .from("accounts")
    .select("id, user_id, currency")
    .eq("account_number", verified.receiver_account_number)
    .eq("provider", "paystack")
    .eq("creation_status", "ACTIVE")
    .single();
  return data || null;
}

async function handlePaystackWebhook(req, res) {
  const signature = req.headers["x-paystack-signature"];
  const rawBody = req.rawBody;
  const payload = req.body;

  if (!rawBody || !paystackService.verifyWebhookSignature(rawBody, signature)) {
    console.warn("[PAYSTACK-WEBHOOK] Rejected: invalid or missing signature");
    return res.status(401).json({ error: "Invalid signature" });
  }

  const event = payload && payload.event;
  const data = payload && payload.data;
  if (!event || !data) {
    console.warn("[PAYSTACK-WEBHOOK] Rejected: malformed payload");
    return res.status(400).json({ error: "Malformed payload" });
  }

  // Paystack doesn't send one universal numeric event id the way
  // Flutterwave does — data.id (charges) or data.reference (transfers)
  // is the closest stable per-event identifier.
  const webhookId = String(data.id || data.reference || `${event}-${Date.now()}`);

  const { data: logRow, error: logErr } = await supabase
    .from("provider_webhook_logs")
    .insert({
      provider_code: "paystack",
      webhook_id: webhookId,
      event_type: event,
      reference: data.reference || null,
      status: "received",
      payload,
      signature,
      ip_address: req.ip,
    })
    .select()
    .single();

  let webhookLogId = logRow?.id || null;
  if (logErr) {
    if (logErr.code === "23505") {
      const { data: existing } = await supabase
        .from("provider_webhook_logs")
        .select("id, processed")
        .eq("provider_code", "paystack")
        .eq("webhook_id", webhookId)
        .single();
      if (existing?.processed) {
        console.log(`[PAYSTACK-WEBHOOK] Duplicate ${webhookId}, already processed — ack only`);
        return res.status(200).json({ status: "duplicate" });
      }
      webhookLogId = existing?.id || null;
    } else {
      console.error("[PAYSTACK-WEBHOOK] Failed to write webhook log:", logErr);
      return res.status(200).json({ status: "log_error" });
    }
  }

  const updateLog = async (fields) => {
    if (!webhookLogId) return;
    await supabase.from("provider_webhook_logs").update(fields).eq("id", webhookLogId);
  };

  try {
    // ---- Deposits ----
    if (event === "charge.success") {
      const verification = await paystackService.verifyTransaction(data.reference);
      if (!verification.success) {
        await updateLog({ status: "verification_failed", error_message: verification.error });
        return res.status(200).json({ status: "queued_for_retry" });
      }
      const v = verification.data;
      if (v.status !== "success") {
        await updateLog({ status: "rejected", processed: true, processed_at: new Date().toISOString() });
        return res.status(200).json({ status: "not_successful" });
      }

      const account = await findAccountForDeposit(v);
      if (!account) {
        await alertNoMatchingAccount({ providerCode: "paystack", verified: { ...v, tx_ref: v.reference } });
        await updateLog({ status: "no_matching_account", processed: true, processed_at: new Date().toISOString() });
        return res.status(200).json({ status: "requires_manual_review" });
      }

      const credit = await creditDeposit({
        account,
        verified: { ...v, tx_ref: v.reference },
        providerCode: "paystack",
      });
      if (!credit.success) {
        await updateLog({ status: "failed", error_message: credit.error });
        return res.status(200).json({ status: "queued_for_retry" });
      }
      await updateLog({
        status: credit.duplicate ? "duplicate" : "completed",
        processed: true,
        processed_at: new Date().toISOString(),
      });
      return res.status(200).json({ status: "ok" });
    }

    // ---- Transfers ----
    if (event === "transfer.success" || event === "transfer.failed" || event === "transfer.reversed") {
      const statusCheck = await paystackService.getTransferStatus(data.transfer_code || data.reference);
      if (!statusCheck.success) {
        await updateLog({ status: "verification_failed", error_message: statusCheck.error });
        return res.status(200).json({ status: "queued_for_retry" });
      }
      try {
        await finalizeVerifiedTransfer({
          reference: data.reference,
          verified: statusCheck.data,
          providerCode: "paystack",
          webhookLogUpdate: updateLog,
        });
      } catch (finalizeErr) {
        console.error("[PAYSTACK-WEBHOOK] Transfer finalize failed:", finalizeErr);
        // Still 200 — the reconciliation sweep in transfer-webhook-handler.js
        // covers stuck transfers regardless of which provider sent them.
      }
      return res.status(200).json({ status: "ok" });
    }

    await updateLog({ status: "ignored_event_type", processed: true, processed_at: new Date().toISOString() });
    return res.status(200).json({ status: "ignored" });
  } catch (err) {
    console.error("[PAYSTACK-WEBHOOK] Processing failed:", err);
    await updateLog({ status: "failed", error_message: err.message });
    return res.status(200).json({ status: "queued_for_reconciliation" });
  }
}

module.exports = { handlePaystackWebhook };