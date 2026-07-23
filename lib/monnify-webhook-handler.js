// monnify-webhook-handler.js
// POST /api/webhooks/monnify — Monnify's dedicated webhook URL.
//
// CRITICAL — same rule as paystack-webhook-handler.js's header: this
// endpoint runs INDEPENDENTLY of service_routing / manual override /
// ServiceRegistry priority. A user whose virtual account or transfer
// was created on Monnify keeps getting Monnify webhooks regardless of
// Monnify's current routing/override status for NEW requests.
// Flutterwave, Paystack, and Monnify each have their own permanently
// -mounted webhook URL and all three run simultaneously, all the time.
// Nothing here calls ServiceRegistry — it hardcodes "monnify" because
// that is exactly and only what this URL ever receives.
//
// Mount in index.js (standard JSON body is fine here — Monnify's
// signature scheme, unlike Paystack's, is computed from documented
// payload fields rather than the raw body, per verifyWebhookSignature()'s
// header note in monnify-service.js):
//   app.post("/api/webhooks/monnify", monnifyWebhookHandler.handleMonnifyWebhook);
//
// Dedupe/audit uses the same provider_webhook_logs table as Paystack's
// handler (013_multi_provider_webhooks_and_capabilities.sql).

const { createClient } = require("@supabase/supabase-js");
const monnifyService = require("./monnify-service");
const { finalizeVerifiedTransfer } = require("./transfer-finalization");
const { creditDeposit, alertNoMatchingAccount } = require("./deposit-credit-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Monnify echoes back the accountReference we set at creation
// (FEECENT-VA-<accountId>, same convention as Flutterwave's tx_ref —
// see virtual-account-worker.js) as eventData.product.reference on
// every deposit into a reserved account. Primary match strategy
// mirrors deposit-webhook-service.js's Flutterwave logic exactly.
async function findAccountForDeposit(verified) {
  const vaMatch = /^FEECENT-VA-([0-9a-f-]{36})$/i.exec(verified.tx_ref || "");
  if (!vaMatch) return null;
  const { data } = await supabase
    .from("accounts")
    .select("id, user_id, currency")
    .eq("id", vaMatch[1])
    .eq("provider", "monnify")
    .eq("creation_status", "ACTIVE")
    .single();
  return data || null;
}

async function handleMonnifyWebhook(req, res) {
  const signature = req.headers["monnify-signature"];
  const payload = req.body;

  // CONFIRM this raw-body/JSON-string distinction against your actual
  // Monnify dashboard callback docs before relying on it in
  // production — Monnify's documented signing input has varied across
  // API versions; monnify-service.js's verifyWebhookSignature() hashes
  // whatever string it's given.
  if (!payload || !monnifyService.verifyWebhookSignature(JSON.stringify(payload), signature)) {
    console.warn("[MONNIFY-WEBHOOK] Rejected: invalid or missing signature");
    return res.status(401).json({ error: "Invalid signature" });
  }

  const event = payload.eventType;
  const data = payload.eventData;
  if (!event || !data) {
    console.warn("[MONNIFY-WEBHOOK] Rejected: malformed payload");
    return res.status(400).json({ error: "Malformed payload" });
  }

  const webhookId = String(data.transactionReference || data.reference || `${event}-${Date.now()}`);

  const { data: logRow, error: logErr } = await supabase
    .from("provider_webhook_logs")
    .insert({
      provider_code: "monnify",
      webhook_id: webhookId,
      event_type: event,
      reference: data.transactionReference || data.reference || null,
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
        .eq("provider_code", "monnify")
        .eq("webhook_id", webhookId)
        .single();
      if (existing?.processed) {
        console.log(`[MONNIFY-WEBHOOK] Duplicate ${webhookId}, already processed — ack only`);
        return res.status(200).json({ status: "duplicate" });
      }
      webhookLogId = existing?.id || null;
    } else {
      console.error("[MONNIFY-WEBHOOK] Failed to write webhook log:", logErr);
      return res.status(200).json({ status: "log_error" });
    }
  }

  const updateLog = async (fields) => {
    if (!webhookLogId) return;
    await supabase.from("provider_webhook_logs").update(fields).eq("id", webhookLogId);
  };

  try {
    // ---- Deposits into a reserved (virtual) account ----
    if (event === "SUCCESSFUL_TRANSACTION") {
      const verification = await monnifyService.verifyTransaction(data.transactionReference);
      if (!verification.success) {
        await updateLog({ status: "verification_failed", error_message: verification.error });
        return res.status(200).json({ status: "queued_for_retry" });
      }
      const v = verification.data;
      if (v.status !== "successful") {
        await updateLog({ status: "rejected", processed: true, processed_at: new Date().toISOString() });
        return res.status(200).json({ status: "not_successful" });
      }

      const account = await findAccountForDeposit(v);
      if (!account) {
        await alertNoMatchingAccount({ providerCode: "monnify", verified: v });
        await updateLog({ status: "no_matching_account", processed: true, processed_at: new Date().toISOString() });
        return res.status(200).json({ status: "requires_manual_review" });
      }

      const credit = await creditDeposit({ account, verified: v, providerCode: "monnify" });
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

    // ---- Disbursements (outbound transfers) ----
    // CONFIRM this event name against your Monnify dashboard — Monnify's
    // disbursement callback event naming is less consistently documented
    // than its collections (SUCCESSFUL_TRANSACTION) event.
    if (event === "DISBURSEMENT_TRANSACTION" || event === "SUCCESSFUL_DISBURSEMENT" || event === "FAILED_DISBURSEMENT") {
      const statusCheck = await monnifyService.getTransferStatus(data.reference);
      if (!statusCheck.success) {
        await updateLog({ status: "verification_failed", error_message: statusCheck.error });
        return res.status(200).json({ status: "queued_for_retry" });
      }
      try {
        await finalizeVerifiedTransfer({
          reference: data.reference,
          verified: statusCheck.data,
          providerCode: "monnify",
          webhookLogUpdate: updateLog,
        });
      } catch (finalizeErr) {
        console.error("[MONNIFY-WEBHOOK] Transfer finalize failed:", finalizeErr);
      }
      return res.status(200).json({ status: "ok" });
    }

    await updateLog({ status: "ignored_event_type", processed: true, processed_at: new Date().toISOString() });
    return res.status(200).json({ status: "ignored" });
  } catch (err) {
    console.error("[MONNIFY-WEBHOOK] Processing failed:", err);
    await updateLog({ status: "failed", error_message: err.message });
    return res.status(200).json({ status: "queued_for_reconciliation" });
  }
}

module.exports = { handleMonnifyWebhook };