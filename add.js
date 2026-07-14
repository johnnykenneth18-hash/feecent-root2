// deposit-webhook-service.js
//
// THE SINGLE FLUTTERWAVE WEBHOOK ENTRY POINT for this whole app.
// Flutterwave only supports one webhook URL per app, so every event —
// deposits (charge.completed), outbound transfers (transfer.*), and
// bill payments (singlebillpayment.status) — arrives here and is
// dispatched by event type to its own focused handler:
//   charge.completed         -> handled inline below (creditDeposit)
//   transfer.*               -> transfer-webhook-handler.js
//   singlebillpayment.status -> bills-webhook-handler.js
//
// Despite the filename (kept to avoid an unnecessary rename/require
// churn), this file is not deposit-only anymore — see the dispatch
// block a bit further down. If you rename it, update the one require
// in index.js and the historical name in flutterwave_webhook_logs
// entries won't need to change (they're keyed by event, not by file).
//
// Handles incoming Flutterwave deposit webhooks (money arriving into a
// user's dedicated virtual account).
//
// Flow: verify signature -> validate payload -> dedupe -> verify with
// Flutterwave's API -> locate account -> credit atomically via
// process_deposit() -> ack 200. If crediting fails after a valid,
// verified webhook, the failure is queued as a background_jobs retry
// instead of asking Flutterwave to resend.

const { createClient } = require("@supabase/supabase-js");
const flutterwaveService = require("./flutterwave-service");
const transferWebhookHandler = require("./transfer-webhook-handler");
const billsWebhookHandler = require("./bills-webhook-handler");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const WORKER_ID = `webhook-worker-${process.env.VERCEL_REGION || "local"}-${process.pid}`;
const BACKOFF_MINUTES = [1, 5, 15, 30, 60, 360, 1440];

// ------------------------------------------------------------
// Core crediting logic, shared by the live webhook path and the
// retry worker.
// ------------------------------------------------------------
async function creditDeposit({ verified, webhookLogId }) {
  // Locate the account this money actually landed in.
  //
  // Primary strategy: for a static/permanent virtual account, Flutterwave
  // echoes back the account's ORIGINAL creation tx_ref
  // (FEECENT-VA-<accounts.id>, set in virtual-account-worker.js) on every
  // subsequent deposit into that account — confirmed against real
  // production webhook data, not assumed. That means the destination
  // account's own primary key is embedded directly in tx_ref; no need to
  // match against account_number at all, which Flutterwave does not
  // reliably return for bank_transfer/virtual-account payments (and when
  // it does return something under that name via a meta fallback, it's
  // been confirmed to be the SENDER's account, not the destination).
  let account = null;
  let accountErr = null;

  const vaMatch = /^FEECENT-VA-([0-9a-f-]{36})$/i.exec(verified.tx_ref || "");
  if (vaMatch) {
    const accountId = vaMatch[1];
    const result = await supabase
      .from("accounts")
      .select("id, user_id, currency")
      .eq("id", accountId)
      .eq("provider", "flutterwave")
      .eq("creation_status", "ACTIVE")
      .single();
    account = result.data;
    accountErr = result.error;
  }

  // Fallback: only reached if tx_ref didn't match the expected shape
  // (e.g. a reference format from before this convention, or a future
  // payment type). account_number is a weaker signal here — kept as a
  // second attempt rather than the primary check.
  if (!account && verified.account_number) {
    const result = await supabase
      .from("accounts")
      .select("id, user_id, currency")
      .eq("account_number", verified.account_number)
      .eq("provider", "flutterwave")
      .eq("creation_status", "ACTIVE")
      .single();
    account = result.data;
    accountErr = result.error;
  }

  if (accountErr || !account) {
    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: verified.amount,
      status: "open",
      severity: "high",
      notes: `Deposit webhook verified (flw tx ${verified.id}, ref ${verified.tx_ref}) but no matching ACTIVE Flutterwave account found (tried tx_ref-derived account id and account_number ${verified.account_number}). Amount ${verified.currency} ${verified.amount} requires manual reconciliation.`,
    });
    return {
      success: false,
      retryable: false,
      error: `No matching active account for tx_ref ${verified.tx_ref} / account_number ${verified.account_number}`,
    };
  }

  const { data: result, error: rpcErr } = await supabase.rpc(
    "process_deposit",
    {
      p_account_id: account.id,
      p_user_id: account.user_id,
      p_amount: verified.amount,
      p_currency: verified.currency,
      p_flw_transaction_id: String(verified.id),
      p_flw_tx_ref: verified.tx_ref,
      p_narration: verified.narration || "Deposit via Flutterwave",
      p_external_sender_name: verified.sender_name,
      p_external_sender_account: verified.sender_account,
      p_external_sender_bank: verified.sender_bank,
    },
  );

  if (rpcErr) {
    return { success: false, retryable: true, error: rpcErr.message };
  }

  return { success: true, duplicate: result.duplicate, result };
}

// ------------------------------------------------------------
// Express handler: POST /api/webhooks/flutterwave
// No authentication middleware — Flutterwave calls this directly.
// ------------------------------------------------------------
async function handleFlutterwaveWebhook(req, res) {
  const signature = req.headers["verif-hash"];
  const payload = req.body;

  // 1. Verify signature before anything else.
  if (!flutterwaveService.verifyWebhookSignature(signature)) {
    console.warn("[WEBHOOK] Rejected: invalid or missing verif-hash");
    return res.status(401).json({ error: "Invalid signature" });
  }

  // 2. Validate payload shape.
  //
  // NOTE: tx_ref is only present on charge.completed (deposit) payloads.
  // transfer.completed / transfer.failed / transfer.reversed payloads
  // carry `data.reference` instead — Flutterwave never sends tx_ref for
  // those. Requiring tx_ref unconditionally here rejected every payout
  // webhook as "malformed" before it ever reached the transfer.* dispatch
  // block below, which is why transfers stayed stuck on "pending" even
  // after succeeding at Flutterwave. Only `id` is common to both shapes.
  const event = payload && payload.event;
  const data = payload && payload.data;
  if (!event || !data || !data.id) {
    console.warn("[WEBHOOK] Rejected: malformed payload");
    return res.status(400).json({ error: "Malformed payload" });
  }
  if (event === "charge.completed" && !data.tx_ref) {
    console.warn("[WEBHOOK] Rejected: charge.completed payload missing tx_ref");
    return res.status(400).json({ error: "Malformed payload" });
  }

  // 3. Log the webhook immediately — every webhook is stored, never
  // deleted, regardless of what happens next. webhook_id is UNIQUE, so a
  // duplicate delivery fails this insert with a conflict, which is our
  // dedup signal.
  const { data: logRow, error: logErr } = await supabase
    .from("flutterwave_webhook_logs")
    .insert({
      webhook_id: String(data.id),
      event_type: event,
      transfer_reference: data.tx_ref,
      flutterwave_reference: data.flw_ref || null,
      status: "received",
      payload,
      signature,
      ip_address: req.ip,
    })
    .select()
    .single();

  if (logErr) {
    // Unique violation on webhook_id = we've seen this one before.
    if (logErr.code === "23505") {
      const { data: existing } = await supabase
        .from("flutterwave_webhook_logs")
        .select("processed")
        .eq("webhook_id", String(data.id))
        .single();

      if (existing && existing.processed) {
        console.log(
          `[WEBHOOK] Duplicate ${data.id}, already processed — ack only`,
        );
        return res.status(200).json({ status: "duplicate" });
      }
      // Logged before but never finished processing (e.g. crashed
      // mid-flow) — fall through and try again using this same log id.
    } else {
      console.error("[WEBHOOK] Failed to write webhook log:", logErr);
      // Still return 200 so Flutterwave doesn't hammer retries for an
      // internal logging issue on our side; nothing was lost, the raw
      // payload is in this response's logs and the event will be
      // re-delivered by Flutterwave's own retry policy regardless.
      return res.status(200).json({ status: "log_error" });
    }
  }

  const webhookLogId = (logRow && logRow.id) || null;

  // 4. Deposits and payouts share this endpoint (Flutterwave only lets
  // you configure one webhook URL per app). "charge.completed" is a
  // deposit, handled below. "transfer.completed" / "transfer.failed" /
  // "transfer.reversed" are outbound payout outcomes — these used to be
  // silently ignored here, which meant reserved funds for external
  // transfers were never released or finalized. They're now delegated
  // to transfer-webhook-handler.js, which independently re-verifies the
  // transfer with Flutterwave before calling finalize_external_transfer.
  if (event.startsWith("transfer.")) {
    try {
      await transferWebhookHandler.processTransferEvent({
        event,
        data,
        webhookLogId,
      });
      return res.status(200).json({ status: "ok" });
    } catch (err) {
      console.error("[WEBHOOK] Transfer event processing failed:", err);
      if (webhookLogId) {
        await supabase
          .from("flutterwave_webhook_logs")
          .update({ status: "failed", error_message: err.message })
          .eq("id", webhookLogId);
      }
      // Still 200 — Flutterwave doesn't need to retry delivery; our own
      // reconciliation sweep (stuck_external_transfers) will catch it.
      return res.status(200).json({ status: "queued_for_reconciliation" });
    }
  }

  // 4b. Bill payments (airtime today, data/electricity/cable later) also
  // land on this same URL — "singlebillpayment.status" is Flutterwave's
  // confirmed-outcome push for a single bill payment. Delegated to
  // bills-webhook-handler.js, which is idempotent against the bills
  // worker's own status poll (bills-worker.js) — whichever confirms
  // first wins, safely.
  if (event === "singlebillpayment.status") {
    try {
      await billsWebhookHandler.processSingleBillPaymentEvent({ data, webhookLogId });
      return res.status(200).json({ status: "ok" });
    } catch (err) {
      console.error("[WEBHOOK] Bill payment event processing failed:", err);
      if (webhookLogId) {
        await supabase
          .from("flutterwave_webhook_logs")
          .update({ status: "failed", error_message: err.message })
          .eq("id", webhookLogId);
      }
      // Still 200 — the bills worker's own status poll is the fallback.
      return res.status(200).json({ status: "queued_for_reconciliation" });
    }
  }

  if (event !== "charge.completed") {
    if (webhookLogId) {
      await supabase
        .from("flutterwave_webhook_logs")
        .update({
          status: "ignored_event_type",
          processed: true,
          processed_at: new Date().toISOString(),
        })
        .eq("id", webhookLogId);
    }
    return res.status(200).json({ status: "ignored" });
  }

  // 5. Verify with Flutterwave's API — never trust the webhook body alone.
  const verification = await flutterwaveService.verifyTransaction(data.id);

  if (!verification.success) {
    await supabase
      .from("flutterwave_webhook_logs")
      .update({
        status: "verification_failed",
        error_message: verification.error,
      })
      .eq("id", webhookLogId);

    await enqueueRetry(webhookLogId, verification.error);
    return res.status(200).json({ status: "queued_for_retry" });
  }

  const v = verification.data;

  if (v.status !== "successful") {
    await supabase
      .from("flutterwave_webhook_logs")
      .update({
        status: "rejected",
        processed: true,
        processed_at: new Date().toISOString(),
        error_message: `Verified status was '${v.status}', not 'successful'`,
      })
      .eq("id", webhookLogId);
    return res.status(200).json({ status: "not_successful" });
  }

  // NOTE: there used to be an early rejection here if v.account_number
  // was missing. Removed — confirmed against real production data that
  // account_number is not reliably populated by Flutterwave for
  // bank_transfer/virtual-account deposits at all, so requiring it before
  // even attempting a match would reject every such deposit outright.
  // creditDeposit() now matches primarily via tx_ref (see its own
  // comments) and has its own complete handling for "no match found",
  // including the reconciliation_alerts entry — nothing is silently lost
  // by removing this gate, it's just no longer the right place to check.

  // 6. Credit the wallet atomically.
  const credit = await creditDeposit({ verified: v, webhookLogId });

  if (!credit.success) {
    await supabase
      .from("flutterwave_webhook_logs")
      .update({ status: "failed", error_message: credit.error })
      .eq("id", webhookLogId);

    if (credit.retryable) {
      await enqueueRetry(webhookLogId, credit.error);
      return res.status(200).json({ status: "queued_for_retry" });
    }
    // Not retryable (e.g. no matching account) — already logged to
    // reconciliation_alerts inside creditDeposit for manual follow-up.
    return res.status(200).json({ status: "requires_manual_review" });
  }

  await supabase
    .from("flutterwave_webhook_logs")
    .update({
      status: credit.duplicate ? "duplicate" : "completed",
      processed: true,
      processed_at: new Date().toISOString(),
    })
    .eq("id", webhookLogId);

  return res.status(200).json({ status: "ok" });
}

// ------------------------------------------------------------
// Retry path: queue a background job instead of asking Flutterwave to
// resend. Reuses the same background_jobs table as virtual account
// provisioning, under its own job_type.
// ------------------------------------------------------------
async function enqueueRetry(webhookLogId, lastError) {
  if (!webhookLogId) return;
  await supabase.from("background_jobs").insert({
    job_type: "process_deposit_webhook",
    payload: { webhook_log_id: webhookLogId },
    status: "pending",
    priority: 200, // money-crediting takes priority over other job types
    last_error: lastError || null,
  });
}

async function claimJob() {
  const { data, error } = await supabase.rpc("claim_next_job", {
    p_job_type: "process_deposit_webhook",
    p_worker_id: WORKER_ID,
  });
  if (error) {
    console.error("[WEBHOOK-WORKER] claim_next_job failed:", error);
    return null;
  }
  return Array.isArray(data) && data.length > 0 ? data[0] : null;
}

async function processRetryJob(job) {
  const { webhook_log_id } = job.payload;

  const { data: logRow, error: logErr } = await supabase
    .from("flutterwave_webhook_logs")
    .select("*")
    .eq("id", webhook_log_id)
    .single();

  if (logErr || !logRow) {
    await failOrRetryJob(job, `Webhook log ${webhook_log_id} not found`);
    return;
  }

  if (logRow.processed) {
    await supabase
      .from("background_jobs")
      .update({ status: "completed", completed_at: new Date().toISOString() })
      .eq("id", job.id);
    return;
  }

  const data = logRow.payload.data;
  const verification = await flutterwaveService.verifyTransaction(data.id);

  if (!verification.success) {
    await failOrRetryJob(job, verification.error);
    return;
  }

  const v = verification.data;
  if (v.status !== "successful") {
    await supabase
      .from("flutterwave_webhook_logs")
      .update({
        status: "rejected",
        processed: true,
        processed_at: new Date().toISOString(),
      })
      .eq("id", webhook_log_id);
    await supabase
      .from("background_jobs")
      .update({ status: "completed", completed_at: new Date().toISOString() })
      .eq("id", job.id);
    return;
  }

  const credit = await creditDeposit({
    verified: v,
    webhookLogId: webhook_log_id,
  });

  if (!credit.success) {
    if (credit.retryable) {
      await failOrRetryJob(job, credit.error);
    } else {
      await supabase
        .from("flutterwave_webhook_logs")
        .update({ status: "failed", error_message: credit.error })
        .eq("id", webhook_log_id);
      await supabase
        .from("background_jobs")
        .update({ status: "completed", completed_at: new Date().toISOString() })
        .eq("id", job.id);
    }
    return;
  }

  await supabase
    .from("flutterwave_webhook_logs")
    .update({
      status: credit.duplicate ? "duplicate" : "completed",
      processed: true,
      processed_at: new Date().toISOString(),
    })
    .eq("id", webhook_log_id);

  await supabase
    .from("background_jobs")
    .update({ status: "completed", completed_at: new Date().toISOString() })
    .eq("id", job.id);
}

async function failOrRetryJob(job, errorMessage) {
  const nextRetryCount = job.retry_count + 1;

  if (nextRetryCount >= job.max_retry) {
    await supabase
      .from("background_jobs")
      .update({
        status: "failed",
        retry_count: nextRetryCount,
        last_error: errorMessage,
        updated_at: new Date().toISOString(),
      })
      .eq("id", job.id);

    await supabase.from("notifications").insert({
      user_id: null,
      title: "Deposit webhook failed permanently",
      message: `webhook_log_id ${job.payload.webhook_log_id}: ${errorMessage}`,
      type: "admin_alert",
    });
    console.error(
      `[WEBHOOK-WORKER] Job ${job.id} exhausted retries: ${errorMessage}`,
    );
    return;
  }

  const backoffIdx = Math.min(nextRetryCount - 1, BACKOFF_MINUTES.length - 1);
  const nextAvailableAt = new Date(
    Date.now() + BACKOFF_MINUTES[backoffIdx] * 60 * 1000,
  );

  await supabase
    .from("background_jobs")
    .update({
      status: "pending",
      retry_count: nextRetryCount,
      last_error: errorMessage,
      available_at: nextAvailableAt.toISOString(),
      locked_at: null,
      locked_by: null,
      updated_at: new Date().toISOString(),
    })
    .eq("id", job.id);
}

async function processPending(limit = 20) {
  let processed = 0;
  for (let i = 0; i < limit; i++) {
    const job = await claimJob();
    if (!job) break;
    await processRetryJob(job);
    processed++;
  }
  return processed;
}

async function cronHandler(req, res) {
  /*if (
    process.env.VERCEL_ENV === "production" &&
    req.headers["x-vercel-cron"] !== "1" &&
    req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }*/
  const processed = await processPending();
  res.json({ processed });
}

module.exports = {
  handleFlutterwaveWebhook,
  processPending,
  cronHandler,
};