// transfer-webhook-handler.js
// Handles the outbound side of Flutterwave webhooks: transfer.completed,
// transfer.failed, transfer.reversed. Called from deposit-webhook-service.js
// (which owns signature verification and webhook_id dedupe — the same
// /api/webhooks/flutterwave endpoint receives both deposit and payout
// events, since Flutterwave only supports one webhook URL per app).
//
// The webhook body is never trusted for the final money-movement
// decision. This module re-verifies the transfer directly against
// Flutterwave's API (flutterwaveService.getTransferStatus) and only
// then calls complete_external_transfer() / fail_external_transfer(),
// the same RPCs external-transfer-worker.js already uses successfully
// for its fast-path/cron completion -- these are the only functions
// allowed to convert a reservation into a real debit or release it.
//
// (This used to call a separate finalize_external_transfer() RPC.
// That function matched rows via a request_id_key column the active
// reserve_external_transfer() never populates, so its internal lookup
// always failed, the ledger insert it depends on threw on a NOT NULL
// violation, and the whole call rolled back -- silently, because the
// error was never checked. Every real transfer.completed webhook was
// quietly a no-op. Switched to the RPCs that are actually wired up
// correctly instead of fixing the drifted duplicate.)

const { createClient } = require("@supabase/supabase-js");
const flutterwaveService = require("./flutterwave-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const WORKER_ID = `transfer-webhook-${process.env.VERCEL_REGION || "local"}-${process.pid}`;
const BACKOFF_MINUTES = [1, 5, 15, 30, 60];

async function processTransferEvent({ event, data, webhookLogId }) {
  if (!data || !data.id) {
    throw new Error("Transfer webhook payload missing data.id");
  }

  // Never trust the webhook body's status/amount — verify directly.
  const verification = await flutterwaveService.getTransferStatus(data.id);

  if (!verification.success) {
    // Flutterwave's API is unreachable/erroring right now. Queue a
    // background retry instead of guessing at the outcome.
    await enqueueRetry(data.id, webhookLogId, verification.error);
    if (webhookLogId) {
      await supabase
        .from("flutterwave_webhook_logs")
        .update({
          status: "verification_failed",
          error_message: verification.error,
        })
        .eq("id", webhookLogId);
    }
    return;
  }

  await finalizeFromVerifiedStatus(verification.data, webhookLogId);
}

async function finalizeFromVerifiedStatus(v, webhookLogId) {
  const { data: transfer, error: lookupErr } = await supabase
    .from("flutterwave_transfers")
    .select("id, status")
    .eq("transaction_reference", v.reference)
    .single();

  if (lookupErr || !transfer) {
    // No matching reservation — either a transfer we never initiated,
    // or the reference format changed. Flag for manual review rather
    // than silently dropping money-movement information.
    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: v.amount,
      status: "open",
      severity: "high",
      notes: `Transfer webhook verified (flw id ${v.id}, ref ${v.reference}, status ${v.status}) but no matching flutterwave_transfers row found.`,
    });
    if (webhookLogId) {
      await supabase
        .from("flutterwave_webhook_logs")
        .update({
          status: "no_matching_transfer",
          processed: true,
          processed_at: new Date().toISOString(),
        })
        .eq("id", webhookLogId);
    }
    return;
  }

  if (v.status === "SUCCESSFUL") {
    // NOTE: this used to call finalize_external_transfer(), which looks up
    // the related transactions_new row via v_transfer.request_id_key. The
    // active reserve_external_transfer() never populates that column (it
    // writes idempotency_key/request_id instead), so that lookup always
    // matched zero rows, v_tx_reference stayed NULL, and the ledger insert
    // (transaction_reference NOT NULL) threw and rolled back the whole
    // call -- silently, because the error was never checked here. That's
    // why transfers stayed "pending" forever even after a real, verified
    // SUCCESSFUL webhook. complete_external_transfer/fail_external_transfer
    // are the RPCs external-transfer-worker.js already uses successfully
    // (matched via metadata->>'transfer_id', which IS populated) -- reuse
    // those instead of maintaining a second, drifted implementation.
    const { error: rpcErr } = await supabase.rpc("complete_external_transfer", {
      p_transfer_id: transfer.id,
      p_flw_transaction_id: String(v.id),
      p_flw_status: v.status,
    });
    if (rpcErr) {
      await alertFinalizeFailure(
        transfer.id,
        "complete_external_transfer",
        rpcErr,
        v.status,
      );
      // Throw so the caller (deposit-webhook-service.js) marks this
      // webhook log "failed" instead of "completed" -- do NOT ack this
      // as processed when we know Flutterwave says SUCCESSFUL but failed
      // to record it. A duplicate delivery or the reconciliation sweep
      // needs another shot at this.
      throw new Error(
        `complete_external_transfer failed for transfer ${transfer.id}: ${rpcErr.message}`,
      );
    }
  } else if (v.status === "FAILED") {
    const { error: rpcErr } = await supabase.rpc("fail_external_transfer", {
      p_transfer_id: transfer.id,
      p_reason: v.complete_message || "Transfer failed at Flutterwave",
      p_failure_code: "FLW_FAILED",
    });
    if (rpcErr) {
      await alertFinalizeFailure(
        transfer.id,
        "fail_external_transfer",
        rpcErr,
        v.status,
      );
      throw new Error(
        `fail_external_transfer failed for transfer ${transfer.id}: ${rpcErr.message}`,
      );
    }
  } else {
    // NEW / PENDING — not a final state yet. Leave the reservation in
    // place; a later webhook delivery or the reconciliation sweep
    // (stuck_external_transfers) will resolve it.
    if (webhookLogId) {
      await supabase
        .from("flutterwave_webhook_logs")
        .update({
          status: "not_final",
          error_message: `Verified status was '${v.status}'`,
        })
        .eq("id", webhookLogId);
    }
    return;
  }

  if (webhookLogId) {
    await supabase
      .from("flutterwave_webhook_logs")
      .update({
        status: "completed",
        processed: true,
        processed_at: new Date().toISOString(),
      })
      .eq("id", webhookLogId);
  }
}

// ------------------------------------------------------------
// Fires when we've already got a verified, final status straight from
// Flutterwave but failed to persist it (a DB/RPC error, not an
// ambiguous outcome). This is more urgent than the usual "still
// pending" alerts elsewhere in this file: the truth is known, we just
// failed to record it, so it needs a human now rather than a retry
// loop that will keep hitting the same bug.
// ------------------------------------------------------------
async function alertFinalizeFailure(transferId, rpcName, rpcErr, knownStatus) {
  console.error(
    `[TRANSFER-WEBHOOK] ${rpcName} failed for transfer ${transferId} (Flutterwave confirmed ${knownStatus}):`,
    rpcErr,
  );
  await supabase.from("reconciliation_alerts").insert({
    user_id: null,
    operational_balance: 0,
    ledger_balance: 0,
    difference: 0,
    status: "open",
    severity: "critical",
    notes: `${rpcName} failed for transfer ${transferId} even though Flutterwave confirmed status ${knownStatus}. The reservation was NOT converted to a real debit/release -- do not assume either outcome, verify and reconcile manually. DB error: ${rpcErr.message}`,
  });
}

async function enqueueRetry(flwTransferId, webhookLogId, lastError) {
  await supabase.from("background_jobs").insert({
    job_type: "reconcile_transfer_webhook",
    payload: { flw_transfer_id: flwTransferId, webhook_log_id: webhookLogId },
    status: "pending",
    priority: 200,
    last_error: lastError || null,
  });
}

// ------------------------------------------------------------
// Reconciliation sweep: catches transfers stuck past the reservation
// window with no definitive webhook (spec item 14). Run on a cron
// alongside the deposit and virtual-account workers.
// ------------------------------------------------------------
async function reconcileStuckTransfers(limit = 20) {
  const { data: stuck, error } = await supabase
    .from("stuck_external_transfers")
    .select("id, transaction_reference")
    .limit(limit);

  if (error) {
    console.error(
      "[TRANSFER-RECONCILE] Failed to load stuck transfers:",
      error,
    );
    return 0;
  }

  let resolved = 0;
  for (const row of stuck || []) {
    const { data: transfer } = await supabase
      .from("flutterwave_transfers")
      .select("flutterwave_reference")
      .eq("id", row.id)
      .single();

    if (!transfer || !transfer.flutterwave_reference) {
      // Flutterwave never even acknowledged this one (processFlutterwaveTransfer
      // never got a response) — nothing to verify against yet, leave it
      // for the next sweep unless it's very old, in which case it should
      // be surfaced to an admin, not auto-failed.
      continue;
    }

    const verification = await flutterwaveService.getTransferStatus(
      transfer.flutterwave_reference,
    );
    if (!verification.success) continue;

    if (verification.data.status === "SUCCESSFUL") {
      const { error: rpcErr } = await supabase.rpc(
        "complete_external_transfer",
        {
          p_transfer_id: row.id,
          p_flw_transaction_id: String(verification.data.id),
          p_flw_status: verification.data.status,
        },
      );
      if (rpcErr) {
        await alertFinalizeFailure(
          row.id,
          "complete_external_transfer",
          rpcErr,
          verification.data.status,
        );
        continue; // don't count this as resolved -- next sweep tries again
      }
      resolved++;
    } else if (verification.data.status === "FAILED") {
      const { error: rpcErr } = await supabase.rpc("fail_external_transfer", {
        p_transfer_id: row.id,
        p_reason: verification.data.complete_message || "Transfer failed",
        p_failure_code: "FLW_FAILED",
      });
      if (rpcErr) {
        await alertFinalizeFailure(
          row.id,
          "fail_external_transfer",
          rpcErr,
          verification.data.status,
        );
        continue;
      }
      resolved++;
    }
  }
  return resolved;
}

async function cronHandler(req, res) {
  /*if (
    //process.env.VERCEL_ENV === "production" &&
    req.headers["x-vercel-cron"] !== "1" &&
    req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }*/

  /*const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }*/
  const resolved = await reconcileStuckTransfers();
  res.json({ resolved });
}

module.exports = {
  processTransferEvent,
  reconcileStuckTransfers,
  cronHandler,
};
