// transfer-webhook-handler.js
// Handles the outbound side of Flutterwave webhooks: transfer.completed,
// transfer.failed, transfer.reversed. Called from deposit-webhook-service.js
// (which owns signature verification and webhook_id dedupe — the same
// /api/webhooks/flutterwave endpoint receives both deposit and payout
// events, since Flutterwave only supports one webhook URL per app).
//
// The webhook body is never trusted for the final money-movement
// decision. This module re-verifies the transfer directly against the
// provider's API and only then delegates to transfer-finalization.js's
// finalizeVerifiedTransfer(), which is the ONE place complete_external_transfer()
// / fail_external_transfer() get called from — shared with
// paystack-webhook-handler.js and monnify-webhook-handler.js so all
// three providers' webhooks finalize transfers identically instead of
// three copies that could drift apart (see transfer-finalization.js's
// header for why that's the whole point of the extraction).
//
// This file stays Flutterwave-specific because it's reached only via
// the Flutterwave-specific webhook URL — same reasoning as
// paystack-webhook-handler.js / monnify-webhook-handler.js each being
// their own file: none of these go through ServiceRegistry routing,
// because routing decides which provider handles a NEW request, not
// which provider a given EXISTING transfer already belongs to.
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
const { ServiceRegistry } = require("./service-registry");
const { finalizeVerifiedTransfer, alertFinalizeFailure } = require("./transfer-finalization");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const WORKER_ID = `transfer-webhook-${process.env.VERCEL_REGION || "local"}-${process.pid}`;

async function processTransferEvent({ event, data, webhookLogId }) {
  if (!data || !data.id) {
    throw new Error("Transfer webhook payload missing data.id");
  }

  // Never trust the webhook body's status/amount — verify directly.
  // This endpoint is Flutterwave's dedicated webhook URL, so naming
  // the provider here (rather than resolving one) is correct — see
  // header note.
  const flutterwaveProvider = ServiceRegistry.getProviderByCode(
    "flutterwave",
  );
  const verification = await flutterwaveProvider.verifyTransfer({
    flwTransferId: data.id,
  });

  if (!verification.success) {
    // Provider's API is unreachable/erroring right now. Queue a
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

  const v = verification.data;
  const updateLog = async (fields) => {
    if (!webhookLogId) return;
    await supabase.from("flutterwave_webhook_logs").update(fields).eq("id", webhookLogId);
  };

  await finalizeVerifiedTransfer({
    reference: v.reference,
    verified: v,
    providerCode: "flutterwave",
    webhookLogUpdate: updateLog,
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
// alongside the deposit and virtual-account workers. Unlike
// processTransferEvent above, this is NOT tied to any one provider's
// webhook — it reads each stuck transfer's own provider_code and asks
// the registry for that exact provider, so it stays correct across
// Flutterwave, Paystack, and Monnify transfers alike.
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
      .select("flutterwave_reference, provider_code, transaction_reference")
      .eq("id", row.id)
      .single();

    if (!transfer || !transfer.flutterwave_reference) {
      // Provider never even acknowledged this one (initiateTransfer
      // never got a response) — nothing to verify against yet, leave
      // it for the next sweep unless it's very old, in which case it
      // should be surfaced to an admin, not auto-failed.
      continue;
    }

    const providerCode = transfer.provider_code || "flutterwave";
    const provider = ServiceRegistry.getProviderByCode(providerCode);
    const verification = await provider.verifyTransfer({
      flwTransferId: transfer.flutterwave_reference,
    });
    if (!verification.success) continue;

    try {
      const result = await finalizeVerifiedTransfer({
        reference: transfer.transaction_reference,
        verified: verification.data,
        providerCode,
      });
      if (result.final) resolved++;
    } catch (finalizeErr) {
      // Already alerted inside finalizeVerifiedTransfer/alertFinalizeFailure
      continue; // don't count this as resolved -- next sweep tries again
    }
  }
  return resolved;
}

async function cronHandler(req, res) {
  const resolved = await reconcileStuckTransfers();
  res.json({ resolved });
}

module.exports = {
  processTransferEvent,
  reconcileStuckTransfers,
  cronHandler,
};