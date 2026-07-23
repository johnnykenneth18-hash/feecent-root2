// external-transfer-worker.js
// Processes `send_external_transfer` jobs created by
// reserve_external_transfer() in external-transfer-service.js.
//
// Same two-path pattern as virtual-account-worker.js:
//   1. Fast path: called directly right after reservation (most transfers
//      resolve in a couple seconds).
//   2. Cron sweep (exported cronHandler): catches anything the fast path
//      lost if the serverless function froze/exited mid-call, and drives
//      retries on backoff.
//
// This worker only ever CALLS a payout provider and records what it said.
// It never marks a transfer completed on its own — completion only
// happens once the outbound webhook (transfer-webhook-handler.js) or
// this worker's own status re-check confirms the provider actually
// says SUCCESSFUL, via complete_external_transfer(). That keeps a
// single, verified path to ever touching the real wallet balance.
//
// CHANGED in this pass: this file used to `require("./flutterwave-service")`
// directly, meaning "external_transfer" routing through
// payment-gateway.js's ProviderRouter never actually applied to real
// payouts — the single most safety-critical money-movement path in the
// app was bypassing the router entirely. It now resolves a provider via
// ServiceRegistry and persists the chosen provider_code onto the
// flutterwave_transfers row (new column, see 011_service_registry.sql)
// so a later re-check or the reconciliation sweep goes back to the
// SAME provider that actually sent the money, never re-routes.

const { createClient } = require("@supabase/supabase-js");
const { ServiceRegistry } = require("./service-registry");
const { finalizeVerifiedTransfer } = require("./transfer-finalization");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const WORKER_ID = `ext-transfer-worker-${process.env.VERCEL_REGION || "local"}-${process.pid}`;
const BACKOFF_MINUTES = [1, 5, 15, 30, 60, 360, 1440];

async function claimJob() {
  const { data, error } = await supabase.rpc("claim_next_job", {
    p_job_type: "send_external_transfer",
    p_worker_id: WORKER_ID,
  });
  if (error) {
    console.error("[EXT-WORKER] claim_next_job failed:", error);
    return null;
  }
  return Array.isArray(data) && data.length > 0 ? data[0] : null;
}

async function markJobCompleted(jobId) {
  await supabase
    .from("background_jobs")
    .update({ status: "completed", completed_at: new Date().toISOString() })
    .eq("id", jobId);
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

    // Exhausted retries without a confirmed outcome from the provider —
    // this needs a human, not a silent failure. Do NOT release the
    // reservation automatically here: we genuinely don't know if the
    // money went out. Flag for manual reconciliation instead of
    // guessing either way.
    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: 0,
      status: "open",
      severity: "critical",
      notes: `send_external_transfer job ${job.id} (transfer ${job.payload.transfer_id}) exhausted retries with unknown final provider status: ${errorMessage}. Do not assume success or failure — verify with the provider dashboard before touching the reservation.`,
    });

    await supabase.from("notifications").insert({
      user_id: null,
      type: "admin_alert",
      title: "External transfer status unknown — needs manual review",
      message: `Transfer ${job.payload.transfer_id}: ${errorMessage}`,
      created_at: new Date().toISOString(),
    });

    console.error(
      `[EXT-WORKER] Job ${job.id} exhausted retries with unknown outcome: ${errorMessage}`,
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

  console.warn(
    `[EXT-WORKER] Job ${job.id} retrying at ${nextAvailableAt.toISOString()}: ${errorMessage}`,
  );
}

async function processSendExternalTransferJob(job) {
  const { transfer_id } = job.payload;

  const { data: transfer, error: fetchErr } = await supabase
    .from("flutterwave_transfers")
    .select("*")
    .eq("id", transfer_id)
    .single();

  if (fetchErr || !transfer) {
    await failOrRetryJob(job, `Transfer ${transfer_id} not found`);
    return;
  }

  if (
    ["completed", "failed", "reversed", "cancelled"].includes(transfer.status)
  ) {
    await markJobCompleted(job.id);
    return;
  }

  // If we already sent this to a provider on a previous attempt
  // (flutterwave_reference is set) but never confirmed the outcome —
  // e.g. the process died right after initiateTransfer() succeeded —
  // check status against the SAME provider instead of calling
  // initiateTransfer() again. Firing a second payout for the same
  // transfer would send the money twice. transfer.provider_code
  // records which provider that was (see 011_service_registry.sql).
  if (transfer.flutterwave_reference) {
    const provider = ServiceRegistry.getProviderByCode(transfer.provider_code);
    const statusCheck = await provider.verifyTransfer({
      flwTransferId: transfer.flutterwave_reference,
    });
    if (!statusCheck.success) {
      await failOrRetryJob(job, statusCheck.error);
      return;
    }
    await applyProviderStatus(transfer, statusCheck.data, job);
    return;
  }

  await supabase
    .from("flutterwave_transfers")
    .update({ status: "processing", processed_at: new Date().toISOString() })
    .eq("id", transfer_id);

  let implementation, providerCode;
  try {
    ({ implementation, providerCode } =
      await ServiceRegistry.resolve("external_transfer"));
  } catch (err) {
    await supabase
      .from("flutterwave_transfers")
      .update({ status: "reserved" })
      .eq("id", transfer_id);
    await failOrRetryJob(job, err.message);
    return;
  }

  const result = await implementation.initiateTransfer({
    accountBank: transfer.bank_code,
    accountNumber: transfer.account_number,
    amount: transfer.amount,
    narration: transfer.narration,
    reference: transfer.transaction_reference,
    beneficiaryName: transfer.beneficiary_name,
  });

  if (!result.success) {
    if (result.retryable) {
      await supabase
        .from("flutterwave_transfers")
        .update({ status: "reserved" }) // back to reserved so the fast-path/worker knows to try initiateTransfer again, not re-check a status
        .eq("id", transfer_id);
      await failOrRetryJob(job, result.error);
    } else {
      // Log this BEFORE attempting the release — if fail_external_transfer
      // itself errors, this is otherwise the only place the provider's
      // actual rejection reason ever appears. Losing it here means
      // losing it entirely.
      console.error(
        `[EXT-WORKER] ${providerCode} rejected transfer ${transfer_id}: ${result.error}`,
        result.raw ? JSON.stringify(result.raw) : "(no raw response captured)",
      );
      const { error: rpcErr } = await supabase.rpc("fail_external_transfer", {
        p_transfer_id: transfer_id,
        p_reason: result.error,
        p_failure_code: "REJECTED_BY_PROVIDER",
      });
      if (rpcErr) {
        console.error(
          "[EXT-WORKER] fail_external_transfer RPC failed:",
          rpcErr,
        );
        await failOrRetryJob(
          job,
          `Also failed to release reservation: ${rpcErr.message}`,
        );
        return;
      }
      await markJobCompleted(job.id);
    }
    return;
  }

  await supabase
    .from("flutterwave_transfers")
    .update({
      provider_code: providerCode,
      flutterwave_reference: String(result.data.flw_id),
      flutterwave_status: result.data.status,
    })
    .eq("id", transfer_id);

  // Provider accepted the request but that's not proof of delivery —
  // re-fetch { ...transfer, flutterwave_reference } and decide from
  // real status, same as the deposit path never trusts the webhook body.
  await applyProviderStatus(
    { ...transfer, provider_code: providerCode },
    { id: result.data.flw_id, status: result.data.status },
    job,
  );
}

async function applyProviderStatus(transfer, flwData, job) {
  // Delegates to the same finalizeVerifiedTransfer() every provider's
  // webhook handler uses (transfer-finalization.js) — this is the
  // worker's own fast-path/reconciliation confirmation of success,
  // and it needs to trigger the exact same side effects (VAT charging,
  // reconciliation alerts on failure) a webhook-driven completion
  // does, not a second copy of that logic that could drift out of
  // sync with it.
  try {
    const result = await finalizeVerifiedTransfer({
      reference: transfer.transaction_reference,
      verified: flwData,
      providerCode: transfer.provider_code || "flutterwave",
    });

    if (!result.matched) {
      // No matching flutterwave_transfers row — already alerted inside
      // finalizeVerifiedTransfer. Nothing more this job can do.
      await markJobCompleted(job.id);
      return;
    }
    if (result.alreadyTerminal) {
      await markJobCompleted(job.id);
      return;
    }
    if (!result.final) {
      // NEW / PENDING — still in flight on the provider's side. Requeue
      // this job to check again later rather than treating it as
      // either outcome.
      await failOrRetryJob(
        job,
        `${transfer.provider_code || "flutterwave"} status still ${flwData.status}, will re-check`,
      );
      return;
    }

    await markJobCompleted(job.id);
    console.log(
      `[EXT-WORKER] Job ${job.id} completed — transfer ${transfer.id} finalized via ${transfer.provider_code || "flutterwave"}`,
    );
  } catch (finalizeErr) {
    // finalizeVerifiedTransfer throws only when the RPC call itself
    // failed after a truly verified status — already alerted inside it
    // (alertFinalizeFailure). Retry the job; do not guess at the
    // outcome ourselves.
    await failOrRetryJob(job, finalizeErr.message);
  }
}

async function processOne(transferId) {
  try {
    const { data: job } = await supabase
      .from("background_jobs")
      .select("*")
      .eq("job_type", "send_external_transfer")
      .eq("status", "pending")
      .contains("payload", { transfer_id: transferId })
      .limit(1)
      .single();

    if (!job) return;

    const claimed = await supabase
      .from("background_jobs")
      .update({
        status: "processing",
        locked_at: new Date().toISOString(),
        locked_by: WORKER_ID,
      })
      .eq("id", job.id)
      .eq("status", "pending")
      .select()
      .single();

    if (claimed.error || !claimed.data) return;

    await processSendExternalTransferJob(claimed.data);
  } catch (err) {
    console.error(`[EXT-WORKER] processOne(${transferId}) threw:`, err);
  }
}

async function processPending(limit = 20) {
  let processed = 0;
  for (let i = 0; i < limit; i++) {
    const job = await claimJob();
    if (!job) break;
    await processSendExternalTransferJob(job);
    processed++;
  }
  return processed;
}

async function cronHandler(req, res) {
  const processed = await processPending();
  res.json({ processed });
}

module.exports = {
  processOne,
  processPending,
  cronHandler,
};
