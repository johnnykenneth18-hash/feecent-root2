// bills-worker.js (v2)
// Same fast-path/cron-sweep worker as before, rebuilt against
// bill_transactions / finalize_bill_transaction / process_bill_transaction
// jobs. The one real behavior change: this worker now dispatches to a
// PaymentGateway method chosen by the transaction's CATEGORY rather
// than being AIRTIME-only. Categories whose PaymentProvider method
// isn't implemented yet (see payment-provider.js) fail loudly and
// immediately with NOT_IMPLEMENTED — never retried, since retrying
// something that will never succeed just delays the honest failure.

const { createClient } = require("@supabase/supabase-js");
const { PaymentGateway } = require("./payment-gateway");
const { NotImplementedError } = require("./payment-provider");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const WORKER_ID = `bills-worker-${process.env.VERCEL_REGION || "local"}-${process.pid}`;
const BACKOFF_MINUTES = [1, 5, 15, 30, 60, 360, 1440];

// Category code -> PaymentGateway method that actually executes the
// purchase. Extending to a new category is adding a row here (once
// the corresponding provider method exists) — not editing the
// dispatch logic below.
const CATEGORY_GATEWAY_METHOD = {
  AIRTIME: "purchaseAirtime",
  DATA: "purchaseData",
  ELECTRICITY: "payElectricity",
  CABLE: "payCable",
  BETTING: "payBetting",
};

async function claimJob() {
  const { data, error } = await supabase.rpc("claim_next_job", {
    p_job_type: "process_bill_transaction",
    p_worker_id: WORKER_ID,
  });
  if (error) {
    console.error("[BILLS-WORKER] claim_next_job failed:", error);
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

    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: 0,
      status: "open",
      severity: "critical",
      notes: `process_bill_transaction job ${job.id} (bill_transaction ${job.payload.bill_transaction_id}) exhausted retries with unknown final status: ${errorMessage}. Do not assume success or failure — verify with the provider dashboard before touching the reservation.`,
    });

    await supabase.from("notifications").insert({
      user_id: null,
      type: "admin_alert",
      title: "Bill payment status unknown — needs manual review",
      message: `Bill transaction ${job.payload.bill_transaction_id}: ${errorMessage}`,
      created_at: new Date().toISOString(),
    });

    console.error(`[BILLS-WORKER] Job ${job.id} exhausted retries with unknown outcome: ${errorMessage}`);
    return;
  }

  const backoffIdx = Math.min(nextRetryCount - 1, BACKOFF_MINUTES.length - 1);
  const nextAvailableAt = new Date(Date.now() + BACKOFF_MINUTES[backoffIdx] * 60 * 1000);

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

  console.warn(`[BILLS-WORKER] Job ${job.id} retrying at ${nextAvailableAt.toISOString()}: ${errorMessage}`);
}

async function failPermanently(bill, job, reason, rawResponse) {
  const { error: rpcErr } = await supabase.rpc("finalize_bill_transaction", {
    p_bill_transaction_id: bill.id,
    p_final_status: "failed",
    p_failure_reason: reason,
    p_provider_response: rawResponse || null,
  });
  if (rpcErr) {
    console.error("[BILLS-WORKER] finalize_bill_transaction (failed) RPC failed:", rpcErr);
    await failOrRetryJob(job, `Also failed to release reservation: ${rpcErr.message}`);
    return;
  }
  await markJobCompleted(job.id);
}

async function processBillTransactionJob(job) {
  const { bill_transaction_id } = job.payload;

  const { data: bill, error: fetchErr } = await supabase
    .from("bill_transactions")
    .select("*, bill_categories(code, name), bill_providers(code, name)")
    .eq("id", bill_transaction_id)
    .single();

  if (fetchErr || !bill) {
    await failOrRetryJob(job, `Bill transaction ${bill_transaction_id} not found`);
    return;
  }

  if (["completed", "failed"].includes(bill.status)) {
    await markJobCompleted(job.id);
    return;
  }

  const categoryCode = bill.bill_categories?.code;
  const gatewayMethod = CATEGORY_GATEWAY_METHOD[categoryCode];

  if (!gatewayMethod) {
    // Should be unreachable — bills-catalog-service.js only prices
    // categories it knows about. If this fires, something let a bad
    // category through, so fail loudly and release the reservation
    // rather than retry forever on a request that can never succeed.
    await failPermanently(bill, job, `No gateway method mapped for category '${categoryCode}'`);
    return;
  }

  // Already sent to the provider on a previous attempt but never
  // confirmed the outcome — poll status instead of purchasing again.
  if (bill.provider_reference) {
    await pollAndFinalize(bill, job);
    return;
  }

  await supabase.from("bill_transactions").update({ status: "processing" }).eq("id", bill_transaction_id);

  let result;
  try {
    result = await PaymentGateway[gatewayMethod]({
      phoneNumber: bill.customer_identifier, // used by purchaseAirtime; harmless extra field for other methods
      customerIdentifier: bill.customer_identifier,
      amount: bill.amount,
      reference: bill.provider_tx_ref,
      billerCode: bill.external_biller_code,
      planCode: bill.external_plan_code,
    });
  } catch (err) {
    if (err instanceof NotImplementedError) {
      // Honest, immediate failure — matches the old bill-payment-engine.js
      // behavior for anything not built yet. Never retried.
      await supabase.from("bill_transactions").update({ status: "reserved" }).eq("id", bill_transaction_id);
      await failPermanently(bill, job, `${categoryCode} payments are not available yet (${err.message})`);
      return;
    }
    await supabase.from("bill_transactions").update({ status: "reserved" }).eq("id", bill_transaction_id);
    await failOrRetryJob(job, err.message || "Provider call threw an unexpected error");
    return;
  }

  if (!result.success) {
    if (result.retryable) {
      await supabase.from("bill_transactions").update({ status: "reserved" }).eq("id", bill_transaction_id);
      await failOrRetryJob(job, result.error);
    } else {
      await failPermanently(bill, job, result.error, result.raw);
    }
    return;
  }

  await supabase
    .from("bill_transactions")
    .update({
      provider_reference: result.data?.flw_ref || null,
      network: result.data?.network || null,
    })
    .eq("id", bill_transaction_id);

  // A 200 from the purchase call means "accepted", not confirmed
  // delivered — poll status before finalizing either way.
  await pollAndFinalize({ ...bill, provider_reference: result.data?.flw_ref }, job);
}

async function pollAndFinalize(bill, job) {
  const statusCheck = await PaymentGateway.getBillStatus({
    providerCode: bill.gateway_code,
    reference: bill.provider_tx_ref,
  });

  if (!statusCheck.success) {
    await failOrRetryJob(job, statusCheck.error);
    return;
  }

  if (statusCheck.data.confirmed) {
    const { error: rpcErr } = await supabase.rpc("finalize_bill_transaction", {
      p_bill_transaction_id: bill.id,
      p_final_status: "completed",
      p_provider_reference: statusCheck.data.flw_ref,
      p_provider_response: statusCheck.raw || null,
      p_network: statusCheck.data.network,
    });
    if (rpcErr) {
      console.error("[BILLS-WORKER] finalize_bill_transaction (completed) RPC failed:", rpcErr);
      await failOrRetryJob(job, `Confirmed by provider but failed to record completion: ${rpcErr.message}`);
      return;
    }
    await markJobCompleted(job.id);
    console.log(`[BILLS-WORKER] Job ${job.id} completed — bill transaction ${bill.id} confirmed`);
    return;
  }

  // Still not confirmed — requeue to poll again rather than guessing.
  await failOrRetryJob(job, `Provider has not confirmed ${bill.provider_tx_ref} yet, will re-check`);
}

async function processOne(billTransactionId) {
  try {
    const { data: job } = await supabase
      .from("background_jobs")
      .select("*")
      .eq("job_type", "process_bill_transaction")
      .eq("status", "pending")
      .contains("payload", { bill_transaction_id: billTransactionId })
      .limit(1)
      .single();

    if (!job) return;

    const claimed = await supabase
      .from("background_jobs")
      .update({ status: "processing", locked_at: new Date().toISOString(), locked_by: WORKER_ID })
      .eq("id", job.id)
      .eq("status", "pending")
      .select()
      .single();

    if (claimed.error || !claimed.data) return;

    await processBillTransactionJob(claimed.data);
  } catch (err) {
    console.error(`[BILLS-WORKER] processOne(${billTransactionId}) threw:`, err);
  }
}

async function processPending(limit = 20) {
  let processed = 0;
  for (let i = 0; i < limit; i++) {
    const job = await claimJob();
    if (!job) break;
    await processBillTransactionJob(job);
    processed++;
  }
  return processed;
}

async function cronHandler(req, res) {
  const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const processed = await processPending();
  res.json({ processed });
}

module.exports = {
  processOne,
  processPending,
  cronHandler,
};