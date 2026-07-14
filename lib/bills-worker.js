// bills-worker.js
// Processes `process_bill_payment` jobs created (atomically, alongside
// the reservation) by reserve_bill_payment() in bills-service.js.
//
// Same two-path pattern as external-transfer-worker.js:
//   1. Fast path: called directly right after reservation.
//   2. Cron sweep (exported cronHandler): catches anything the fast
//      path lost, and drives retries on backoff.
//
// This worker only ever CALLS the payment gateway and records what it
// said. It never marks a bill payment completed on a bare 200 from
// purchaseAirtime() — Flutterwave's own docs say that call can return
// success/pending/failed, so an ambiguous response is followed by a
// status poll before finalize_bill_payment() is ever invoked. That
// mirrors why external-transfer-worker.js re-checks status after
// initiateTransfer() instead of trusting the initial response.

const { createClient } = require("@supabase/supabase-js");
const { PaymentGateway } = require("./payment-gateway");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const WORKER_ID = `bills-worker-${process.env.VERCEL_REGION || "local"}-${process.pid}`;
const BACKOFF_MINUTES = [1, 5, 15, 30, 60, 360, 1440];

async function claimJob() {
  const { data, error } = await supabase.rpc("claim_next_job", {
    p_job_type: "process_bill_payment",
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

    // Exhausted retries without a confirmed outcome — same principle
    // as external transfers: we genuinely don't know whether the
    // airtime was delivered, so don't guess either way. Flag it.
    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: 0,
      status: "open",
      severity: "critical",
      notes: `process_bill_payment job ${job.id} (bill_payment ${job.payload.bill_payment_id}) exhausted retries with unknown final status: ${errorMessage}. Do not assume success or failure — verify with Flutterwave dashboard before touching the reservation.`,
    });

    await supabase.from("notifications").insert({
      user_id: null,
      type: "admin_alert",
      title: "Bill payment status unknown — needs manual review",
      message: `Bill payment ${job.payload.bill_payment_id}: ${errorMessage}`,
      created_at: new Date().toISOString(),
    });

    console.error(
      `[BILLS-WORKER] Job ${job.id} exhausted retries with unknown outcome: ${errorMessage}`,
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
    `[BILLS-WORKER] Job ${job.id} retrying at ${nextAvailableAt.toISOString()}: ${errorMessage}`,
  );
}

async function processBillPaymentJob(job) {
  const { bill_payment_id } = job.payload;

  const { data: bill, error: fetchErr } = await supabase
    .from("bill_payments")
    .select("*, providers(code)")
    .eq("id", bill_payment_id)
    .single();

  if (fetchErr || !bill) {
    await failOrRetryJob(job, `Bill payment ${bill_payment_id} not found`);
    return;
  }

  if (["completed", "failed"].includes(bill.status)) {
    await markJobCompleted(job.id);
    return;
  }

  const providerCode = bill.providers?.code || "flutterwave";

  // If we already sent this to the provider on a previous attempt
  // (provider_reference is set) but never confirmed the outcome —
  // e.g. the process died right after purchaseAirtime() succeeded —
  // poll status instead of purchasing again. Firing a second airtime
  // purchase for the same bill_payment_id would top up the phone twice.
  if (bill.provider_reference) {
    await pollAndFinalize(bill, providerCode, job);
    return;
  }

  await supabase
    .from("bill_payments")
    .update({ status: "processing" })
    .eq("id", bill_payment_id);

  if (bill.service_type !== "AIRTIME") {
    // Should be unreachable — bill-payment-engine.js rejects
    // unsupported types before a reservation is ever created. If this
    // fires, something upstream let a bad service_type through, so
    // fail loudly and release the reservation rather than retry
    // forever on a request the worker can never fulfill.
    const { error: rpcErr } = await supabase.rpc("finalize_bill_payment", {
      p_bill_payment_id: bill_payment_id,
      p_final_status: "failed",
      p_failure_reason: `No processor implemented for service_type '${bill.service_type}'`,
    });
    if (rpcErr) {
      await failOrRetryJob(
        job,
        `Also failed to release reservation: ${rpcErr.message}`,
      );
      return;
    }
    await markJobCompleted(job.id);
    return;
  }

  const result = await PaymentGateway.purchaseAirtime({
    phoneNumber: bill.customer_identifier,
    amount: bill.amount,
    reference: bill.provider_tx_ref,
  });

  if (!result.success) {
    if (result.retryable) {
      await supabase
        .from("bill_payments")
        .update({ status: "reserved" })
        .eq("id", bill_payment_id);
      await failOrRetryJob(job, result.error);
    } else {
      const { error: rpcErr } = await supabase.rpc("finalize_bill_payment", {
        p_bill_payment_id: bill_payment_id,
        p_final_status: "failed",
        p_provider_response: result.raw || null,
        p_failure_reason: result.error,
      });
      if (rpcErr) {
        console.error(
          "[BILLS-WORKER] finalize_bill_payment (failed) RPC failed:",
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
    .from("bill_payments")
    .update({
      provider_reference: result.data.flw_ref,
      network: result.data.network,
    })
    .eq("id", bill_payment_id);

  // A 200 from purchaseAirtime means "accepted", not confirmed
  // delivered — poll status before finalizing either way.
  await pollAndFinalize(
    { ...bill, provider_reference: result.data.flw_ref },
    providerCode,
    job,
  );
}

async function pollAndFinalize(bill, providerCode, job) {
  const statusCheck = await PaymentGateway.getBillStatus({
    providerCode,
    reference: bill.provider_tx_ref,
  });

  if (!statusCheck.success) {
    await failOrRetryJob(job, statusCheck.error);
    return;
  }

  if (statusCheck.data.confirmed) {
    const { error: rpcErr } = await supabase.rpc("finalize_bill_payment", {
      p_bill_payment_id: bill.id,
      p_final_status: "completed",
      p_provider_reference: statusCheck.data.flw_ref,
      p_provider_response: statusCheck.raw || null,
      p_network: statusCheck.data.network,
    });
    if (rpcErr) {
      console.error(
        "[BILLS-WORKER] finalize_bill_payment (completed) RPC failed:",
        rpcErr,
      );
      await failOrRetryJob(
        job,
        `Confirmed by provider but failed to record completion: ${rpcErr.message}`,
      );
      return;
    }
    await markJobCompleted(job.id);
    console.log(
      `[BILLS-WORKER] Job ${job.id} completed — bill payment ${bill.id} confirmed`,
    );
    return;
  }

  // Still not confirmed — requeue to poll again rather than guessing.
  // If this exhausts max_retry, failOrRetryJob raises it for manual
  // review instead of silently marking it either way.
  await failOrRetryJob(
    job,
    `Provider has not confirmed bill ${bill.provider_tx_ref} yet, will re-check`,
  );
}

async function processOne(billPaymentId) {
  try {
    const { data: job } = await supabase
      .from("background_jobs")
      .select("*")
      .eq("job_type", "process_bill_payment")
      .eq("status", "pending")
      .contains("payload", { bill_payment_id: billPaymentId })
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

    await processBillPaymentJob(claimed.data);
  } catch (err) {
    console.error(`[BILLS-WORKER] processOne(${billPaymentId}) threw:`, err);
  }
}

async function processPending(limit = 20) {
  let processed = 0;
  for (let i = 0; i < limit; i++) {
    const job = await claimJob();
    if (!job) break;
    await processBillPaymentJob(job);
    processed++;
  }
  return processed;
}

async function cronHandler(req, res) {
  /*if (
    //process.env.VERCEL_ENV === "production" &&
    //req.headers["x-vercel-cron"] !== "1" &&
    req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }*/
  /*const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }*/
  const processed = await processPending();
  res.json({ processed });
}

module.exports = {
  processOne,
  processPending,
  cronHandler,
};
