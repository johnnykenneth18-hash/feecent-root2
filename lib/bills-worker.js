// bills-worker.js (v2 + secret_data)
// Same fast-path/cron-sweep worker as before, rebuilt against
// bill_transactions / finalize_bill_transaction / process_bill_transaction
// jobs. The one real behavior change: this worker now dispatches to a
// PaymentGateway method chosen by the transaction's CATEGORY rather
// than being AIRTIME-only. Categories whose PaymentProvider method
// isn't implemented yet (see payment-provider.js) fail loudly and
// immediately with NOT_IMPLEMENTED — never retried, since retrying
// something that will never succeed just delays the honest failure.
//
// CHANGE (bills v3 metadata/secret-data upgrade): on successful
// finalize, this now builds the universal secret_data shape
// ({ title, items: [{label, value}] }) from the provider's getBillStatus()
// response and passes it to finalize_bill_transaction()'s new
// p_secret_data param — see 014_bills_v3_metadata_and_secret_data.sql.
// buildSecretData() below is NOT verified against live provider
// payloads (see its own header comment) — confirm real field names
// against an actual electricity/exam-PIN purchase before trusting this
// in production, same caveat flutterwave-provider.js already carries
// for the underlying purchase/status calls themselves.

const { createClient } = require("@supabase/supabase-js");
const { PaymentGateway } = require("./payment-gateway");
const { ServiceRegistry } = require("./service-registry");
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
  FROZYLA: "fundWallet",
};

// ------------------------------------------------------------
// Builds the universal secret-data structure (spec section 4) from
// whatever fields the provider's getBillStatus() call returned.
// Returns null when the category doesn't declare returns_secret_data,
// or when none of the known field names showed up in the response —
// either is treated as "nothing to reveal," not an error, since not
// every completed purchase of a secret-data category necessarily
// carries one on every provider response shape.
//
// NOT VERIFIED: Flutterwave/VTpass don't use consistent field names
// for token/pin/serial/voucher across products. This checks every
// name we've seen used in the wild. Confirm against a real provider
// payload before relying on this for a live electricity/exam-PIN
// purchase — same "CONFIRM before relying on this" caveat as
// flutterwave-provider.js's purchaseData/payElectricity/payCable/
// payBetting.
// ------------------------------------------------------------
function buildSecretData(category, data) {
  if (!category || !category.returns_secret_data || !data) return null;

  const candidates = [
    { keys: ["token", "electricityToken", "meterToken"], label: "Token" },
    { keys: ["units"], label: "Units" },
    { keys: ["pin"], label: "PIN" },
    { keys: ["serial", "serialNumber"], label: "Serial Number" },
    { keys: ["voucher", "voucherCode"], label: "Voucher Code" },
    { keys: ["code", "activationCode"], label: "Code" },
  ];

  const items = [];
  for (const { keys, label } of candidates) {
    for (const key of keys) {
      const value = data[key];
      if (value !== undefined && value !== null && value !== "") {
        items.push({ label, value: String(value) });
        break; // only one field per candidate group, first match wins
      }
    }
  }

  if (items.length === 0) return null;

  return {
    title: category.secret_data_label || `Your ${category.name}`,
    items,
  };
}

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

async function failPermanently(bill, job, reason, rawResponse) {
  const { error: rpcErr } = await supabase.rpc("finalize_bill_transaction", {
    p_bill_transaction_id: bill.id,
    p_final_status: "failed",
    p_failure_reason: reason,
    p_provider_response: rawResponse || null,
  });
  if (rpcErr) {
    console.error(
      "[BILLS-WORKER] finalize_bill_transaction (failed) RPC failed:",
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

async function processBillTransactionJob(job) {
  const { bill_transaction_id } = job.payload;

  const { data: bill, error: fetchErr } = await supabase
    .from("bill_transactions")
    .select(
      "*, bill_categories(code, name, returns_secret_data, secret_data_label), bill_providers(code, name)",
    )
    .eq("id", bill_transaction_id)
    .single();

  if (fetchErr || !bill) {
    await failOrRetryJob(
      job,
      `Bill transaction ${bill_transaction_id} not found`,
    );
    return;
  }

  if (["completed", "failed"].includes(bill.status)) {
    await markJobCompleted(job.id);
    return;
  }

  const categoryCode = bill.bill_categories?.code;
  const gatewayMethod = CATEGORY_GATEWAY_METHOD[categoryCode];

  // TEMPORARY DIAGNOSTIC — remove once confirmed fixed.
  console.log(
    "[DIAGNOSTIC] categoryCode:", categoryCode,
    "| gatewayMethod:", gatewayMethod,
    "| CATEGORY_GATEWAY_METHOD keys:", Object.keys(CATEGORY_GATEWAY_METHOD),
  );

  if (!gatewayMethod) {
    // Should be unreachable — bills-catalog-service.js only prices
    // categories it knows about. If this fires, something let a bad
    // category through, so fail loudly and release the reservation
    // rather than retry forever on a request that can never succeed.
    await failPermanently(
      bill,
      job,
      `No gateway method mapped for category '${categoryCode}'`,
    );
    return;
  }

  // Already sent to the provider on a previous attempt but never
  // confirmed the outcome — poll status instead of purchasing again.
  if (bill.provider_reference) {
    await pollAndFinalize(bill, job);
    return;
  }

  // FIXED (before this could ever matter — see header note added with
  // multi-provider support): this MUST call the exact provider
  // recorded in bill.gateway_code, the same one bills-catalog-service.js
  // priced this purchase against at request time. It must NOT go
  // through PaymentGateway's capability-based auto-routing
  // (ServiceRegistry.resolve()) — that picks whichever provider
  // currently wins routing priority for the category generally, which
  // is a completely different question from "which provider was this
  // SPECIFIC bill_transaction already priced and locked in for." With
  // only one bills provider (Flutterwave) those two questions always
  // had the same answer, so this was invisible; the moment a second
  // bills-capable provider is registered (e.g. VTpass) with routing
  // priority for the same category, auto-routing here could silently
  // execute a purchase through a different provider than the one the
  // user's price quote was actually based on. getBillStatus() below
  // already does this correctly (providerCode: bill.gateway_code) —
  // this now matches it.
  let providerImplementation;
  try {
    providerImplementation = ServiceRegistry.getProviderByCode(
      bill.gateway_code,
    );
  } catch (err) {
    await failPermanently(
      bill,
      job,
      `No provider implementation registered for gateway_code '${bill.gateway_code}' — this is a code/config bug, not a provider failure. No request was ever sent, so releasing the reservation is safe.`,
    );
    return;
  }

  // GUARD (added after a real incident): if the provider has no method
  // for this category — e.g. purchaseData was missing before a
  // payment-gateway.js fix — calling it threw a bare TypeError, which
  // fell into the generic catch below, retried with backoff, and once
  // retries exhausted just marked the JOB failed while leaving the
  // bill_transaction (and its reserved funds) stuck in "reserved"
  // forever — no provider was ever contacted, so this is never
  // ambiguous and is always safe to fail immediately.
  if (typeof providerImplementation[gatewayMethod] !== "function") {
    await failPermanently(
      bill,
      job,
      `Provider '${bill.gateway_code}' has no method '${gatewayMethod}' wired up for category '${categoryCode}' — this is a code/config bug, not a provider failure. No request was ever sent to any provider, so releasing the reservation is safe.`,
    );
    return;
  }

  await supabase
    .from("bill_transactions")
    .update({ status: "processing" })
    .eq("id", bill_transaction_id);

  let result;
  try {
    result = await providerImplementation[gatewayMethod]({
      phoneNumber: bill.customer_identifier, // used by purchaseAirtime; harmless extra field for other methods
      customerIdentifier: bill.customer_identifier,
      amount: bill.amount,
      reference: bill.provider_tx_ref,
      billerCode: bill.external_biller_code,
      planCode: bill.external_plan_code, // purchaseData/payCable's param name
      itemCode: bill.external_plan_code, // payElectricity's param name — same underlying catalog value, different name per Flutterwave's own inconsistent shape between products
    });
  } catch (err) {
    if (err instanceof NotImplementedError) {
      // Honest, immediate failure — matches the old bill-payment-engine.js
      // behavior for anything not built yet. Never retried.
      await supabase
        .from("bill_transactions")
        .update({ status: "reserved" })
        .eq("id", bill_transaction_id);
      await failPermanently(
        bill,
        job,
        `${categoryCode} payments are not available yet (${err.message})`,
      );
      return;
    }
    await supabase
      .from("bill_transactions")
      .update({ status: "reserved" })
      .eq("id", bill_transaction_id);
    await failOrRetryJob(
      job,
      err.message || "Provider call threw an unexpected error",
    );
    return;
  }

  if (!result.success) {
    if (result.retryable) {
      await supabase
        .from("bill_transactions")
        .update({ status: "reserved" })
        .eq("id", bill_transaction_id);
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
  await pollAndFinalize(
    { ...bill, provider_reference: result.data?.flw_ref },
    job,
  );
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

  // A provider that CAN definitively assert failure (VTpass:
  // "failed"/"reversed" via requery) should end this here — not be
  // left to poll forever the way a merely-inconclusive check would.
  // Flutterwave's getBillStatus() always returns failed:false (it has
  // no reliable failure signal), so this branch never fires for it —
  // its existing "never assume failed" behavior is unchanged.
  if (statusCheck.data.failed) {
    await failPermanently(
      bill,
      job,
      statusCheck.data.failure_reason ||
        "Provider confirmed this transaction as failed",
      statusCheck.raw || null,
    );
    return;
  }

  if (statusCheck.data.confirmed) {
    const secretData = buildSecretData(bill.bill_categories, statusCheck.data);

    const { error: rpcErr } = await supabase.rpc("finalize_bill_transaction", {
      p_bill_transaction_id: bill.id,
      p_final_status: "completed",
      p_provider_reference: statusCheck.data.flw_ref,
      p_provider_response: statusCheck.raw || null,
      p_network: statusCheck.data.network,
      p_secret_data: secretData,
    });
    if (rpcErr) {
      console.error(
        "[BILLS-WORKER] finalize_bill_transaction (completed) RPC failed:",
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
      `[BILLS-WORKER] Job ${job.id} completed — bill transaction ${bill.id} confirmed` +
        (secretData ? " (secret data captured)" : ""),
    );
    return;
  }

  // Still not confirmed — requeue to poll again rather than guessing.
  await failOrRetryJob(
    job,
    `Provider has not confirmed ${bill.provider_tx_ref} yet, will re-check`,
  );
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

    await processBillTransactionJob(claimed.data);
  } catch (err) {
    console.error(
      `[BILLS-WORKER] processOne(${billTransactionId}) threw:`,
      err,
    );
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
 /* const authHeader = req.headers.authorization;
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