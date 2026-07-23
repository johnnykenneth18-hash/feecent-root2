// virtual-account-worker.js
// Processes `create_virtual_account` jobs from the background_jobs queue.
//
// Two ways this runs:
// 1. Fire-and-forget immediately after a job is enqueued (fast path — most
//    users see their account go ACTIVE within a couple seconds).
// 2. A scheduled sweep (Vercel Cron hitting the exported Express handler)
//    that catches anything the fast path missed and drives retries on their
//    backoff schedule. This is the safety net — required because a
//    fire-and-forget call can itself be lost if the serverless function
//    freezes/exits before it finishes.
//
// CHANGED in this pass: this file used to `require("./flutterwave-service")`
// directly and call it by name — meaning virtual account creation never
// actually went through payment-gateway.js's ProviderRouter (now
// service-registry.js's ServiceRegistry), even though that router existed
// specifically to decide which provider handles "virtual_account". It now
// asks ServiceRegistry.resolve("virtual_account") and records whichever
// provider code actually served the request, instead of writing the
// literal string "flutterwave" — so adding a second virtual-account
// provider later (Paystack/Monnify, per the spec's worked example) is a
// service_routing data change, not a code change here.

const { createClient } = require("@supabase/supabase-js");
const { ServiceRegistry } = require("./service-registry");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const WORKER_ID = `worker-${process.env.VERCEL_REGION || "local"}-${process.pid}`;

// Exponential backoff schedule in minutes, matching the retry strategy spec.
const BACKOFF_MINUTES = [1, 5, 15, 30, 60, 360, 1440];

async function claimJob(jobType) {
  const { data, error } = await supabase.rpc("claim_next_job", {
    p_job_type: jobType,
    p_worker_id: WORKER_ID,
  });

  if (error) {
    console.error("[VA-WORKER] claim_next_job RPC failed:", error);
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

async function markJobFailedOrRetry(job, errorMessage) {
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

    await supabase
      .from("accounts")
      .update({
        creation_status: "FAILED",
        failure_reason: errorMessage,
        retry_count: nextRetryCount,
        last_retry_at: new Date().toISOString(),
      })
      .eq("id", job.payload.account_id);

    await supabase.from("notifications").insert({
      user_id: null,
      type: "admin_alert",
      title: "Virtual account creation failed permanently",
      message: `User ${job.payload.user_id} / account ${job.payload.account_id}: ${errorMessage}`,
      created_at: new Date().toISOString(),
    });

    console.error(
      `[VA-WORKER] Job ${job.id} exhausted retries (${nextRetryCount}/${job.max_retry}): ${errorMessage}`,
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

  await supabase
    .from("accounts")
    .update({
      retry_count: nextRetryCount,
      last_retry_at: new Date().toISOString(),
      failure_reason: errorMessage,
    })
    .eq("id", job.payload.account_id);

  console.warn(
    `[VA-WORKER] Job ${job.id} failed (attempt ${nextRetryCount}/${job.max_retry}), retrying at ${nextAvailableAt.toISOString()}: ${errorMessage}`,
  );
}

async function processCreateVirtualAccountJob(job) {
  const { account_id, user_id, email, bvn, first_name, last_name, phone } =
    job.payload;

  const { data: account, error: fetchErr } = await supabase
    .from("accounts")
    .select("id, creation_status, provider_account_id")
    .eq("id", account_id)
    .single();

  if (fetchErr || !account) {
    await markJobFailedOrRetry(job, `Account ${account_id} not found`);
    return;
  }

  if (account.creation_status === "ACTIVE") {
    await markJobCompleted(job.id);
    return;
  }

  await supabase
    .from("accounts")
    .update({ creation_status: "PROCESSING" })
    .eq("id", account_id);

  // Ask the registry who currently handles virtual_account creation,
  // rather than assuming Flutterwave. See NoProviderConfiguredError
  // catch below for what happens if nothing is routed.
  let implementation, providerCode;
  try {
    ({ implementation, providerCode } = await ServiceRegistry.resolve(
      "virtual_account",
    ));
  } catch (err) {
    await supabase
      .from("accounts")
      .update({ creation_status: "PENDING" })
      .eq("id", account_id);
    await markJobFailedOrRetry(job, err.message);
    return;
  }

  const result = await implementation.createVirtualAccount({
    email,
    bvn,
    firstname: first_name,
    lastname: last_name,
    phonenumber: phone,
    txRef: `FEECENT-VA-${account_id}`,
  });

  if (!result.success) {
    await supabase
      .from("accounts")
      .update({ creation_status: "PENDING" })
      .eq("id", account_id);
    await markJobFailedOrRetry(job, result.error);
    return;
  }

  await supabase
    .from("accounts")
    .update({
      provider: providerCode,
      provider_customer_id: email,
      provider_account_id: result.data.provider_account_id,
      account_number: result.data.account_number,
      bank_name: result.data.bank_name,
      bank_code: result.data.bank_code,
      creation_status: "ACTIVE",
      failure_reason: null,
      updated_at: new Date().toISOString(),
    })
    .eq("id", account_id);

  await supabase.from("audit_logs").insert({
    user_id,
    action: "virtual_account_activated",
    details: {
      account_id,
      account_number: result.data.account_number,
      bank_name: result.data.bank_name,
      provider: providerCode,
    },
    created_at: new Date().toISOString(),
  });

  await supabase.from("notifications").insert({
    user_id,
    type: "account_update",
    title: "Your dedicated account is ready",
    message: `Your Feecent account number ${result.data.account_number} (${result.data.bank_name}) is now active.`,
    created_at: new Date().toISOString(),
  });

  await markJobCompleted(job.id);
  console.log(
    `[VA-WORKER] Job ${job.id} completed — account ${account_id} ACTIVE via ${providerCode}`,
  );
}

async function processOne(jobId) {
  try {
    const { data: job, error } = await supabase
      .from("background_jobs")
      .select("*")
      .eq("id", jobId)
      .eq("status", "pending")
      .single();

    if (error || !job) return;

    const claimed = await supabase
      .from("background_jobs")
      .update({
        status: "processing",
        locked_at: new Date().toISOString(),
        locked_by: WORKER_ID,
      })
      .eq("id", jobId)
      .eq("status", "pending")
      .select()
      .single();

    if (claimed.error || !claimed.data) return;

    await processCreateVirtualAccountJob(claimed.data);
  } catch (err) {
    console.error(`[VA-WORKER] processOne(${jobId}) threw:`, err);
  }
}

async function processPending(jobType = "create_virtual_account", limit = 20) {
  let processed = 0;
  for (let i = 0; i < limit; i++) {
    const job = await claimJob(jobType);
    if (!job) break;
    await processCreateVirtualAccountJob(job);
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