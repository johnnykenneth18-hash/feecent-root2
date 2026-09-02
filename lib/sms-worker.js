// lib/sms/sms-worker.js
//
// Processes 'send_sms' background_jobs (queued by sms-service.js).
// Mirrors virtual-account-worker.js's cronHandler shape exactly —
// mounted the same way in index.js:
//
//   app.get("/api/cron/sms-worker", smsWorker.cronHandler);
//
// and driven by the same Vercel cron mechanism as the other workers
// (see vercel.json note in INTEGRATION.md).
//
// One job = one logical SMS. Within a single job, SMSRouter tries
// every eligible provider in priority order (Termii -> Africa's
// Talking -> ...) — that failover happens INSIDE one job execution, not
// across separate job retries. A job is only retried (via
// background_jobs.retry_count/backoff) if the ENTIRE provider chain
// was exhausted (all RETRYABLE/UNKNOWN) or every provider is
// circuit-open. A NON_RETRYABLE outcome (bad number) marks the job
// (and the sms_messages row) permanently failed on the first attempt —
// retrying it would just fail the same way N more times against every
// provider (section 15).

const { createClient } = require("@supabase/supabase-js");
const { SMSRouter, SMSAllProvidersFailedError } = require("./sms-router");
const smsService = require("./sms-service");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const router = new SMSRouter(supabase);

const WORKER_ID = `sms-worker-${process.env.VERCEL_REGION || "local"}-${process.pid}`;
const MAX_JOBS_PER_INVOCATION = parseInt(process.env.SMS_WORKER_BATCH_SIZE || "20", 10);

function backoffMs(retryCount) {
  const base = Math.min(60_000 * 2 ** retryCount, 30 * 60_000); // cap at 30 min
  const jitter = Math.floor(Math.random() * 5_000);
  return base + jitter;
}

async function claimNextJob() {
  const { data, error } = await supabase.rpc("claim_next_job", { p_job_type: "send_sms", p_worker_id: WORKER_ID });
  if (error) throw error;
  return data && data[0] ? data[0] : null;
}

// processOne(jobId) — claims and processes ONE specific job by id,
// regardless of priority ordering. This is what sms-service.js calls
// via waitUntil() right after enqueueing (mirroring
// onboarding-routes.js's `waitUntil(virtualAccountWorker.processOne(id))`
// pattern) so an OTP doesn't sit waiting for the next cron tick —
// the cron (cronHandler, via claimNextJob) remains the safety net for
// anything that doesn't get to run inline (function killed before
// waitUntil resolves, non-Vercel environments, etc).
async function processOne(jobId) {
  // Scoped, single-row version of claim_next_job's locking: only claim
  // if still 'pending' (or due for retry — available_at <= now), so a
  // concurrent cron pass and this inline call can't both process the
  // same job.
  const { data: claimed, error } = await supabase
    .from("background_jobs")
    .update({ status: "processing", locked_at: new Date().toISOString(), locked_by: WORKER_ID })
    .eq("id", jobId)
    .eq("status", "pending")
    .lte("available_at", new Date().toISOString())
    .select()
    .maybeSingle();

  if (error) {
    console.error(`[SMS_WORKER] processOne(${jobId}) claim failed:`, error);
    return;
  }
  if (!claimed) return; // already claimed elsewhere, or not yet due — cron will pick it up

  await processJob(claimed);
}

async function recordAttempt(smsMessageId, attempt) {
  await supabase.from("sms_delivery_attempts").insert({
    sms_message_id: smsMessageId,
    provider: attempt.provider,
    provider_message_id: attempt.providerMessageId || null,
    attempt_number: attempt.attemptNumber,
    status: attempt.status,
    error_category: attempt.errorCategory || null,
    error_code: attempt.errorCode ? String(attempt.errorCode) : null,
    error_message: attempt.errorMessage || null,
    response_ms: attempt.responseMs || null,
    completed_at: new Date().toISOString(),
  });
}

async function processJob(job) {
  const payload = job.payload;
  const smsMessageId = payload.sms_message_id;

  await supabase.from("sms_messages").update({ status: "sending" }).eq("id", smsMessageId);

  const message = smsService.decryptMessage(payload.message_enc);
  const phone = smsService.decryptMessage(payload.phone_enc);

  try {
    const result = await router.sendWithFailover(
      payload.service_code,
      { to: phone, message, reference: smsMessageId },
      (attempt) => recordAttempt(smsMessageId, attempt),
    );

    await supabase
      .from("sms_messages")
      .update({
        status: "sent",
        selected_provider: result.provider,
        provider_message_id: result.providerMessageId,
        sent_at: new Date().toISOString(),
      })
      .eq("id", smsMessageId);

    await supabase.from("background_jobs").update({ status: "completed", completed_at: new Date().toISOString() }).eq("id", job.id);
  } catch (err) {
    const terminal = err instanceof SMSAllProvidersFailedError && err.terminal; // NON_RETRYABLE — a retry can't fix this
    const exhausted = err instanceof SMSAllProvidersFailedError;
    const retryCount = job.retry_count + 1;
    const outOfRetries = retryCount >= job.max_retry;

    if (terminal || (exhausted && outOfRetries)) {
      // Section 15/35: don't mark "delivered" or even ambiguously
      // "unknown" here if we genuinely know it failed everywhere —
      // mark failed. If the LAST attempt in the chain was UNKNOWN
      // (timeout) rather than a definite rejection, the message stays
      // reflecting that specific attempt's status via
      // sms_delivery_attempts even though the message-level status is
      // 'failed' — never silently mark it 'delivered' either way.
      await supabase
        .from("sms_messages")
        .update({ status: "failed", failed_at: new Date().toISOString() })
        .eq("id", smsMessageId);
      await supabase
        .from("background_jobs")
        .update({ status: "failed", last_error: err.message, completed_at: new Date().toISOString() })
        .eq("id", job.id);
      return;
    }

    // Retryable exhaustion (every provider was RETRYABLE/UNKNOWN, or
    // none were eligible e.g. all circuits open) — reschedule the SAME
    // job with backoff+jitter (section 19). sms_messages.status stays
    // 'sending'/'unknown' rather than 'failed' so it isn't mistaken for
    // a terminal outcome by anything reading that table meanwhile.
    await supabase
      .from("sms_messages")
      .update({ status: "unknown" })
      .eq("id", smsMessageId);

    await supabase
      .from("background_jobs")
      .update({
        status: "pending",
        retry_count: retryCount,
        available_at: new Date(Date.now() + backoffMs(retryCount)).toISOString(),
        last_error: err.message,
        locked_at: null,
        locked_by: null,
      })
      .eq("id", job.id);
  }
}

// cronHandler — claims and processes up to MAX_JOBS_PER_INVOCATION
// jobs per invocation, matching virtual-account-worker.js's shape so
// it can sit on the same Vercel cron cadence.
async function cronHandler(req, res) {
  let processed = 0;
  try {
    for (let i = 0; i < MAX_JOBS_PER_INVOCATION; i++) {
      const job = await claimNextJob();
      if (!job) break;
      await processJob(job);
      processed += 1;
    }
    res.json({ ok: true, processed });
  } catch (err) {
    console.error("[SMS_WORKER] cron error:", err);
    res.status(500).json({ ok: false, processed, error: err.message });
  }
}

module.exports = { cronHandler, processJob, processOne, claimNextJob };
