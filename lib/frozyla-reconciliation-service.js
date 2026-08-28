// frozyla-reconciliation-service.js (FEECENT side)
//
// Periodic cross-check between FEECENT's view of FROZYLA-category
// bill_transactions and Frozyla's actual feecent_funding_requests
// records, via the same GET /status/:reference endpoint
// frozyla-provider.js's getBillStatus() already calls. This is
// deliberately a SEPARATE pass from bills-worker.js's own retry loop:
// that loop exists to move a transaction TOWARD a terminal state;
// this exists to catch cases where FEECENT and Frozyla have already
// BOTH reached a terminal state, but disagree on what it was (spec
// section 17's FEECENT-completed-Frozyla-failed / vice versa cases) —
// something a "still not confirmed, keep retrying" loop wouldn't
// otherwise re-examine once FEECENT itself thinks it's done.
//
// This never corrects a mismatch automatically — it only flags
// bill_transactions.reconciliation_status = 'mismatch' (or 'matched')
// for admin review. Silently "fixing" a discrepancy by picking one
// side's answer is exactly what spec section 17/42 warns against;
// a flagged mismatch with both sides' data attached is more useful to
// a human than a guess.
//
// Call runFrozylaReconciliationSweep() from wherever your existing
// cron dispatcher lives (memory notes an external cron service
// authenticated via `Authorization: Bearer <CRON_SECRET>` — wire this
// in as one more job the same way, e.g. a route like
// POST /api/sys/cron/reconcile-frozyla guarded by that same check).

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);
const frozylaProvider = require("./frozyla-provider");

// Only look at transactions old enough that Frozyla has had a real
// chance to settle (avoids flagging something bills-worker.js's own
// retry loop is still actively working, seconds into its first
// attempt, as a "mismatch").
const MIN_AGE_MINUTES = 10;
// Cap how far back a single sweep looks — this is a periodic catch-up
// check, not a full historical audit; anything older than this either
// already got flagged by an earlier sweep or is stale enough to need
// manual investigation regardless.
const LOOKBACK_HOURS = 72;

async function runFrozylaReconciliationSweep({ limit = 200 } = {}) {
  const cutoff = new Date(Date.now() - MIN_AGE_MINUTES * 60 * 1000).toISOString();
  const lookback = new Date(Date.now() - LOOKBACK_HOURS * 60 * 60 * 1000).toISOString();

  const { data: candidates, error } = await supabase
    .from("bill_transactions")
    .select("id, status, provider_reference, amount, reconciliation_status, bill_categories!inner(code)")
    .eq("bill_categories.code", "FROZYLA")
    .eq("reconciliation_status", "none")
    .lte("created_at", cutoff)
    .gte("created_at", lookback)
    .not("provider_reference", "is", null)
    .limit(limit);

  if (error) throw error;

  const results = { checked: 0, matched: 0, mismatched: 0, errors: 0 };

  for (const bill of candidates || []) {
    results.checked++;
    try {
      const statusCheck = await frozylaProvider.getBillStatus({ reference: bill.provider_reference });

      if (!statusCheck.success) {
        // Couldn't reach Frozyla for this one — leave reconciliation_status
        // as 'none' so the next sweep retries; not a mismatch, just an
        // inconclusive check.
        continue;
      }

      const frozylaTerminal = statusCheck.data.confirmed || statusCheck.data.failed;
      if (!frozylaTerminal) {
        // Frozyla itself hasn't resolved this yet — nothing to compare
        // against terminal-state-wise. Leave for a later sweep.
        continue;
      }

      const feecentSaysCompleted = bill.status === "completed";
      const feecentSaysFailed = bill.status === "failed";
      const frozylaSaysCompleted = statusCheck.data.confirmed;
      const frozylaSaysFailed = statusCheck.data.failed;

      const agree =
        (feecentSaysCompleted && frozylaSaysCompleted) ||
        (feecentSaysFailed && frozylaSaysFailed);

      if (agree) {
        await supabase
          .from("bill_transactions")
          .update({ reconciliation_status: "matched" })
          .eq("id", bill.id);
        results.matched++;
        continue;
      }

      // Disagreement — including the case where FEECENT is still
      // 'processing' (worker gave up retrying / exhausted backoff)
      // while Frozyla has already reached a terminal state. Flag it;
      // do not touch bill_transactions.status here.
      await supabase
        .from("bill_transactions")
        .update({
          reconciliation_status: "mismatch",
          reconciliation_notes:
            `Sweep at ${new Date().toISOString()}: FEECENT status='${bill.status}', ` +
            `Frozyla status='${frozylaSaysCompleted ? "success" : "failed"}' ` +
            `(reference ${bill.provider_reference}).`,
        })
        .eq("id", bill.id);
      results.mismatched++;
    } catch (err) {
      console.error(`[FROZYLA-RECONCILE] Error checking ${bill.provider_reference}:`, err);
      results.errors++;
    }
  }

  return results;
}

module.exports = { runFrozylaReconciliationSweep };