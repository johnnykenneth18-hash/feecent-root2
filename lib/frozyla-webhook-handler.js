// frozyla-webhook-handler.js (FEECENT side)
//
// Processes an incoming, already-signature-verified webhook from
// Frozyla about a wallet-funding transaction's status. Mirrors
// bills-webhook-handler.js's processSingleBillPaymentEvent shape
// (lookup by reference, check terminal state, call
// finalize_bill_transaction, log orphans to reconciliation_alerts) —
// separate file because this is a completely different signature
// scheme and payload shape from Flutterwave's webhooks, not a new
// branch of that dispatcher.
//
// NOT the only way a Frozyla transaction gets finalized — bills-worker.js's
// own poll-via-getBillStatus loop (pollAndFinalize) can also finalize
// the same transaction. Both call finalize_bill_transaction(), which
// is itself idempotent (returns duplicate:true on an already-terminal
// transaction), so whichever gets there first wins and the other is a
// harmless no-op. This webhook exists to make that resolution faster
// (push instead of poll), not because polling alone would be incorrect.

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Payload shape (spec section 13):
// { eventId, event, reference, status, amount, currency, timestamp }
async function processFrozylaWebhookEvent(payload) {
  const { eventId, reference, status, amount, currency } = payload;

  if (!eventId || !reference || !status) {
    throw Object.assign(new Error("Webhook payload missing eventId/reference/status"), {
      code: "INVALID_PAYLOAD",
    });
  }

  // Idempotency gate: event_id UNIQUE. Second delivery of the same
  // event hits the unique violation and this function returns early
  // without touching bill_transactions again.
  const { error: logErr } = await supabase.from("frozyla_webhook_logs").insert({
    event_id: eventId,
    event_type: payload.event || "unknown",
    payload,
    signature_valid: true, // caller (frozyla-webhook-routes.js) only invokes this after verification
    status: "received",
  });

  if (logErr) {
    if (logErr.code === "23505") {
      return { duplicate: true };
    }
    throw logErr;
  }

  const { data: bill, error: lookupErr } = await supabase
    .from("bill_transactions")
    .select("id, status, amount, provider_reference, category_id, bill_categories!inner(code)")
    .eq("provider_reference", reference)
    .eq("bill_categories.code", "FROZYLA")
    .maybeSingle();

  if (lookupErr) throw lookupErr;

  if (!bill) {
    // Orphan webhook — same handling as bills-webhook-handler.js's
    // no-matching-transfer case: flag it, never silently drop it.
    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: amount || 0,
      status: "open",
      severity: "high",
      notes: `Frozyla webhook received (event ${eventId}, reference ${reference}, status ${status}) but no matching bill_transactions row found.`,
    });
    await supabase
      .from("frozyla_webhook_logs")
      .update({ status: "no_matching_transaction", processed: true, processed_at: new Date().toISOString() })
      .eq("event_id", eventId);
    return { matched: false };
  }

  if (["completed", "failed"].includes(bill.status)) {
    await supabase
      .from("frozyla_webhook_logs")
      .update({
        status: "already_terminal",
        transaction_reference: bill.id,
        processed: true,
        processed_at: new Date().toISOString(),
      })
      .eq("event_id", eventId);
    return { matched: true, alreadyTerminal: true };
  }

  // Sanity-check the amount before trusting this webhook to finalize
  // anything — spec section 40: never trust a webhook payload without
  // validating it against what we expect. A mismatch here means
  // something is wrong enough that a human should look, not that we
  // should silently finalize with whatever number Frozyla sent.
  if (amount != null && Number(amount) !== Number(bill.amount)) {
    await supabase
      .from("bill_transactions")
      .update({
        reconciliation_status: "mismatch",
        reconciliation_notes: `Webhook amount ${amount} ${currency || ""} does not match bill_transactions.amount ${bill.amount} (event ${eventId})`,
      })
      .eq("id", bill.id);
    await supabase
      .from("frozyla_webhook_logs")
      .update({
        status: "amount_mismatch",
        transaction_reference: bill.id,
        processed: true,
        processed_at: new Date().toISOString(),
      })
      .eq("event_id", eventId);
    return { matched: true, amountMismatch: true };
  }

  if (status === "success") {
    await supabase.rpc("finalize_bill_transaction", {
      p_bill_transaction_id: bill.id,
      p_final_status: "completed",
      p_provider_reference: reference,
      p_provider_response: payload,
    });
  } else if (status === "failed") {
    await supabase.rpc("finalize_bill_transaction", {
      p_bill_transaction_id: bill.id,
      p_final_status: "failed",
      p_provider_reference: reference,
      p_provider_response: payload,
      p_failure_reason: payload.message || "Frozyla reported this funding as failed",
    });
  } else {
    // 'pending' or anything else — leave it in processing, worker's
    // own poll loop keeps checking. Just record that we heard from
    // Frozyla, no finalization action.
    await supabase
      .from("frozyla_webhook_logs")
      .update({ status: "not_final", processed: false })
      .eq("event_id", eventId);
    return { matched: true, finalized: false };
  }

  await supabase
    .from("frozyla_webhook_logs")
    .update({
      status: "completed",
      transaction_reference: bill.id,
      processed: true,
      processed_at: new Date().toISOString(),
    })
    .eq("event_id", eventId);

  return { matched: true, finalized: true };
}

module.exports = { processFrozylaWebhookEvent };