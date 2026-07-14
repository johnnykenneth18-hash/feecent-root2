// bills-webhook-handler.js
// Handles Flutterwave's `singlebillpayment.status` webhook event —
// the confirmed-outcome push for bill payments, arriving on the SAME
// webhook URL as deposits and transfers (Flutterwave only supports one
// webhook URL per app; deposit-webhook-service.js is the single entry
// point and dispatches by event type — see the patch below).
//
// Sample payload (verified against Flutterwave's current docs):
// {
//   "event": "singlebillpayment.status",
//   "data": {
//     "customer": "+2347065657658",
//     "amount": 200,
//     "network": "MTN",
//     "tx_ref": "...",
//     "flw_ref": "BPUSSD...",
//     "customer_reference": "FEECENT-BILL-<uuid>",  // == our provider_tx_ref
//     "status": "success" | "failed",
//     "message": "..."
//   }
// }
//
// This webhook is the PRIMARY completion signal — faster than the
// worker's own status poll. The worker's poll (bills-worker.js) stays
// in place as the fallback for when a webhook is delayed or dropped.
// Both paths call the same finalize_bill_payment(), which is idempotent
// (returns `duplicate: true` on a second call for the same bill_payment
// id), so there's no race condition between "webhook arrives first" and
// "worker's poll arrives first" — whichever gets there first wins,
// cleanly.

const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

async function processSingleBillPaymentEvent({ data, webhookLogId }) {
  if (!data || !data.customer_reference) {
    throw new Error(
      "Bill payment webhook payload missing data.customer_reference",
    );
  }

  // customer_reference is what we sent Flutterwave as `reference` when
  // creating the bill payment (provider_tx_ref in our own table) — the
  // only reliable join key back to our reservation. flw_ref is
  // Flutterwave's own id and isn't known until after their response.
  const { data: bill, error: lookupErr } = await supabase
    .from("bill_payments")
    .select("id, status")
    .eq("provider_tx_ref", data.customer_reference)
    .single();

  if (lookupErr || !bill) {
    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: data.amount || 0,
      status: "open",
      severity: "high",
      notes: `Bill payment webhook received (flw_ref ${data.flw_ref}, customer_reference ${data.customer_reference}, status ${data.status}) but no matching bill_payments row found.`,
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

  if (["completed", "failed"].includes(bill.status)) {
    // Worker's own poll (or an earlier webhook delivery) already
    // finalized this one — nothing to do, just close out the log.
    if (webhookLogId) {
      await supabase
        .from("flutterwave_webhook_logs")
        .update({
          status: "already_terminal",
          processed: true,
          processed_at: new Date().toISOString(),
        })
        .eq("id", webhookLogId);
    }
    return;
  }

  // Flutterwave's webhook body carries the final status directly
  // (unlike the polling endpoint, which only confirms the record
  // exists). "success"/"failed" here are as documented; anything else
  // is treated as not-yet-final and left for the worker's poll or a
  // later webhook delivery to resolve.
  if (data.status === "success") {
    await supabase.rpc("finalize_bill_payment", {
      p_bill_payment_id: bill.id,
      p_final_status: "completed",
      p_provider_reference: data.flw_ref,
      p_provider_response: data,
      p_network: data.network || null,
    });
  } else if (data.status === "failed") {
    await supabase.rpc("finalize_bill_payment", {
      p_bill_payment_id: bill.id,
      p_final_status: "failed",
      p_provider_reference: data.flw_ref,
      p_provider_response: data,
      p_failure_reason:
        data.message || "Flutterwave reported bill payment as failed",
    });
  } else {
    if (webhookLogId) {
      await supabase
        .from("flutterwave_webhook_logs")
        .update({
          status: "not_final",
          error_message: `Webhook status was '${data.status}'`,
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

module.exports = { processSingleBillPaymentEvent };
