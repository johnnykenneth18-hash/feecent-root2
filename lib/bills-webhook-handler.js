// bills-webhook-handler.js (v2)
// Same singlebillpayment.status handling as before, rebuilt against
// bill_transactions / finalize_bill_transaction. Still the same
// dispatch target from deposit-webhook-service.js's single webhook
// URL — no changes needed there.

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

  const { data: bill, error: lookupErr } = await supabase
    .from("bill_transactions")
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
      notes: `Bill payment webhook received (flw_ref ${data.flw_ref}, customer_reference ${data.customer_reference}, status ${data.status}) but no matching bill_transactions row found.`,
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

  if (data.status === "success") {
    await supabase.rpc("finalize_bill_transaction", {
      p_bill_transaction_id: bill.id,
      p_final_status: "completed",
      p_provider_reference: data.flw_ref,
      p_provider_response: data,
      p_network: data.network || null,
    });
  } else if (data.status === "failed") {
    await supabase.rpc("finalize_bill_transaction", {
      p_bill_transaction_id: bill.id,
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
