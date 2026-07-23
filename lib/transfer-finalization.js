// transfer-finalization.js
// Shared "we have a verified, final status from a transfer provider —
// now record it" logic. Extracted out of transfer-webhook-handler.js
// (which used to inline this only for Flutterwave) so
// transfer-webhook-handler.js (Flutterwave), paystack-webhook-handler.js,
// and monnify-webhook-handler.js all finalize transfers through the
// exact same, single path instead of three copies that could quietly
// drift apart from each other — which is precisely the bug class
// transfer-webhook-handler.js's own header comment describes
// happening once already with a duplicated finalize implementation.
//
// complete_external_transfer() / fail_external_transfer() remain the
// only RPCs allowed to convert a reservation into a real debit or
// release it, regardless of which provider's webhook triggered the
// call.

const { createClient } = require("@supabase/supabase-js");
const { triggerVatForCompletedTransfer } = require("./vat-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

async function alertFinalizeFailure(transferId, rpcName, rpcErr, knownStatus, providerCode) {
  console.error(
    `[TRANSFER-FINALIZE] ${rpcName} failed for transfer ${transferId} (${providerCode} confirmed ${knownStatus}):`,
    rpcErr,
  );
  await supabase.from("reconciliation_alerts").insert({
    user_id: null,
    operational_balance: 0,
    ledger_balance: 0,
    difference: 0,
    status: "open",
    severity: "critical",
    notes: `${rpcName} failed for transfer ${transferId} even though ${providerCode} confirmed status ${knownStatus}. The reservation was NOT converted to a real debit/release -- do not assume either outcome, verify and reconcile manually. DB error: ${rpcErr.message}`,
  });
}

/**
 * @param {string} reference - transaction_reference WE generated and
 *   sent to the provider (matches flutterwave_transfers.transaction_reference)
 * @param {object} verified - { id, status: 'SUCCESSFUL'|'FAILED'|other, amount, complete_message }
 * @param {string} providerCode - which provider's webhook this came from, for logging/alerts only
 * @param {function} [webhookLogUpdate] - optional async (fields) => void, to update that provider's own webhook log row
 */
async function finalizeVerifiedTransfer({ reference, verified, providerCode, webhookLogUpdate }) {
  const { data: transfer, error: lookupErr } = await supabase
    .from("flutterwave_transfers")
    .select("id, status")
    .eq("transaction_reference", reference)
    .single();

  if (lookupErr || !transfer) {
    await supabase.from("reconciliation_alerts").insert({
      user_id: null,
      operational_balance: 0,
      ledger_balance: 0,
      difference: verified.amount || 0,
      status: "open",
      severity: "high",
      notes: `${providerCode} transfer webhook verified (id ${verified.id}, ref ${reference}, status ${verified.status}) but no matching flutterwave_transfers row found.`,
    });
    if (webhookLogUpdate) {
      await webhookLogUpdate({
        status: "no_matching_transfer",
        processed: true,
        processed_at: new Date().toISOString(),
      });
    }
    return { matched: false };
  }

  if (["completed", "failed", "reversed", "cancelled"].includes(transfer.status)) {
    if (webhookLogUpdate) {
      await webhookLogUpdate({
        status: "already_terminal",
        processed: true,
        processed_at: new Date().toISOString(),
      });
    }
    return { matched: true, alreadyTerminal: true };
  }

  if (verified.status === "SUCCESSFUL") {
    const { error: rpcErr } = await supabase.rpc("complete_external_transfer", {
      p_transfer_id: transfer.id,
      p_flw_transaction_id: String(verified.id),
      p_flw_status: verified.status,
    });
    if (rpcErr) {
      await alertFinalizeFailure(transfer.id, "complete_external_transfer", rpcErr, verified.status, providerCode);
      throw new Error(`complete_external_transfer failed for transfer ${transfer.id}: ${rpcErr.message}`);
    }

    // Fire-and-forget: VAT on the fee is a separate concern from the
    // transfer itself and must never block or fail this response. If
    // the user can't cover it right now it just sits pending — see
    // vat-service.js / 014_vat_on_transfer_fees.sql.
    triggerVatForCompletedTransfer(transfer.id).catch((err) =>
      console.error(`[TRANSFER-FINALIZE] VAT trigger threw for transfer ${transfer.id}:`, err),
    );
  } else if (verified.status === "FAILED") {
    const { error: rpcErr } = await supabase.rpc("fail_external_transfer", {
      p_transfer_id: transfer.id,
      p_reason: verified.complete_message || `${providerCode} reported transfer as failed`,
      p_failure_code: `${providerCode.toUpperCase()}_FAILED`,
    });
    if (rpcErr) {
      await alertFinalizeFailure(transfer.id, "fail_external_transfer", rpcErr, verified.status, providerCode);
      throw new Error(`fail_external_transfer failed for transfer ${transfer.id}: ${rpcErr.message}`);
    }
  } else {
    // NEW / PENDING — not final yet.
    if (webhookLogUpdate) {
      await webhookLogUpdate({
        status: "not_final",
        error_message: `Verified status was '${verified.status}'`,
      });
    }
    return { matched: true, final: false };
  }

  if (webhookLogUpdate) {
    await webhookLogUpdate({
      status: "completed",
      processed: true,
      processed_at: new Date().toISOString(),
    });
  }
  return { matched: true, final: true };
}

module.exports = { finalizeVerifiedTransfer, alertFinalizeFailure };