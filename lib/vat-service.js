// vat-service.js
// Computes and triggers VAT charged on the FEE portion of a
// successful external transfer — see 014_vat_on_transfer_fees.sql for
// the SQL side (reserve_vat_debit / retry_pending_vat_debits).
//
// Called from exactly two places, both fire-and-forget from the
// caller's perspective:
//   1. transfer-finalization.js, right after a transfer transitions to
//      SUCCESSFUL — fires the initial VAT charge attempt.
//   2. deposit-credit-service.js, right after ANY successful deposit
//      credit — retries whatever VAT charges are still pending on
//      that account.
// VAT charging must NEVER block, delay, or fail the transfer
// completion or deposit crediting it's attached to — every function
// here catches its own errors and only logs/alerts, never throws back
// to its caller.

const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

async function getActiveVatPercentage() {
  const { data, error } = await supabase
    .from("vat_config")
    .select("vat_percentage, is_active")
    .order("updated_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  // Fail SAFE: if config can't be read, or VAT is switched off, charge
  // nothing rather than guessing a rate. A missed VAT charge is
  // recoverable (admin can see it never ran); an invented rate is not.
  if (error || !data || !data.is_active) return 0;
  return Number(data.vat_percentage);
}

/**
 * Fires the initial VAT charge attempt right after a transfer
 * completes. transferId is flutterwave_transfers.id.
 *
 * CONFIRM the column names below (account_id, user_id, fee_amount,
 * transaction_reference) against your actual flutterwave_transfers
 * schema — these are this codebase's most likely names based on every
 * other file that reads that table (external-transfer-worker.js,
 * transfer-webhook-handler.js), not verified against your live schema
 * from here. If fee_amount is stored somewhere else (e.g. only on the
 * transactions_new row, not on flutterwave_transfers), point me at
 * where and I'll adjust this one query.
 */
async function triggerVatForCompletedTransfer(transferId) {
  try {
    const { data: transfer, error } = await supabase
      .from("flutterwave_transfers")
      .select("id, account_id, user_id, fee_amount, transaction_reference")
      .eq("id", transferId)
      .single();

    if (error || !transfer) {
      console.error(
        `[VAT] Could not load transfer ${transferId} for VAT:`,
        error?.message,
      );
      return;
    }
    if (!transfer.fee_amount || Number(transfer.fee_amount) <= 0) {
      return; // no fee was charged on this transfer -> no VAT to charge
    }

    const vatPercentage = await getActiveVatPercentage();
    if (vatPercentage <= 0) return; // VAT off or unreadable — see fail-safe note above

    const vatAmount =
      Math.round(Number(transfer.fee_amount) * (vatPercentage / 100) * 100) /
      100;
    if (vatAmount <= 0) return;

    const { data: result, error: rpcErr } = await supabase.rpc(
      "reserve_vat_debit",
      {
        p_account_id: transfer.account_id,
        p_user_id: transfer.user_id,
        p_source_type: "external_transfer_fee",
        p_source_reference: transfer.transaction_reference,
        p_fee_amount: transfer.fee_amount,
        p_vat_percentage: vatPercentage,
        p_vat_amount: vatAmount,
      },
    );

    if (rpcErr) {
      console.error(
        `[VAT] reserve_vat_debit failed for transfer ${transferId}:`,
        rpcErr.message,
      );
      await supabase.from("reconciliation_alerts").insert({
        user_id: transfer.user_id,
        operational_balance: 0,
        ledger_balance: 0,
        difference: vatAmount,
        status: "open",
        severity: "medium",
        notes: `VAT charge failed to even reserve for transfer ${transfer.transaction_reference}: ${rpcErr.message}`,
      });
      return;
    }

    if (result.status === "pending" && !result.duplicate) {
      console.log(
        `[VAT] Insufficient balance right now for transfer ${transfer.transaction_reference} (₦${vatAmount}) — will retry on next credit`,
      );
    }
  } catch (err) {
    console.error(
      `[VAT] triggerVatForCompletedTransfer(${transferId}) threw:`,
      err,
    );
  }
}

/**
 * Retries any VAT charges still pending on this account. Call after
 * ANY successful credit — deposits from all three providers already
 * call this (see deposit-credit-service.js). Wire an internal-transfer
 * -received RPC into this too if you want a P2P credit to also unblock
 * a pending VAT charge immediately rather than waiting for the user's
 * next deposit.
 */
async function retryPendingVatForAccount(accountId) {
  try {
    const { data: settled, error } = await supabase.rpc(
      "retry_pending_vat_debits",
      {
        p_account_id: accountId,
      },
    );
    if (error) {
      console.error(
        `[VAT] retry_pending_vat_debits failed for account ${accountId}:`,
        error.message,
      );
      return;
    }
    if (settled > 0) {
      console.log(
        `[VAT] Settled ${settled} pending VAT charge(s) for account ${accountId}`,
      );
    }
  } catch (err) {
    console.error(`[VAT] retryPendingVatForAccount(${accountId}) threw:`, err);
  }
}

module.exports = {
  triggerVatForCompletedTransfer,
  retryPendingVatForAccount,
  getActiveVatPercentage,
};
