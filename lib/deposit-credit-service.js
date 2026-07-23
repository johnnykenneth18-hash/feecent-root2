// deposit-credit-service.js
// Shared "credit a deposit into an account" logic used by every
// provider's webhook handler — deposit-webhook-service.js's inline
// creditDeposit() for Flutterwave, and paystack-webhook-handler.js /
// monnify-webhook-handler.js below. Calls the same process_deposit()
// RPC and writes the same reconciliation_alerts shape regardless of
// which provider the money came in through, so all three stay
// identical in how they credit a wallet — only how they LOCATE the
// destination account differs per provider (see each handler).
//
// NOTE on process_deposit()'s own parameter names
// (p_flw_transaction_id, p_flw_tx_ref): these predate multi-provider
// support and are generic string/id fields functionally — Paystack's
// and Monnify's own transaction id/reference are passed into them
// exactly the same way Flutterwave's are. Renaming the SQL function's
// parameters is a separate, higher-risk change to a live
// money-crediting RPC and is out of scope here.

const { createClient } = require("@supabase/supabase-js");
const { retryPendingVatForAccount } = require("./vat-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

async function creditDeposit({ account, verified, providerCode }) {
  const { data: result, error: rpcErr } = await supabase.rpc("process_deposit", {
    p_account_id: account.id,
    p_user_id: account.user_id,
    p_amount: verified.amount,
    p_currency: verified.currency || "NGN",
    p_flw_transaction_id: String(verified.id),
    p_flw_tx_ref: verified.tx_ref || verified.reference,
    p_narration: verified.narration || `Deposit via ${providerCode}`,
    p_external_sender_name: verified.sender_name,
    p_external_sender_account: verified.sender_account,
    p_external_sender_bank: verified.sender_bank,
  });

  if (rpcErr) {
    return { success: false, retryable: true, error: rpcErr.message };
  }

  // Fire-and-forget: any deposit is a chance to settle VAT charges
  // that were left pending on this account for insufficient balance —
  // this is the "any day user just credits his account, VAT initiates
  // immediately" behavior. Never blocks or fails the deposit itself.
  retryPendingVatForAccount(account.id).catch((err) =>
    console.error(`[DEPOSIT-CREDIT] VAT retry threw for account ${account.id}:`, err),
  );

  return { success: true, duplicate: result.duplicate, result };
}

async function alertNoMatchingAccount({ providerCode, verified, extra }) {
  await supabase.from("reconciliation_alerts").insert({
    user_id: null,
    operational_balance: 0,
    ledger_balance: 0,
    difference: verified.amount || 0,
    status: "open",
    severity: "high",
    notes: `${providerCode} deposit webhook verified (id ${verified.id}, ref ${verified.tx_ref || verified.reference}) but no matching ACTIVE ${providerCode} account found.${extra ? " " + extra : ""} Amount ${verified.currency || "NGN"} ${verified.amount} requires manual reconciliation.`,
  });
}

module.exports = { creditDeposit, alertNoMatchingAccount };