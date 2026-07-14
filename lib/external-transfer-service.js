// external-transfer-service.js
//
// Replaces the old inline /api/flutterwave/transfer handler in index.js.
//
// Fixes, relative to the old route:
//   - Real atomicity: reservation, transfer row, transaction row, ledger
//     row and the background job are one Postgres transaction inside
//     reserve_external_transfer(), not five separate supabase-js calls
//     wrapped in a no-op begin_transaction()/commit_transaction() RPC.
//   - createTransferLedgerEntries() (undefined, would throw every time)
//     is gone; ledger writes happen inside the SQL function.
//   - Idempotency now checks the same table it's supposed to check
//     (flutterwave_transfers.idempotency_key, UNIQUE), not a misspelled
//     table ("flutterware_idempotency_keys") that was never written to.
//   - The PIN check is now cryptographically bound to this exact
//     transfer's amount/recipient via a single-use token, instead of
//     PIN-verify and transfer being two unrelated API calls.
//   - Flutterwave is called from a queued background job (with the
//     same fire-and-forget-plus-cron-safety-net pattern already used
//     for virtual account creation and deposit webhook retries), not
//     a bare unawaited async call that can be lost if the function
//     freezes before it completes.

const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const flutterwaveService = require("./flutterwave-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const MIN_TRANSFER_AMOUNT = 100;
const MAX_TRANSFER_AMOUNT = 15000000;
const PIN_TOKEN_PURPOSE = "external_transfer";

function contextHash({ account_number, bank_code, amount }) {
  return crypto
    .createHash("sha256")
    .update(`${account_number}:${bank_code}:${Number(amount).toFixed(2)}`)
    .digest("hex");
}

async function getTransferFeePercentage() {
  const { data } = await supabase
    .from("admin_settings")
    .select("setting_value")
    .eq("setting_key", "flutterwave_transfer_fee_percentage")
    .single();
  const pct = data ? parseFloat(data.setting_value) : 0.5;
  return Number.isFinite(pct) ? pct : 0.5;
}

// ------------------------------------------------------------
// POST /api/flutterwave/verify-transfer-pin
// Verifies the user's transfer PIN AND, only on success, mints a
// single-use token bound to the exact recipient + amount the frontend
// is about to submit. The transfer route below requires and consumes
// this token — a bare PIN check with no transfer attached is no longer
// accepted.
// ------------------------------------------------------------
async function handleVerifyTransferPinForTransfer(req, res) {
  const bcrypt = require("bcryptjs");
  const { pin, account_number, bank_code, amount } = req.body;

  if (!pin || pin.length !== 4) {
    return res.status(400).json({ valid: false, error: "Invalid PIN format" });
  }
  if (!account_number || !bank_code || !amount) {
    return res.status(400).json({
      valid: false,
      error:
        "account_number, bank_code and amount are required to bind this PIN check to a transfer",
    });
  }

  const { data: user, error } = await supabase
    .from("users")
    .select("transfer_pin, pin_attempts")
    .eq("id", req.user.id)
    .single();

  if (error) throw error;
  if (!user.transfer_pin) {
    return res.json({ valid: false, needs_setup: true });
  }
  if (user.pin_attempts >= 4) {
    return res.status(403).json({
      valid: false,
      frozen: true,
      error: "Too many incorrect PIN attempts. Account frozen.",
    });
  }

  const isValid = await bcrypt.compare(pin, user.transfer_pin);

  if (!isValid) {
    const newAttempts = (user.pin_attempts || 0) + 1;
    const updates = { pin_attempts: newAttempts, last_pin_attempt: new Date() };
    if (newAttempts >= 4) {
      updates.is_frozen = true;
      updates.freeze_reason =
        "Too many incorrect PIN attempts - Contact support to unfreeze";
      updates.unfreeze_method = "support";
    }
    await supabase.from("users").update(updates).eq("id", req.user.id);
    return res.json({
      valid: false,
      attempts_remaining: 4 - newAttempts,
      frozen: newAttempts >= 4,
    });
  }

  await supabase
    .from("users")
    .update({ pin_attempts: 0, last_pin_attempt: null })
    .eq("id", req.user.id);

  const hash = contextHash({ account_number, bank_code, amount });
  const { data: token, error: tokenErr } = await supabase.rpc(
    "issue_pin_verification_token",
    {
      p_user_id: req.user.id,
      p_purpose: PIN_TOKEN_PURPOSE,
      p_context_hash: hash,
      p_ip_address: req.ip,
      p_ttl_seconds: 180,
    },
  );

  if (tokenErr) {
    console.error("[EXT-TRANSFER] Failed to issue PIN token:", tokenErr);
    return res
      .status(500)
      .json({ valid: false, error: "Could not authorize transfer" });
  }

  res.json({ valid: true, pin_token: token, expires_in: 180 });
}

// ------------------------------------------------------------
// POST /api/flutterwave/transfer
// ------------------------------------------------------------
async function handleCreateTransfer(req, res) {
  const {
    from_account_id,
    account_number,
    bank_code,
    bank_name,
    amount,
    narration,
    beneficiary_name,
    idempotency_key,
    pin_token,
  } = req.body;

  const requestId = req.headers["x-request-id"] || crypto.randomUUID();

  try {
    if (!account_number || !bank_code || !amount || !beneficiary_name) {
      return res.status(400).json({
        error: "Missing required fields",
        code: "MISSING_FIELDS",
        required: ["account_number", "bank_code", "amount", "beneficiary_name"],
      });
    }
    if (!/^\d{10}$/.test(account_number)) {
      return res
        .status(400)
        .json({
          error: "Invalid account number format",
          code: "INVALID_ACCOUNT_NUMBER",
        });
    }
    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res
        .status(400)
        .json({ error: "Invalid amount", code: "INVALID_AMOUNT" });
    }
    if (numericAmount < MIN_TRANSFER_AMOUNT) {
      return res.status(400).json({
        error: `Minimum external transfer amount is ₦${MIN_TRANSFER_AMOUNT.toLocaleString()}`,
        code: "AMOUNT_TOO_LOW",
      });
    }
    if (numericAmount > MAX_TRANSFER_AMOUNT) {
      return res.status(400).json({
        error: `Maximum external transfer amount is ₦${MAX_TRANSFER_AMOUNT.toLocaleString()}`,
        code: "AMOUNT_TOO_HIGH",
      });
    }
    if (!pin_token) {
      return res.status(401).json({
        error: "Transaction PIN verification required",
        code: "PIN_VERIFICATION_REQUIRED",
      });
    }

    // Consume the PIN token: single-use, bound to these exact params,
    // short-lived. If the amount, account number, or bank was changed
    // after the PIN step (e.g. tampered request), this fails.
    const hash = contextHash({
      account_number,
      bank_code,
      amount: numericAmount,
    });
    const { data: pinOk, error: pinErr } = await supabase.rpc(
      "consume_pin_verification_token",
      {
        p_user_id: req.user.id,
        p_token: pin_token,
        p_purpose: PIN_TOKEN_PURPOSE,
        p_context_hash: hash,
      },
    );
    if (pinErr) {
      console.error("[EXT-TRANSFER] PIN token consume error:", pinErr);
      return res
        .status(500)
        .json({
          error: "Could not verify transaction authorization",
          code: "PIN_TOKEN_ERROR",
        });
    }
    if (!pinOk) {
      return res.status(401).json({
        error:
          "PIN verification expired or does not match this transfer. Please re-enter your PIN.",
        code: "PIN_TOKEN_INVALID",
      });
    }

    const { data: account, error: accError } = await supabase
      .from("accounts")
      .select("id")
      .eq("user_id", req.user.id)
      .eq(
        from_account_id ? "id" : "account_type",
        from_account_id || "checking",
      )
      .single();

    if (accError || !account) {
      return res
        .status(404)
        .json({ error: "Source account not found", code: "ACCOUNT_NOT_FOUND" });
    }

    const feePercentage = await getTransferFeePercentage();
    const feeAmount =
      Math.round(numericAmount * (feePercentage / 100) * 100) / 100;

    const { data: result, error: rpcErr } = await supabase.rpc(
      "reserve_external_transfer",
      {
        p_user_id: req.user.id,
        p_account_id: account.id,
        p_amount: numericAmount,
        p_fee_amount: feeAmount,
        p_beneficiary_name: beneficiary_name,
        p_bank_code: bank_code,
        p_bank_name: bank_name || bank_code,
        p_account_number: account_number,
        p_narration: narration || null,
        p_idempotency_key: idempotency_key || null,
        p_ip_address: req.ip,
        p_user_agent: req.headers["user-agent"] || null,
        p_device_fingerprint: req.headers["x-device-fingerprint"] || null,
        p_request_id: requestId,
      },
    );

    if (rpcErr) {
      const message = rpcErr.message || "";
      if (message.includes("INSUFFICIENT_FUNDS")) {
        return res
          .status(400)
          .json({
            error: "Insufficient balance",
            code: "INSUFFICIENT_BALANCE",
          });
      }
      if (message.includes("ACCOUNT_NOT_ACTIVE")) {
        return res
          .status(403)
          .json({ error: "Account is not active", code: "ACCOUNT_NOT_ACTIVE" });
      }
      console.error("[EXT-TRANSFER] reserve_external_transfer failed:", rpcErr);
      return res
        .status(500)
        .json({
          error: "Failed to reserve funds for transfer",
          code: "RESERVE_FAILED",
        });
    }

    if (result.duplicate) {
      return res.json({
        success: true,
        duplicate: true,
        message: "Transfer already submitted",
        data: {
          transfer_id: result.transfer_id,
          transaction_reference: result.transaction_reference,
          reference: result.reference,
          status: result.status,
        },
      });
    }

    await supabase.from("notifications").insert({
      user_id: req.user.id,
      title: "External Transfer Initiated",
      message: `Your transfer of ₦${numericAmount.toLocaleString()} to ${beneficiary_name} has been initiated.`,
      type: "info",
      created_at: new Date().toISOString(),
    });

    // Fast path: kick the worker immediately so most users see this
    // resolve within seconds. If this process freezes/exits before it
    // finishes, the row is still sitting in background_jobs and the
    // cron sweep in external-transfer-worker.js picks it up — same
    // safety-net pattern as virtual account creation.
    const worker = require("./external-transfer-worker");
    worker.processOne(result.transfer_id).catch((err) => {
      console.error("[EXT-TRANSFER] Fast-path worker call failed:", err);
    });

    res.json({
      success: true,
      duplicate: false,
      message: "Transfer initiated successfully",
      data: {
        transfer_id: result.transfer_id,
        transaction_reference: result.transaction_reference,
        reference: result.reference,
        amount: numericAmount,
        fee: feeAmount,
        total_deducted: numericAmount + feeAmount,
        beneficiary_name,
        bank_name: bank_name || bank_code,
        account_number,
        status: "pending",
        new_spendable_balance: result.new_spendable_balance,
        estimated_completion: "1-3 minutes",
      },
    });
  } catch (error) {
    console.error("[EXT-TRANSFER] Unhandled error:", error);
    res
      .status(500)
      .json({
        error: "Transfer failed",
        code: "TRANSFER_FAILED",
        message: error.message,
      });
  }
}

module.exports = {
  handleVerifyTransferPinForTransfer,
  handleCreateTransfer,
};
