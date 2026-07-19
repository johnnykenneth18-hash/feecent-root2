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

// Tiered fee, admin-editable via the Fee Management screen
// (transfer_fee_tiers table + PUT /api/sys/fee-tiers). Replaces the old
// flat flutterwave_transfer_fee_percentage admin_settings value.
//
// IMPORTANT: this is called for every external transfer, including
// ones that turn out to be internal redirects (see
// detectInternalRecipient() below). The fee must be identical either
// way — the only free path is the Internal Transfer button itself,
// never this one. Do not branch this function on is_internal.
async function calculateExternalTransferFee(amount) {
  const { data, error } = await supabase.rpc(
    "calculate_external_transfer_fee",
    { p_amount: Number(amount) },
  );
  if (error) {
    console.error("[EXT-TRANSFER] Fee calculation RPC failed:", error);
    // Fail safe with a flat, non-zero fee rather than ever charging
    // ₦0 because the fee tiers table/RPC had a problem.
    return 50;
  }
  return Number(data);
}

// ------------------------------------------------------------
// Silent internal-recipient detection.
//
// Feecent users get a real NUBAN at whatever partner bank Flutterwave
// assigned them (accounts.bank_code / bank_name) — never a bank
// literally named "FEECENT" — so bank_name can't be used to spot an
// internal recipient. account_number is globally UNIQUE across every
// Feecent account (see setup.sql), so a match there is authoritative
// on its own, but per spec this only redirects internally when ALL
// THREE line up:
//   1. account_number matches an active Feecent account
//   2. the selected bank_code matches that account's own bank_code
//   3. the resolved/entered beneficiary name matches both the
//      "FEECENT" marker and the actual account holder's name
// Any mismatch on any of the three falls through to a real external
// transfer — Flutterwave will still deliver the money to that account
// over real NIP rails, it's a genuine bank account, so being
// conservative here costs a transfer fee at worst, never money.
// ------------------------------------------------------------
function normalizeName(s) {
  return String(s || "")
    .toUpperCase()
    .replace(/[^A-Z ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function namesLooselyMatch(candidateName, accountHolderFirst, accountHolderLast) {
  const candidate = normalizeName(candidateName);
  if (!candidate.includes("FEECENT")) return false;

  const withoutMarker = candidate.replace("FEECENT", "").trim();
  const first = normalizeName(accountHolderFirst);
  const last = normalizeName(accountHolderLast);
  if (!first || !last) return false;

  return withoutMarker.includes(first) && withoutMarker.includes(last);
}

async function detectInternalRecipient({
  account_number,
  bank_code,
  beneficiary_name,
}) {
  const { data: account, error } = await supabase
    .from("accounts")
    .select(
      "id, user_id, account_number, bank_code, bank_name, status, users!inner(first_name, last_name, kyc_status)",
    )
    .eq("account_number", account_number)
    .eq("status", "active")
    .maybeSingle();

  if (error) {
    console.error("[EXT-TRANSFER] Internal-recipient lookup failed:", error);
    return { isInternal: false };
  }
  if (!account) {
    return { isInternal: false };
  }
  if (
    !account.bank_code ||
    String(account.bank_code).trim().toLowerCase() !==
      String(bank_code).trim().toLowerCase()
  ) {
    return { isInternal: false };
  }
  if (
    !namesLooselyMatch(
      beneficiary_name,
      account.users.first_name,
      account.users.last_name,
    )
  ) {
    return { isInternal: false };
  }

  return {
    isInternal: true,
    receiverAccountId: account.id,
    receiverUserId: account.user_id,
  };
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
      .select("id, users!inner(first_name, last_name)")
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

    // Fee is computed BEFORE we know whether this redirects internally,
    // and used unchanged either way — per spec, the TRANSFER button is
    // never free, only the dedicated Internal Transfer button is. See
    // calculateExternalTransferFee()'s comment.
    const feeAmount = await calculateExternalTransferFee(numericAmount);

    // Narration: recipient banks show whatever's in this field (subject
    // to the CBN/settlement-account caveat below), so lead with the
    // sender's actual name instead of a generic line, and fold any
    // user-supplied description in after it.
    const senderName =
      `${account.users.first_name || ""} ${account.users.last_name || ""}`.trim() ||
      "Feecent User";
    const builtNarration = narration
      ? `${senderName} - ${narration}`
      : senderName;
    // NOTE ON WHAT ACTUALLY REACHES THE RECEIVING BANK: this narration
    // field is what Feecent sends to Flutterwave, but NIP payouts made
    // through an aggregator are typically settled from the aggregator's
    // (or its underlying licensed disbursement partner's) settlement
    // account, and many receiving banks display THAT account's
    // registered name on the alert/statement line rather than the
    // narration text — this is a function of Feecent not yet holding
    // its own CBN payment license/direct NIBSS connection, not a bug in
    // this code. Setting the narration to the sender's name is the
    // correct and complete fix on Feecent's side; whether it's what the
    // recipient ultimately sees depends on Flutterwave/NIBSS/the
    // receiving bank, and that layer isn't something this codebase
    // controls. If direct CBN licensing or a different settlement
    // arrangement changes that later, no code here needs to change —
    // this already sends the right value.

    const internalCheck = await detectInternalRecipient({
      account_number,
      bank_code,
      beneficiary_name,
    });

    let result, rpcErr, isInternal;

    if (internalCheck.isInternal) {
      isInternal = true;
      ({ data: result, error: rpcErr } = await supabase.rpc(
        "reserve_internal_transfer_as_external",
        {
          p_sender_user_id: req.user.id,
          p_sender_account_id: account.id,
          p_receiver_account_id: internalCheck.receiverAccountId,
          p_amount: numericAmount,
          p_fee_amount: feeAmount,
          p_beneficiary_name: beneficiary_name,
          p_description: narration || null,
          p_idempotency_key: idempotency_key || null,
          p_ip_address: req.ip,
          p_user_agent: req.headers["user-agent"] || null,
          p_device_fingerprint: req.headers["x-device-fingerprint"] || null,
          p_request_id: requestId,
        },
      ));
    } else {
      isInternal = false;
      ({ data: result, error: rpcErr } = await supabase.rpc(
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
          p_narration: builtNarration,
          p_idempotency_key: idempotency_key || null,
          p_ip_address: req.ip,
          p_user_agent: req.headers["user-agent"] || null,
          p_device_fingerprint: req.headers["x-device-fingerprint"] || null,
          p_request_id: requestId,
        },
      ));
    }

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
      console.error(
        `[EXT-TRANSFER] reserve${isInternal ? "_internal_transfer_as_external" : "_external_transfer"} failed:`,
        rpcErr,
      );
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

    if (!isInternal) {
      // Fast path: kick the worker immediately so most users see this
      // resolve within seconds. If this process freezes/exits before it
      // finishes, the row is still sitting in background_jobs and the
      // cron sweep in external-transfer-worker.js picks it up — same
      // safety-net pattern as virtual account creation.
      //
      // Internal redirects skip this entirely: reserve_internal_transfer_as_external()
      // already moved the money and marked the transfer 'completed' in
      // the same DB transaction — there's nothing for Flutterwave to do.
      const worker = require("./external-transfer-worker");
      worker.processOne(result.transfer_id).catch((err) => {
        console.error("[EXT-TRANSFER] Fast-path worker call failed:", err);
      });
    }

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
        // Sender sees the same shape and copy either way — "NOTE: user
        // doesn't need to know any difference" from the spec. Internal
        // redirects are already 'completed' (no Flutterwave leg to
        // wait on) but we still report "pending" / the normal
        // estimated_completion window so the UI behaves identically;
        // the status-polling endpoint will simply resolve to
        // "completed" almost immediately for these.
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