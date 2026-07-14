// bills-service.js
// Replaces the old, unsafe /api/user/bill-payment route in index.js.
//
// Same shape as external-transfer-service.js, deliberately:
//   - PIN verification mints a single-use token bound to the exact
//     service_type/customer_identifier/amount being submitted, the
//     same way transfer PINs are bound to recipient+amount. A bare
//     "PIN was correct" with no transaction attached is not accepted.
//   - The actual provider call does NOT happen in this request. This
//     route only validates and reserves funds atomically via
//     reserve_bill_payment(); bills-worker.js does the real work
//     (fast-path immediately after, cron sweep as the safety net).
//   - Idempotency key is required from the client and is expected to
//     be generated once per submission attempt and reused on retry —
//     see the frontend patch for exactly where that happens.

const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { validateBillRequest } = require("./bill-payment-engine");
// bcryptjs, not bcrypt: pure JS, no native binary to mismatch against
// Vercel's build target, fully hash-compatible with existing bcrypt
// hashes. Required lazily inside the handler that actually needs it
// (below), not at module top-level — a missing/broken dependency here
// should only break PIN verification, never take the whole app down
// at cold start the way a top-level require would.

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const PIN_TOKEN_PURPOSE = "bill_payment";

const billPaymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many bill payment requests. Please try again shortly.",
  },
  keyGenerator: (req) => `${req.user?.id || req.ip}`,
});

function contextHash({ service_type, customer_identifier, amount }) {
  return crypto
    .createHash("sha256")
    .update(
      `${service_type}:${customer_identifier}:${Number(amount).toFixed(2)}`,
    )
    .digest("hex");
}

async function getBillPaymentFeePercentage(serviceType) {
  const { data } = await supabase
    .from("admin_settings")
    .select("setting_value")
    .eq(
      "setting_key",
      `bill_payment_fee_percentage_${serviceType.toLowerCase()}`,
    )
    .single();
  const pct = data ? parseFloat(data.setting_value) : 0; // airtime is fee-free by default
  return Number.isFinite(pct) ? pct : 0;
}

// ------------------------------------------------------------
// POST /api/user/bills/verify-pin
// ------------------------------------------------------------
async function handleVerifyBillPaymentPin(req, res) {
  const bcrypt = require("bcryptjs");
  const { pin, service_type, customer_identifier, amount } = req.body;

  if (!pin || pin.length !== 4) {
    return res.status(400).json({ valid: false, error: "Invalid PIN format" });
  }
  if (!service_type || !customer_identifier || !amount) {
    return res.status(400).json({
      valid: false,
      error:
        "service_type, customer_identifier and amount are required to bind this PIN check",
    });
  }

  const validation = validateBillRequest({
    service_type,
    customer_identifier,
    amount,
  });
  if (!validation.valid) {
    return res
      .status(400)
      .json({ valid: false, error: validation.error, code: validation.code });
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

  const hash = contextHash({ service_type, customer_identifier, amount });
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
    console.error("[BILLS] Failed to issue PIN token:", tokenErr);
    return res
      .status(500)
      .json({ valid: false, error: "Could not authorize payment" });
  }

  res.json({ valid: true, pin_token: token, expires_in: 180 });
}

// ------------------------------------------------------------
// POST /api/user/bills
// ------------------------------------------------------------
async function handleCreateBillPayment(req, res) {
  const {
    from_account_id,
    service_type,
    customer_identifier,
    amount,
    idempotency_key,
    pin_token,
  } = req.body;

  try {
    if (!from_account_id || !service_type || !customer_identifier || !amount) {
      return res.status(400).json({
        error: "Missing required fields",
        code: "MISSING_FIELDS",
        required: [
          "from_account_id",
          "service_type",
          "customer_identifier",
          "amount",
        ],
      });
    }
    if (!idempotency_key) {
      return res.status(400).json({
        error: "idempotency_key is required",
        code: "MISSING_IDEMPOTENCY_KEY",
      });
    }

    const validation = validateBillRequest({
      service_type,
      customer_identifier,
      amount,
    });
    if (!validation.valid) {
      const status = validation.code === "NOT_SUPPORTED_YET" ? 501 : 400;
      return res
        .status(status)
        .json({ error: validation.error, code: validation.code });
    }

    const numericAmount = Number(amount);

    if (!pin_token) {
      return res.status(401).json({
        error: "Transaction PIN verification required",
        code: "PIN_VERIFICATION_REQUIRED",
      });
    }

    const hash = contextHash({
      service_type,
      customer_identifier,
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
      console.error("[BILLS] PIN token consume error:", pinErr);
      return res
        .status(500)
        .json({
          error: "Could not verify authorization",
          code: "PIN_TOKEN_ERROR",
        });
    }
    if (!pinOk) {
      return res.status(401).json({
        error:
          "PIN verification expired or does not match this payment. Please re-enter your PIN.",
        code: "PIN_TOKEN_INVALID",
      });
    }

    const feePercentage = await getBillPaymentFeePercentage(service_type);
    const feeAmount =
      Math.round(numericAmount * (feePercentage / 100) * 100) / 100;

    const providerTxRef = `FEECENT-BILL-${crypto.randomUUID()}`;

    const { data: result, error: rpcErr } = await supabase.rpc(
      "reserve_bill_payment",
      {
        p_idempotency_key: idempotency_key,
        p_user_id: req.user.id,
        p_account_id: from_account_id,
        p_provider_code: "flutterwave",
        p_service_type: service_type,
        p_customer_identifier: customer_identifier,
        p_amount: numericAmount,
        p_fee_amount: feeAmount,
        p_provider_tx_ref: providerTxRef,
        p_ip_address: req.ip,
        p_user_agent: req.headers["user-agent"] || null,
        p_device_fingerprint: req.headers["x-device-fingerprint"] || null,
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
      console.error("[BILLS] reserve_bill_payment failed:", rpcErr);
      return res
        .status(500)
        .json({ error: "Failed to reserve funds", code: "RESERVE_FAILED" });
    }

    if (result.duplicate) {
      return res.json({
        success: true,
        duplicate: true,
        message: "Payment already submitted",
        data: {
          bill_payment_id: result.bill_payment_id,
          transaction_reference: result.transaction_reference,
          status: result.status,
        },
      });
    }

    // Fast path — same pattern as external transfers and virtual
    // account creation: kick the worker immediately, cron sweep is the
    // safety net if this process dies before the call returns.
    const worker = require("./bills-worker");
    worker.processOne(result.bill_payment_id).catch((err) => {
      console.error("[BILLS] Fast-path worker call failed:", err);
    });

    res.json({
      success: true,
      duplicate: false,
      message: "Payment initiated",
      data: {
        bill_payment_id: result.bill_payment_id,
        transaction_reference: result.transaction_reference,
        service_type,
        customer_identifier,
        amount: numericAmount,
        fee: feeAmount,
        total_deducted: numericAmount + feeAmount,
        status: "pending",
        new_available_balance: result.available_balance,
      },
    });
  } catch (error) {
    console.error("[BILLS] Unhandled error:", error);
    res
      .status(500)
      .json({
        error: "Bill payment failed",
        code: "BILL_PAYMENT_FAILED",
        message: error.message,
      });
  }
}

module.exports = {
  billPaymentLimiter,
  handleVerifyBillPaymentPin,
  handleCreateBillPayment,
};
