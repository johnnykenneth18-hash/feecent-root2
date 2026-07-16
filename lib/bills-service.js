// bills-service.js (v2)
// Replaces the previous bills-service.js, which validated against the
// hardcoded PROCESSORS map in bill-payment-engine.js and wrote to
// bill_payments. This version validates/prices via
// bills-catalog-service.js (reading bill_categories/providers/plans/
// pricing) and writes to bill_transactions via
// reserve_bill_transaction().
//
// Request shape changes from the old route:
//   OLD: { service_type, customer_identifier, amount }
//   NEW: { category_code, provider_code, plan_id?, customer_identifier, amount? }
//   (amount is required for variable-amount categories, ignored —
//   plan.selling_price is authoritative — for plan-based ones.)
//
// Everything else — PIN token binding, idempotency, reserve-then-
// worker-processes flow — is unchanged in shape from before.

const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const catalog = require("./bills-catalog-service");

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

function contextHash({ category_code, provider_code, plan_id, customer_identifier, amount }) {
  return crypto
    .createHash("sha256")
    .update(
      `${category_code}:${provider_code}:${plan_id || ""}:${customer_identifier}:${Number(amount || 0).toFixed(2)}`,
    )
    .digest("hex");
}

// ------------------------------------------------------------
// POST /api/user/bills/verify-pin
// ------------------------------------------------------------
async function handleVerifyBillPaymentPin(req, res) {
  const bcrypt = require("bcryptjs");
  const { pin, category_code, provider_code, plan_id, customer_identifier, amount } = req.body;

  if (!pin || pin.length !== 4) {
    return res.status(400).json({ valid: false, error: "Invalid PIN format" });
  }
  if (!category_code || !provider_code || !customer_identifier) {
    return res.status(400).json({
      valid: false,
      error: "category_code, provider_code and customer_identifier are required to bind this PIN check",
    });
  }

  const validation = await catalog.validateAndPriceBillRequest({
    category_code,
    provider_code,
    plan_id,
    customer_identifier,
    amount,
  });
  if (!validation.valid) {
    return res.status(400).json({ valid: false, error: validation.error, code: validation.code });
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
      updates.freeze_reason = "Too many incorrect PIN attempts - Contact support to unfreeze";
      updates.unfreeze_method = "support";
    }
    await supabase.from("users").update(updates).eq("id", req.user.id);
    return res.json({
      valid: false,
      attempts_remaining: 4 - newAttempts,
      frozen: newAttempts >= 4,
    });
  }

  await supabase.from("users").update({ pin_attempts: 0, last_pin_attempt: null }).eq("id", req.user.id);

  const hash = contextHash({ category_code, provider_code, plan_id, customer_identifier, amount });
  const { data: token, error: tokenErr } = await supabase.rpc("issue_pin_verification_token", {
    p_user_id: req.user.id,
    p_purpose: PIN_TOKEN_PURPOSE,
    p_context_hash: hash,
    p_ip_address: req.ip,
    p_ttl_seconds: 180,
  });

  if (tokenErr) {
    console.error("[BILLS] Failed to issue PIN token:", tokenErr);
    return res.status(500).json({ valid: false, error: "Could not authorize payment" });
  }

  res.json({ valid: true, pin_token: token, expires_in: 180 });
}

// ------------------------------------------------------------
// POST /api/user/bills
// ------------------------------------------------------------
async function handleCreateBillPayment(req, res) {
  const {
    from_account_id,
    category_code,
    provider_code,
    plan_id,
    customer_identifier,
    amount,
    idempotency_key,
    pin_token,
  } = req.body;

  try {
    if (!from_account_id || !category_code || !provider_code || !customer_identifier) {
      return res.status(400).json({
        error: "Missing required fields",
        code: "MISSING_FIELDS",
        required: ["from_account_id", "category_code", "provider_code", "customer_identifier"],
      });
    }
    if (!idempotency_key) {
      return res.status(400).json({ error: "idempotency_key is required", code: "MISSING_IDEMPOTENCY_KEY" });
    }

    const validation = await catalog.validateAndPriceBillRequest({
      category_code,
      provider_code,
      plan_id,
      customer_identifier,
      amount,
    });
    if (!validation.valid) {
      const status = ["CATEGORY_NOT_AVAILABLE", "PROVIDER_NOT_AVAILABLE", "PLAN_NOT_AVAILABLE"].includes(validation.code)
        ? 501
        : 400;
      return res.status(status).json({ error: validation.error, code: validation.code });
    }
    const { category, provider, plan, amount: priceAmount, provider_cost, fee_amount, gateway_code, external_biller_code, external_plan_code } = validation.pricing;

    if (!pin_token) {
      return res.status(401).json({ error: "Transaction PIN verification required", code: "PIN_VERIFICATION_REQUIRED" });
    }

    const hash = contextHash({ category_code, provider_code, plan_id, customer_identifier, amount });
    const { data: pinOk, error: pinErr } = await supabase.rpc("consume_pin_verification_token", {
      p_user_id: req.user.id,
      p_token: pin_token,
      p_purpose: PIN_TOKEN_PURPOSE,
      p_context_hash: hash,
    });
    if (pinErr) {
      console.error("[BILLS] PIN token consume error:", pinErr);
      return res.status(500).json({ error: "Could not verify authorization", code: "PIN_TOKEN_ERROR" });
    }
    if (!pinOk) {
      return res.status(401).json({
        error: "PIN verification expired or does not match this payment. Please re-enter your PIN.",
        code: "PIN_TOKEN_INVALID",
      });
    }

    const providerTxRef = `FEECENT-BILL-${crypto.randomUUID()}`;

    const { data: result, error: rpcErr } = await supabase.rpc("reserve_bill_transaction", {
      p_idempotency_key: idempotency_key,
      p_user_id: req.user.id,
      p_account_id: from_account_id,
      p_category_id: category.id,
      p_provider_id: provider.id,
      p_plan_id: plan ? plan.id : null,
      p_gateway_code: gateway_code,
      p_external_biller_code: external_biller_code || null,
      p_external_plan_code: external_plan_code || null,
      p_customer_identifier: customer_identifier,
      p_amount: priceAmount,
      p_provider_cost: provider_cost,
      p_fee_amount: fee_amount,
      p_provider_tx_ref: providerTxRef,
      p_ip_address: req.ip,
      p_user_agent: req.headers["user-agent"] || null,
      p_device_fingerprint: req.headers["x-device-fingerprint"] || null,
    });

    if (rpcErr) {
      const message = rpcErr.message || "";
      if (message.includes("INSUFFICIENT_FUNDS")) {
        return res.status(400).json({ error: "Insufficient balance", code: "INSUFFICIENT_BALANCE" });
      }
      if (message.includes("ACCOUNT_NOT_ACTIVE")) {
        return res.status(403).json({ error: "Account is not active", code: "ACCOUNT_NOT_ACTIVE" });
      }
      if (message.includes("CATEGORY_NOT_AVAILABLE")) {
        return res.status(501).json({ error: `${category.name} is not available right now`, code: "CATEGORY_NOT_AVAILABLE" });
      }
      console.error("[BILLS] reserve_bill_transaction failed:", rpcErr);
      return res.status(500).json({ error: "Failed to reserve funds", code: "RESERVE_FAILED" });
    }

    if (result.duplicate) {
      return res.json({
        success: true,
        duplicate: true,
        message: "Payment already submitted",
        data: {
          bill_transaction_id: result.bill_transaction_id,
          status: result.status,
        },
      });
    }

    // Fast path — cron sweep is the safety net if this process dies
    // before the call returns.
    const worker = require("./bills-worker");
    worker.processOne(result.bill_transaction_id).catch((err) => {
      console.error("[BILLS] Fast-path worker call failed:", err);
    });

    res.json({
      success: true,
      duplicate: false,
      message: "Payment initiated",
      data: {
        bill_transaction_id: result.bill_transaction_id,
        category: category.code,
        provider: provider.code,
        plan: plan ? plan.display_name : null,
        customer_identifier,
        amount: priceAmount,
        fee: fee_amount,
        total_deducted: priceAmount + fee_amount,
        status: "pending",
        new_available_balance: result.available_balance,
      },
    });
  } catch (error) {
    console.error("[BILLS] Unhandled error:", error);
    res.status(500).json({ error: "Bill payment failed", code: "BILL_PAYMENT_FAILED", message: error.message });
  }
}

module.exports = {
  billPaymentLimiter,
  handleVerifyBillPaymentPin,
  handleCreateBillPayment,
};