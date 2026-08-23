// savings-generic-engine.js
// The "admin fully defines new logic" engine — processes
// savings_enrollments rows for engine_type='generic' products, driven
// entirely by each product's config (contribution model, duration
// model, completion rule, reward, early withdrawal policy) rather
// than bespoke per-type code.
//
// Does NOT touch, replace, or run alongside the 5 existing engines'
// OWN processing in savings-cron.js — this is a separate, parallel
// system. harvest_plans/user_harvest_enrollments/fixed_savings/
// target_savings/savebox_savings/spare_change_savings keep being
// processed exactly as today, by savings-cron.js, unchanged.
//
// Reuses recordLedgerEntry/getSavingsPoolAccount/updateSavingsPoolBalance
// from savings-cron.js rather than duplicating them, so ledger-entry
// shape can never drift between the two engines.

const { createClient } = require("@supabase/supabase-js");
const {
  recordLedgerEntry,
  getSavingsPoolAccount,
  updateSavingsPoolBalance,
} = require("./savings-cron");
const catalog = require("./savings-catalog-service");

const { notifyAndPush } = require("../../lib/notification-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const POOL_ACCOUNT_TYPE = "generic_savings_pool";

// ------------------------------------------------------------
// Enrollment creation — validates against the product's config,
// snapshots that config onto the enrollment row (so a later admin
// edit to the product never retroactively changes this enrollment's
// terms — same principle bills' pricing snapshot uses), and takes the
// first deposit immediately, mirroring the "Started X savings"
// pattern already used by every existing engine.
// ------------------------------------------------------------
async function createEnrollment({
  userId,
  accountId,
  productCode,
  initialAmount,
  targetAmount,
  targetDate,
}) {
  const product = await catalog.getProductByCode(productCode);
  if (!product || product.engine_type !== "generic") {
    return { success: false, error: "Unknown or non-generic savings product", code: "UNKNOWN_PRODUCT" };
  }
  if (product.status !== "ACTIVE") {
    return {
      success: false,
      error: product.status === "COMING_SOON" ? "This savings type is coming soon" : `${product.name} is not available right now`,
      code: product.status === "MAINTENANCE" ? "PRODUCT_MAINTENANCE" : "PRODUCT_NOT_AVAILABLE",
    };
  }

  if (!product.allow_multiple_per_user) {
    const { data: existing } = await supabase
      .from("savings_enrollments")
      .select("id")
      .eq("user_id", userId)
      .eq("product_id", product.id)
      .in("status", ["active", "matured"])
      .maybeSingle();
    if (existing) {
      return { success: false, error: `You already have an active ${product.name} plan`, code: "ALREADY_ENROLLED" };
    }
  }

  const amount = Number(initialAmount) || 0;
  if (product.min_contribution_amount != null && amount < Number(product.min_contribution_amount)) {
    return { success: false, error: `Minimum amount is ₦${product.min_contribution_amount}`, code: "AMOUNT_TOO_LOW" };
  }
  if (product.max_contribution_amount != null && amount > Number(product.max_contribution_amount)) {
    return { success: false, error: `Maximum amount is ₦${product.max_contribution_amount}`, code: "AMOUNT_TOO_HIGH" };
  }

  // Compute maturity_date from whichever duration_model this product uses.
  let maturityDate = null;
  if (product.duration_model === "fixed_days" && product.duration_days) {
    const d = new Date();
    d.setDate(d.getDate() + product.duration_days);
    maturityDate = d.toISOString().slice(0, 10);
  } else if (product.duration_model === "target_date") {
    if (!targetDate) {
      return { success: false, error: "target_date is required for this savings type", code: "TARGET_DATE_REQUIRED" };
    }
    maturityDate = targetDate;
  }
  // open_ended -> maturityDate stays null, same as spare_change_savings today.

  if (
    (product.completion_rule === "target_amount_reached" || product.completion_rule === "both") &&
    !targetAmount
  ) {
    return { success: false, error: "target_amount is required for this savings type", code: "TARGET_AMOUNT_REQUIRED" };
  }

  // Debit the user's account for the first contribution — locked
  // behind a real balance check, matching every other money-movement
  // path in this codebase.
  const { data: account, error: accErr } = await supabase
    .from("accounts")
    .select("id, balance, available_balance")
    .eq("id", accountId)
    .eq("user_id", userId)
    .single();
  if (accErr || !account) {
    return { success: false, error: "Account not found", code: "ACCOUNT_NOT_FOUND" };
  }
  if (Number(account.available_balance) < amount) {
    return { success: false, error: "Insufficient balance", code: "INSUFFICIENT_BALANCE" };
  }

  const newBalance = Number(account.balance) - amount;
  const newAvailable = Number(account.available_balance) - amount;

  const { error: balErr } = await supabase
    .from("accounts")
    .update({ balance: newBalance, available_balance: newAvailable, updated_at: new Date().toISOString() })
    .eq("id", accountId);
  if (balErr) {
    return { success: false, error: "Failed to debit account", code: "DEBIT_FAILED" };
  }

  const { data: enrollment, error: insErr } = await supabase
    .from("savings_enrollments")
    .insert({
      user_id: userId,
      account_id: accountId,
      product_id: product.id,
      contribution_model: product.contribution_model,
      contribution_amount: product.contribution_amount,
      contribution_percentage: product.contribution_percentage,
      contribution_frequency: product.contribution_frequency,
      duration_model: product.duration_model,
      duration_days: product.duration_days,
      completion_rule: product.completion_rule,
      reward_type: product.reward_type,
      interest_rate: product.interest_rate,
      reward_items: product.reward_items,
      early_withdrawal_policy: product.early_withdrawal_policy,
      early_withdrawal_fee_percent: product.early_withdrawal_fee_percent,
      free_withdrawal_window_days: product.free_withdrawal_window_days,
      target_amount: targetAmount || null,
      target_date: product.duration_model === "target_date" ? targetDate : null,
      current_saved: amount,
      maturity_date: maturityDate,
      next_deduction_due:
        product.contribution_model === "fixed_periodic" ? nextDeductionFrom(product.contribution_frequency) : null,
    })
    .select()
    .single();

  if (insErr) {
    // Roll back the debit — the enrollment insert failing after a
    // real debit would otherwise silently take the user's money with
    // nothing to show for it.
    await supabase
      .from("accounts")
      .update({ balance: account.balance, available_balance: account.available_balance })
      .eq("id", accountId);
    return { success: false, error: "Failed to create enrollment", code: "ENROLLMENT_FAILED" };
  }

  await updateSavingsPoolBalance(POOL_ACCOUNT_TYPE, amount, true);

  const { data: txRecord } = await supabase
    .from("savings_transactions")
    .insert({
      user_id: userId,
      savings_type: "generic",
      savings_id: enrollment.id,
      amount,
      transaction_type: "deposit",
      description: `Started ${product.name} savings`,
    })
    .select("id")
    .single();

  await recordLedgerEntry({
    transactionReference: `SAVINGS-GENERIC-${enrollment.id}`,
    userId,
    accountId,
    entryType: "DEBIT",
    amount,
    balanceBefore: account.balance,
    balanceAfter: newBalance,
    description: `Started ${product.name} savings`,
  });

  return { success: true, enrollment };
}

function nextDeductionFrom(frequency) {
  const d = new Date();
  if (frequency === "weekly") d.setDate(d.getDate() + 7);
  else if (frequency === "monthly") d.setMonth(d.getMonth() + 1);
  else d.setDate(d.getDate() + 1); // daily, default
  return d.toISOString();
}

// ------------------------------------------------------------
// Periodic processing — call from process-savings.js's cron handler
// alongside (not instead of) the existing processAllSavings().
// ------------------------------------------------------------
async function processGenericSavings() {
  console.log(`[${new Date().toISOString()}] Processing generic savings enrollments...`);

  const { data: enrollments, error } = await supabase
    .from("savings_enrollments")
    .select("*, savings_products(name, reward_type)")
    .eq("status", "active")
    .eq("auto_save", true)
    .eq("contribution_model", "fixed_periodic");

  if (error) {
    console.error("[GENERIC-SAVINGS] fetch error:", error);
    return;
  }

  const due = (enrollments || []).filter(
    (e) => !e.next_deduction_due || new Date(e.next_deduction_due) <= new Date(),
  );

  console.log(`[GENERIC-SAVINGS] ${due.length} enrollment(s) due for deduction`);

  for (const enrollment of due) {
    await processSingleDeduction(enrollment);
  }
}

async function processSingleDeduction(enrollment) {
  const { data: account, error: accErr } = await supabase
    .from("accounts")
    .select("*")
    .eq("id", enrollment.account_id)
    .single();

  if (accErr || !account) {
    console.error(`[GENERIC-SAVINGS] No account for enrollment ${enrollment.id}`);
    return;
  }

  const amount = Number(enrollment.contribution_amount) || 0;
  if (amount <= 0) return;

  if (Number(account.available_balance) < amount) {
    await supabase.from("savings_deduction_queue").insert({
      user_id: enrollment.user_id,
      savings_type: "generic",
      savings_id: enrollment.id,
      amount,
      due_date: new Date().toISOString().slice(0, 10),
      attempts: 1,
      status: "pending",
    });
    return;
  }

  const newBalance = Number(account.balance) - amount;
  const newAvailable = Number(account.available_balance) - amount;

  await supabase
    .from("accounts")
    .update({ balance: newBalance, available_balance: newAvailable, updated_at: new Date().toISOString() })
    .eq("id", account.id);

  await updateSavingsPoolBalance(POOL_ACCOUNT_TYPE, amount, true);

  await recordLedgerEntry({
    transactionReference: `SAVINGS-GENERIC-DEDUCT-${enrollment.id}-${Date.now()}`,
    userId: enrollment.user_id,
    accountId: account.id,
    entryType: "DEBIT",
    amount,
    balanceBefore: account.balance,
    balanceAfter: newBalance,
    description: `${enrollment.savings_products?.name || "Savings"} deduction`,
  });

  await supabase.from("savings_transactions").insert({
    user_id: enrollment.user_id,
    savings_type: "generic",
    savings_id: enrollment.id,
    amount,
    transaction_type: "deposit",
    description: `${enrollment.savings_products?.name || "Savings"} auto-deduction`,
  });

  const newCurrentSaved = Number(enrollment.current_saved) + amount;
  const newDaysCompleted = (enrollment.days_completed || 0) + 1;

  const updates = {
    current_saved: newCurrentSaved,
    days_completed: newDaysCompleted,
    last_deduction_date: new Date().toISOString().slice(0, 10),
    next_deduction_due: nextDeductionFrom(enrollment.contribution_frequency),
    updated_at: new Date().toISOString(),
  };

  // Completion check — driven entirely by this enrollment's own
  // snapshotted completion_rule, not a hardcoded per-type check.
  const durationMet =
    enrollment.duration_model === "fixed_days" && newDaysCompleted >= (enrollment.duration_days || Infinity);
  const targetMet =
    enrollment.target_amount != null && newCurrentSaved >= Number(enrollment.target_amount);
  const dateMet = enrollment.maturity_date && new Date(enrollment.maturity_date) <= new Date();

  let isDone = false;
  if (enrollment.completion_rule === "duration_elapsed") isDone = durationMet || dateMet;
  else if (enrollment.completion_rule === "target_amount_reached") isDone = targetMet;
  else if (enrollment.completion_rule === "both") isDone = targetMet && (dateMet || durationMet);

  if (isDone) {
    updates.status = enrollment.reward_type === "interest" ? "matured" : "completed";
    updates.completed_at = new Date().toISOString();
    if (enrollment.free_withdrawal_window_days) {
      const freeDate = new Date();
      freeDate.setDate(freeDate.getDate() + enrollment.free_withdrawal_window_days);
      updates.next_free_withdrawal_date = freeDate.toISOString().slice(0, 10);
    }

    //await supabase.from("notifications").insert
    await notifyAndPush({
      user_id: enrollment.user_id,
      title: "Savings Goal Reached",
      message: `Your ${enrollment.savings_products?.name || "savings"} plan is complete!`,
      type: "success",
    });
  }

  await supabase.from("savings_enrollments").update(updates).eq("id", enrollment.id);
}

// ------------------------------------------------------------
// Withdrawal — enforces the enrollment's own snapshotted
// early_withdrawal_policy.
// ------------------------------------------------------------
async function processWithdrawal({ enrollmentId, userId }) {
  const { data: enrollment, error } = await supabase
    .from("savings_enrollments")
    .select("*, savings_products(name)")
    .eq("id", enrollmentId)
    .eq("user_id", userId)
    .single();

  if (error || !enrollment) {
    return { success: false, error: "Savings plan not found", code: "NOT_FOUND" };
  }
  if (["withdrawn", "cancelled"].includes(enrollment.status)) {
    return { success: false, error: "This plan has already been withdrawn", code: "ALREADY_WITHDRAWN" };
  }

  const isMaturedOrCompleted = ["matured", "completed"].includes(enrollment.status);
  let feePercent = 0;
  let feeReason = null;

  if (enrollment.early_withdrawal_policy === "blocked" && !isMaturedOrCompleted) {
    return { success: false, error: "This savings plan cannot be withdrawn before maturity", code: "WITHDRAWAL_BLOCKED" };
  }

  if (enrollment.early_withdrawal_policy === "fee_percent" && !isMaturedOrCompleted) {
    feePercent = Number(enrollment.early_withdrawal_fee_percent) || 0;
    feeReason = "early withdrawal fee";
  }

  if (enrollment.early_withdrawal_policy === "free_window_then_fee") {
    const withinFreeWindow =
      isMaturedOrCompleted &&
      enrollment.next_free_withdrawal_date &&
      new Date() <= new Date(enrollment.next_free_withdrawal_date);
    if (!isMaturedOrCompleted) {
      feePercent = Number(enrollment.early_withdrawal_fee_percent) || 0;
      feeReason = "early withdrawal fee";
    } else if (!withinFreeWindow) {
      feePercent = Number(enrollment.early_withdrawal_fee_percent) || 0;
      feeReason = "late withdrawal fee (outside free window)";
    }
  }

  let principal = Number(enrollment.current_saved) || 0;
  let interest = 0;
  if (isMaturedOrCompleted && enrollment.reward_type === "interest" && enrollment.interest_rate) {
    interest = principal * (Number(enrollment.interest_rate) / 100);
  }
  const gross = principal + interest;
  const fee = gross * (feePercent / 100);
  const payout = gross - fee;

  const { data: account, error: accErr } = await supabase
    .from("accounts")
    .select("*")
    .eq("id", enrollment.account_id)
    .single();
  if (accErr || !account) {
    return { success: false, error: "Account not found", code: "ACCOUNT_NOT_FOUND" };
  }

  const pool = await getSavingsPoolAccount(POOL_ACCOUNT_TYPE);
  if (pool && Number(pool.available_balance) < payout) {
    return { success: false, error: "Withdrawal temporarily unavailable — please try again shortly", code: "POOL_INSUFFICIENT" };
  }

  const newBalance = Number(account.balance) + payout;
  const newAvailable = Number(account.available_balance) + payout;

  await supabase
    .from("accounts")
    .update({ balance: newBalance, available_balance: newAvailable, updated_at: new Date().toISOString() })
    .eq("id", account.id);

  await updateSavingsPoolBalance(POOL_ACCOUNT_TYPE, payout, false);

  await recordLedgerEntry({
    transactionReference: `SAVINGS-GENERIC-WITHDRAW-${enrollment.id}`,
    userId,
    accountId: account.id,
    entryType: "CREDIT",
    amount: payout,
    balanceBefore: account.balance,
    balanceAfter: newBalance,
    description: `${enrollment.savings_products?.name || "Savings"} withdrawal${feeReason ? ` (${feeReason} applied)` : ""}`,
  });

  await supabase.from("savings_transactions").insert({
    user_id: userId,
    savings_type: "generic",
    savings_id: enrollment.id,
    amount: payout,
    transaction_type: "withdrawal",
    description: `${enrollment.savings_products?.name || "Savings"} withdrawal`,
  });

  await supabase
    .from("savings_enrollments")
    .update({
      status: "withdrawn",
      free_withdrawal_used: true,
      updated_at: new Date().toISOString(),
    })
    .eq("id", enrollment.id);

  return { success: true, payout, fee, interest, principal };
}

module.exports = {
  createEnrollment,
  processGenericSavings,
  processWithdrawal,
  // Exported so savings-cron.js's retryFailedDeductions() can lazy-
  // require it when reprocessing a queued generic-plan deduction,
  // instead of leaving the retry queue to silently skip generic plans.
  processSingleDeduction,
};