// savings-cron.js - COMPLETE FIXED VERSION
const { createClient } = require("@supabase/supabase-js");
const nodemailer = require("nodemailer");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_PORT == 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ==================== LEDGER ====================
// Every balance-affecting movement needs a row in `ledger` (the table
// admin-ledger reconciliation and derive_ledger_balance() read from) in
// addition to the transactions_new business-event row. Deposits already
// did this via process_deposit(); savings deductions/withdrawals never
// did, which is why reconciliation flagged accounts as out of balance
// after any savings activity. Mirrors the single-entry-per-user
// convention process_deposit() uses (one row per user per movement,
// not full double-entry against a pool account).
async function recordLedgerEntry({
  transactionReference,
  userId,
  accountId,
  entryType, // 'DEBIT' | 'CREDIT'
  amount,
  balanceBefore,
  balanceAfter,
  description,
  currency = "NGN",
}) {
  if (!transactionReference) {
    console.error(
      "Ledger entry skipped: no transaction_reference (savings transactions_new insert failed or didn't return one)",
    );
    return false;
  }

  const { error } = await supabase.from("ledger").insert({
    transaction_reference: transactionReference,
    user_id: userId,
    account_id: accountId,
    currency,
    entry_type: entryType,
    amount,
    balance_before: balanceBefore,
    balance_after: balanceAfter,
    running_balance: balanceAfter,
    description,
    status: "completed",
    created_by: userId,
  });

  if (error) {
    console.error("Ledger entry error:", error);
    return false;
  }
  return true;
}

// ==================== SAVINGS POOL ACCOUNTS ====================
// These are the bank's internal accounts tracking where savings money goes

async function getSavingsPoolAccount(accountType) {
  const { data, error } = await supabase
    .from("savings_pool_accounts")
    .select("*")
    .eq("account_type", accountType)
    .single();

  if (error && error.code !== "PGRST116") {
    console.error(`Failed to get ${accountType} pool account:`, error);
  }

  return data;
}

async function updateSavingsPoolBalance(accountType, amount, isCredit) {
  const account = await getSavingsPoolAccount(accountType);
  if (!account) {
    console.error(`Pool account ${accountType} not found`);
    return false;
  }

  const newBalance = isCredit
    ? account.balance + amount
    : account.balance - amount;

  const { error } = await supabase
    .from("savings_pool_accounts")
    .update({
      balance: newBalance,
      available_balance: newBalance,
      last_updated: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq("id", account.id);

  if (error) {
    console.error(`Failed to update ${accountType} pool balance:`, error);
    return false;
  }

  console.log(
    `${accountType} pool balance updated: ₦${account.balance} → ₦${newBalance}`,
  );
  return true;
}

// ==================== HARVEST PLANS (FIXED DEDUCTION) ====================

async function processHarvestPlans() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  console.log(`[${new Date().toISOString()}] Processing Harvest Plans...`);

  const { data: enrollments, error } = await supabase
    .from("user_harvest_enrollments")
    .select(
      `
      *,
      users!inner(id, email, first_name, last_name, is_frozen),
      harvest_plans!inner(daily_amount, duration_days, name, reward_items)
    `,
    )
    .eq("status", "active")
    .eq("auto_save", true);

  if (error) {
    console.error("Harvest plans fetch error:", error);
    return;
  }

  const now = new Date().toISOString();
  const needDeduction = (enrollments || []).filter((e) => {
    if (!e.next_deduction_due) return true;
    return new Date(e.next_deduction_due) <= new Date();
  });

  console.log(
    `Found ${needDeduction.length} harvest enrollments needing deduction out of ${enrollments?.length || 0} total`,
  );

  for (const enrollment of needDeduction) {
    await processSingleHarvestDeduction(enrollment);
  }
}

async function processSingleHarvestDeduction(enrollment) {
  try {
    console.log(`Processing harvest deduction for enrollment ${enrollment.id}`);

    // Get user's primary checking account
    const { data: account, error: accError } = await supabase
      .from("accounts")
      .select("*")
      .eq("user_id", enrollment.user_id)
      .eq("account_type", "checking")
      .single();

    if (accError || !account) {
      console.error(`No account for user ${enrollment.user_id}`);
      await logFailedDeduction(
        enrollment.user_id,
        enrollment.id,
        "harvest",
        enrollment.daily_amount,
      );
      return;
    }

    if (enrollment.users?.is_frozen) {
      console.log(
        `User ${enrollment.user_id} is frozen - pausing harvest deductions`,
      );
      return;
    }

    if (account.available_balance < enrollment.daily_amount) {
      console.log(
        `Insufficient balance for user ${enrollment.user_id} - adding to retry queue`,
      );
      await addToRetryQueue(
        enrollment.user_id,
        enrollment.id,
        "harvest",
        enrollment.daily_amount,
      );
      await sendLowBalanceNotification(
        enrollment.users,
        enrollment.harvest_plans?.name || "Harvest Plan",
      );
      return;
    }

    // ========== DEDUCT FROM USER ACCOUNT ==========
    const newBalance = account.balance - enrollment.daily_amount;
    const newAvailable = account.available_balance - enrollment.daily_amount;

    const { error: updateBalanceError } = await supabase
      .from("accounts")
      .update({
        balance: newBalance,
        available_balance: newAvailable,
        updated_at: new Date().toISOString(),
      })
      .eq("id", account.id);

    if (updateBalanceError) {
      console.error(
        `Balance update error for user ${enrollment.user_id}:`,
        updateBalanceError,
      );
      return;
    }

    console.log(
      `✅ Deducted ₦${enrollment.daily_amount} from user ${enrollment.user_id}. New balance: ₦${newAvailable}`,
    );

    // ========== ADD TO HARVEST POOL ACCOUNT ==========
    await updateSavingsPoolBalance(
      "harvest_pool",
      enrollment.daily_amount,
      true,
    );

    // Update enrollment
    const planDuration = enrollment.harvest_plans?.duration_days || 0;
    const newTotalSaved =
      (enrollment.total_saved || 0) + enrollment.daily_amount;
    const newDaysCompleted = (enrollment.days_completed || 0) + 1;
    const isCompleted = newDaysCompleted >= planDuration;

    const nextDeduction = new Date();
    nextDeduction.setDate(nextDeduction.getDate() + 1);
    nextDeduction.setHours(0, 0, 0, 0);

    const { error: updateError } = await supabase
      .from("user_harvest_enrollments")
      .update({
        total_saved: newTotalSaved,
        days_completed: newDaysCompleted,
        last_deduction_date: new Date().toISOString(),
        next_deduction_due: nextDeduction.toISOString(),
        status: isCompleted ? "completed" : "active",
        failed_deductions: 0,
      })
      .eq("id", enrollment.id);

    if (updateError) {
      console.error(
        `Update error for enrollment ${enrollment.id}:`,
        updateError,
      );
      return;
    }

    // Create transaction record
    const { data: txRecord, error: txError } = await supabase
      .from("transactions_new")
      .insert({
        sender_account_id: account.id,
        sender_user_id: enrollment.user_id,
        amount: enrollment.daily_amount,
        description: `Harvest Plan: ${enrollment.harvest_plans?.name || "Harvest Plan"} - Day ${newDaysCompleted}`,
        transaction_type: "savings",
        status: "completed",
        completed_at: new Date().toISOString(),
        metadata: { is_admin_adjusted: false },
      })
      .select("transaction_reference")
      .single();

    if (txError) {
      console.error("Transaction creation error:", txError);
    } else {
      await recordLedgerEntry({
        transactionReference: txRecord.transaction_reference,
        userId: enrollment.user_id,
        accountId: account.id,
        entryType: "DEBIT",
        amount: enrollment.daily_amount,
        balanceBefore: account.balance,
        balanceAfter: newBalance,
        description: `Harvest Plan: ${enrollment.harvest_plans?.name || "Harvest Plan"} - Day ${newDaysCompleted}`,
      });
    }

    // Create savings transaction with pool tracking
    const { error: savingsTxError } = await supabase
      .from("savings_transactions")
      .insert({
        user_id: enrollment.user_id,
        savings_type: "harvest",
        savings_id: enrollment.id,
        amount: enrollment.daily_amount,
        transaction_type: "deposit",
        description: `Auto-save day ${newDaysCompleted}`,
        to_pool_account_id: (await getSavingsPoolAccount("harvest_pool"))?.id,
      });

    if (savingsTxError)
      console.error("Savings transaction error:", savingsTxError);

    console.log(
      `Harvest deduction completed: ₦${enrollment.daily_amount}, Day ${newDaysCompleted}/${planDuration}`,
    );

    if (isCompleted) {
      await sendHarvestCompletionNotification(enrollment);
    }
  } catch (error) {
    console.error(
      `Harvest deduction error for user ${enrollment.user_id}:`,
      error,
    );
    await logFailedDeduction(
      enrollment.user_id,
      enrollment.id,
      "harvest",
      enrollment.daily_amount,
    );
  }
}

// ==================== FIXED SAVINGS ====================

async function processFixedSavings() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const { data: savings, error } = await supabase
    .from("fixed_savings")
    .select(
      `
      *,
      users!inner(id, email, first_name, last_name, is_frozen)
    `,
    )
    .eq("status", "active")
    .eq("auto_save", true)
    .lt("last_deduction_date", today.toISOString())
    .limit(100);

  if (error) {
    console.error("Fixed savings fetch error:", error);
    return;
  }

  for (const saving of savings || []) {
    await processSingleFixedDeduction(saving);
  }
}

async function processSingleFixedDeduction(saving) {
  try {
    const dailyAmount = saving.daily_amount;

    if (!dailyAmount || dailyAmount <= 0) {
      console.error(`Invalid daily amount for fixed savings ${saving.id}`);
      return;
    }

    const { data: account, error: accError } = await supabase
      .from("accounts")
      .select("*")
      .eq("user_id", saving.user_id)
      .eq("account_type", "checking")
      .single();

    if (accError || !account) {
      console.error(`No account for user ${saving.user_id}`);
      await addToRetryQueue(saving.user_id, saving.id, "fixed", dailyAmount);
      return;
    }

    if (saving.users?.is_frozen) return;

    if (account.available_balance < dailyAmount) {
      console.log(
        `Insufficient balance for user ${saving.user_id} - adding to retry queue`,
      );
      await addToRetryQueue(saving.user_id, saving.id, "fixed", dailyAmount);
      await sendLowBalanceNotification(saving.users, "Fixed Savings");
      return;
    }

    // ========== DEDUCT FROM USER ACCOUNT ==========
    const newBalance = account.balance - dailyAmount;
    const newAvailable = account.available_balance - dailyAmount;

    const { error: updateBalanceError } = await supabase
      .from("accounts")
      .update({
        balance: newBalance,
        available_balance: newAvailable,
        updated_at: new Date().toISOString(),
      })
      .eq("id", account.id);

    if (updateBalanceError) {
      console.error(
        `Balance update error for user ${saving.user_id}:`,
        updateBalanceError,
      );
      return;
    }

    console.log(
      `✅ Deducted ₦${dailyAmount} from user ${saving.user_id} for Fixed Savings`,
    );

    // ========== ADD TO FIXED SAVINGS POOL ACCOUNT ==========
    await updateSavingsPoolBalance("fixed_pool", dailyAmount, true);

    const newCurrentSaved = (saving.current_saved || 0) + dailyAmount;
    const isMatured = new Date() >= new Date(saving.maturity_date);

    const { error: updateError } = await supabase
      .from("fixed_savings")
      .update({
        current_saved: newCurrentSaved,
        last_deduction_date: new Date().toISOString(),
        status: isMatured ? "matured" : "active",
      })
      .eq("id", saving.id);

    if (updateError) {
      console.error(
        `Update error for fixed savings ${saving.id}:`,
        updateError,
      );
      return;
    }

    // Create transaction record
    const fixedDescription = `Fixed Savings Deposit - Day ${Math.ceil(newCurrentSaved / dailyAmount)} of 30`;
    const { data: txRecord, error: txError } = await supabase
      .from("transactions_new")
      .insert({
        sender_account_id: account.id,
        sender_user_id: saving.user_id,
        amount: dailyAmount,
        description: fixedDescription,
        transaction_type: "savings",
        status: "completed",
        completed_at: new Date().toISOString(),
      })
      .select("transaction_reference")
      .single();

    if (txError) {
      console.error("Transaction creation error:", txError);
    } else {
      await recordLedgerEntry({
        transactionReference: txRecord.transaction_reference,
        userId: saving.user_id,
        accountId: account.id,
        entryType: "DEBIT",
        amount: dailyAmount,
        balanceBefore: account.balance,
        balanceAfter: newBalance,
        description: fixedDescription,
      });
    }

    // Create savings transaction with pool tracking
    const { error: savingsTxError } = await supabase
      .from("savings_transactions")
      .insert({
        user_id: saving.user_id,
        savings_type: "fixed",
        savings_id: saving.id,
        amount: dailyAmount,
        transaction_type: "deposit",
        description: "Daily fixed savings deposit",
        to_pool_account_id: (await getSavingsPoolAccount("fixed_pool"))?.id,
      });

    if (savingsTxError)
      console.error("Savings transaction error:", savingsTxError);

    console.log(
      `Fixed savings deduction completed for user ${saving.user_id}: ₦${dailyAmount}`,
    );

    if (isMatured) {
      await sendFixedMaturityNotification(saving);
    }
  } catch (error) {
    console.error(`Fixed savings error for user ${saving.user_id}:`, error);
    await addToRetryQueue(
      saving.user_id,
      saving.id,
      "fixed",
      saving.daily_amount,
    );
  }
}

// ==================== SAVEBOX SAVINGS ====================

async function processSaveboxSavings() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const { data: savings, error } = await supabase
    .from("savebox_savings")
    .select(
      `
      *,
      users!inner(id, email, first_name, last_name, is_frozen)
    `,
    )
    .eq("status", "active")
    .eq("auto_save", true)
    .lt("last_deduction_date", today.toISOString())
    .limit(100);

  if (error) {
    console.error("Savebox savings fetch error:", error);
    return;
  }

  for (const saving of savings || []) {
    await processSingleSaveboxDeduction(saving);
  }
}

async function processSingleSaveboxDeduction(saving) {
  try {
    const dailyAmount = saving.daily_amount;

    if (!dailyAmount || dailyAmount <= 0) {
      console.error(`Invalid daily amount for savebox savings ${saving.id}`);
      return;
    }

    const { data: account, error: accError } = await supabase
      .from("accounts")
      .select("*")
      .eq("user_id", saving.user_id)
      .eq("account_type", "checking")
      .single();

    if (accError || !account) {
      console.error(`No account for user ${saving.user_id}`);
      await addToRetryQueue(saving.user_id, saving.id, "savebox", dailyAmount);
      return;
    }

    if (saving.users?.is_frozen) return;

    if (account.available_balance < dailyAmount) {
      console.log(
        `Insufficient balance for user ${saving.user_id} - adding to retry queue`,
      );
      await addToRetryQueue(saving.user_id, saving.id, "savebox", dailyAmount);
      await sendLowBalanceNotification(saving.users, "SaveBox");
      return;
    }

    // ========== DEDUCT FROM USER ACCOUNT ==========
    const newBalance = account.balance - dailyAmount;
    const newAvailable = account.available_balance - dailyAmount;

    const { error: updateBalanceError } = await supabase
      .from("accounts")
      .update({
        balance: newBalance,
        available_balance: newAvailable,
        updated_at: new Date().toISOString(),
      })
      .eq("id", account.id);

    if (updateBalanceError) {
      console.error(
        `Balance update error for user ${saving.user_id}:`,
        updateBalanceError,
      );
      return;
    }

    console.log(
      `✅ Deducted ₦${dailyAmount} from user ${saving.user_id} for SaveBox`,
    );

    // ========== ADD TO SAVEBOX POOL ACCOUNT ==========
    await updateSavingsPoolBalance("savebox_pool", dailyAmount, true);

    const newCurrentSaved = (saving.current_saved || 0) + dailyAmount;
    const isCompleted =
      new Date() >= new Date(saving.target_date) ||
      newCurrentSaved >= saving.amount;

    const { error: updateError } = await supabase
      .from("savebox_savings")
      .update({
        current_saved: newCurrentSaved,
        last_deduction_date: new Date().toISOString(),
        status: isCompleted ? "completed" : "active",
      })
      .eq("id", saving.id);

    if (updateError) {
      console.error(`Update error for savebox ${saving.id}:`, updateError);
      return;
    }

    // Create transaction
    const saveboxDescription = `SaveBox Savings - Target: ₦${saving.amount?.toFixed(2) || "0.00"}`;
    const { data: txRecord, error: txError } = await supabase
      .from("transactions_new")
      .insert({
        sender_account_id: account.id,
        sender_user_id: saving.user_id,
        amount: dailyAmount,
        description: saveboxDescription,
        transaction_type: "savings",
        status: "completed",
        completed_at: new Date().toISOString(),
      })
      .select("transaction_reference")
      .single();

    if (txError) {
      console.error("Transaction creation error:", txError);
    } else {
      await recordLedgerEntry({
        transactionReference: txRecord.transaction_reference,
        userId: saving.user_id,
        accountId: account.id,
        entryType: "DEBIT",
        amount: dailyAmount,
        balanceBefore: account.balance,
        balanceAfter: newBalance,
        description: saveboxDescription,
      });
    }

    // Create savings transaction with pool tracking
    const { error: savingsTxError } = await supabase
      .from("savings_transactions")
      .insert({
        user_id: saving.user_id,
        savings_type: "savebox",
        savings_id: saving.id,
        amount: dailyAmount,
        transaction_type: "deposit",
        description: "Daily SaveBox deposit",
        to_pool_account_id: (await getSavingsPoolAccount("savebox_pool"))?.id,
      });

    if (savingsTxError)
      console.error("Savings transaction error:", savingsTxError);

    console.log(
      `Savebox deduction completed for user ${saving.user_id}: ₦${dailyAmount}`,
    );

    if (isCompleted) {
      await sendSaveboxCompletionNotification(saving);
    }
  } catch (error) {
    console.error(`Savebox error for user ${saving.user_id}:`, error);
    await addToRetryQueue(
      saving.user_id,
      saving.id,
      "savebox",
      saving.daily_amount,
    );
  }
}

// ==================== TARGET SAVINGS ====================

async function processTargetSavings() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const { data: savings, error } = await supabase
    .from("target_savings")
    .select(
      `
      *,
      users!inner(id, email, first_name, last_name, is_frozen)
    `,
    )
    .eq("status", "active")
    .eq("auto_save", true)
    .eq("target_met", false)
    .eq("withdrawn", false)
    .lt("last_deduction_date", today.toISOString())
    .limit(100);

  if (error) {
    console.error("Target savings fetch error:", error);
    return;
  }

  for (const saving of savings || []) {
    await processSingleTargetDeduction(saving);
  }
}

async function processSingleTargetDeduction(saving) {
  try {
    const dailyAmount = saving.daily_savings_amount;

    if (!dailyAmount || dailyAmount <= 0) {
      console.error(`Invalid daily amount for target savings ${saving.id}`);
      await addToRetryQueue(saving.user_id, saving.id, "target", dailyAmount);
      return;
    }

    const { data: account, error: accError } = await supabase
      .from("accounts")
      .select("*")
      .eq("user_id", saving.user_id)
      .eq("account_type", "checking")
      .single();

    if (accError || !account) {
      console.error(`No account for user ${saving.user_id}`);
      await addToRetryQueue(saving.user_id, saving.id, "target", dailyAmount);
      return;
    }

    if (saving.users?.is_frozen) return;

    if (account.available_balance < dailyAmount) {
      console.log(
        `Insufficient balance for user ${saving.user_id} - adding to retry queue`,
      );
      await addToRetryQueue(saving.user_id, saving.id, "target", dailyAmount);
      await sendLowBalanceNotification(saving.users, "Target Savings");
      return;
    }

    // ========== DEDUCT FROM USER ACCOUNT ==========
    const newBalance = account.balance - dailyAmount;
    const newAvailable = account.available_balance - dailyAmount;

    const { error: updateBalanceError } = await supabase
      .from("accounts")
      .update({
        balance: newBalance,
        available_balance: newAvailable,
        updated_at: new Date().toISOString(),
      })
      .eq("id", account.id);

    if (updateBalanceError) {
      console.error(
        `Balance update error for user ${saving.user_id}:`,
        updateBalanceError,
      );
      return;
    }

    console.log(
      `✅ Deducted ₦${dailyAmount} from user ${saving.user_id} for Target Savings`,
    );

    // ========== ADD TO TARGET SAVINGS POOL ACCOUNT ==========
    await updateSavingsPoolBalance("target_pool", dailyAmount, true);

    const newCurrentSaved = (saving.current_saved || 0) + dailyAmount;
    const newDaysRemaining = (saving.days_remaining || 0) - 1;
    const targetMet = newCurrentSaved >= saving.target_amount;

    const withdrawalDate = new Date(saving.withdrawal_date);
    const now = new Date();
    const canWithdraw = withdrawalDate <= now || targetMet;

    const { error: updateError } = await supabase
      .from("target_savings")
      .update({
        current_saved: newCurrentSaved,
        days_remaining: newDaysRemaining,
        last_deduction_date: new Date().toISOString(),
        target_met: targetMet,
        status: canWithdraw ? "completed" : "active",
      })
      .eq("id", saving.id);

    if (updateError) {
      console.error(`Update error for target ${saving.id}:`, updateError);
      return;
    }

    // Create transaction record
    const targetDescription = `Target Savings - Daily deposit ₦${dailyAmount}`;
    const { data: txRecord, error: txError } = await supabase
      .from("transactions_new")
      .insert({
        sender_account_id: account.id,
        sender_user_id: saving.user_id,
        amount: dailyAmount,
        description: targetDescription,
        transaction_type: "savings",
        status: "completed",
        completed_at: new Date().toISOString(),
      })
      .select("transaction_reference")
      .single();

    if (txError) {
      console.error("Transaction creation error:", txError);
    } else {
      await recordLedgerEntry({
        transactionReference: txRecord.transaction_reference,
        userId: saving.user_id,
        accountId: account.id,
        entryType: "DEBIT",
        amount: dailyAmount,
        balanceBefore: account.balance,
        balanceAfter: newBalance,
        description: targetDescription,
      });
    }

    // Create savings transaction with pool tracking
    const { error: savingsTxError } = await supabase
      .from("savings_transactions")
      .insert({
        user_id: saving.user_id,
        savings_type: "target",
        savings_id: saving.id,
        amount: dailyAmount,
        transaction_type: "deposit",
        description: "Daily target savings deposit",
        to_pool_account_id: (await getSavingsPoolAccount("target_pool"))?.id,
      });

    if (savingsTxError)
      console.error("Savings transaction error:", savingsTxError);

    console.log(
      `Target savings deduction completed for user ${saving.user_id}: ₦${dailyAmount}, Total: ₦${newCurrentSaved}`,
    );

    if (targetMet || canWithdraw) {
      await sendTargetCompletionNotification(saving);
    }
  } catch (error) {
    console.error(`Target savings error for user ${saving.user_id}:`, error);
    await addToRetryQueue(
      saving.user_id,
      saving.id,
      "target",
      saving.daily_savings_amount,
    );
  }
}

// ==================== WITHDRAWAL FROM SAVINGS (CRITICAL FIX) ====================

async function processSavingsWithdrawal(
  savingsType,
  savingsId,
  userId,
  amount,
  feeAmount = 0,
) {
  try {
    console.log(
      `Processing withdrawal: Type=${savingsType}, User=${userId}, Amount=${amount}, Fee=${feeAmount}`,
    );

    // Determine pool account type
    let poolType = "";
    switch (savingsType) {
      case "fixed":
        poolType = "fixed_pool";
        break;
      case "savebox":
        poolType = "savebox_pool";
        break;
      case "target":
        poolType = "target_pool";
        break;
      case "spare_change":
        poolType = "spare_change_pool";
        break;
      case "harvest":
        // Harvest withdrawals are handled separately via admin approval
        // They return money from harvest_pool to user
        poolType = "harvest_pool";
        break;
      default:
        console.error(`Unknown savings type for withdrawal: ${savingsType}`);
        return false;
    }

    // Get the savings pool account
    const poolAccount = await getSavingsPoolAccount(poolType);
    if (!poolAccount) {
      console.error(`Pool account not found: ${poolType}`);
      return false;
    }

    // Check if pool has sufficient funds
    if (poolAccount.balance < amount) {
      console.error(
        `Insufficient funds in ${poolType}. Available: ₦${poolAccount.balance}, Required: ₦${amount}`,
      );
      return false;
    }

    // Get user's checking account
    const { data: userAccount, error: accError } = await supabase
      .from("accounts")
      .select("*")
      .eq("user_id", userId)
      .eq("account_type", "checking")
      .single();

    if (accError || !userAccount) {
      console.error(`User account not found for ${userId}`);
      return false;
    }

    // ========== ADD MONEY TO USER ACCOUNT ==========
    const netAmount = amount - feeAmount;
    const newUserBalance = userAccount.balance + netAmount;
    const newUserAvailable = userAccount.available_balance + netAmount;

    const { error: updateUserBalanceError } = await supabase
      .from("accounts")
      .update({
        balance: newUserBalance,
        available_balance: newUserAvailable,
        updated_at: new Date().toISOString(),
      })
      .eq("id", userAccount.id);

    if (updateUserBalanceError) {
      console.error(`Failed to update user balance:`, updateUserBalanceError);
      return false;
    }

    console.log(
      `✅ Added ₦${netAmount} to user ${userId}. New balance: ₦${newUserAvailable}`,
    );

    // ========== DEDUCT FROM SAVINGS POOL ACCOUNT ==========
    const newPoolBalance = poolAccount.balance - amount;

    const { error: updatePoolError } = await supabase
      .from("savings_pool_accounts")
      .update({
        balance: newPoolBalance,
        available_balance: newPoolBalance,
        updated_at: new Date().toISOString(),
      })
      .eq("id", poolAccount.id);

    if (updatePoolError) {
      console.error(`Failed to update pool balance:`, updatePoolError);
      // Note: User already got money, but pool deduction failed - need to log this discrepancy
    }

    console.log(
      `✅ Deducted ₦${amount} from ${poolType}. New pool balance: ₦${newPoolBalance}`,
    );

    // ========== CREATE TRANSACTION RECORD ==========
    const withdrawalDescription = `${savingsType.charAt(0).toUpperCase() + savingsType.slice(1)} Savings Withdrawal${feeAmount > 0 ? ` (Fee: ₦${feeAmount})` : ""}`;
    const { data: txRecord, error: txError } = await supabase
      .from("transactions_new")
      .insert({
        receiver_account_id: userAccount.id,
        receiver_user_id: userId,
        amount: netAmount,
        metadata: { fee_amount: feeAmount },
        description: withdrawalDescription,
        transaction_type: "savings_withdrawal",
        status: "completed",
        completed_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
      })
      .select("transaction_reference")
      .single();

    if (txError) {
      console.error("Transaction creation error:", txError);
    } else {
      await recordLedgerEntry({
        transactionReference: txRecord.transaction_reference,
        userId: userId,
        accountId: userAccount.id,
        entryType: "CREDIT",
        amount: netAmount,
        balanceBefore: userAccount.balance,
        balanceAfter: newUserBalance,
        description: withdrawalDescription,
      });
    }

    // ========== CREATE SAVINGS TRANSACTION RECORD ==========
    const { error: savingsTxError } = await supabase
      .from("savings_transactions")
      .insert({
        user_id: userId,
        savings_type: savingsType,
        savings_id: savingsId,
        amount: amount,
        fee_amount: feeAmount,
        transaction_type: "withdrawal",
        description: `Withdrawn from ${savingsType} savings${feeAmount > 0 ? `, fee: ₦${feeAmount}` : ""}`,
        from_pool_account_id: poolAccount.id,
        processed_by: null,
        processed_at: new Date().toISOString(),
      });

    if (savingsTxError)
      console.error("Savings transaction error:", savingsTxError);

    // ========== CREATE FEE TRANSACTION IF APPLICABLE ==========
    if (feeAmount > 0) {
      const feeAccount = await getSavingsPoolAccount("fee_account");
      if (feeAccount) {
        const newFeeBalance = feeAccount.balance + feeAmount;
        await supabase
          .from("savings_pool_accounts")
          .update({
            balance: newFeeBalance,
            available_balance: newFeeBalance,
            updated_at: new Date().toISOString(),
          })
          .eq("id", feeAccount.id);

        console.log(
          `✅ Added fee ₦${feeAmount} to fee_account. New balance: ₦${newFeeBalance}`,
        );
      }
    }

    // ========== UPDATE SAVINGS RECORD STATUS ==========
    let tableName = "";
    switch (savingsType) {
      case "fixed":
        tableName = "fixed_savings";
        break;
      case "savebox":
        tableName = "savebox_savings";
        break;
      case "target":
        tableName = "target_savings";
        break;
      case "spare_change":
        tableName = "spare_change_savings";
        break;
      case "harvest":
        tableName = "user_harvest_enrollments";
        break;
    }

    if (tableName) {
      await supabase
        .from(tableName)
        .update({
          status: "withdrawn",
          updated_at: new Date().toISOString(),
        })
        .eq("id", savingsId);
    }

    console.log(`Withdrawal completed successfully for user ${userId}`);
    return true;
  } catch (error) {
    console.error(`Withdrawal processing error:`, error);
    return false;
  }
}

// ==================== HELPER FUNCTIONS ====================

async function addToRetryQueue(userId, savingsId, savingsType, amount) {
  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + 1);

  await supabase.from("savings_deduction_queue").insert({
    user_id: userId,
    savings_type: savingsType,
    savings_id: savingsId,
    amount: amount,
    due_date: dueDate,
    attempts: 1,
    status: "pending",
  });
}

async function retryFailedDeductions() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const { data: failedItems, error } = await supabase
    .from("savings_deduction_queue")
    .select("*")
    .eq("status", "pending")
    .lte("due_date", today.toISOString())
    .lt("attempts", 5)
    .limit(50);

  if (error) {
    console.error("Retry queue fetch error:", error);
    return;
  }

  for (const item of failedItems || []) {
    const { data: account, error: accError } = await supabase
      .from("accounts")
      .select("*")
      .eq("user_id", item.user_id)
      .eq("account_type", "checking")
      .single();

    if (accError || !account) continue;

    if (account.available_balance >= item.amount) {
      const newBalance = account.balance - item.amount;
      const newAvailable = account.available_balance - item.amount;

      await supabase
        .from("accounts")
        .update({ balance: newBalance, available_balance: newAvailable })
        .eq("id", account.id);

      const retryDescription = `${item.savings_type.charAt(0).toUpperCase() + item.savings_type.slice(1)} Savings Deposit (retry)`;
      const { data: txRecord, error: txError } = await supabase
        .from("transactions_new")
        .insert({
          sender_account_id: account.id,
          sender_user_id: item.user_id,
          amount: item.amount,
          description: retryDescription,
          transaction_type: "savings",
          status: "completed",
          completed_at: new Date().toISOString(),
        })
        .select("transaction_reference")
        .single();

      if (txError) {
        console.error("Retry transaction creation error:", txError);
      } else {
        await recordLedgerEntry({
          transactionReference: txRecord.transaction_reference,
          userId: item.user_id,
          accountId: account.id,
          entryType: "DEBIT",
          amount: item.amount,
          balanceBefore: account.balance,
          balanceAfter: newBalance,
          description: retryDescription,
        });
      }

      await supabase
        .from("savings_deduction_queue")
        .update({ status: "completed" })
        .eq("id", item.id);

      console.log(
        `Retry successful for ${item.savings_type} savings, user ${item.user_id}`,
      );
    } else {
      await supabase
        .from("savings_deduction_queue")
        .update({ attempts: item.attempts + 1 })
        .eq("id", item.id);
    }
  }
}

async function logFailedDeduction(userId, savingsId, savingsType, amount) {
  await supabase.from("savings_deduction_queue").insert({
    user_id: userId,
    savings_type: savingsType,
    savings_id: savingsId,
    amount: amount,
    due_date: new Date(),
    attempts: 1,
    status: "pending",
  });
}

// ==================== NOTIFICATIONS ====================

async function sendLowBalanceNotification(user, planName) {
  if (!user?.email) return;

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: user.email,
      subject: `Low Balance Alert - ${planName} Savings`,
      html: `
        <h2>⚠️ Low Balance Notification</h2>
        <p>Dear ${user.first_name} ${user.last_name},</p>
        <p>Your ${planName} savings deduction failed due to insufficient funds.</p>
        <p>Please fund your account to continue your savings plan.</p>
        <p><strong>Recommended action:</strong> Add money to your account to avoid missing future deductions.</p>
        <p>Thank you for banking with us.</p>
      `,
    });
  } catch (err) {
    console.error("Email error:", err);
  }

  await supabase.from("notifications").insert({
    user_id: user.id,
    title: "Low Balance Alert",
    message: `Your ${planName} savings deduction failed due to insufficient funds. Please fund your account.`,
    type: "warning",
  });
}

async function sendHarvestCompletionNotification(enrollment) {
  const rewardItems = enrollment.harvest_plans?.reward_items;
  let itemsList = "";
  if (rewardItems) {
    try {
      const items = JSON.parse(rewardItems);
      itemsList = items.map((item) => `<li>${item}</li>`).join("");
    } catch (e) {
      itemsList = "<li>Your reward items</li>";
    }
  }

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: enrollment.users.email,
    subject: "🎉 Harvest Plan Completed!",
    html: `
      <h2>Congratulations!</h2>
      <p>Dear ${enrollment.users.first_name},</p>
      <p>You have successfully completed your Harvest Plan: <strong>${enrollment.harvest_plans?.name}</strong></p>
      <p>Total saved: ₦${(enrollment.total_saved || 0).toFixed(2)}</p>
      <h3>Your Reward Items:</h3>
      <ul>${itemsList}</ul>
      <p>Your reward items will be delivered within 5-7 business days.</p>
      <p>Thank you for saving with us!</p>
    `,
  });
}

async function sendFixedMaturityNotification(saving) {
  const interest = saving.current_saved * (saving.interest_rate / 100);
  const totalWithInterest = (saving.current_saved || 0) + interest;

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: saving.users.email,
    subject: "🔓 Fixed Savings Matured!",
    html: `
      <h2>Your Fixed Savings Has Matured!</h2>
      <p>Dear ${saving.users.first_name},</p>
      <p>Your fixed savings of <strong>₦${(saving.current_saved || 0).toFixed(2)}</strong> has matured.</p>
      <p>Interest earned: <strong>₦${interest.toFixed(2)}</strong></p>
      <p>Total amount available for withdrawal: <strong>₦${totalWithInterest.toFixed(2)}</strong></p>
      <p>You have 2 days for free withdrawal. After that, a small fee may apply.</p>
      <p><a href="${process.env.APP_URL}/dashboard?tab=savings">Click here to withdraw</a></p>
    `,
  });
}

async function sendTargetCompletionNotification(saving) {
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: saving.users.email,
    subject: "🎯 Target Savings Goal Achieved!",
    html: `
      <h2>Congratulations!</h2>
      <p>Dear ${saving.users.first_name},</p>
      <p>You've reached your target savings goal of <strong>₦${saving.target_amount.toFixed(2)}</strong>!</p>
      <p>Your savings are now available for withdrawal with no fees.</p>
      <p><a href="${process.env.APP_URL}/dashboard?tab=savings">Withdraw Now</a></p>
    `,
  });
}

async function sendSaveboxCompletionNotification(saving) {
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: saving.users.email,
    subject: "📦 SaveBox Target Achieved!",
    html: `
      <h2>Congratulations!</h2>
      <p>Dear ${saving.users.first_name},</p>
      <p>You've reached your SaveBox target of <strong>₦${(saving.amount || 0).toFixed(2)}</strong>!</p>
      <p>Total saved: <strong>₦${(saving.current_saved || 0).toFixed(2)}</strong></p>
      <p>Your savings are now available for withdrawal with no fees!</p>
      <p><a href="${process.env.APP_URL}/dashboard?tab=savings">Withdraw Now</a></p>
      <p>Thank you for saving with us!</p>
    `,
  });
}

async function sendDailyNotifications() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const freeWithdrawalDate = new Date();
  freeWithdrawalDate.setDate(freeWithdrawalDate.getDate() + 1);

  const { data: maturingSavings, error } = await supabase
    .from("fixed_savings")
    .select("*, users!inner(id, email, first_name, last_name)")
    .eq("status", "matured")
    .eq("free_withdrawal_used", false)
    .lte("next_free_withdrawal_date", freeWithdrawalDate.toISOString());

  if (!error && maturingSavings) {
    for (const saving of maturingSavings) {
      await supabase.from("notifications").insert({
        user_id: saving.user_id,
        title: "Free Withdrawal Day Reminder",
        message: `Your fixed savings (₦${(saving.current_saved || 0).toFixed(2)}) is available for free withdrawal today!`,
        type: "success",
      });
    }
  }
}

// Export functions for cron job and API routes
module.exports = {
  processAllSavings: async () => {
    console.log(`[${new Date().toISOString()}] Starting savings processing...`);
    await processHarvestPlans();
    await processFixedSavings();
    await processSaveboxSavings();
    await processTargetSavings();
    await retryFailedDeductions();
    await sendDailyNotifications();
    console.log(`[${new Date().toISOString()}] Savings processing completed`);
  },
  processSavingsWithdrawal,
  getSavingsPoolAccount,
  updateSavingsPoolBalance,
};