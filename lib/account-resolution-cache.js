// account-resolution-cache.js
// Central service for account name resolution with caching.
// Eliminates redundant provider API calls by maintaining a local
// registry of verified account details populated from:
//   1. Successful provider verifications (Flutterwave/Paystack/Monnify)
//   2. Inbound deposits (sender details from webhook payloads)
//   3. Outbound transfers (receiver details at execution time)
//
// Resolution priority:
//   1. User's personal beneficiaries table (instant, no API)
//   2. account_resolution_cache (instant, no API)
//   3. Provider API (Flutterwave/Paystack/Monnify) — only as fallback
//
// This module is the ONLY place that should call provider verify-account
// endpoints. All other code goes through resolveAccount() here.

const { createClient } = require("@supabase/supabase-js");
const { ServiceRegistry } = require("./service-registry");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Cache TTL: 90 days for verified, 30 days for observed
const CACHE_TTL_VERIFIED_DAYS = 90;
const CACHE_TTL_OBSERVED_DAYS = 30;

/**
 * Primary resolution function. Checks cache before hitting any provider.
 *
 * @param {Object} params
 * @param {string} params.accountNumber - 10-digit NUBAN
 * @param {string} [params.bankCode] - Optional bank code to narrow search
 * @param {string} [params.userId] - Requesting user (for beneficiary lookup)
 * @param {number} [params.maxResults=5] - Max cache results to return
 * @returns {Promise<{
 *   found: boolean,
 *   source: 'beneficiary'|'cache'|'provider'|null,
 *   results: Array<{account_number, bank_code, bank_name, account_name, confidence}>,
 *   needsProviderCall: boolean
 * }>}
 */
async function resolveAccount({
  accountNumber,
  bankCode = null,
  userId = null,
  maxResults = 5,
}) {
  if (!accountNumber || !/^\d{10}$/.test(accountNumber)) {
    return {
      found: false,
      source: null,
      results: [],
      needsProviderCall: false,
      error: "Invalid account number format",
    };
  }

  // ── Step 1: Check user's personal beneficiaries ──────────────────
  if (userId) {
    const beneficiaryResult = await checkUserBeneficiaries(
      userId,
      accountNumber,
      bankCode,
    );
    if (beneficiaryResult.found) {
      return beneficiaryResult;
    }
  }

  // ── Step 2: Check global resolution cache ────────────────────────
  const cacheResult = await checkResolutionCache(
    accountNumber,
    bankCode,
    maxResults,
  );
  if (cacheResult.found) {
    return cacheResult;
  }

  // ── Step 3: Signal that a provider call is needed ────────────────
  return {
    found: false,
    source: null,
    results: [],
    needsProviderCall: true,
  };
}

/**
 * Check user's personal beneficiaries table.
 * Returns immediately if found — no API call needed.
 */
async function checkUserBeneficiaries(userId, accountNumber, bankCode) {
  try {
    let query = supabase
      .from("beneficiaries")
      .select(
        "id, beneficiary_name, account_number, bank_code, bank_name, beneficiary_type, is_pinned, last_used_at, usage_count",
      )
      .eq("user_id", userId)
      .eq("account_number", accountNumber)
      .eq("is_active", true);

    if (bankCode) {
      query = query.eq("bank_code", bankCode);
    }

    const { data, error } = await query.order("last_used_at", {
      ascending: false,
    });

    if (error || !data || data.length === 0) {
      return { found: false, source: null, results: [], needsProviderCall: true };
    }

    return {
      found: true,
      source: "beneficiary",
      results: data.map((b) => ({
        id: b.id,
        account_number: b.account_number,
        bank_code: b.bank_code,
        bank_name: b.bank_name,
        account_name: b.beneficiary_name,
        confidence: "verified",
        is_pinned: b.is_pinned,
        beneficiary_type: b.beneficiary_type,
      })),
      needsProviderCall: false,
    };
  } catch (err) {
    console.error("[ARC] Beneficiary check error:", err);
    return { found: false, source: null, results: [], needsProviderCall: true };
  }
}

/**
 * Check the global account_resolution_cache.
 * Returns all matching banks for the account number (up to maxResults).
 */
async function checkResolutionCache(accountNumber, bankCode, maxResults) {
  try {
    const { data, error } = await supabase.rpc("resolve_account_from_cache", {
      p_account_number: accountNumber,
      p_bank_code: bankCode,
      p_limit: maxResults,
    });

    if (error || !data || data.length === 0) {
      return { found: false, source: null, results: [], needsProviderCall: true };
    }

    return {
      found: true,
      source: "cache",
      results: data.map((r) => ({
        account_number: r.account_number,
        bank_code: r.bank_code,
        bank_name: r.bank_name,
        account_name: r.account_name,
        confidence: r.confidence,
        verified_at: r.verified_at,
      })),
      needsProviderCall: false,
    };
  } catch (err) {
    console.error("[ARC] Cache lookup error:", err);
    return { found: false, source: null, results: [], needsProviderCall: true };
  }
}

/**
 * Call provider API to verify an account, then cache the result.
 * This is the ONLY function that should call provider verify endpoints.
 *
 * @param {Object} params
 * @param {string} params.accountNumber
 * @param {string} params.bankCode
 * @param {string} [params.userId] - User who triggered this (for caching)
 * @returns {Promise<{success: boolean, account_name?: string, error?: string}>}
 */
async function verifyViaProvider({ accountNumber, bankCode, userId = null }) {
  try {
    // Resolve provider via ServiceRegistry
    const { implementation } = await ServiceRegistry.resolve(
      "bank_account_resolution",
    );

    const result = await implementation.verifyAccount({
      accountNumber,
      bankCode,
    });

    if (!result.success) {
      return {
        success: false,
        error: result.error || "Provider verification failed",
      };
    }

    const accountName = result.data.account_name;

    // Cache the successful verification
    await cacheResolution({
      accountNumber,
      bankCode,
      bankName: result.data.bank_name || null,
      accountName,
      source: "provider_api",
      confidence: "verified",
      createdBy: userId,
    });

    return {
      success: true,
      account_name: accountName,
      bank_code: bankCode,
    };
  } catch (err) {
    console.error("[ARC] Provider verification error:", err);
    return {
      success: false,
      error: err.message || "Provider verification failed",
    };
  }
}

/**
 * Store a verified/observed account in the cache.
 * Called after successful provider verification, deposit receipt,
 * or transfer execution.
 */
async function cacheResolution({
  accountNumber,
  bankCode,
  bankName,
  accountName,
  source,
  confidence,
  createdBy = null,
}) {
  try {
    const { error } = await supabase.rpc("cache_account_resolution", {
      p_account_number: accountNumber,
      p_bank_code: bankCode,
      p_bank_name: bankName,
      p_account_name: accountName,
      p_source: source,
      p_confidence: confidence,
      p_created_by: createdBy,
    });

    if (error) {
      console.error("[ARC] Cache write error:", error);
    }
  } catch (err) {
    // Never let caching failure break the main flow
    console.error("[ARC] Cache write exception:", err);
  }
}

/**
 * Record a cache hit (for analytics/freshness tracking).
 */
async function recordHit(accountNumber, bankCode) {
  try {
    await supabase.rpc("record_beneficiary_hit", {
      p_account_number: accountNumber,
      p_bank_code: bankCode,
    });
  } catch (err) {
    // Non-critical, ignore
  }
}

/**
 * Save a beneficiary to the user's personal list.
 * Called after successful external transfer execution.
 */
async function saveBeneficiary({
  userId,
  beneficiaryName,
  accountNumber,
  bankCode,
  bankName,
  beneficiaryType = "external",
  verificationSource = "provider_api",
}) {
  try {
    // Check if already exists
    const { data: existing } = await supabase
      .from("beneficiaries")
      .select("id, usage_count")
      .eq("user_id", userId)
      .eq("account_number", accountNumber)
      .eq("bank_code", bankCode)
      .maybeSingle();

    if (existing) {
      // Update usage
      await supabase
        .from("beneficiaries")
        .update({
          usage_count: (existing.usage_count || 0) + 1,
          last_used_at: new Date().toISOString(),
          beneficiary_name: beneficiaryName, // refresh name
        })
        .eq("id", existing.id);
      return { success: true, updated: true };
    }

    // Insert new
    const { error } = await supabase.from("beneficiaries").insert({
      user_id: userId,
      beneficiary_name: beneficiaryName,
      account_number: accountNumber,
      bank_code: bankCode,
      bank_name: bankName,
      beneficiary_type: beneficiaryType,
      verification_source: verificationSource,
      verified_at: new Date().toISOString(),
      last_used_at: new Date().toISOString(),
      usage_count: 1,
      is_active: true,
    });

    if (error) {
      console.error("[ARC] Save beneficiary error:", error);
      return { success: false, error: error.message };
    }

    return { success: true, created: true };
  } catch (err) {
    console.error("[ARC] Save beneficiary exception:", err);
    return { success: false, error: err.message };
  }
}

/**
 * Get user's recent beneficiaries for the transfer form dropdown.
 * Prioritizes: pinned > recently used > most used.
 */
async function getRecentBeneficiaries(userId, limit = 10) {
  try {
    const { data, error } = await supabase
      .from("beneficiaries")
      .select(
        "id, beneficiary_name, account_number, bank_code, bank_name, beneficiary_type, is_pinned, usage_count, last_used_at",
      )
      .eq("user_id", userId)
      .eq("is_active", true)
      .order("is_pinned", { ascending: false })
      .order("last_used_at", { ascending: false })
      .limit(limit);

    if (error) {
      console.error("[ARC] Get beneficiaries error:", error);
      return [];
    }

    return data || [];
  } catch (err) {
    console.error("[ARC] Get beneficiaries exception:", err);
    return [];
  }
}

/**
 * Store sender details from an inbound deposit.
 * Called by the deposit webhook handler after crediting a wallet.
 */
async function cacheDepositSender({
  senderName,
  senderAccount,
  senderBank,
  senderBankCode,
}) {
  if (!senderName || !senderAccount) return;

  await cacheResolution({
    accountNumber: senderAccount,
    bankCode: senderBankCode || "unknown",
    bankName: senderBank || null,
    accountName: senderName,
    source: "deposit_received",
    confidence: "observed",
  });
}

/**
 * Store receiver details after a successful outbound transfer.
 * Called by the transfer finalization handler.
 */
async function cacheTransferReceiver({
  userId,
  receiverName,
  receiverAccount,
  receiverBankCode,
  receiverBankName,
}) {
  if (!receiverName || !receiverAccount) return;

  // Cache globally
  await cacheResolution({
    accountNumber: receiverAccount,
    bankCode: receiverBankCode,
    bankName: receiverBankName,
    accountName: receiverName,
    source: "transfer_sent",
    confidence: "verified",
    createdBy: userId,
  });

  // Save to user's personal beneficiaries
  await saveBeneficiary({
    userId,
    beneficiaryName: receiverName,
    accountNumber: receiverAccount,
    bankCode: receiverBankCode,
    bankName: receiverBankName,
    beneficiaryType: "external",
    verificationSource: "provider_api",
  });
}

module.exports = {
  resolveAccount,
  verifyViaProvider,
  cacheResolution,
  recordHit,
  saveBeneficiary,
  getRecentBeneficiaries,
  cacheDepositSender,
  cacheTransferReceiver,
};