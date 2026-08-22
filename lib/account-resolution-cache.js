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
//
// MATCHING KEY: bank_name, not bank_code. Flutterwave never returns a
// bank code on inbound deposits (see cacheDepositSender below), so
// bank_code can't be trusted as an identity column — only bank_name is
// reliably present from every source. bank_code is still stored
// alongside it (needed to actually initiate a payout), and
// resolve_account_from_cache() backfills it from the flutterwave_banks
// table by name whenever a cache row itself doesn't have one, so a
// deposit-observed match still comes back with a real, sendable code.
// See account_resolution_cache_bank_name_fix.sql for the DB-side half
// of this.
//
// TTL: 90 days for 'verified' entries (provider API or a completed
// transfer), 30 days for 'observed' entries (seen only via an inbound
// deposit, never independently verified). Enforced server-side in
// cache_account_resolution()/resolve_account_from_cache() — the
// constants below are kept for reference/logging, not because the JS
// computes expiry itself.

const { createClient } = require("@supabase/supabase-js");
const { ServiceRegistry } = require("./service-registry");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Mirrors the TTL logic inside cache_account_resolution()'s CASE
// expression — kept in sync manually, not read by any query here.
const CACHE_TTL_VERIFIED_DAYS = 90;
const CACHE_TTL_OBSERVED_DAYS = 30;

/**
 * Primary resolution function. Checks cache before hitting any provider.
 *
 * @param {Object} params
 * @param {string} params.accountNumber - 10-digit NUBAN
 * @param {string} [params.bankCode] - Optional bank code, used only for
 *   the personal-beneficiaries lookup (those rows always have a real,
 *   provider-verified code).
 * @param {string} [params.bankName] - Optional bank name, used to narrow
 *   the global cache lookup (the reliable cross-source identity field).
 * @param {string} [params.userId] - Requesting user (for beneficiary lookup)
 * @param {number} [params.maxResults=4] - Max results to return. Also the
 *   hard cap on distinct banks shown to the sender when no bank has been
 *   chosen yet (see "PROBE MODE" below) — the UI never lists more than
 *   4 bank chips.
 * @returns {Promise<{
 *   found: boolean,
 *   source: 'beneficiary'|'cache'|'mixed'|'provider'|null,
 *   results: Array<{account_number, bank_code, bank_name, account_name, confidence}>,
 *   needsProviderCall: boolean
 * }>}
 */
async function resolveAccount({
  accountNumber,
  bankCode = null,
  bankName = null,
  userId = null,
  maxResults = 4,
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

  // ── EXPLICIT MODE: caller already knows which bank (sender tapped a
  // suggested chip, picked one from the full bank list, or is re-typing
  // the account number with a bank already selected). Narrow,
  // authoritative lookup for that ONE account+bank pairing only — never
  // returns a match belonging to a different bank. ────────────────────
  if (bankCode || bankName) {
    if (userId) {
      const beneficiaryResult = await checkUserBeneficiaries(
        userId,
        accountNumber,
        bankCode,
      );
      if (beneficiaryResult.found) {
        const narrowed = narrowToBank(beneficiaryResult.results, bankCode, bankName);
        if (narrowed.length) {
          return { ...beneficiaryResult, results: narrowed };
        }
      }
    }

    const cacheResult = await checkResolutionCache(
      accountNumber,
      bankName,
      maxResults,
    );
    if (cacheResult.found) {
      const narrowed = narrowToBank(cacheResult.results, bankCode, bankName);
      if (narrowed.length) {
        return { ...cacheResult, results: narrowed };
      }
    }

    return {
      found: false,
      source: null,
      results: [],
      needsProviderCall: true,
    };
  }

  // ── PROBE MODE: no bank chosen yet. The same 10-digit account number
  // can legitimately belong to several different banks (Opay, Palmpay,
  // Moniepoint, etc all let customers pick their own digits), so this
  // never guesses a bank on the sender's behalf. Merge personal
  // beneficiaries AND the global cache across every bank we've seen
  // this account number at, dedupe by bank, and hand back up to
  // maxResults distinct banks for the UI to show as tappable chips.
  // Deliberately does NOT stop at the first source that hits — a lone
  // beneficiary match at Opay must not hide a Palmpay match sitting in
  // the global cache. ─────────────────────────────────────────────────
  const merged = new Map(); // key: normalized bank name -> result row
  let sawBeneficiary = false;
  let sawCache = false;

  if (userId) {
    const beneficiaryResult = await checkUserBeneficiaries(
      userId,
      accountNumber,
      null,
    );
    if (beneficiaryResult.found) {
      sawBeneficiary = true;
      for (const r of beneficiaryResult.results) {
        const key = bankKey(r.bank_name || r.bank_code);
        if (key) merged.set(key, r);
      }
    }
  }

  const cacheResult = await checkResolutionCache(accountNumber, null, 20);
  if (cacheResult.found) {
    sawCache = true;
    for (const r of cacheResult.results) {
      const key = bankKey(r.bank_name || r.bank_code);
      // Beneficiary rows win ties — they're the sender's own,
      // provider-verified record, more trustworthy than an
      // observed-only global cache row for the same bank.
      if (key && !merged.has(key)) merged.set(key, r);
    }
  }

  const results = Array.from(merged.values()).slice(0, maxResults);

  if (results.length > 0) {
    return {
      found: true,
      source: sawBeneficiary && sawCache ? "mixed" : sawBeneficiary ? "beneficiary" : "cache",
      results,
      needsProviderCall: false,
    };
  }

  return {
    found: false,
    source: null,
    results: [],
    needsProviderCall: true,
  };
}

function bankKey(name) {
  return String(name || "")
    .trim()
    .toLowerCase();
}

// Filters a result set down to one specific bank, matching on bank_code
// first (authoritative when present) and falling back to a
// case-insensitive bank_name match (needed because deposit-observed
// cache rows can carry a null bank_code — see header note on bank_name
// as the cross-source identity key).
function narrowToBank(results, bankCode, bankName) {
  const wantCode = bankCode ? String(bankCode).trim().toLowerCase() : null;
  const wantName = bankName ? bankKey(bankName) : null;
  return results.filter((r) => {
    if (wantCode && r.bank_code && String(r.bank_code).trim().toLowerCase() === wantCode) {
      return true;
    }
    if (wantName && bankKey(r.bank_name) === wantName) {
      return true;
    }
    return false;
  });
}

/**
 * Check user's personal beneficiaries table.
 * Returns immediately if found — no API call needed.
 * Rows here always came from a real provider verification or a
 * completed transfer, so bank_code is trustworthy here — unlike the
 * global cache, this table doesn't need the bank_name-matching fix.
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
 * Check the global account_resolution_cache, matched by bank_name.
 * Returns all matching banks for the account number (up to maxResults).
 * Every result is guaranteed a real bank_code (resolve_account_from_cache
 * backfills it from flutterwave_banks and excludes anything it can't
 * resolve one for), so callers can send straight into a transfer.
 */
async function checkResolutionCache(accountNumber, bankName, maxResults) {
  try {
    const { data, error } = await supabase.rpc("resolve_account_from_cache", {
      p_account_number: accountNumber,
      p_bank_name: bankName,
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
 * Provider verification always requires a real bank_code (that's how
 * the provider API itself works) — this path is unaffected by the
 * bank_name-matching change, it's the source of "verified" confidence.
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
 *
 * bankCode may legitimately be null here (deposit-observed path) — the
 * DB function stores that honestly instead of a fake placeholder, and
 * resolve_account_from_cache() backfills a real code from
 * flutterwave_banks by bank_name at read time.
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
      p_bank_code: bankCode || null,
      p_bank_name: bankName || null,
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
 * Keyed by bank_name, matching how the cache is looked up.
 */
async function recordHit(accountNumber, bankName) {
  try {
    await supabase.rpc("record_beneficiary_hit", {
      p_account_number: accountNumber,
      p_bank_name: bankName,
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
 *
 * No bank code from Flutterwave on deposits — pass null honestly rather
 * than a placeholder string. bank_name is the real identity here; a
 * real bank_code gets backfilled from flutterwave_banks whenever this
 * row is later matched (see resolve_account_from_cache).
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
    bankCode: senderBankCode || null,
    bankName: senderBank || null,
    accountName: senderName,
    source: "deposit_received",
    confidence: "observed",
  });
}

/**
 * Store receiver details after a successful outbound transfer.
 * Called by the transfer finalization handler. This path always has a
 * real bank_code (the transfer couldn't have been sent without one),
 * so this is how a previously deposit-observed, code-less row gets
 * upgraded to a real bank_code — cache_account_resolution() keeps
 * whichever bank_code it already has, filling in a missing one.
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

/**
 * Delete expired cache rows. Not required for correctness —
 * resolve_account_from_cache() already excludes anything past
 * expires_at — this is table hygiene so account_resolution_cache
 * doesn't grow unbounded. Safe to run daily via cronHandler below.
 */
async function cleanupExpiredCache() {
  try {
    const { data, error } = await supabase.rpc(
      "cleanup_expired_account_resolution_cache",
    );
    if (error) {
      console.error("[ARC] Cleanup error:", error);
      return { success: false, error: error.message };
    }
    return { success: true, deleted: data };
  } catch (err) {
    console.error("[ARC] Cleanup exception:", err);
    return { success: false, error: err.message };
  }
}

// Wire up as: app.get("/api/cron/cleanup-account-cache", accountResolutionCache.cronHandler);
async function cronHandler(req, res) {
  const result = await cleanupExpiredCache();
  res.json(result);
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
  cleanupExpiredCache,
  cronHandler,
};