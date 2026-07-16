// bills-catalog-service.js
// Single source of truth for reading the bills catalog (categories,
// providers, plans, pricing, the global on/off switch) and for
// computing what a given purchase actually costs.
//
// Everything the frontend (user-facing AND admin) shows about what
// bill products exist comes from here, not from anything hardcoded
// in HTML/JS. Everything bills-service.js debits a wallet for is
// priced here — never trust a client-supplied amount/fee for
// anything beyond "how much airtime do you want", which itself gets
// validated against category/provider min/max before use.
//
// Caching: catalog data (categories/providers/plans) is the same for
// every user, so this uses plain fixed-key cache-aside via
// cache-service.js — not the per-user version-counter pattern that
// file's getCachedUser() uses, since there's no per-user variant to
// track here. Every admin write in bills-admin-service.js calls
// invalidateCatalogCache() after it commits, so the invalidate half of
// cache-aside always has an explicit call site — see cache-service.js
// design note 2.
//
// Pricing money-path values (bill_pricing, bill_plans.selling_price)
// are NOT cached — a stale price is a wrong receipt, not a stale
// dashboard number, so those go straight to Postgres every time. The
// query is a single indexed lookup either way; the cost of not
// caching it is negligible next to the cost of getting it wrong.

const { createClient } = require("@supabase/supabase-js");
const { cacheGet, cacheSet, cacheDel } = require("./cache-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const CATALOG_TTL_SECONDS = 60;
const SETTINGS_TTL_SECONDS = 15; // short — this gates the global kill switch, propagation speed matters

const CATEGORIES_CACHE_KEY = "bills:categories:v1";
const BILLS_ENABLED_CACHE_KEY = "bills:settings:bills_enabled";

function providersCacheKey(categoryId) {
  return `bills:providers:v1:${categoryId}`;
}
function plansCacheKey(providerId) {
  return `bills:plans:v1:${providerId}`;
}

// ------------------------------------------------------------
// Public reads (used by both the user-facing API and, with
// includeHidden=true, the admin API).
// ------------------------------------------------------------

async function getCategories({
  featuredOnly = false,
  includeHidden = false,
} = {}) {
  // Only the plain "everything visible" shape is cached — featured
  // and admin views are comparatively rare and filtering server-side
  // post-cache is cheap, so one cache entry covers every public call.
  const canUseCache = !includeHidden;
  const cacheKey = CATEGORIES_CACHE_KEY;

  let categories = canUseCache ? await cacheGet(cacheKey) : null;

  if (!categories) {
    let query = supabase
      .from("bill_categories")
      .select("*")
      .is("deleted_at", null)
      .order("sort_order", { ascending: true });

    if (!includeHidden) {
      query = query.neq("status", "HIDDEN");
    }

    const { data, error } = await query;
    if (error) throw error;
    categories = data || [];

    if (canUseCache) {
      await cacheSet(cacheKey, categories, CATALOG_TTL_SECONDS);
    }
  }

  if (featuredOnly) {
    return categories
      .filter((c) => c.is_featured)
      .sort((a, b) => a.featured_sort_order - b.featured_sort_order);
  }
  return categories;
}

async function getCategoryByCode(code, { includeHidden = false } = {}) {
  const categories = await getCategories({ includeHidden: true });
  const category = categories.find((c) => c.code === code);
  if (!category) return null;
  if (!includeHidden && category.status === "HIDDEN") return null;
  return category;
}

async function getCategoryById(id) {
  const categories = await getCategories({ includeHidden: true });
  return categories.find((c) => c.id === id) || null;
}

async function getProvidersForCategory(
  categoryId,
  { includeHidden = false } = {},
) {
  const cacheKey = providersCacheKey(categoryId);
  let providers = includeHidden ? null : await cacheGet(cacheKey);

  if (!providers) {
    let query = supabase
      .from("bill_providers")
      .select("*")
      .eq("category_id", categoryId)
      .is("deleted_at", null)
      .order("sort_order", { ascending: true });

    if (!includeHidden) {
      query = query.neq("status", "HIDDEN");
    }

    const { data, error } = await query;
    if (error) throw error;
    providers = data || [];

    if (!includeHidden) {
      await cacheSet(cacheKey, providers, CATALOG_TTL_SECONDS);
    }
  }
  return providers;
}

async function getProviderById(providerId) {
  const { data, error } = await supabase
    .from("bill_providers")
    .select("*")
    .eq("id", providerId)
    .is("deleted_at", null)
    .single();
  if (error) return null;
  return data;
}

async function getPlansForProvider(providerId, { includeHidden = false } = {}) {
  const cacheKey = plansCacheKey(providerId);
  let plans = includeHidden ? null : await cacheGet(cacheKey);

  if (!plans) {
    let query = supabase
      .from("bill_plans")
      .select("*")
      .eq("provider_id", providerId)
      .is("deleted_at", null)
      .order("sort_order", { ascending: true });

    if (!includeHidden) {
      query = query.neq("status", "HIDDEN");
    }

    const { data, error } = await query;
    if (error) throw error;
    plans = data || [];

    if (!includeHidden) {
      await cacheSet(cacheKey, plans, CATALOG_TTL_SECONDS);
    }
  }
  return plans;
}

async function getPlanById(planId) {
  const { data, error } = await supabase
    .from("bill_plans")
    .select("*")
    .eq("id", planId)
    .is("deleted_at", null)
    .single();
  if (error) return null;
  return data;
}

// Provider-level pricing row wins over category-level — see
// bill_pricing's header comment in 010_bills_v2_schema.sql.
async function getPricingRule(categoryId, providerId) {
  const { data: providerRule } = await supabase
    .from("bill_pricing")
    .select("*")
    .eq("category_id", categoryId)
    .eq("provider_id", providerId)
    .maybeSingle();
  if (providerRule) return providerRule;

  const { data: categoryRule } = await supabase
    .from("bill_pricing")
    .select("*")
    .eq("category_id", categoryId)
    .is("provider_id", null)
    .maybeSingle();
  return categoryRule || null;
}

async function isBillsEnabled() {
  let cached = await cacheGet(BILLS_ENABLED_CACHE_KEY);
  if (cached !== null && cached !== undefined) return cached.enabled === true;

  const { data } = await supabase
    .from("bill_settings")
    .select("value")
    .eq("key", "bills_enabled")
    .single();

  const enabled = data
    ? data.value === true ||
      data.value?.enabled === true ||
      data.value === "true"
    : true;
  await cacheSet(BILLS_ENABLED_CACHE_KEY, { enabled }, SETTINGS_TTL_SECONDS);
  return enabled;
}

// ------------------------------------------------------------
// Cache invalidation — call after any admin write to categories,
// providers, plans, or settings.
// ------------------------------------------------------------
async function invalidateCatalogCache({ categoryId, providerId } = {}) {
  const keys = [CATEGORIES_CACHE_KEY];
  if (categoryId) keys.push(providersCacheKey(categoryId));
  if (providerId) keys.push(plansCacheKey(providerId));
  await cacheDel(...keys);
}

async function invalidateBillsEnabledCache() {
  await cacheDel(BILLS_ENABLED_CACHE_KEY);
}

// ------------------------------------------------------------
// Validation + pricing — the replacement for bill-payment-engine.js's
// hardcoded PROCESSORS map. Everything here reads live catalog rows;
// nothing about a specific bill type is hardcoded except the generic
// shape of "variable-amount vs plan-based".
// ------------------------------------------------------------

function isUsableStatus(status) {
  return status === "ACTIVE";
}

/**
 * Validates and prices a bill purchase request. Returns either
 * { valid: true, pricing: {...} } or { valid: false, error, code }.
 * `pricing` is exactly what gets passed to reserve_bill_transaction —
 * nothing downstream should recompute amount/provider_cost/fee_amount.
 */
async function validateAndPriceBillRequest({
  category_code,
  provider_code,
  plan_id,
  customer_identifier,
  amount,
}) {
  if (!(await isBillsEnabled())) {
    return {
      valid: false,
      error: "Bills are temporarily unavailable.",
      code: "BILLS_DISABLED",
    };
  }

  const category = await getCategoryByCode(category_code);
  if (!category) {
    return {
      valid: false,
      error: `Unknown category '${category_code}'`,
      code: "UNKNOWN_CATEGORY",
    };
  }
  if (!isUsableStatus(category.status)) {
    return {
      valid: false,
      error:
        category.status === "MAINTENANCE"
          ? category.maintenance_message ||
            `${category.name} is under maintenance`
          : `${category.name} is not available right now`,
      code:
        category.status === "MAINTENANCE"
          ? "CATEGORY_MAINTENANCE"
          : "CATEGORY_NOT_AVAILABLE",
    };
  }

  if (
    category.identifier_regex &&
    !new RegExp(category.identifier_regex).test(customer_identifier || "")
  ) {
    return {
      valid: false,
      error: `Invalid ${category.identifier_label}`,
      code: "INVALID_IDENTIFIER",
    };
  }

  const providers = await getProvidersForCategory(category.id, {
    includeHidden: true,
  });
  const provider = providers.find((p) => p.code === provider_code);
  if (!provider || provider.status === "HIDDEN") {
    return {
      valid: false,
      error: `Unknown provider '${provider_code}'`,
      code: "UNKNOWN_PROVIDER",
    };
  }
  if (!isUsableStatus(provider.status)) {
    return {
      valid: false,
      error:
        provider.status === "MAINTENANCE"
          ? provider.maintenance_message ||
            `${provider.name} is under maintenance`
          : `${provider.name} is not available right now`,
      code:
        provider.status === "MAINTENANCE"
          ? "PROVIDER_MAINTENANCE"
          : "PROVIDER_NOT_AVAILABLE",
    };
  }

  if (category.requires_plan) {
    if (!plan_id) {
      return {
        valid: false,
        error: "plan_id is required for this category",
        code: "PLAN_REQUIRED",
      };
    }
    const plan = await getPlanById(plan_id);
    if (!plan || plan.provider_id !== provider.id || plan.status === "HIDDEN") {
      return { valid: false, error: "Unknown plan", code: "UNKNOWN_PLAN" };
    }
    if (!isUsableStatus(plan.status) || !plan.is_available) {
      return {
        valid: false,
        error:
          plan.status === "MAINTENANCE"
            ? plan.maintenance_message ||
              `${plan.display_name} is under maintenance`
            : `${plan.display_name} is currently unavailable`,
        code:
          plan.status === "MAINTENANCE"
            ? "PLAN_MAINTENANCE"
            : "PLAN_NOT_AVAILABLE",
      };
    }

    return {
      valid: true,
      pricing: {
        category,
        provider,
        plan,
        amount: Number(plan.selling_price),
        provider_cost: Number(plan.provider_cost),
        fee_amount: 0, // margin is embedded in selling_price for plan-based purchases, not a separate visible fee
        gateway_code: provider.gateway_code,
        external_biller_code: provider.external_biller_code,
        external_plan_code: plan.external_plan_code,
      },
    };
  }

  // Variable-amount path (AIRTIME / ELECTRICITY / BETTING).
  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    return { valid: false, error: "Invalid amount", code: "INVALID_AMOUNT" };
  }
  const minAmount = provider.min_amount ?? category.min_amount;
  const maxAmount = provider.max_amount ?? category.max_amount;
  if (minAmount != null && numericAmount < minAmount) {
    return {
      valid: false,
      error: `Minimum amount is ₦${minAmount}`,
      code: "AMOUNT_TOO_LOW",
    };
  }
  if (maxAmount != null && numericAmount > maxAmount) {
    return {
      valid: false,
      error: `Maximum amount is ₦${Number(maxAmount).toLocaleString()}`,
      code: "AMOUNT_TOO_HIGH",
    };
  }

  const pricingRule = await getPricingRule(category.id, provider.id);
  let feeAmount = 0;
  if (pricingRule) {
    feeAmount =
      pricingRule.pricing_mode === "FIXED_FEE"
        ? Number(pricingRule.fixed_fee)
        : Math.round(
            numericAmount * (Number(pricingRule.markup_percent) / 100) * 100,
          ) / 100;
  }

  return {
    valid: true,
    pricing: {
      category,
      provider,
      plan: null,
      amount: numericAmount,
      provider_cost: numericAmount, // variable-amount purchases: face value is what we owe the provider
      fee_amount: feeAmount,
      gateway_code: provider.gateway_code,
      external_biller_code: provider.external_biller_code,
      external_plan_code: null,
    },
  };
}

module.exports = {
  getCategories,
  getCategoryByCode,
  getCategoryById,
  getProvidersForCategory,
  getProviderById,
  getPlansForProvider,
  getPlanById,
  getPricingRule,
  isBillsEnabled,
  invalidateCatalogCache,
  invalidateBillsEnabledCache,
  validateAndPriceBillRequest,
};
