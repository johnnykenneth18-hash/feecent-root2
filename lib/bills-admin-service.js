// bills-admin-service.js
// CRUD + analytics backing the new admin "Bills Management" section.
// Every write here:
//   1. touches only bill_categories/bill_providers/bill_plans/bill_pricing/bill_settings
//   2. calls bills-catalog-service.invalidateCatalogCache() (or
//      invalidateBillsEnabledCache()) so public reads never serve a
//      stale row after an admin edit
//   3. writes a financial_audit_log row for traceability
//
// "Delete" everywhere here means soft-delete (deleted_at = now()) —
// nothing in this file issues a hard DELETE. Admins un-delete by
// clearing deleted_at via the same update path (not exposed as a
// separate endpoint yet — direct DB fix until there's demand for a
// "restore" button).
//
// NOTE ON logAdminAction: middleware/auth.js (not in this upload set)
// exports a logAdminAction helper that index.js imports but that I
// haven't seen called anywhere in the uploaded code, so its exact
// call signature is a best guess below (`logAdminAction(req, action,
// details)`), wrapped so a signature mismatch can't break the actual
// admin action. Verify/adjust against middleware/auth.js.

const { createClient } = require("@supabase/supabase-js");
const catalog = require("./bills-catalog-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

async function auditLog(adminId, actionType, details) {
  try {
    await supabase.from("financial_audit_log").insert({
      user_id: adminId,
      action_type: actionType,
      details,
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error(`[BILLS-ADMIN] audit log write failed for ${actionType}:`, err.message);
  }
}

function safeLogAdminAction(req, action, details) {
  try {
    const { logAdminAction } = require("../middleware/auth");
    if (typeof logAdminAction === "function") {
      Promise.resolve(logAdminAction(req, action, details)).catch((err) =>
        console.error("[BILLS-ADMIN] logAdminAction failed:", err.message),
      );
    }
  } catch (err) {
    // middleware/auth not resolvable from this file's location in some
    // deployments — non-fatal, financial_audit_log above is the
    // authoritative record either way.
  }
}

// ------------------------------------------------------------
// Categories
// ------------------------------------------------------------
async function listCategoriesAdmin() {
  return catalog.getCategories({ includeHidden: true });
}

async function createCategory(adminId, req, fields) {
  const { data, error } = await supabase.from("bill_categories").insert(fields).select().single();
  if (error) throw error;
  await catalog.invalidateCatalogCache();
  await auditLog(adminId, "bills_admin_category_create", { category_id: data.id, fields });
  safeLogAdminAction(req, "bills_admin_category_create", { category_id: data.id });
  return data;
}

async function updateCategory(adminId, req, categoryId, fields) {
  const { data, error } = await supabase
    .from("bill_categories")
    .update(fields)
    .eq("id", categoryId)
    .select()
    .single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ categoryId });
  await auditLog(adminId, "bills_admin_category_update", { category_id: categoryId, fields });
  safeLogAdminAction(req, "bills_admin_category_update", { category_id: categoryId, fields });
  return data;
}

async function deleteCategory(adminId, req, categoryId) {
  const { data, error } = await supabase
    .from("bill_categories")
    .update({ deleted_at: new Date().toISOString() })
    .eq("id", categoryId)
    .select()
    .single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ categoryId });
  await auditLog(adminId, "bills_admin_category_delete", { category_id: categoryId });
  safeLogAdminAction(req, "bills_admin_category_delete", { category_id: categoryId });
  return data;
}

// ------------------------------------------------------------
// Providers
// ------------------------------------------------------------
async function listProvidersAdmin(categoryId) {
  return catalog.getProvidersForCategory(categoryId, { includeHidden: true });
}

async function createProvider(adminId, req, fields) {
  const { data, error } = await supabase.from("bill_providers").insert(fields).select().single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ categoryId: fields.category_id });
  await auditLog(adminId, "bills_admin_provider_create", { provider_id: data.id, fields });
  safeLogAdminAction(req, "bills_admin_provider_create", { provider_id: data.id });
  return data;
}

async function updateProvider(adminId, req, providerId, fields) {
  const existing = await catalog.getProviderById(providerId);
  const { data, error } = await supabase
    .from("bill_providers")
    .update(fields)
    .eq("id", providerId)
    .select()
    .single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ categoryId: existing?.category_id, providerId });
  await auditLog(adminId, "bills_admin_provider_update", { provider_id: providerId, fields });
  safeLogAdminAction(req, "bills_admin_provider_update", { provider_id: providerId, fields });
  return data;
}

async function deleteProvider(adminId, req, providerId) {
  const existing = await catalog.getProviderById(providerId);
  const { data, error } = await supabase
    .from("bill_providers")
    .update({ deleted_at: new Date().toISOString() })
    .eq("id", providerId)
    .select()
    .single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ categoryId: existing?.category_id, providerId });
  await auditLog(adminId, "bills_admin_provider_delete", { provider_id: providerId });
  safeLogAdminAction(req, "bills_admin_provider_delete", { provider_id: providerId });
  return data;
}

// ------------------------------------------------------------
// Plans
// ------------------------------------------------------------
async function listPlansAdmin(providerId) {
  return catalog.getPlansForProvider(providerId, { includeHidden: true });
}

async function createPlan(adminId, req, fields) {
  const { data, error } = await supabase.from("bill_plans").insert(fields).select().single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ providerId: fields.provider_id });
  await auditLog(adminId, "bills_admin_plan_create", { plan_id: data.id, fields });
  safeLogAdminAction(req, "bills_admin_plan_create", { plan_id: data.id });
  return data;
}

async function updatePlan(adminId, req, planId, fields) {
  const existing = await catalog.getPlanById(planId);
  const { data, error } = await supabase.from("bill_plans").update(fields).eq("id", planId).select().single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ providerId: existing?.provider_id });
  await auditLog(adminId, "bills_admin_plan_update", { plan_id: planId, fields });
  safeLogAdminAction(req, "bills_admin_plan_update", { plan_id: planId, fields });
  return data;
}

async function deletePlan(adminId, req, planId) {
  const existing = await catalog.getPlanById(planId);
  const { data, error } = await supabase
    .from("bill_plans")
    .update({ deleted_at: new Date().toISOString() })
    .eq("id", planId)
    .select()
    .single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ providerId: existing?.provider_id });
  await auditLog(adminId, "bills_admin_plan_delete", { plan_id: planId });
  safeLogAdminAction(req, "bills_admin_plan_delete", { plan_id: planId });
  return data;
}

// Pulls the biller's current item list from its payment gateway
// (Flutterwave today) and upserts into bill_plans — matched by
// external_plan_code, so re-running this is safe: existing plans get
// their provider_cost refreshed, new ones are added, nothing already
// customized (display_name, pricing_mode, markup) is touched unless
// the code below explicitly says so.
//
// provider_cost comes from Flutterwave's own `amount` field when they
// return one — some billers don't (fixed-price bundles may omit it),
// in which case the existing/manually-set provider_cost is left alone
// rather than overwritten with a guess.
// Best-effort guess at DAILY/WEEKLY/MONTHLY/BROADBAND from the biller's
// own display name — Flutterwave's bill-categories response doesn't
// include a structured validity field, only free-text names like
// "MTN 200MB - 1 Day" or "1GB - 30 Days", so this is pattern-matching
// on that text, not a reliable parse. Defaults to OTHER when nothing
// matches — admin should review/correct these after a refresh, same
// as the 0%-markup default already nudges them to review pricing.
function guessDisplayGroup(name) {
  const n = (name || "").toLowerCase();
  if (/\b(1\s*day|daily|24\s*hour)/.test(n)) return "DAILY";
  if (/\b(7\s*day|weekly|1\s*week)/.test(n)) return "WEEKLY";
  if (/\b(30\s*day|31\s*day|monthly|1\s*month)/.test(n)) return "MONTHLY";
  if (/\b(broadband|unlimited|90\s*day|180\s*day|365\s*day|1\s*year|annual)/.test(n)) return "BROADBAND";
  return "OTHER";
}

async function refreshPlansFromProvider(adminId, req, providerId) {
  const provider = await catalog.getProviderById(providerId);
  if (!provider) {
    const err = new Error("Provider not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  if (!provider.external_biller_code) {
    const err = new Error(
      `${provider.name} has no External Biller Code set — add Flutterwave's biller_code for this provider first (Providers tab → Edit) before refreshing plans.`,
    );
    err.code = "MISSING_BILLER_CODE";
    throw err;
  }

  const { PaymentGateway } = require("./payment-gateway");
  const result = await PaymentGateway.listBillerItems({
    providerCode: provider.gateway_code,
    billerCode: provider.external_biller_code,
  });

  if (!result.success) {
    const err = new Error(result.error || "Failed to fetch plans from provider");
    err.code = "PROVIDER_FETCH_FAILED";
    throw err;
  }

  const existingPlans = await catalog.getPlansForProvider(providerId, { includeHidden: true });
  const existingByCode = new Map(existingPlans.map((p) => [p.external_plan_code, p]));

  let created = 0;
  let updated = 0;

  for (const item of result.items) {
    if (!item.external_plan_code) continue; // skip anything Flutterwave returned without a usable identifier
    const existing = existingByCode.get(item.external_plan_code);

    if (existing) {
      const fields = { display_name: item.display_name || existing.display_name };
      if (item.provider_cost != null) fields.provider_cost = item.provider_cost;
      await supabase.from("bill_plans").update(fields).eq("id", existing.id);
      updated++;
    } else {
      await supabase.from("bill_plans").insert({
        provider_id: providerId,
        external_plan_code: item.external_plan_code,
        display_name: item.display_name || item.external_plan_code,
        display_group: guessDisplayGroup(item.display_name),
        provider_cost: item.provider_cost ?? 0,
        pricing_mode: "MARKUP_PERCENT",
        markup_percent: 0, // safe default — admin must set a real markup before this plan is usable; status defaults to HIDDEN below so it can't be bought at 0 margin by accident
        status: "HIDDEN",
        is_available: true,
        sort_order: 0,
      });
      created++;
    }
  }

  await catalog.invalidateCatalogCache({ providerId });
  await auditLog(adminId, "bills_admin_plans_refreshed", { provider_id: providerId, created, updated });
  safeLogAdminAction(req, "bills_admin_plans_refreshed", { provider_id: providerId, created, updated });

  return {
    created,
    updated,
    total_from_provider: result.items.length,
    note:
      created > 0
        ? `${created} new plan(s) were added as HIDDEN with 0% markup — review pricing and cost before setting them ACTIVE.`
        : undefined,
  };
}

// ------------------------------------------------------------
// Pricing (variable-amount categories only — plans price themselves)
// ------------------------------------------------------------
async function upsertPricingRule(adminId, req, { category_id, provider_id, pricing_mode, markup_percent, fixed_fee }) {
  const { data, error } = await supabase
    .from("bill_pricing")
    .upsert(
      { category_id, provider_id: provider_id || null, pricing_mode, markup_percent, fixed_fee },
      { onConflict: "category_id,provider_id" },
    )
    .select()
    .single();
  if (error) throw error;
  await catalog.invalidateCatalogCache({ categoryId: category_id, providerId: provider_id });
  await auditLog(adminId, "bills_admin_pricing_update", { category_id, provider_id, pricing_mode, markup_percent, fixed_fee });
  safeLogAdminAction(req, "bills_admin_pricing_update", { category_id, provider_id });
  return data;
}

// ------------------------------------------------------------
// Settings
// ------------------------------------------------------------
async function getSetting(key) {
  const { data } = await supabase.from("bill_settings").select("*").eq("key", key).maybeSingle();
  return data;
}

async function setSetting(adminId, req, key, value) {
  const { data, error } = await supabase
    .from("bill_settings")
    .upsert({ key, value, updated_at: new Date().toISOString(), updated_by: adminId })
    .select()
    .single();
  if (error) throw error;
  if (key === "bills_enabled") await catalog.invalidateBillsEnabledCache();
  await auditLog(adminId, "bills_admin_setting_update", { key, value });
  safeLogAdminAction(req, "bills_admin_setting_update", { key, value });
  return data;
}

// ------------------------------------------------------------
// Analytics — per-category counts for the admin dashboard.
// ------------------------------------------------------------
async function getCategoryAnalytics() {
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);

  const { data: todayRows, error } = await supabase
    .from("bill_transactions")
    .select("category_id, status, amount, fee_amount, provider_cost")
    .gte("created_at", startOfToday.toISOString());

  if (error) throw error;

  const categories = await catalog.getCategories({ includeHidden: true });
  const byCategory = {};
  for (const cat of categories) {
    byCategory[cat.id] = {
      category_id: cat.id,
      category_code: cat.code,
      category_name: cat.name,
      purchases_today: 0,
      revenue_today: 0,
      profit_today: 0,
      pending: 0,
      completed: 0,
      failed: 0,
    };
  }

  for (const row of todayRows || []) {
    const bucket = byCategory[row.category_id];
    if (!bucket) continue;
    bucket.purchases_today += 1;
    if (row.status === "completed") {
      bucket.completed += 1;
      bucket.revenue_today += Number(row.amount) + Number(row.fee_amount);
      bucket.profit_today += Number(row.amount) + Number(row.fee_amount) - Number(row.provider_cost);
    } else if (row.status === "failed") {
      bucket.failed += 1;
    } else {
      bucket.pending += 1;
    }
  }

  return Object.values(byCategory).map((b) => ({
    ...b,
    success_rate: b.purchases_today > 0 ? Math.round((b.completed / b.purchases_today) * 1000) / 10 : null,
    failure_rate: b.purchases_today > 0 ? Math.round((b.failed / b.purchases_today) * 1000) / 10 : null,
  }));
}

module.exports = {
  listCategoriesAdmin,
  createCategory,
  updateCategory,
  deleteCategory,
  listProvidersAdmin,
  createProvider,
  updateProvider,
  deleteProvider,
  listPlansAdmin,
  createPlan,
  updatePlan,
  deletePlan,
  refreshPlansFromProvider,
  upsertPricingRule,
  getSetting,
  setSetting,
  getCategoryAnalytics,
};