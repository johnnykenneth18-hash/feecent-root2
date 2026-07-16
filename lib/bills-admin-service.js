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

// "Refresh plans from provider" — honest NOT_IMPLEMENTED for now:
// there is no provider-side "list available plans" integration built
// yet (FlutterwaveProvider doesn't expose one). Wiring this up is
// future work, not something to fake with a silent no-op.
async function refreshPlansFromProvider(_providerId) {
  const err = new Error(
    "Refreshing plans from the provider isn't implemented yet — add plans manually via POST /api/sys/bills/plans until a provider-side plan-listing integration exists.",
  );
  err.code = "NOT_IMPLEMENTED";
  throw err;
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