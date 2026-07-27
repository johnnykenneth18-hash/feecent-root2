// savings-admin-service.js
// Admin control for the savings catalog — mirrors bills-admin-service.js's
// pattern exactly (audit-logged writes, cache invalidation after every
// write). Manages savings_products (both the 5 built-in catalog
// wrappers AND fully admin-defined generic products),
// savings_status_copy, and the global savings_enabled kill switch.
//
// IMPORTANT — built-in engines (harvest/fixed/target/savebox/
// spare_change) can only have their CATALOG fields edited here (name,
// description, icon, status, sort_order) — never their config columns
// (contribution_model, duration_days, interest_rate, etc.), because
// those mechanics are hardcoded in index.js's existing routes and
// savings-cron.js, not read from savings_products at all for those 5.
// Editing those columns on a built-in row would silently do nothing
// except confuse the next admin who looks at it — updateProduct()
// below strips them out for built-in engine_types rather than
// pretending they'd take effect.

const { createClient } = require("@supabase/supabase-js");
const catalog = require("./savings-catalog-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const BUILT_IN_ENGINES = ["harvest", "fixed", "target", "savebox", "spare_change"];
const CATALOG_ONLY_FIELDS = ["name", "description", "icon", "sort_order", "status", "maintenance_message"];
const GENERIC_CONFIG_FIELDS = [
  "contribution_model",
  "contribution_amount",
  "contribution_percentage",
  "contribution_frequency",
  "min_contribution_amount",
  "max_contribution_amount",
  "duration_model",
  "duration_days",
  "completion_rule",
  "reward_type",
  "interest_rate",
  "reward_items",
  "early_withdrawal_policy",
  "early_withdrawal_fee_percent",
  "free_withdrawal_window_days",
  "allow_multiple_per_user",
];

async function auditLog(adminId, actionType, details) {
  try {
    await supabase.from("financial_audit_log").insert({
      user_id: adminId,
      action_type: actionType,
      details,
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error(`[SAVINGS-ADMIN] audit log write failed for ${actionType}:`, err.message);
  }
}

// ------------------------------------------------------------
// Products
// ------------------------------------------------------------
async function listProducts() {
  return catalog.getProducts({ includeHidden: true });
}

async function getProduct(id) {
  const product = await catalog.getProductById(id);
  if (!product) {
    const err = new Error("Savings product not found");
    err.code = "NOT_FOUND";
    throw err;
  }
  return product;
}

/**
 * Creates a NEW generic product — the "admin fully defines new logic"
 * path. engine_type is always 'generic' here; only
 * savings-admin-routes.js's dedicated (and much narrower) built-in
 * update path can touch the 5 fixed engine catalog rows, and even
 * that never changes engine_type.
 */
async function createGenericProduct(adminId, req, fields) {
  const required = ["code", "name", "contribution_model", "duration_model", "completion_rule", "reward_type", "early_withdrawal_policy"];
  for (const field of required) {
    if (!fields[field]) {
      const err = new Error(`${field} is required to create a savings product`);
      err.code = "MISSING_FIELD";
      throw err;
    }
  }

  const payload = { engine_type: "generic", status: fields.status || "COMING_SOON", created_by: adminId };
  for (const f of [...CATALOG_ONLY_FIELDS, ...GENERIC_CONFIG_FIELDS, "code"]) {
    if (fields[f] !== undefined) payload[f] = fields[f];
  }

  const { data, error } = await supabase.from("savings_products").insert(payload).select().single();
  if (error) throw error;

  await catalog.invalidateCatalogCache();
  await auditLog(adminId, "savings_product_create", { product_id: data.id, fields: payload });
  return data;
}

/**
 * Updates any product. For built-in engines, silently strips config
 * fields (see header) rather than erroring — an admin editing the
 * catalog card for "Fixed Savings" shouldn't get a confusing rejection
 * just because they also had an irrelevant field in the form payload.
 */
async function updateProduct(adminId, req, productId, fields) {
  const existing = await getProduct(productId);
  const isBuiltIn = BUILT_IN_ENGINES.includes(existing.engine_type);

  const payload = { updated_at: new Date().toISOString() };
  const allowedFields = isBuiltIn ? CATALOG_ONLY_FIELDS : [...CATALOG_ONLY_FIELDS, ...GENERIC_CONFIG_FIELDS];
  for (const f of allowedFields) {
    if (fields[f] !== undefined) payload[f] = fields[f];
  }

  const { data, error } = await supabase
    .from("savings_products")
    .update(payload)
    .eq("id", productId)
    .select()
    .single();
  if (error) throw error;

  await catalog.invalidateCatalogCache();
  await auditLog(adminId, "savings_product_update", { product_id: productId, fields: payload, was_built_in: isBuiltIn });
  return data;
}

async function deleteProduct(adminId, req, productId) {
  const existing = await getProduct(productId);
  if (BUILT_IN_ENGINES.includes(existing.engine_type)) {
    const err = new Error("Built-in savings engines can't be deleted — hide them instead (set status to HIDDEN).");
    err.code = "CANNOT_DELETE_BUILT_IN";
    throw err;
  }

  // Refuse to delete a generic product with any enrollments, ever —
  // same "don't orphan real user data" rule bills' category/provider
  // deletes should follow. Hide it instead.
  const { count } = await supabase
    .from("savings_enrollments")
    .select("id", { count: "exact", head: true })
    .eq("product_id", productId);
  if (count && count > 0) {
    const err = new Error(`This product has ${count} enrollment(s) — hide it instead of deleting (set status to HIDDEN).`);
    err.code = "HAS_ENROLLMENTS";
    throw err;
  }

  const { error } = await supabase.from("savings_products").delete().eq("id", productId);
  if (error) throw error;

  await catalog.invalidateCatalogCache();
  await auditLog(adminId, "savings_product_delete", { product_id: productId });
  return { deleted: true };
}

// ------------------------------------------------------------
// Status copy
// ------------------------------------------------------------
async function listStatusCopy(productId) {
  return catalog.getAllStatusCopyForProduct(productId);
}

async function upsertStatusCopy(adminId, req, { product_id, status_key, title, body }) {
  const { data, error } = await supabase
    .from("savings_status_copy")
    .upsert(
      { product_id, status_key, title, body, updated_at: new Date().toISOString(), updated_by: adminId },
      { onConflict: "product_id,status_key" },
    )
    .select()
    .single();
  if (error) throw error;

  await auditLog(adminId, "savings_status_copy_update", { product_id, status_key, title, body });
  return data;
}

// ------------------------------------------------------------
// Global kill switch — the "well-designed Coming Soon page" toggle
// for the whole Savings/Finance section.
// ------------------------------------------------------------
async function getSavingsEnabled() {
  return catalog.isSavingsEnabled();
}

async function setSavingsEnabled(adminId, req, enabled) {
  const { error } = await supabase
    .from("savings_settings")
    .upsert(
      { key: "savings_enabled", value: Boolean(enabled), updated_at: new Date().toISOString(), updated_by: adminId },
      { onConflict: "key" },
    );
  if (error) throw error;

  await catalog.invalidateSavingsEnabledCache();
  await auditLog(adminId, "savings_enabled_toggle", { enabled });
  return { savings_enabled: Boolean(enabled) };
}

module.exports = {
  listProducts,
  getProduct,
  createGenericProduct,
  updateProduct,
  deleteProduct,
  listStatusCopy,
  upsertStatusCopy,
  getSavingsEnabled,
  setSavingsEnabled,
};