// savings-catalog-service.js
// Single source of truth for reading the savings catalog — mirrors
// bills-catalog-service.js's role for bills. Everything the frontend
// shows about what savings products exist (built-in or admin-defined
// generic) comes from here, not from a hardcoded switch(type) in
// dashboard.js/index.js anymore.
//
// IMPORTANT: this file does NOT touch, replace, or duplicate any of
// the 5 existing engines' status computation (matured/completed/etc
// — that logic stays exactly where it is today, in index.js's
// existing /api/user/savings* routes and savings-cron.js). This file
// only reads catalog metadata (name/description/icon/status/config)
// and admin-authored status copy.

const { createClient } = require("@supabase/supabase-js");
const { cacheGet, cacheSet, cacheDel } = require("../../lib/cache-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const CATALOG_TTL_SECONDS = 60;
const SETTINGS_TTL_SECONDS = 15; // short — gates the global kill switch, propagation speed matters

const PRODUCTS_CACHE_KEY = "savings:products:v1";
const SAVINGS_ENABLED_CACHE_KEY = "savings:settings:savings_enabled";

async function getProducts({ includeHidden = false } = {}) {
  let products = !includeHidden ? await cacheGet(PRODUCTS_CACHE_KEY) : null;

  if (!products) {
    let query = supabase
      .from("savings_products")
      .select("*")
      .order("sort_order", { ascending: true });

    if (!includeHidden) {
      query = query.neq("status", "HIDDEN");
    }

    const { data, error } = await query;
    if (error) throw error;
    products = data || [];

    if (!includeHidden) {
      await cacheSet(PRODUCTS_CACHE_KEY, products, CATALOG_TTL_SECONDS);
    }
  }
  return products;
}

async function getProductByCode(code, { includeHidden = false } = {}) {
  const products = await getProducts({ includeHidden: true });
  const product = products.find((p) => p.code === code);
  if (!product) return null;
  if (!includeHidden && product.status === "HIDDEN") return null;
  return product;
}

async function getProductById(id) {
  const products = await getProducts({ includeHidden: true });
  return products.find((p) => p.id === id) || null;
}

async function isSavingsEnabled() {
  const cached = await cacheGet(SAVINGS_ENABLED_CACHE_KEY);
  if (cached !== null && cached !== undefined) return cached.enabled === true;

  const { data } = await supabase
    .from("savings_settings")
    .select("value")
    .eq("key", "savings_enabled")
    .single();

  const enabled = data ? data.value === true || data.value?.enabled === true : true;
  await cacheSet(SAVINGS_ENABLED_CACHE_KEY, { enabled }, SETTINGS_TTL_SECONDS);
  return enabled;
}

async function invalidateCatalogCache() {
  await cacheDel(PRODUCTS_CACHE_KEY);
}

async function invalidateSavingsEnabledCache() {
  await cacheDel(SAVINGS_ENABLED_CACHE_KEY);
}

// ------------------------------------------------------------
// Status copy — admin-authored title/body per (product, status_key).
// Falls back to a generic, honest default if admin hasn't written
// custom copy yet for a given status, so a new product never shows a
// blank modal.
// ------------------------------------------------------------
const DEFAULT_STATUS_COPY = {
  not_started: { title: "Not Started", body: "You haven't started this savings plan yet." },
  active: { title: "Saving in Progress", body: "Your savings plan is active and running." },
  matured: { title: "Matured", body: "Your savings has matured and is ready for withdrawal." },
  completed: { title: "Goal Reached", body: "Congratulations — you've reached your savings goal." },
  withdrawn: { title: "Withdrawn", body: "This savings plan has been withdrawn." },
  cancelled: { title: "Cancelled", body: "This savings plan was cancelled." },
};

async function getStatusCopy(productId, statusKey) {
  const { data } = await supabase
    .from("savings_status_copy")
    .select("title, body")
    .eq("product_id", productId)
    .eq("status_key", statusKey)
    .maybeSingle();

  if (data && (data.title || data.body)) return data;
  return DEFAULT_STATUS_COPY[statusKey] || { title: statusKey, body: "" };
}

async function getAllStatusCopyForProduct(productId) {
  const { data, error } = await supabase
    .from("savings_status_copy")
    .select("*")
    .eq("product_id", productId);
  if (error) throw error;
  return data || [];
}

module.exports = {
  getProducts,
  getProductByCode,
  getProductById,
  isSavingsEnabled,
  invalidateCatalogCache,
  invalidateSavingsEnabledCache,
  getStatusCopy,
  getAllStatusCopyForProduct,
  DEFAULT_STATUS_COPY,
};