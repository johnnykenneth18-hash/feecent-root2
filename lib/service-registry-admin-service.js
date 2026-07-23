// service-registry-admin-service.js
// CRUD backing the admin "Service Registry" section — manages
// providers, their declared capabilities, and per-service routing
// (primary/fallback assignment + priority). Mirrors
// bills-admin-service.js's pattern exactly: every write here
//   1. touches only providers / provider_capabilities / service_routing
//   2. enforces the spec's "Admin Panel must prevent assigning
//      providers to services they do not support" rule via
//      ServiceRegistry.assertCapability() before any service_routing
//      write
//   3. writes a financial_audit_log row for traceability
//
// provider_categories and services are fixed vocabulary seeded by
// 011_service_registry.sql — this file exposes them as read-only lists
// (no create/delete here) since adding a genuinely new service or
// category is a migration, not an admin-panel action; keeps the same
// "schema changes are deploys, data changes are admin actions"
// boundary the rest of this codebase already follows.

const { createClient } = require("@supabase/supabase-js");
const { ServiceRegistry, PROVIDER_IMPLEMENTATIONS } = require("./service-registry");

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
    console.error(`[REGISTRY-ADMIN] audit log write failed for ${actionType}:`, err.message);
  }
}

function safeLogAdminAction(req, action, details) {
  try {
    const { logAdminAction } = require("../middleware/auth");
    if (typeof logAdminAction === "function") {
      Promise.resolve(logAdminAction(req, action, details)).catch((err) =>
        console.error("[REGISTRY-ADMIN] logAdminAction failed:", err.message),
      );
    }
  } catch (err) {
    // Same fallback as bills-admin-service.js — financial_audit_log
    // above is the authoritative record either way.
  }
}

// ------------------------------------------------------------
// Categories & services — read-only, fixed vocabulary (see header).
// ------------------------------------------------------------
async function listCategories() {
  const { data, error } = await supabase
    .from("provider_categories")
    .select("*")
    .order("sort_order", { ascending: true });
  if (error) throw error;
  return data;
}

async function listServices({ categoryId } = {}) {
  let query = supabase.from("services").select("*, provider_categories(code, name)");
  if (categoryId) query = query.eq("category_id", categoryId);
  const { data, error } = await query.order("code", { ascending: true });
  if (error) throw error;
  return data;
}

// ------------------------------------------------------------
// Providers
// ------------------------------------------------------------
async function listProviders({ categoryId } = {}) {
  let query = supabase.from("providers").select("*, provider_categories(code, name)");
  if (categoryId) query = query.eq("category_id", categoryId);
  const { data, error } = await query.order("priority", { ascending: true });
  if (error) throw error;
  return data;
}

async function createProvider(adminId, req, fields) {
  // Reject up front if there's no code implementation registered for
  // this provider code — a provider row with no matching module in
  // service-registry.js's PROVIDER_IMPLEMENTATIONS map would be
  // silently skipped by resolve() forever, which is confusing to
  // debug from the admin panel with no signal why routing "isn't
  // working".
  if (!PROVIDER_IMPLEMENTATIONS[fields.code]) {
    const err = new Error(
      `No implementation module is registered for provider code '${fields.code}'. Add it to PROVIDER_IMPLEMENTATIONS in service-registry.js first (this is expected for a genuinely new integration — build and register the module, then create this row).`,
    );
    err.code = "NO_IMPLEMENTATION";
    throw err;
  }
  const { data, error } = await supabase.from("providers").insert(fields).select().single();
  if (error) throw error;
  await auditLog(adminId, "registry_provider_create", { provider_id: data.id, fields });
  safeLogAdminAction(req, "registry_provider_create", { provider_id: data.id });
  return data;
}

async function updateProvider(adminId, req, providerId, fields) {
  const { data, error } = await supabase
    .from("providers")
    .update(fields)
    .eq("id", providerId)
    .select()
    .single();
  if (error) throw error;
  await auditLog(adminId, "registry_provider_update", { provider_id: providerId, fields });
  safeLogAdminAction(req, "registry_provider_update", { provider_id: providerId, fields });
  return data;
}

async function setProviderHealth(adminId, req, providerCode, status, note) {
  await ServiceRegistry.setProviderHealth(providerCode, status);
  await auditLog(adminId, "registry_provider_health_change", { provider_code: providerCode, status, note });
  safeLogAdminAction(req, "registry_provider_health_change", { provider_code: providerCode, status });
  return { provider_code: providerCode, health_status: status };
}

// ------------------------------------------------------------
// Capabilities — what a provider is DECLARED to support. Must exist
// before service_routing can reference (provider, service) — enforced
// in upsertRouting() below via ServiceRegistry.assertCapability().
// ------------------------------------------------------------
async function listCapabilities(providerId) {
  const { data, error } = await supabase
    .from("provider_capabilities")
    .select("*, services(code, name, category_id)")
    .eq("provider_id", providerId);
  if (error) throw error;
  return data;
}

async function addCapability(adminId, req, providerId, serviceCode) {
  const { data, error } = await supabase
    .from("provider_capabilities")
    .upsert({ provider_id: providerId, service_code: serviceCode, is_active: true })
    .select()
    .single();
  if (error) throw error;
  await auditLog(adminId, "registry_capability_add", { provider_id: providerId, service_code: serviceCode });
  safeLogAdminAction(req, "registry_capability_add", { provider_id: providerId, service_code: serviceCode });
  return data;
}

async function removeCapability(adminId, req, providerId, serviceCode) {
  // Removing a capability a provider is currently ROUTED for would
  // silently orphan that service_routing row (resolve() would then
  // fall through to the next-priority provider, or throw
  // NoProviderConfiguredError if there is none) — surface that
  // instead of letting an admin accidentally take a live service
  // offline with no warning.
  const { data: activeRoute } = await supabase
    .from("service_routing")
    .select("id, priority, is_active")
    .eq("provider_id", providerId)
    .eq("service_code", serviceCode)
    .eq("is_active", true)
    .maybeSingle();

  if (activeRoute) {
    const err = new Error(
      `This provider is actively routed for '${serviceCode}' (priority ${activeRoute.priority}). Remove or reassign that routing first before removing the capability.`,
    );
    err.code = "ROUTING_DEPENDS_ON_CAPABILITY";
    throw err;
  }

  const { error } = await supabase
    .from("provider_capabilities")
    .delete()
    .eq("provider_id", providerId)
    .eq("service_code", serviceCode);
  if (error) throw error;
  await auditLog(adminId, "registry_capability_remove", { provider_id: providerId, service_code: serviceCode });
  safeLogAdminAction(req, "registry_capability_remove", { provider_id: providerId, service_code: serviceCode });
  return { removed: true };
}

// ------------------------------------------------------------
// Routing — per-service provider assignment + priority. This is what
// ServiceRegistry.resolve() actually reads at request time.
// ------------------------------------------------------------
async function listRouting(serviceCode) {
  const { data, error } = await supabase
    .from("service_routing")
    .select("*, providers(id, code, name, is_active, health_status)")
    .eq("service_code", serviceCode)
    .order("priority", { ascending: true });
  if (error) throw error;
  return data;
}

async function upsertRouting(adminId, req, { service_code, provider_id, priority, is_active = true }) {
  // Enforced here (not just in resolve()) — this is the actual
  // "Admin Panel must prevent assigning providers to services they do
  // not support" gate from the spec.
  await ServiceRegistry.assertCapability(provider_id, service_code);

  const { data, error } = await supabase
    .from("service_routing")
    .upsert(
      { service_code, provider_id, priority, is_active, updated_at: new Date().toISOString() },
      { onConflict: "service_code,provider_id" },
    )
    .select()
    .single();
  if (error) throw error;
  await auditLog(adminId, "registry_routing_upsert", { service_code, provider_id, priority, is_active });
  safeLogAdminAction(req, "registry_routing_upsert", { service_code, provider_id, priority });
  return data;
}

async function removeRouting(adminId, req, routingId) {
  const { data, error } = await supabase
    .from("service_routing")
    .delete()
    .eq("id", routingId)
    .select()
    .single();
  if (error) throw error;
  await auditLog(adminId, "registry_routing_remove", { routing_id: routingId });
  safeLogAdminAction(req, "registry_routing_remove", { routing_id: routingId });
  return data;
}

module.exports = {
  listCategories,
  listServices,
  listProviders,
  createProvider,
  updateProvider,
  setProviderHealth,
  listCapabilities,
  addCapability,
  removeCapability,
  listRouting,
  upsertRouting,
  removeRouting,
};