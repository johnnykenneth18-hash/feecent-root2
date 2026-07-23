// vat-admin-service.js
// Admin control for the VAT rate applied to external transfer fees
// (see 014_vat_on_transfer_fees.sql / vat-service.js for where it's
// actually charged). Deliberately tiny — one config row, plus a
// read-only view of what's still pending — following the same
// audit-logged write pattern as bills-admin-service.js /
// service-registry-admin-service.js.

const { createClient } = require("@supabase/supabase-js");

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
    console.error(`[VAT-ADMIN] audit log write failed for ${actionType}:`, err.message);
  }
}

async function getVatConfig() {
  const { data, error } = await supabase
    .from("vat_config")
    .select("*")
    .order("updated_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function updateVatConfig(adminId, req, { vat_percentage, is_active }) {
  const current = await getVatConfig();
  const fields = { updated_at: new Date().toISOString(), updated_by: adminId };
  if (vat_percentage !== undefined) {
    const pct = Number(vat_percentage);
    if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
      const err = new Error("vat_percentage must be a number between 0 and 100");
      err.code = "INVALID_VAT_PERCENTAGE";
      throw err;
    }
    fields.vat_percentage = pct;
  }
  if (is_active !== undefined) fields.is_active = Boolean(is_active);

  let data, error;
  if (current) {
    ({ data, error } = await supabase.from("vat_config").update(fields).eq("id", current.id).select().single());
  } else {
    ({ data, error } = await supabase
      .from("vat_config")
      .insert({ vat_percentage: 7.5, is_active: true, ...fields })
      .select()
      .single());
  }
  if (error) throw error;

  await auditLog(adminId, "vat_config_update", { previous: current, fields });
  return data;
}

// Visibility into what's stuck waiting for a user's balance to cover
// it — helps support/finance answer "why hasn't my VAT been charged"
// without querying the DB directly.
async function listPendingVat({ limit = 100 } = {}) {
  const { data, error } = await supabase
    .from("vat_transactions")
    .select("*")
    .eq("status", "pending")
    .order("created_at", { ascending: true })
    .limit(limit);
  if (error) throw error;
  return data;
}

module.exports = { getVatConfig, updateVatConfig, listPendingVat };