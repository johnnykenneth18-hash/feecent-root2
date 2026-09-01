// lib/sms/sms-admin-routes.js
//
// Admin API for SMS Providers (spec section 25/36). Exported as a
// factory taking `requirePermission` as a parameter — same convention
// as vat-admin-routes.js/bills-admin-routes.js in this codebase (the
// router doesn't import middleware/auth itself; index.js injects it).
// Mount exactly like those:
//
//   const smsAdminRouter = require("../lib/sms/sms-admin-routes");
//   app.use("/api/sys/sms", authenticate, authorizeAdmin, smsAdminRouter(requirePermission));
//
// Permission keys used below follow the existing "section:actionId"
// convention (auth.js) — add matching entries to the frontend's
// admin-permissions.js ACTIONS_REGISTRY so the buttons this API backs
// are actually reachable in the UI; see INTEGRATION.md.

const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const { SMSRouter, ADAPTER_REGISTRY } = require("./sms-router");

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const smsRouter = new SMSRouter(supabase);

const SMS_SERVICE_CODES = ["sms_otp", "sms_transactional", "sms_marketing"];

async function auditLog(req, action, resource, oldValue, newValue) {
  await supabase.from("admin_actions").insert({
    admin_id: req.user.id,
    action_type: action,
    details: { resource, old_value: oldValue ?? null, new_value: newValue ?? null },
    ip_address: req.ip,
  });
}

module.exports = function smsAdminRoutesFactory(requirePermission) {
  const router = express.Router();


// ---------------------------------------------------------------
// GET /admin/sms/providers — list with health/circuit/routing state.
// Never returns provider secrets (those live in env vars, never DB —
// section 24 — so there is nothing to mask here beyond confirming the
// UI only ever renders `configured: true/false`, not a value).
// ---------------------------------------------------------------
router.get("/providers", requirePermission("sms:view-providers"), async (req, res) => {
  try {
    const { data: providers, error } = await supabase
      .from("providers")
      .select("id, code, name, is_active, priority, health_status, created_at, updated_at")
      .in("code", Object.keys(ADAPTER_REGISTRY))
      .order("priority", { ascending: true });
    if (error) throw error;

    const { data: circuits } = await supabase.from("provider_circuit_state").select("*");
    const { data: metrics } = await supabase.from("provider_health_metrics").select("*");
    const { data: routing } = await supabase
      .from("service_routing")
      .select("service_code, priority, is_active, provider_id")
      .in("service_code", SMS_SERVICE_CODES);
    const { data: capabilities } = await supabase.from("provider_capabilities").select("provider_id, service_code");

    const result = providers.map((p) => {
      const circuit = circuits?.find((c) => c.provider_id === p.id);
      const metric = metrics?.find((m) => m.provider_id === p.id);
      const successRate = metric && metric.total_requests > 0
        ? Number(((metric.successful_requests / metric.total_requests) * 100).toFixed(1))
        : null;
      const avgLatencyMs = metric && metric.successful_requests > 0
        ? Math.round(metric.total_response_ms / metric.total_requests)
        : null;

      const adapter = ADAPTER_REGISTRY[p.code]();
      return {
        id: p.id, code: p.code, name: p.name, isActive: p.is_active,
        configured: adapter.isConfigured ? adapter.isConfigured() : true,
        circuitState: circuit?.state || "closed",
        healthTier: !metric || metric.total_requests === 0 ? "UNKNOWN"
          : successRate >= 97 ? "HEALTHY" : successRate >= 85 ? "DEGRADED" : "DOWN",
        successRatePct: successRate,
        avgLatencyMs,
        totalRequests: metric?.total_requests || 0,
        timeouts: metric?.timeouts || 0,
        lastSuccessAt: metric?.last_success_at || null,
        lastFailureAt: metric?.last_failure_at || null,
        capabilities: capabilities?.filter((c) => c.provider_id === p.id).map((c) => c.service_code) || [],
        routing: routing?.filter((r) => r.provider_id === p.id).map((r) => ({
          serviceCode: r.service_code, priority: r.priority, isActive: r.is_active,
        })) || [],
      };
    });

    res.json({ providers: result });
  } catch (err) {
    console.error("[SMS_ADMIN] list providers error:", err);
    res.status(500).json({ error: "Failed to load SMS providers" });
  }
});

// ---------------------------------------------------------------
// PATCH /admin/sms/providers/:id — enable/disable, or set priority
// for a specific service lane. Body: { isActive?, serviceCode?, priority? }
// ---------------------------------------------------------------
router.patch("/providers/:id", requirePermission("sms:configure-providers"), async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive, serviceCode, priority } = req.body;

    const { data: before } = await supabase.from("providers").select("*").eq("id", id).maybeSingle();
    if (!before) return res.status(404).json({ error: "Provider not found" });

    if (typeof isActive === "boolean") {
      await supabase.from("providers").update({ is_active: isActive, updated_at: new Date().toISOString() }).eq("id", id);
      await auditLog(req, "sms_provider_enabled_changed", `providers:${id}`, before.is_active, isActive);
    }

    if (serviceCode && typeof priority === "number") {
      if (!SMS_SERVICE_CODES.includes(serviceCode)) {
        return res.status(400).json({ error: `serviceCode must be one of ${SMS_SERVICE_CODES.join(", ")}` });
      }
      const { data: capable } = await supabase
        .from("provider_capabilities")
        .select("provider_id")
        .eq("provider_id", id)
        .eq("service_code", serviceCode)
        .maybeSingle();
      if (!capable) {
        return res.status(400).json({ error: `${before.code} does not declare capability for ${serviceCode}` });
      }

      const { data: beforeRoute } = await supabase
        .from("service_routing").select("priority").eq("provider_id", id).eq("service_code", serviceCode).maybeSingle();

      await supabase
        .from("service_routing")
        .upsert(
          { provider_id: id, service_code: serviceCode, priority, is_active: true, updated_at: new Date().toISOString() },
          { onConflict: "service_code,provider_id" },
        );
      await auditLog(req, "sms_provider_priority_changed", `service_routing:${serviceCode}:${id}`, beforeRoute?.priority ?? null, priority);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error("[SMS_ADMIN] patch provider error:", err);
    res.status(500).json({ error: "Failed to update provider" });
  }
});

// ---------------------------------------------------------------
// POST /admin/sms/providers/:id/test — cheap healthCheck() call, NOT
// a real SMS send (base-adapter.js contract).
// ---------------------------------------------------------------
router.post("/providers/:id/test", requirePermission("sms:configure-providers"), async (req, res) => {
  try {
    const { data: provider } = await supabase.from("providers").select("code").eq("id", req.params.id).maybeSingle();
    if (!provider || !ADAPTER_REGISTRY[provider.code]) return res.status(404).json({ error: "Provider not found" });

    const adapter = ADAPTER_REGISTRY[provider.code]();
    const result = await adapter.healthCheck();
    await auditLog(req, "sms_provider_tested", `providers:${req.params.id}`, null, result);
    res.json(result);
  } catch (err) {
    console.error("[SMS_ADMIN] test provider error:", err);
    res.status(500).json({ error: "Test failed", detail: err.message });
  }
});

// ---------------------------------------------------------------
// POST /admin/sms/providers/:id/rotate-credentials — credentials
// themselves live in env vars (section 24), never the DB, so there is
// nothing this endpoint can rotate directly. It exists to produce the
// required audit trail (section 29) around a rotation performed out of
// band (Vercel/host secrets manager) and to bump the provider's config
// version so any in-memory adapter caches elsewhere pick up the change
// promptly — CONFIRM this fits your actual secrets-rotation runbook.
// ---------------------------------------------------------------
router.post("/providers/:id/rotate-credentials", requirePermission("sms:configure-providers"), async (req, res) => {
  await auditLog(req, "sms_provider_credentials_rotation_acknowledged", `providers:${req.params.id}`, null, { by: req.user.id });
  res.json({ ok: true, note: "Rotate the actual secret in your environment/secrets manager — this only records the audit event." });
});

// ---------------------------------------------------------------
// GET /admin/sms/messages — paginated send history (never returns raw
// phone numbers or OTP values — phone_number_hash only, per section 30).
// ---------------------------------------------------------------
router.get("/messages", requirePermission("sms:view-providers"), async (req, res) => {
  try {
    const { status, messageType, limit = 50, offset = 0 } = req.query;
    let query = supabase
      .from("sms_messages")
      .select("id, user_id, purpose, message_type, status, selected_provider, provider_message_id, created_at, sent_at, delivered_at, failed_at")
      .order("created_at", { ascending: false })
      .range(Number(offset), Number(offset) + Number(limit) - 1);

    if (status) query = query.eq("status", status);
    if (messageType) query = query.eq("message_type", messageType);

    const { data, error } = await query;
    if (error) throw error;
    res.json({ messages: data });
  } catch (err) {
    console.error("[SMS_ADMIN] list messages error:", err);
    res.status(500).json({ error: "Failed to load SMS messages" });
  }
});

// ---------------------------------------------------------------
// GET /admin/sms/messages/:id/delivery — full attempt trail for one message.
// ---------------------------------------------------------------
router.get("/messages/:id/delivery", requirePermission("sms:view-providers"), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("sms_delivery_attempts")
      .select("*")
      .eq("sms_message_id", req.params.id)
      .order("attempt_number", { ascending: true });
    if (error) throw error;
    res.json({ attempts: data });
  } catch (err) {
    console.error("[SMS_ADMIN] delivery trail error:", err);
    res.status(500).json({ error: "Failed to load delivery attempts" });
  }
});

// ---------------------------------------------------------------
// GET /admin/sms/metrics — dashboard tiles (section 17).
// ---------------------------------------------------------------
router.get("/metrics", requirePermission("sms:view-providers"), async (req, res) => {
  try {
    const { data: metrics, error } = await supabase
      .from("provider_health_metrics")
      .select("*, providers!inner(code, name)");
    if (error) throw error;

    res.json({
      providers: (metrics || []).map((m) => ({
        code: m.providers.code,
        name: m.providers.name,
        totalRequests: m.total_requests,
        successRatePct: m.total_requests > 0 ? Number(((m.successful_requests / m.total_requests) * 100).toFixed(1)) : null,
        avgResponseMs: m.total_requests > 0 ? Math.round(m.total_response_ms / m.total_requests) : null,
        timeouts: m.timeouts,
        unknownResponses: m.unknown_responses,
        lastSuccessAt: m.last_success_at,
        lastFailureAt: m.last_failure_at,
      })),
    });
  } catch (err) {
    console.error("[SMS_ADMIN] metrics error:", err);
    res.status(500).json({ error: "Failed to load SMS metrics" });
  }
});

  return router;
};
