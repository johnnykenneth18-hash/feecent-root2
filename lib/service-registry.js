// service-registry.js
// Generalizes payment-gateway.js's ProviderRouter to every service
// category in the platform (Payment, Bills, Card, Identity, Fraud,
// Notification, FX, Loan, Savings, Investment) — implements the
// Service Registry & Capability-Based Routing spec.
//
// The one rule everything else in the codebase should follow from
// here on: business logic asks ServiceRegistry.getProvider('<service_
// code>'), never a specific provider module and never a hardcoded
// provider name. payment-gateway.js is kept only as a thin,
// backward-compatible facade over this file (see its own header) so
// bills-worker.js / bills-admin-service.js / the transfer workers
// don't have to change their call shape while the routing engine
// underneath is swapped out.
//
// Routing precedence read from service_routing, joined to providers
// (see 011_service_registry.sql):
//   1. service_routing.is_active AND providers.is_active
//   2. providers.health_status != 'down'
//   3. lowest service_routing.priority wins (1 = primary, 2 = first
//      fallback, ...)
// The first candidate that ALSO has a registered code implementation
// in PROVIDER_IMPLEMENTATIONS wins. A category can be fully
// configured in the database (rows in services/providers/
// service_routing) with no working code behind it yet — that's a
// scaffolded-but-not-built service, and resolve() skips such rows
// rather than crashing, but still reports a clear error if nothing
// usable was found at all.

const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// ------------------------------------------------------------
// Registered implementations, keyed by provider code. Adding a real
// provider = write the module (implementing the interface its
// category needs — see payment-provider.js for the Payment/Bills
// shape), register it here, then add its `providers` row +
// provider_capabilities + service_routing rows via migration or the
// admin panel. Nothing in this file ever branches on a provider name
// beyond this one map.
// ------------------------------------------------------------
const PROVIDER_IMPLEMENTATIONS = {
  flutterwave: require("./flutterwave-provider"),
  paystack: require("./paystack-provider"),
  monnify: require("./monnify-provider"),
  // Not built yet — uncomment once implemented and given a `providers`
  // row + capabilities:
  // termii: require("./termii-provider"),
  // "smile-identity": require("./smile-identity-provider"),
};

class NoProviderConfiguredError extends Error {
  constructor(serviceCode) {
    super(
      `No active, healthy provider with a working implementation is routed for service '${serviceCode}'`,
    );
    this.name = "NoProviderConfiguredError";
    this.code = "SERVICE_NOT_CONFIGURED";
    this.serviceCode = serviceCode;
  }
}

class ServiceRegistry {
  /**
   * Resolves a service code to the provider that should handle it
   * right now. Returns { implementation, providerCode, providerId }.
   * Throws NoProviderConfiguredError if nothing usable exists —
   * callers should not have to guess why a request silently didn't
   * happen (same philosophy as the old ProviderRouter).
   *
   * Checks a manual override FIRST, before any automatic priority/
   * health logic: services.manual_override_provider_id (see
   * 012_manual_provider_override.sql). This is the escape hatch for
   * "automatic failover isn't behaving, force this provider right
   * now" — set from the admin panel via
   * service-registry-admin-service.js's setManualOverride(). An
   * override is honored regardless of health_status (the admin is
   * overriding the health heuristic on purpose) but NOT if the
   * overridden provider is is_active=false or has no implementation —
   * those fail loudly with a clear error rather than silently falling
   * back to automatic, since a silent fallback would defeat the whole
   * point of an operator forcing a specific provider.
   */
  async resolve(serviceCode) {
    const { data: service, error: serviceErr } = await supabase
      .from("services")
      .select("manual_override_provider_id, providers!services_manual_override_provider_id_fkey(id, code, name, is_active)")
      .eq("code", serviceCode)
      .maybeSingle();

    if (serviceErr) {
      throw new Error(`Service lookup failed for '${serviceCode}': ${serviceErr.message}`);
    }

    if (service?.manual_override_provider_id) {
      const overrideProvider = service.providers;
      if (!overrideProvider || !overrideProvider.is_active) {
        throw new Error(
          `Manual override for '${serviceCode}' points to a provider that is missing or inactive. Fix or clear the override from the admin panel — refusing to silently fall back to automatic routing.`,
        );
      }
      const implementation = PROVIDER_IMPLEMENTATIONS[overrideProvider.code];
      if (!implementation) {
        throw new Error(
          `Manual override for '${serviceCode}' points to provider '${overrideProvider.code}', which has no registered implementation.`,
        );
      }
      return {
        implementation,
        providerCode: overrideProvider.code,
        providerId: overrideProvider.id,
        manualOverride: true,
      };
    }

    const { data: routes, error } = await supabase
      .from("service_routing")
      .select("priority, providers(id, code, name, is_active, health_status)")
      .eq("service_code", serviceCode)
      .eq("is_active", true)
      .order("priority", { ascending: true });

    if (error) {
      throw new Error(
        `Service routing lookup failed for '${serviceCode}': ${error.message}`,
      );
    }

    for (const route of routes || []) {
      const provider = route.providers;
      if (!provider || !provider.is_active) continue;
      if (provider.health_status === "down") continue;
      const implementation = PROVIDER_IMPLEMENTATIONS[provider.code];
      if (!implementation) continue; // configured in DB, no code behind it yet
      return {
        implementation,
        providerCode: provider.code,
        providerId: provider.id,
        manualOverride: false,
      };
    }

    throw new NoProviderConfiguredError(serviceCode);
  }

  async getProvider(serviceCode) {
    const { implementation } = await this.resolve(serviceCode);
    return implementation;
  }

  /**
   * Returns a specific provider by code, bypassing routing entirely.
   * Used for anything that must go back to the exact provider that
   * handled the original request (status checks, verification,
   * reversal) — re-routing those by service code again could hand a
   * follow-up call to a different provider once more than one is
   * configured for the same service, silently querying the wrong
   * system.
   */
  getProviderByCode(code) {
    const implementation = PROVIDER_IMPLEMENTATIONS[code];
    if (!implementation) {
      throw new Error(
        `No provider implementation registered for code '${code}'`,
      );
    }
    return implementation;
  }

  /**
   * Manual (or future health-check-driven) circuit breaker. Kept
   * deliberately simple — there's no automatic health probing yet;
   * this just gives admin overrides and future monitoring code one
   * place to write to without touching is_active (which would also
   * hide the provider from history/reporting, not just routing).
   */
  async setProviderHealth(providerCode, status) {
    if (!["healthy", "degraded", "down"].includes(status)) {
      throw new Error(`Invalid health status '${status}'`);
    }
    const { error } = await supabase
      .from("providers")
      .update({
        health_status: status,
        health_updated_at: new Date().toISOString(),
      })
      .eq("code", providerCode);
    if (error) throw error;
  }

  /**
   * Forces a specific provider for a service, bypassing priority and
   * health entirely — the manual override switch. Validates the
   * provider actually declares the capability first (same rule as
   * automatic routing assignment) so an override can't point at a
   * provider that has no code path for this service at all.
   */
  async setManualOverride(serviceCode, providerId) {
    await this.assertCapability(providerId, serviceCode);
    const { error } = await supabase
      .from("services")
      .update({
        manual_override_provider_id: providerId,
        manual_override_set_at: new Date().toISOString(),
      })
      .eq("code", serviceCode);
    if (error) throw error;
  }

  /** Reverts a service to automatic priority/health-based routing. */
  async clearManualOverride(serviceCode) {
    const { error } = await supabase
      .from("services")
      .update({ manual_override_provider_id: null, manual_override_set_at: null })
      .eq("code", serviceCode);
    if (error) throw error;
  }

  /**
   * Validates a provider actually declares a capability before
   * allowing it to be routed to that service — the spec's "Admin
   * Panel must prevent assigning providers to services they do not
   * support" requirement. Call this from the admin service_routing
   * write path, not from resolve() (resolve() trusts the data is
   * already valid — this is where that invariant gets enforced).
   */
  async assertCapability(providerId, serviceCode) {
    const { data, error } = await supabase
      .from("provider_capabilities")
      .select("provider_id")
      .eq("provider_id", providerId)
      .eq("service_code", serviceCode)
      .eq("is_active", true)
      .maybeSingle();
    if (error) throw error;
    if (!data) {
      const err = new Error(
        `This provider does not declare capability '${serviceCode}'. Add it under Capabilities before routing this service to it.`,
      );
      err.code = "CAPABILITY_NOT_DECLARED";
      throw err;
    }
  }
}

module.exports = {
  ServiceRegistry: new ServiceRegistry(),
  NoProviderConfiguredError,
  PROVIDER_IMPLEMENTATIONS,
};