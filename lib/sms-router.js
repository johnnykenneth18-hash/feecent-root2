// lib/sms/sms-router.js
//
// SMSRouter — the only piece of code that knows "which provider
// handles this service right now." Reads provider order from
// service_routing (admin-configurable, see sms-admin-routes.js),
// filters out disabled providers and open circuits, then calls
// adapters in priority order until one succeeds or the list is
// exhausted.
//
// Deliberately mirrors the existing ServiceRegistry.resolve() pattern
// (service_routing/provider_capabilities, see 013_service_registry.sql)
// rather than inventing a separate routing table — this is that same
// pattern applied to SMS.

const { CircuitBreaker } = require("./circuit-breaker");
const { TermiiAdapter } = require("./termii-adapter");
const { AfricasTalkingAdapter } = require("./africastalking-adapter");
const { BulkSmsNigeriaAdapter } = require("./bulksmsnigeria-adapter");
const { ArkeselAdapter } = require("./arkesel-adapter");

// Adding a fifth provider: write its adapter file, register it here,
// add its `providers` row + capabilities/service_routing in a new
// migration. Nothing else in the app changes (spec section 1).
const ADAPTER_REGISTRY = {
  termii: () => new TermiiAdapter(),
  africastalking: () => new AfricasTalkingAdapter(),
  bulksmsnigeria: () => new BulkSmsNigeriaAdapter(),
  arkesel: () => new ArkeselAdapter(),
};

class SMSRouter {
  constructor(supabase) {
    this.supabase = supabase;
    this.circuitBreaker = new CircuitBreaker(supabase);
  }

  // Ordered, currently-usable providers for a service code — enabled
  // at the provider level, enabled at the routing level, and not
  // presently open-circuit. Admin panel changes take effect on the
  // very next call (no caching layer here — SMS volume doesn't
  // warrant it, and correctness beats a few ms of DB round-trip).
  async resolveProviderChain(serviceCode) {
    const { data: routes, error } = await this.supabase
      .from("service_routing")
      .select("priority, providers!inner(id, code, name, is_active)")
      .eq("service_code", serviceCode)
      .eq("is_active", true)
      .eq("providers.is_active", true)
      .order("priority", { ascending: true });

    if (error) throw error;

    const chain = [];
    for (const route of routes || []) {
      const provider = route.providers;
      if (!ADAPTER_REGISTRY[provider.code]) continue; // no adapter implemented yet — skip, don't crash routing
      const { eligible, isProbe } = await this.circuitBreaker.isEligible(provider.id);
      if (!eligible) continue;
      chain.push({ id: provider.id, code: provider.code, name: provider.name, isProbe });
    }
    return chain;
  }

  // sendWithFailover walks the chain in order. `onAttempt` is called
  // after every attempt (success or failure) so the caller can persist
  // an sms_delivery_attempts row without this router knowing anything
  // about the DB schema for that table — keeps the router unit-testable
  // with a plain mock instead of a live Supabase instance.
  //
  // Returns { success, provider, providerMessageId, raw, attempts } on
  // success, or throws SMSAllProvidersFailedError with `attempts` on
  // exhaustion.
  async sendWithFailover(serviceCode, { to, message, reference }, onAttempt = async () => {}) {
    const chain = await this.resolveProviderChain(serviceCode);
    if (chain.length === 0) {
      const err = new Error(`No eligible SMS provider for service "${serviceCode}"`);
      err.code = "NO_PROVIDER_AVAILABLE";
      throw err;
    }

    const attempts = [];
    let attemptNumber = 0;

    for (const provider of chain) {
      attemptNumber += 1;
      const adapter = ADAPTER_REGISTRY[provider.code]();
      const start = Date.now();

      try {
        const result = await adapter.sendSMS({ to, message, reference });
        const responseMs = Date.now() - start;

        await this.circuitBreaker.recordSuccess(provider.id);
        await this.circuitBreaker.recordMetrics(provider.id, { success: true, responseMs });

        const attempt = {
          provider: provider.code, attemptNumber, status: "sent",
          providerMessageId: result.providerMessageId, responseMs,
        };
        attempts.push(attempt);
        await onAttempt(attempt);

        return { success: true, provider: provider.code, providerMessageId: result.providerMessageId, raw: result.raw, attempts };
      } catch (err) {
        const responseMs = Date.now() - start;
        const normalized = adapter.normalizeError(err);

        await this.circuitBreaker.recordFailure(provider.id, normalized.category);
        await this.circuitBreaker.recordMetrics(provider.id, {
          success: false,
          timedOut: normalized.category === "UNKNOWN",
          unknown: normalized.category === "UNKNOWN",
          responseMs,
        });

        const attempt = {
          provider: provider.code, attemptNumber,
          status: normalized.category === "UNKNOWN" ? "unknown" : "failed",
          errorCategory: normalized.category, errorCode: normalized.code, errorMessage: normalized.message, responseMs,
        };
        attempts.push(attempt);
        await onAttempt(attempt);

        // NON_RETRYABLE and PROVIDER_CONFIGURATION_ERROR: another
        // provider genuinely might succeed where this one has a config
        // problem, so we DO still fail over for config errors — only a
        // bad phone number (NON_RETRYABLE) stops the whole chain, since
        // every provider would reject the same malformed number.
        if (normalized.category === "NON_RETRYABLE") {
          const finalErr = new SMSAllProvidersFailedError("Recipient rejected by provider", attempts);
          finalErr.terminal = true;
          throw finalErr;
        }
        // RETRYABLE / UNKNOWN / PROVIDER_CONFIGURATION_ERROR -> continue to next provider
      }
    }

    throw new SMSAllProvidersFailedError("All eligible SMS providers failed", attempts);
  }
}

class SMSAllProvidersFailedError extends Error {
  constructor(message, attempts) {
    super(message);
    this.name = "SMSAllProvidersFailedError";
    this.attempts = attempts;
  }
}

module.exports = { SMSRouter, SMSAllProvidersFailedError, ADAPTER_REGISTRY };
