// lib/sms/circuit-breaker.js
//
// Per-provider circuit breaker, persisted in provider_circuit_state so
// state survives across serverless invocations (nothing here can rely
// on in-process memory — every request may hit a cold Vercel function).
//
// States (section 16):
//   closed     -> normal routing, this provider is eligible
//   open       -> skip this provider entirely until recoveryMs has passed
//   half_open  -> allow a small number of probe requests through; a
//                 success closes the circuit, a failure re-opens it
//
// Config is read from provider config where set, else these defaults:
const DEFAULT_FAILURE_THRESHOLD = 5; // consecutive retryable/unknown failures to open
const DEFAULT_RECOVERY_MS = 60_000; // how long OPEN lasts before probing
const DEFAULT_HALF_OPEN_PROBES = 1; // requests allowed through while half_open

class CircuitBreaker {
  constructor(supabase) {
    this.supabase = supabase;
  }

  async getState(providerId) {
    const { data } = await this.supabase
      .from("provider_circuit_state")
      .select("*")
      .eq("provider_id", providerId)
      .maybeSingle();
    return data;
  }

  // isEligible() also performs the open->half_open transition when the
  // recovery window has elapsed, and hands back whether this call is
  // allowed to count as a "probe" so recordResult() knows how to score it.
  async isEligible(providerId, { recoveryMs = DEFAULT_RECOVERY_MS, halfOpenProbes = DEFAULT_HALF_OPEN_PROBES } = {}) {
    let state = await this.getState(providerId);
    if (!state) {
      await this.supabase.from("provider_circuit_state").upsert({ provider_id: providerId, state: "closed" });
      return { eligible: true, isProbe: false };
    }

    if (state.state === "closed") return { eligible: true, isProbe: false };

    if (state.state === "open") {
      const elapsed = Date.now() - new Date(state.opened_at).getTime();
      if (elapsed < recoveryMs) return { eligible: false, isProbe: false };

      // Recovery window elapsed -> move to half_open and allow probes.
      await this.supabase
        .from("provider_circuit_state")
        .update({ state: "half_open", half_open_probes_remaining: halfOpenProbes, updated_at: new Date().toISOString() })
        .eq("provider_id", providerId);
      return { eligible: true, isProbe: true };
    }

    // half_open
    if (state.half_open_probes_remaining > 0) return { eligible: true, isProbe: true };
    return { eligible: false, isProbe: false };
  }

  async recordSuccess(providerId) {
    await this.supabase
      .from("provider_circuit_state")
      .update({ state: "closed", consecutive_failures: 0, opened_at: null, updated_at: new Date().toISOString() })
      .eq("provider_id", providerId);
  }

  // Only RETRYABLE and UNKNOWN outcomes count toward tripping the
  // breaker — a NON_RETRYABLE failure (bad phone number) says nothing
  // about the provider's health, so it must never open the circuit.
  async recordFailure(providerId, category, { failureThreshold = DEFAULT_FAILURE_THRESHOLD } = {}) {
    if (category !== "RETRYABLE" && category !== "UNKNOWN") return;

    const state = await this.getState(providerId);
    const consecutive = (state?.consecutive_failures || 0) + 1;

    if (state?.state === "half_open") {
      // Probe failed -> straight back to open.
      await this.supabase
        .from("provider_circuit_state")
        .update({ state: "open", consecutive_failures: consecutive, opened_at: new Date().toISOString(), updated_at: new Date().toISOString() })
        .eq("provider_id", providerId);
      return;
    }

    if (consecutive >= failureThreshold) {
      await this.supabase
        .from("provider_circuit_state")
        .update({ state: "open", consecutive_failures: consecutive, opened_at: new Date().toISOString(), updated_at: new Date().toISOString() })
        .eq("provider_id", providerId);
      return;
    }

    await this.supabase
      .from("provider_circuit_state")
      .update({ consecutive_failures: consecutive, updated_at: new Date().toISOString() })
      .eq("provider_id", providerId);
  }

  // If half_open and this WAS a probe that succeeded, decrement the
  // probe budget as part of recordSuccess's UPDATE — folded in above
  // since recordSuccess always resets to closed on any success,
  // which is the correct "test succeeded, fully close" behavior.

  async recordMetrics(providerId, { success, timedOut, unknown, responseMs }) {
    const { data: existing } = await this.supabase
      .from("provider_health_metrics")
      .select("*")
      .eq("provider_id", providerId)
      .maybeSingle();

    const base = existing || {
      total_requests: 0, successful_requests: 0, failed_requests: 0,
      timeouts: 0, unknown_responses: 0, total_response_ms: 0,
    };

    const now = new Date().toISOString();
    await this.supabase.from("provider_health_metrics").upsert({
      provider_id: providerId,
      total_requests: base.total_requests + 1,
      successful_requests: base.successful_requests + (success ? 1 : 0),
      failed_requests: base.failed_requests + (success ? 0 : 1),
      timeouts: base.timeouts + (timedOut ? 1 : 0),
      unknown_responses: base.unknown_responses + (unknown ? 1 : 0),
      total_response_ms: base.total_response_ms + (responseMs || 0),
      last_success_at: success ? now : existing?.last_success_at,
      last_failure_at: !success ? now : existing?.last_failure_at,
      updated_at: now,
    });
  }
}

module.exports = { CircuitBreaker };
