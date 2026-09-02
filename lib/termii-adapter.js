// lib/sms/providers/termii-adapter.js
//
// Termii (https://developer.termii.com) — primary provider.
//
// CONFIRM before relying on this in production: Termii's API has
// changed field names across versions before (e.g. `sms` vs
// `message`); verify the request/response shape below against your
// current Termii dashboard/docs and adjust TERMII_SEND_PATH /
// TERMII_BALANCE_PATH or the payload keys if they've drifted. Same
// convention this codebase already uses for CONFIRM comments on
// provider integrations (see feecent.sql's VTpass/VAT migration notes).
//
// Required env vars:
//   TERMII_API_KEY
//   TERMII_SENDER_ID        (registered/approved sender ID)
//   TERMII_BASE_URL         (default https://api.ng.termii.com)

const axios = require("axios");
const { BaseSmsAdapter } = require("./base-adapter");
const { classifyHttpError, NON_RETRYABLE } = require("./error-classifier");

const TERMII_SEND_PATH = "/api/sms/send";
const TERMII_BALANCE_PATH = "/api/get-balance";

class TermiiAdapter extends BaseSmsAdapter {
  constructor() {
    super({ code: "termii", timeoutMs: 5000 });
    this.apiKey = process.env.TERMII_API_KEY;
    this.senderId = process.env.TERMII_SENDER_ID;
    this.baseUrl = process.env.TERMII_BASE_URL || "https://api.ng.termii.com";
  }

  isConfigured() {
    return !!(this.apiKey && this.senderId);
  }

  async sendSMS({ to, message, reference }) {
    if (!this.isConfigured()) {
      const err = new Error("Termii is not configured (missing API key/sender id)");
      err.category = "PROVIDER_CONFIGURATION_ERROR";
      throw err;
    }

    try {
      const { data } = await axios.post(
        `${this.baseUrl}${TERMII_SEND_PATH}`,
        {
          api_key: this.apiKey,
          to,
          from: this.senderId,
          sms: message,
          type: "plain",
          channel: "generic",
          // CONFIRM: if your Termii account plan supports a client-side
          // idempotency/reference field, thread `reference` through
          // here instead of only logging it locally.
        },
        { timeout: this.timeoutMs },
      );

      // CONFIRM: Termii's documented success shape returns
      // `message_id` and `code: "ok"`. Some historical responses used
      // `message_id_str`. If `code` is present and not "ok", treat as
      // NON_RETRYABLE (provider understood and rejected the request).
      if (data && data.code && data.code !== "ok") {
        const err = new Error(data.message || "Termii rejected the request");
        err.category = NON_RETRYABLE;
        err.providerCode = data.code;
        throw err;
      }

      return { providerMessageId: data?.message_id || data?.message_id_str || null, raw: data };
    } catch (err) {
      if (err.category) throw err; // already classified above
      err.category = classifyHttpError(err);
      throw err;
    }
  }

  async getDeliveryStatus(_providerMessageId) {
    // CONFIRM: Termii's delivery-report retrieval endpoint/shape
    // against current docs before wiring this up for real — left as a
    // documented gap rather than guessed at, per the "don't invent
    // API contracts" rule. Delivery webhooks (section 18) are the
    // primary path; this is only a manual-lookup fallback.
    return { status: "unknown", raw: null };
  }

  normalizeError(err) {
    return {
      category: err.category || classifyHttpError(err),
      code: err.providerCode || err.response?.status || err.code || "UNKNOWN",
      message: err.message,
    };
  }

  async healthCheck() {
    if (!this.isConfigured()) return { healthy: false, latencyMs: 0, detail: "not configured" };
    const start = Date.now();
    try {
      await axios.get(`${this.baseUrl}${TERMII_BALANCE_PATH}`, {
        params: { api_key: this.apiKey },
        timeout: this.timeoutMs,
      });
      return { healthy: true, latencyMs: Date.now() - start, detail: "balance check ok" };
    } catch (err) {
      return { healthy: false, latencyMs: Date.now() - start, detail: err.message };
    }
  }
}

module.exports = { TermiiAdapter };
