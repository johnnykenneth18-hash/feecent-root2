// lib/sms/providers/arkesel-adapter.js
//
// Arkesel — optional third fallback. Seeded DISABLED (see
// 020_sms_infrastructure.sql). Arkesel is Ghana-headquartered; CONFIRM
// it actually delivers reliably to Nigerian numbers on your account
// tier before enabling this in production — if it doesn't, swap this
// file for a different "fourth provider" adapter and nothing else in
// the system needs to change (that's the point of the adapter
// boundary — see base-adapter.js).
//
// CONFIRM the exact endpoint/payload shape against Arkesel's current
// API docs before enabling — the shape below follows their commonly
// documented v2 SMS send pattern, not a value verified against a live
// account by this change.
//
// Required env vars:
//   ARKESEL_API_KEY
//   ARKESEL_SENDER_ID
//   ARKESEL_BASE_URL   (default https://sms.arkesel.com)

const axios = require("axios");
const { BaseSmsAdapter } = require("./base-adapter");
const { classifyHttpError, NON_RETRYABLE } = require("./error-classifier");

class ArkeselAdapter extends BaseSmsAdapter {
  constructor() {
    super({ code: "arkesel", timeoutMs: 5000 });
    this.apiKey = process.env.ARKESEL_API_KEY;
    this.senderId = process.env.ARKESEL_SENDER_ID;
    this.baseUrl = process.env.ARKESEL_BASE_URL || "https://sms.arkesel.com";
  }

  isConfigured() {
    return !!(this.apiKey && this.senderId);
  }

  async sendSMS({ to, message }) {
    if (!this.isConfigured()) {
      const err = new Error("Arkesel is not configured (missing API key/sender id)");
      err.category = "PROVIDER_CONFIGURATION_ERROR";
      throw err;
    }

    try {
      const { data } = await axios.post(
        `${this.baseUrl}/api/v2/sms/send`,
        { sender: this.senderId, message, recipients: [to] },
        { timeout: this.timeoutMs, headers: { "api-key": this.apiKey, "Content-Type": "application/json" } },
      );

      if (data && data.status && data.status !== "success") {
        const err = new Error(data.message || "Arkesel rejected the request");
        err.category = NON_RETRYABLE;
        throw err;
      }

      return { providerMessageId: data?.data?.[0]?.id || null, raw: data };
    } catch (err) {
      if (err.category) throw err;
      err.category = classifyHttpError(err);
      throw err;
    }
  }

  async getDeliveryStatus(_providerMessageId) {
    return { status: "unknown", raw: null };
  }

  normalizeError(err) {
    return {
      category: err.category || classifyHttpError(err),
      code: err.response?.status || err.code || "UNKNOWN",
      message: err.message,
    };
  }

  async healthCheck() {
    if (!this.isConfigured()) return { healthy: false, latencyMs: 0, detail: "not configured" };
    const start = Date.now();
    try {
      await axios.get(`${this.baseUrl}/api/v2/clients/balance-details`, {
        timeout: this.timeoutMs,
        headers: { "api-key": this.apiKey },
      });
      return { healthy: true, latencyMs: Date.now() - start, detail: "balance check ok" };
    } catch (err) {
      return { healthy: false, latencyMs: Date.now() - start, detail: err.message };
    }
  }
}

module.exports = { ArkeselAdapter };
