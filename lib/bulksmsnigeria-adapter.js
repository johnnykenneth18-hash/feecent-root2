// lib/sms/providers/bulksmsnigeria-adapter.js
//
// BulkSMSNigeria — fallback provider #2. Seeded DISABLED in the
// migration (see 020_sms_infrastructure.sql) until real credentials
// are supplied and this is verified against a live account.
//
// CONFIRM the exact endpoint/auth/payload shape against BulkSMSNigeria's
// current API documentation before enabling in production — write this
// adapter's request/response handling to match what their dashboard's
// API docs show at integration time; the shape below is a best-effort
// placeholder using their commonly-documented token-auth REST pattern,
// not a value verified against a live account by this change.
//
// Required env vars:
//   BULKSMSNIGERIA_API_TOKEN
//   BULKSMSNIGERIA_SENDER_ID
//   BULKSMSNIGERIA_BASE_URL   (default https://www.bulksmsnigeria.com)

const axios = require("axios");
const { BaseSmsAdapter } = require("./base-adapter");
const { classifyHttpError, NON_RETRYABLE } = require("../../../../lib/error-classifier");

class BulkSmsNigeriaAdapter extends BaseSmsAdapter {
  constructor() {
    super({ code: "bulksmsnigeria", timeoutMs: 5000 });
    this.apiToken = process.env.BULKSMSNIGERIA_API_TOKEN;
    this.senderId = process.env.BULKSMSNIGERIA_SENDER_ID;
    this.baseUrl = process.env.BULKSMSNIGERIA_BASE_URL || "https://www.bulksmsnigeria.com";
  }

  isConfigured() {
    return !!(this.apiToken && this.senderId);
  }

  async sendSMS({ to, message }) {
    if (!this.isConfigured()) {
      const err = new Error("BulkSMSNigeria is not configured (missing API token/sender id)");
      err.category = "PROVIDER_CONFIGURATION_ERROR";
      throw err;
    }

    try {
      const { data } = await axios.post(
        `${this.baseUrl}/api/v2/sms`,
        { from: this.senderId, to, body: message, dnd: 2 },
        {
          timeout: this.timeoutMs,
          headers: { Authorization: `Bearer ${this.apiToken}`, "Content-Type": "application/json" },
        },
      );

      if (data && data.error) {
        const err = new Error(data.error);
        err.category = NON_RETRYABLE;
        throw err;
      }

      return { providerMessageId: data?.data?.message_id || data?.message_id || null, raw: data };
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
      await axios.get(`${this.baseUrl}/api/v2/balance`, {
        timeout: this.timeoutMs,
        headers: { Authorization: `Bearer ${this.apiToken}` },
      });
      return { healthy: true, latencyMs: Date.now() - start, detail: "balance check ok" };
    } catch (err) {
      return { healthy: false, latencyMs: Date.now() - start, detail: err.message };
    }
  }
}

module.exports = { BulkSmsNigeriaAdapter };
