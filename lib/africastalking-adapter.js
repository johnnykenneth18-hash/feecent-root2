// lib/sms/providers/africastalking-adapter.js
//
// Africa's Talking (https://developers.africastalking.com) — fallback
// provider #1. Uses their REST messaging endpoint directly (not the
// official Node SDK) to keep this adapter dependency-free and
// consistent with how the other three are written.
//
// CONFIRM the exact request/response shape against your current
// Africa's Talking docs before production use — the sandbox vs. live
// base URL differs, and per-recipient status codes have changed
// format across API versions in the past.
//
// Required env vars:
//   AFRICASTALKING_USERNAME
//   AFRICASTALKING_API_KEY
//   AFRICASTALKING_SENDER_ID   (optional — alphanumeric sender ID/shortcode)
//   AFRICASTALKING_BASE_URL    (default https://api.africastalking.com, sandbox: https://api.sandbox.africastalking.com)

const axios = require("axios");
const { BaseSmsAdapter } = require("./base-adapter");
const { classifyHttpError, RETRYABLE, NON_RETRYABLE } = require("../error-classifier");

class AfricasTalkingAdapter extends BaseSmsAdapter {
  constructor() {
    super({ code: "africastalking", timeoutMs: 5000 });
    this.username = process.env.AFRICASTALKING_USERNAME;
    this.apiKey = process.env.AFRICASTALKING_API_KEY;
    this.senderId = process.env.AFRICASTALKING_SENDER_ID; // optional
    this.baseUrl = process.env.AFRICASTALKING_BASE_URL || "https://api.africastalking.com";
  }

  isConfigured() {
    return !!(this.username && this.apiKey);
  }

  async sendSMS({ to, message }) {
    if (!this.isConfigured()) {
      const err = new Error("Africa's Talking is not configured (missing username/API key)");
      err.category = "PROVIDER_CONFIGURATION_ERROR";
      throw err;
    }

    const body = new URLSearchParams({ username: this.username, to, message });
    if (this.senderId) body.set("from", this.senderId);

    try {
      const { data } = await axios.post(
        `${this.baseUrl}/version1/messaging`,
        body.toString(),
        {
          timeout: this.timeoutMs,
          headers: {
            apiKey: this.apiKey,
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
          },
        },
      );

      // CONFIRM: shape is { SMSMessageData: { Recipients: [{ statusCode, status, messageId, number, cost }] } }
      const recipient = data?.SMSMessageData?.Recipients?.[0];
      if (!recipient) {
        const err = new Error("Africa's Talking returned no recipient data");
        err.category = "UNKNOWN";
        throw err;
      }

      // statusCode 100/101 = success family in AT's docs; anything else
      // is a per-recipient rejection (bad number, insufficient balance, etc).
      if (recipient.statusCode !== 100 && recipient.statusCode !== 101) {
        const err = new Error(recipient.status || "Africa's Talking rejected the recipient");
        err.category = /balance|credit/i.test(recipient.status || "") ? RETRYABLE : NON_RETRYABLE;
        err.providerCode = String(recipient.statusCode);
        throw err;
      }

      return { providerMessageId: recipient.messageId, raw: data };
    } catch (err) {
      if (err.category) throw err;
      err.category = classifyHttpError(err);
      throw err;
    }
  }

  async getDeliveryStatus(_providerMessageId) {
    // CONFIRM: Africa's Talking primarily pushes delivery reports via
    // webhook (section 18) rather than offering a simple pull-by-id
    // status endpoint — verify against current docs if a pull path is
    // needed for the "query before assuming unknown" flow in section 14.
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
      await axios.get(`${this.baseUrl}/version1/user`, {
        params: { username: this.username },
        headers: { apiKey: this.apiKey, Accept: "application/json" },
        timeout: this.timeoutMs,
      });
      return { healthy: true, latencyMs: Date.now() - start, detail: "account check ok" };
    } catch (err) {
      return { healthy: false, latencyMs: Date.now() - start, detail: err.message };
    }
  }
}

module.exports = { AfricasTalkingAdapter };
