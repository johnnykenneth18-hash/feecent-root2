// lib/sms/providers/base-adapter.js
//
// The one interface every provider adapter implements. sms-router.js
// only ever calls these five methods — it never knows Termii's or
// Africa's Talking's actual request/response shape. This is what
// makes "add a fifth provider later" a new file + one migration
// INSERT, not an application-logic change (spec section 1).

class BaseSmsAdapter {
  constructor({ code, timeoutMs = 5000 }) {
    if (new.target === BaseSmsAdapter) {
      throw new Error("BaseSmsAdapter is abstract");
    }
    this.code = code;
    this.timeoutMs = timeoutMs;
  }

  // sendSMS({ to, message, reference }) -> Promise<{ providerMessageId, raw }>
  // `reference` is our sms_message_id / idempotency key — adapters that
  // support an idempotency/client-reference field on their API MUST
  // pass it through (section 13). Must throw a classified error (see
  // error-classifier.js) on any non-success outcome — never resolve
  // with a fabricated "success".
  async sendSMS(_params) {
    throw new Error(`${this.code}: sendSMS not implemented`);
  }

  // OTP delivery is just an SMS with the OTP text already rendered by
  // sms-service.js's template layer (section 22 — adapters never see
  // provider-specific "OTP APIs" so that OUR OTP generation/storage/
  // verification stays the single source of truth, never the
  // provider's own OTP feature).
  async sendOTP({ to, message, reference }) {
    return this.sendSMS({ to, message, reference });
  }

  // getDeliveryStatus(providerMessageId) -> Promise<{ status, raw }>
  // status is one of 'sent' | 'delivered' | 'failed' | 'unknown'.
  // Used by the worker to resolve UNKNOWN attempts before deciding to
  // fail over (section 14) and by the delivery-status admin endpoint.
  async getDeliveryStatus(_providerMessageId) {
    throw new Error(`${this.code}: getDeliveryStatus not implemented`);
  }

  // normalizeError(err) -> { category, code, message }
  // category is one of error-classifier.js's four buckets.
  normalizeError(_err) {
    throw new Error(`${this.code}: normalizeError not implemented`);
  }

  // healthCheck() -> Promise<{ healthy, latencyMs, detail }>
  // Cheap balance/account-status call, NOT a real SMS send. Used by
  // the admin "Test provider" button and can optionally be polled by
  // a cron to pre-empt the circuit breaker.
  async healthCheck() {
    throw new Error(`${this.code}: healthCheck not implemented`);
  }
}

module.exports = { BaseSmsAdapter };
