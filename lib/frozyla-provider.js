// frozyla-provider.js
//
// FEECENT's side of the FEECENT <-> Frozyla integration. Extends
// PaymentProvider (payment-provider.js) the same way FlutterwaveProvider
// and VTpassProvider presumably do — never calls Flutterwave or VTpass,
// never imports flutterwave-service.js. Every call in this file goes
// directly to Frozyla's API, HMAC-signed, over HTTPS.
//
// Implements exactly the three methods this integration needs; every
// other PaymentProvider method (purchaseAirtime, payElectricity, etc.)
// is correctly left as the base class's NotImplementedError stub —
// Frozyla doesn't do any of those things.
//
// Registration (confirmed against service-registry.js): add one line
// to that file's PROVIDER_IMPLEMENTATIONS map —
//
//   const PROVIDER_IMPLEMENTATIONS = {
//     flutterwave: require("./flutterwave-provider"),
//     paystack: require("./paystack-provider"),
//     monnify: require("./monnify-provider"),
//     vtpass: require("./vtpass-provider"),
//     frozyla: require("./frozyla-provider"),   // <-- add this line
//   };
//
// That's the entire registration. No `services` / `service_routing` /
// `provider_capabilities` rows are needed for this: those tables only
// feed ServiceRegistry.resolve()/getProvider() (the auto-routing
// path), and bills-worker.js/bills-service.js both call
// getProviderByCode(bill.gateway_code) directly instead — a straight
// PROVIDER_IMPLEMENTATIONS[code] lookup that skips the DB-driven
// routing/capability system entirely. Same reason bills purchases
// already bypass PaymentGateway's auto-routing methods (see
// payment-gateway.js's own comment on that).

const crypto = require("crypto");
const { PaymentProvider, NotImplementedError } = require("./payment-provider");
const hmac = require("./frozyla-hmac");

const FROZYLA_API_BASE_URL = process.env.FROZYLA_API_BASE_URL; // e.g. https://api.frozyla.com
const HMAC_SECRET = process.env.FEECENT_FROZYLA_HMAC_SECRET;
const REQUEST_TIMEOUT_MS = 15000;

// Thrown when Frozyla positively confirms the customer ID doesn't
// exist. bills-service.js's handleVerifyCustomer needs to treat this
// differently from "couldn't reach Frozyla" — see PHASE2_PATCHES.md
// item 2b for the one extra catch-block branch this requires there.
class CustomerNotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = "CustomerNotFoundError";
    this.code = "CUSTOMER_NOT_FOUND";
  }
}

// Deterministic, stable per bill_transaction — same input always
// produces the same output, so a retried call (which reuses
// bill.provider_tx_ref as `reference`) naturally reuses the same
// Frozyla-facing reference too. Hash-derived rather than string-sliced
// so this doesn't silently break if FEECENT's internal
// "FEECENT-BILL-<uuid>" provider_tx_ref convention ever changes shape.
function toFrozylaReference(providerTxRef) {
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const suffix = crypto
    .createHash("sha256")
    .update(providerTxRef)
    .digest("hex")
    .slice(0, 8)
    .toUpperCase();
  return `FCT-FRZ-${day}-${suffix}`;
}

class FrozylaProvider extends PaymentProvider {
  get code() {
    return "frozyla";
  }

  async #signedRequest({ method, path, body }) {
    if (!FROZYLA_API_BASE_URL || !HMAC_SECRET) {
      return {
        ok: false,
        networkError: true,
        error: "Frozyla integration is not configured (missing env vars)",
      };
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = hmac.generateNonce();
    const rawBody = body ? JSON.stringify(body) : "";
    const signature = hmac.sign({ secret: HMAC_SECRET, method, path, timestamp, nonce, rawBody });

    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const res = await fetch(`${FROZYLA_API_BASE_URL}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-Feecent-Timestamp": timestamp,
          "X-Feecent-Nonce": nonce,
          "X-Feecent-Signature": signature,
        },
        body: rawBody || undefined,
        signal: controller.signal,
      });

      let json = null;
      try {
        json = await res.json();
      } catch {
        // Non-JSON response — leave json null, caller handles via res.ok/status.
      }
      return { ok: res.ok, status: res.status, json };
    } catch (err) {
      // AbortError (our own timeout) and any fetch-level failure land
      // here. Both are genuinely ambiguous — Frozyla may or may not
      // have received/processed the request — always networkError:true.
      return {
        ok: false,
        networkError: true,
        error: err.name === "AbortError" ? "Request timed out" : err.message,
      };
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  // ------------------------------------------------------------
  // POST /api/v1/integrations/feecent/frozyla/verify
  // Called by bills-service.js's handleVerifyCustomer with
  // { customerIdentifier, billerCode, itemCode, categoryCode } — this
  // only needs customerIdentifier; the others are Flutterwave-shaped
  // params this provider correctly ignores.
  // ------------------------------------------------------------
  async verifyCustomer({ customerIdentifier }) {
    const path = "/api/v1/integrations/feecent/frozyla/verify";
    const result = await this.#signedRequest({
      method: "POST",
      path,
      body: { customerId: customerIdentifier },
    });

    if (result.networkError) {
      // Normal Error — handleVerifyCustomer's generic catch already
      // turns this into a safe, skippable 500, which is correct when
      // we genuinely don't know Frozyla's answer (vs. a confirmed "no").
      throw new Error(`Frozyla verification unavailable: ${result.error}`);
    }
    if (result.status === 404) {
      throw new CustomerNotFoundError(`No Frozyla account found for '${customerIdentifier}'`);
    }
    if (!result.ok || !result.json || result.json.status !== "success") {
      throw new Error(result.json?.message || `Frozyla verification failed (${result.status})`);
    }

    return { id: result.json.customer.id, name: result.json.customer.name };
  }

  // ------------------------------------------------------------
  // POST /api/v1/integrations/feecent/frozyla/credit
  // Dispatched by bills-worker.js's CATEGORY_GATEWAY_METHOD.FROZYLA.
  // Must return { success, retryable, error, data, raw }.
  // ------------------------------------------------------------
  async fundWallet({ customerIdentifier, amount, reference }) {
    const frozylaRef = toFrozylaReference(reference);
    const path = "/api/v1/integrations/feecent/frozyla/credit";

    const result = await this.#signedRequest({
      method: "POST",
      path,
      body: {
        reference: frozylaRef,
        customerId: customerIdentifier,
        amount,
        currency: "NGN",
        idempotencyKey: reference, // stable across retries — see file header
        timestamp: new Date().toISOString(),
      },
    });

    if (result.networkError) {
      // Ambiguous, not failed — spec's failure-safety principle.
      // retryable:true re-enters bills-worker.js's backoff loop, which
      // resends with the SAME frozylaRef/idempotencyKey; Frozyla's own
      // idempotency guard (credit_wallet_from_feecent's INSERT-based
      // gate) prevents a double credit even if the original request
      // actually succeeded and only the response was lost.
      return { success: false, retryable: true, error: `Frozyla credit request uncertain: ${result.error}` };
    }

    if ([400, 401, 403, 404, 422].includes(result.status)) {
      // Permanent rejection — bad customer/amount/auth. Retrying
      // would fail again forever.
      return {
        success: false,
        retryable: false,
        error: result.json?.message || `Frozyla rejected the request (${result.status})`,
        raw: result.json,
      };
    }

    if (!result.ok || !result.json) {
      return { success: false, retryable: true, error: `Frozyla credit request failed (${result.status})` };
    }

    const { status, transactionId } = result.json;

    if (status === "success" || status === "pending") {
      // Either way, accepted — getBillStatus() (called right after
      // this by pollAndFinalize) is what actually confirms completion.
      // "pending" just means that check won't confirm on the first
      // pass; bills-worker.js's existing not-yet-confirmed retry path
      // handles that with no extra code needed here.
      return { success: true, data: { flw_ref: transactionId || frozylaRef, network: null }, raw: result.json };
    }
    if (status === "failed") {
      return {
        success: false,
        retryable: false,
        error: result.json.message || "Frozyla reported this funding as failed",
        raw: result.json,
      };
    }

    // Unrecognized status — don't guess; retryable, surfaces via
    // bills-worker.js's reconciliation_alerts path if retries exhaust.
    return { success: false, retryable: true, error: `Frozyla returned an unrecognized status: '${status}'`, raw: result.json };
  }

  // ------------------------------------------------------------
  // GET /api/v1/integrations/feecent/frozyla/status/:reference
  // Called by PaymentGateway.getBillStatus({ providerCode, ...params })
  // -> ServiceRegistry.getProviderByCode(providerCode).getBillStatus(params)
  // per payment-gateway.js. Must return
  // { success, data: { confirmed, failed, failure_reason, network, flw_ref }, raw }.
  // Same lookup also serves the spec's reconciliation/timeout-recovery
  // flow (section 15/17) — one endpoint, two callers.
  // ------------------------------------------------------------
  async getBillStatus({ reference }) {
    const frozylaRef = toFrozylaReference(reference);
    const path = `/api/v1/integrations/feecent/frozyla/status/${frozylaRef}`;

    const result = await this.#signedRequest({ method: "GET", path });

    if (result.networkError) {
      return { success: false, error: `Frozyla status check unavailable: ${result.error}` };
    }
    if (result.status === 404) {
      // Shouldn't happen (fundWallet already got an ok response before
      // this is called) — treat as not-yet-confirmed, not failed, in
      // case this is a propagation-delay race rather than a real problem.
      return { success: true, data: { confirmed: false, failed: false } };
    }
    if (!result.ok || !result.json) {
      return { success: false, error: `Frozyla status check failed (${result.status})` };
    }

    const { status, transactionId } = result.json;
    return {
      success: true,
      data: {
        confirmed: status === "success",
        failed: status === "failed",
        failure_reason: status === "failed" ? result.json.message : undefined,
        flw_ref: transactionId || frozylaRef,
        network: null,
      },
      raw: result.json,
    };
  }
}

const instance = new FrozylaProvider();
module.exports = instance;
module.exports.FrozylaProvider = FrozylaProvider;
module.exports.CustomerNotFoundError = CustomerNotFoundError;