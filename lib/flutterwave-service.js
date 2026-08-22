// flutterwave-service.js
// The ONLY module that talks to Flutterwave for virtual account creation.
// No route, controller, or worker should call the Flutterwave API directly —
// they all go through the functions exported here.

// FLUTTERWAVE_BASE_URL lets you point at a different environment
// (Flutterwave sandbox, a regional endpoint, or a proxy) without
// touching this file — same principle as FLUTTERWAVE_SECRET_KEY
// already being env-driven. Defaults to production v3 if unset.
const FLW_BASE_URL =
  process.env.FLUTTERWAVE_BASE_URL || "https://api.flutterwave.com/v3";

// Flutterwave's Transfers API requires a whitelisted static IP.
// Node's built-in fetch (Undici under the hood) ignores HTTPS_PROXY
// entirely, so a proxy has to be attached explicitly via a dispatcher —
// setting the env var alone does nothing here.
//
// Set STATIC_IP_PROXY_URL to your proxy's full URL, e.g.:
//   http://user:pass@proxy-host:port
// Leave it unset and every fetch() below behaves exactly as before
// (no proxy, direct connection) — safe to deploy this with the env var
// absent while you're setting the proxy up.
let flwDispatcher;
if (process.env.STATIC_IP_PROXY_URL) {
  const { ProxyAgent } = require("undici");
  flwDispatcher = new ProxyAgent(process.env.STATIC_IP_PROXY_URL);
}

function flwFetchOptions(baseOptions) {
  return flwDispatcher
    ? { ...baseOptions, dispatcher: flwDispatcher }
    : baseOptions;
}

function getSecretKey() {
  const key = process.env.FLUTTERWAVE_SECRET_KEY;
  if (!key) {
    throw new Error("FLUTTERWAVE_SECRET_KEY is not set");
  }
  return key;
}

/**
 * Creates a permanent dedicated virtual account for a user.
 * Requires a BVN — Flutterwave rejects permanent account creation without one.
 *
 * @param {Object} params
 * @param {string} params.email
 * @param {string} params.bvn - 11-digit BVN
 * @param {string} params.firstname
 * @param {string} params.lastname
 * @param {string} params.phonenumber
 * @param {string} params.txRef - unique reference for this creation attempt,
 *   used for idempotency on Flutterwave's side (safe to retry with the same
 *   txRef; Flutterwave will not create a duplicate for the same reference).
 * @returns {Promise<{success: boolean, data?: object, error?: string, raw?: object}>}
 */
async function createVirtualAccount({
  email,
  bvn,
  firstname,
  lastname,
  phonenumber,
  txRef,
}) {
  if (!bvn || !/^\d{11}$/.test(bvn)) {
    return { success: false, error: "Invalid or missing BVN" };
  }

  const body = {
    email,
    is_permanent: true,
    bvn,
    tx_ref: txRef,
    phonenumber,
    firstname,
    lastname,
    narration: `Feecent - ${firstname} ${lastname}`,
  };

  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/virtual-account-numbers`,
      flwFetchOptions({
        method: "POST",
        headers: {
          Authorization: `Bearer ${getSecretKey()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      }),
    );
  } catch (networkErr) {
    // Network-level failure (timeout, DNS, Flutterwave fully down) —
    // treat as retryable, never let this bubble up and block a caller.
    return {
      success: false,
      error: `Network error contacting Flutterwave: ${networkErr.message}`,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON from Flutterwave (HTTP ${response.status})`,
    };
  }

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error: json.message || `Flutterwave error (HTTP ${response.status})`,
      raw: json,
    };
  }

  const d = json.data;
  return {
    success: true,
    data: {
      provider_account_id: String(d.order_ref || d.id || ""),
      account_number: d.account_number,
      bank_name: d.bank_name,
      // Flutterwave's virtual-account-numbers response doesn't return a
      // separate numeric bank_code on this endpoint — bank_name is the
      // identifying field. Leave bank_code null unless you resolve it
      // separately against the /v3/banks list.
      bank_code: null,
    },
    raw: json,
  };
}

/**
 * Initiates a payout (external transfer) via Flutterwave's Transfers API.
 * This is the ONLY place in the codebase that should call POST /transfers.
 */
async function initiateTransfer({
  accountBank,
  accountNumber,
  amount,
  narration,
  reference,
  beneficiaryName,
}) {
  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/transfers`,
      flwFetchOptions({
        method: "POST",
        headers: {
          Authorization: `Bearer ${getSecretKey()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          account_bank: accountBank,
          account_number: accountNumber,
          amount,
          narration: narration || `Transfer to ${beneficiaryName}`,
          currency: "NGN",
          reference,
          callback_url: process.env.FLUTTERWAVE_TRANSFER_WEBHOOK_URL,
          beneficiary_name: beneficiaryName,
          debit_currency: "NGN",
        }),
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error contacting Flutterwave transfers API: ${networkErr.message}`,
      retryable: true,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON from Flutterwave transfers API (HTTP ${response.status})`,
      retryable: true,
    };
  }

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error:
        json.message || `Flutterwave transfer error (HTTP ${response.status})`,
      retryable: response.status >= 500,
      raw: json,
    };
  }

  const d = json.data;
  return {
    success: true,
    data: {
      flw_id: d.id,
      status: d.status,
      reference: d.reference,
    },
    raw: json,
  };
}

/**
 * Checks the current status of a previously-initiated transfer directly
 * with Flutterwave. Used by the retry worker and the outbound webhook
 * handler to confirm status before crediting/debiting anything.
 */
async function getTransferStatus(flwTransferId) {
  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/transfers/${flwTransferId}`,
      flwFetchOptions({
        method: "GET",
        headers: { Authorization: `Bearer ${getSecretKey()}` },
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error checking transfer status: ${networkErr.message}`,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON checking transfer status (HTTP ${response.status})`,
    };
  }

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error: json.message || `Status check failed (HTTP ${response.status})`,
    };
  }

  const d = json.data;
  return {
    success: true,
    data: {
      id: d.id,
      reference: d.reference,
      status: d.status,
      complete_message: d.complete_message,
      amount: d.amount,
      account_number: d.account_number,
      bank_code: d.bank_code,
    },
  };
}

/**
 * Verifies a Flutterwave webhook signature.
 * Flutterwave sends the secret hash you configured in the dashboard back
 * verbatim in the `verif-hash` header — no HMAC computation needed, just a
 * constant-time string comparison.
 */
function redactedPreview(value) {
  if (!value) return "(empty)";
  if (value.length <= 6) return `len=${value.length}`;
  return `len=${value.length} starts="${value.slice(0, 3)}..." ends="...${value.slice(-3)}"`;
}

function verifyWebhookSignature(headerHash) {
  const expected = (process.env.FLUTTERWAVE_WEBHOOK_SECRET || "").trim();
  const received = (headerHash || "").trim();

  if (!expected) {
    console.warn(
      "[WEBHOOK-SIG] FLUTTERWAVE_WEBHOOK_SECRET is not set in this deployment's environment — every webhook will be rejected until it's added and the app is redeployed.",
    );
    return false;
  }
  if (!received) {
    console.warn(
      "[WEBHOOK-SIG] Request arrived with no verif-hash header at all.",
    );
    return false;
  }
  if (received.length !== expected.length) {
    console.warn(
      `[WEBHOOK-SIG] Length mismatch. Configured secret: ${redactedPreview(expected)}. Received verif-hash: ${redactedPreview(received)}. ` +
        `Common causes: extra whitespace/newline copied into one side, or the value in Flutterwave's dashboard doesn't match FLUTTERWAVE_WEBHOOK_SECRET on the server.`,
    );
    return false;
  }

  // Constant-time comparison to avoid timing attacks.
  const crypto = require("crypto");
  const match = crypto.timingSafeEqual(
    Buffer.from(received),
    Buffer.from(expected),
  );
  if (!match) {
    console.warn(
      `[WEBHOOK-SIG] Same length but different value. Configured secret: ${redactedPreview(expected)}. Received verif-hash: ${redactedPreview(received)}. ` +
        `The value on your server doesn't match what's saved in Flutterwave's dashboard — re-copy it from Flutterwave into FLUTTERWAVE_WEBHOOK_SECRET and redeploy.`,
    );
  }
  return match;
}

/**
 * Verifies a transaction directly with Flutterwave's API. Webhook payloads
 * must never be trusted on their own — this confirms amount, currency,
 * status, and the destination account straight from Flutterwave before any
 * wallet is credited.
 *
 * @param {string|number} transactionId - Flutterwave's `data.id` from the webhook
 * @returns {Promise<{success: boolean, data?: object, error?: string}>}
 */
async function verifyTransaction(transactionId) {
  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/transactions/${transactionId}/verify`,
      flwFetchOptions({
        method: "GET",
        headers: { Authorization: `Bearer ${getSecretKey()}` },
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error verifying transaction: ${networkErr.message}`,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON verifying transaction (HTTP ${response.status})`,
    };
  }

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error: json.message || `Verify failed (HTTP ${response.status})`,
    };
  }

  const d = json.data;
  return {
    success: true,
    data: {
      id: d.id,
      tx_ref: d.tx_ref,
      flw_ref: d.flw_ref,
      amount: d.amount,
      currency: d.currency,
      status: d.status, // "successful", "failed", "pending"
      payment_type: d.payment_type,
      // account_id is Flutterwave's own numeric identifier and, per their
      // docs, the field actually present on virtual-account bank-transfer
      // webhooks — account_number is NOT reliably present for this
      // payment type despite being tried first below. Kept both while we
      // confirm against a real payload which one (if either) our stored
      // accounts rows can actually be matched against.
      account_id: d.account_id ?? null,
      // NOTE: this is ONLY Flutterwave's own account_number field when
      // present (rare for bank_transfer/virtual-account payments). The
      // previous fallback to meta.originatoraccountnumber has been
      // removed — confirmed against real production data that field is
      // the SENDER's account number, not the destination virtual
      // account, and using it as a fallback here caused deposits to
      // fail matching (or worse, risked a false match) every time.
      // creditDeposit() in deposit-webhook-service.js primarily matches
      // via tx_ref now, not this field.
      account_number: d.account_number || null,
      // For dedicated virtual account credits, Flutterwave includes the
      // receiving account's details under `data.account_id` /
      // `data.card`/`data.meta` depending on payment type — the safest
      // universal field for NUBAN transfers into a virtual account is
      // `data.customer.email` combined with `data.narration`, but the
      // account number match below is the authoritative check.
      narration: d.narration,
      customer_email: d.customer && d.customer.email,
      // Best-effort sender details for bank-transfer deposits — field
      // names vary by how the sending bank populates Flutterwave's meta;
      // confirm exact keys against a real sandbox payload.
      sender_name:
        (d.meta && (d.meta.originatorname || d.meta.originator_name)) || null,
      sender_account:
        (d.meta &&
          (d.meta.originatoraccountnumber ||
            d.meta.originator_account_number)) ||
        null,
      sender_bank:
        (d.meta && (d.meta.originatorbank || d.meta.originator_bank)) || null,
    },
    raw: json,
  };
}

/**
 * Purchases airtime via Flutterwave's Bills API. This is the ONLY place
 * in the codebase that should call POST /v3/bills for airtime.
 *
 * Flutterwave resolves the network (MTN/GLO/AIRTEL/9MOBILE) from the
 * phone number itself — we don't ask the user to pick it, and we don't
 * guess it client-side.
 *
 * Per Flutterwave's own docs: a call here can come back success,
 * pending, or failed. "Pending" is common enough that callers (the
 * bills worker) must be ready to poll getBillStatus() rather than
 * treat this response as final on its own.
 */
/**
 * Shared implementation behind purchaseAirtime/purchaseData/
 * payElectricity/payCable/payBetting — Flutterwave's Bills API is one
 * endpoint (POST /bills) for all of these, distinguished by `type`
 * and, for anything beyond Airtime, a biller/item code identifying
 * exactly which product/plan is being bought.
 *
 * IMPORTANT — verify before relying on this for real money:
 * Flutterwave's exact `type` strings and whether a given product needs
 * `biller_code`, `item_code`, both, or neither are things I can only
 * give my best-known values for, not verify without hitting their live
 * /bill-categories endpoint against your actual account. Airtime
 * (unchanged from before) is confirmed working. Before enabling
 * DATA/ELECTRICITY/CABLE/BETTING for real customers, run one small
 * test purchase per category and check `raw` in the response against
 * what Flutterwave's dashboard shows for that transaction.
 */
async function purchaseBill({
  type,
  customerIdentifier,
  amount,
  reference,
  billerCode,
  itemCode,
}) {
  const body = {
    country: "NG",
    customer: customerIdentifier,
    amount,
    recurrence: "ONCE",
    type,
    reference,
  };
  // Only included when the catalog actually has them set (Airtime
  // doesn't need either) — sending undefined keys would otherwise
  // serialize as literal "undefined" strings via some body-builders,
  // so they're only added when present.
  if (billerCode) body.biller_code = billerCode;
  if (itemCode) body.item_code = itemCode;

  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/bills`,
      flwFetchOptions({
        method: "POST",
        headers: {
          Authorization: `Bearer ${getSecretKey()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error contacting Flutterwave bills API: ${networkErr.message}`,
      retryable: true,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON from Flutterwave bills API (HTTP ${response.status})`,
      retryable: true,
    };
  }

  // FIX: same "pending" bug fixed in payElectricity() below — Flutterwave
  // documents success/pending/failed as the three possible outcomes here,
  // and pending is a normal, expected first response, not a failure. This
  // used to reject anything but "success", which would have killed any
  // airtime/data/cable/betting purchase that happened to come back
  // pending instead of failing it forward to pollAndFinalize() the way
  // it's designed to. Hasn't been observed in practice for these
  // categories yet (per your report), but it's the identical latent bug.
  const accepted =
    response.ok && (json.status === "success" || json.status === "pending");
  if (!accepted) {
    return {
      success: false,
      error:
        json.message || `Flutterwave bills error (HTTP ${response.status})`,
      retryable: response.status >= 500,
      // Includes the exact request body sent, not just Flutterwave's
      // response — added after a real incident where "Transaction
      // Failed" gave no way to confirm what `type`/`biller_code`
      // values actually went out without re-deriving them by hand.
      // This is now stored verbatim in bill_transactions.provider_response.
      raw: { request: body, response: json },
    };
  }

  const d = json.data || {};
  return {
    success: true,
    // Same caveat as before: a 200 here means "accepted", not
    // necessarily "delivered" — callers must still confirm via
    // getBillStatus() before treating this as completed.
    data: {
      flw_ref: d.flw_ref || null,
      tx_ref: d.tx_ref || reference,
      network: d.network || null,
      phone_number: d.phone_number || customerIdentifier,
      amount: d.amount || amount,
      // Prepaid electricity token — Flutterwave returns this in the
      // purchase response for electricity bills specifically (absent
      // for every other bill type, harmlessly null). CONFIRM the
      // exact field name against a real successful electricity
      // purchase on your account — Flutterwave's docs are not fully
      // consistent on whether this is `token`, `Token`, or nested
      // under a sub-object across API versions.
      token: d.token || d.Token || null,
    },
    raw: { request: body, response: json },
  };
}

async function purchaseAirtime({ phoneNumber, amount, reference }) {
  return purchaseBill({
    type: "AIRTIME",
    customerIdentifier: phoneNumber,
    amount,
    reference,
  });
}

// CORRECTED from an earlier guess: Flutterwave's Bills API does not
// use a generic "DATA_BUNDLE" type + separate item_code. Per their
// documented flow, you first call GET /bill-categories filtered by
// biller_code (see listBillerItems() below) to get the list of
// available bundles for that network, and each returned item has a
// `name` field — THAT exact string is what you send back as `type`
// on the actual purchase. planCode here is expected to be that same
// string, stored in bill_plans.external_plan_code by
// listBillerItems()/the admin "refresh from provider" action — not a
// separately-invented SKU.
async function purchaseData({
  customerIdentifier,
  amount,
  reference,
  planCode,
  billerCode,
}) {
  if (!planCode) {
    return {
      success: false,
      error:
        "planCode (Flutterwave's bill-category item name) is required for data purchases",
      retryable: false,
    };
  }
  // FIX: billerCode was previously accepted by bills-worker.js/
  // payment-gateway.js but silently dropped here and in
  // flutterwave-provider.js's purchaseData(), so purchaseBill() never
  // received biller_code for data purchases — only `type` (the plan's
  // display-name-shaped item code). Flutterwave needs biller_code to
  // know WHICH network's catalog that item name belongs to (MTN vs
  // Airtel vs Glo can all have similarly-named bundles); without it,
  // real purchases were failing (confirmed against live transactions —
  // see the bill_transactions rows this was diagnosed from).
  return purchaseBill({
    type: planCode,
    customerIdentifier,
    amount,
    reference,
    billerCode,
  });
}

// Same corrected shape as purchaseData — cable/TV packages are also
// bill-category items, so `type` is the package's own name string.
async function payCable({
  customerIdentifier,
  amount,
  reference,
  planCode,
  billerCode,
}) {
  if (!planCode) {
    return {
      success: false,
      error:
        "planCode (Flutterwave's bill-category item name) is required for cable purchases",
      retryable: false,
    };
  }
  // FIX: same missing billerCode bug as purchaseData above.
  return purchaseBill({
    type: planCode,
    customerIdentifier,
    amount,
    reference,
    billerCode,
  });
}

// CONFIRMED root cause of the "Invalid Biller selected" failures on
// every electricity purchase: this used to reuse purchaseBill(), which
// posts to the generic POST /v3/bills endpoint with `type` as a literal
// string ("UTILITY_BILLS") plus biller_code/item_code folded into the
// body. That generic endpoint resolves the product from `type` itself
// — for AIRTIME that's the documented literal "AIRTIME", for DATA/CABLE
// it's the plan's own item name (see purchaseData/payCable above) — but
// "UTILITY_BILLS" isn't a real Flutterwave type value, so Flutterwave
// never got a valid product to resolve biller_code against and rejected
// it as an invalid biller, regardless of whether BIL115 itself is a
// real electricity biller_code on the account.
//
// Flutterwave's own bill-payment flow for anything with a real
// biller_code + item_code (electricity, cable, etc.) is instead:
//   POST /v3/billers/{biller_code}/items/{item_code}/payment
//   body: { country, customer_id, amount, reference, callback_url? }
// — biller_code/item_code go in the URL path, not the body, and there
// is no `type` field at all. This is the path this function now uses.
// (See developer.flutterwave.com's "Create a bill payment" reference
// and its worked electricity/cable examples.)
//
// Electricity meters are also PREPAID or POSTPAID; if that needs to be
// explicit in the request, it isn't threaded through yet (would come
// from bill_providers.external_metadata) — flagging rather than
// guessing, same as before.
async function payElectricity({
  customerIdentifier,
  amount,
  reference,
  billerCode,
  itemCode,
}) {
  if (!billerCode || !itemCode) {
    return {
      success: false,
      error:
        "billerCode and itemCode are both required for electricity purchases",
      retryable: false,
    };
  }

  const body = {
    country: "NG",
    customer_id: customerIdentifier,
    amount,
    reference,
  };

  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/billers/${encodeURIComponent(billerCode)}/items/${encodeURIComponent(itemCode)}/payment`,
      flwFetchOptions({
        method: "POST",
        headers: {
          Authorization: `Bearer ${getSecretKey()}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error contacting Flutterwave bills API: ${networkErr.message}`,
      retryable: true,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON from Flutterwave bills API (HTTP ${response.status})`,
      retryable: true,
    };
  }

  // FIX: Flutterwave documents three possible statuses on this call —
  // "success", "pending", and "failed" — and says pending is common and
  // expected for anything not instant (which is most of utility bills).
  // This used to only accept "success" and treated "pending" as an
  // outright failure, so bills-worker.js never got the chance to poll
  // getBillStatus()/wait for the webhook the way pollAndFinalize() and
  // bills-webhook-handler.js are already built to do — every pending
  // electricity purchase was being killed immediately with
  // failure_reason "Bill payment is Pending" instead of being left to
  // resolve asynchronously. A real "failed" status (or a non-2xx HTTP
  // response) still fails here exactly as before.
  const accepted =
    response.ok && (json.status === "success" || json.status === "pending");
  if (!accepted) {
    return {
      success: false,
      error:
        json.message || `Flutterwave bills error (HTTP ${response.status})`,
      retryable: response.status >= 500,
      // Same reasoning as purchaseBill()'s raw field: keep the exact
      // request body alongside Flutterwave's response so a failure can
      // be diagnosed from bill_transactions.provider_response alone.
      raw: { request: body, response: json },
    };
  }

  // NOTE on field names — this endpoint's documented sample response
  // uses `reference` for Flutterwave's own transaction reference (not
  // `flw_ref`, which the generic /bills endpoint's docs use) and
  // `recharge_token` for the prepaid token (not `token`/`Token`).
  // Kept both old and new field names below as fallbacks since this
  // hasn't been confirmed against a live electricity purchase yet —
  // check bill_transactions.provider_response on your first real
  // transaction and simplify this once confirmed.
  const d = json.data || {};
  return {
    success: true,
    data: {
      flw_ref: d.reference || d.flw_ref || null,
      tx_ref: d.tx_ref || reference,
      network: d.network || null,
      phone_number: d.phone_number || customerIdentifier,
      amount: d.amount || amount,
      token:
        d.recharge_token ||
        (d.extra && (d.extra.token || d.extra.Token)) ||
        d.token ||
        d.Token ||
        null,
    },
    raw: { request: body, response: json },
  };
}

// No documentation found confirming betting's exact shape — kept as
// my prior best-known convention. CONFIRM before relying on this one
// more than the others.
async function payBetting({
  customerIdentifier,
  amount,
  reference,
  billerCode,
}) {
  return purchaseBill({
    type: "BETTING_BILLS",
    customerIdentifier,
    amount,
    reference,
    billerCode,
  });
}

/**
 * Lists purchasable items (data bundles, cable packages, etc.) for a
 * given biller from Flutterwave's bill-categories catalog — this is
 * what backs the admin panel's "Refresh Plans from Provider" action.
 * Each returned item's `name` is exactly what purchaseData()/payCable()
 * above send back as `type` — store it as bill_plans.external_plan_code
 * verbatim, don't reformat it.
 *
 * CONFIRM the exact response shape against your account — I'm mapping
 * documented field names (biller_code, name, amount) but haven't run
 * this against a live account myself.
 */
async function listBillerItems(billerCode, { country = "NG" } = {}) {
  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/bill-categories?biller_code=${encodeURIComponent(billerCode)}&country=${encodeURIComponent(country)}`,
      flwFetchOptions({
        method: "GET",
        headers: { Authorization: `Bearer ${getSecretKey()}` },
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error contacting Flutterwave bill-categories API: ${networkErr.message}`,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON from Flutterwave bill-categories API (HTTP ${response.status})`,
    };
  }

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error:
        json.message ||
        `Flutterwave bill-categories error (HTTP ${response.status})`,
      raw: json,
    };
  }

  const items = Array.isArray(json.data) ? json.data : [];
  return {
    success: true,
    items: items.map((item) => ({
      external_plan_code: item.name, // exact string to pass as `type` on purchase — do not alter
      // FIX: previously discarded. item_code is a THIRD identifier
      // distinct from both `name` (-> external_plan_code, used as
      // `type` on purchase) and `biller_code` — it's what Flutterwave's
      // Validate Customer Details endpoint keys on
      // (GET /bill-items/{item_code}/validate), and it's also the
      // `item_code` payElectricity() requires in the purchase body
      // for electricity specifically. CONFIRM the exact field name
      // (`item_code`) against a real refresh — not independently
      // verified against a live response here, same caveat as
      // external_plan_code/display_name/provider_cost above already
      // carry.
      external_item_code: item.item_code || null,
      display_name: item.biller_name
        ? `${item.biller_name} — ${item.name}`
        : item.name,
      provider_cost: item.amount != null ? Number(item.amount) : null,
      raw: item,
    })),
    raw: json,
  };
}

/**
 * Checks the status of a previously-submitted bill payment directly
 * with Flutterwave. Used by the bills worker to confirm outcome before
 * calling finalize_bill_payment() — never trust the create-bill
 * response alone as final.
 *
 * @param {string} reference - the reference we originally sent when
 *   creating the bill payment (Flutterwave's `customer_reference`).
 */
async function getBillStatus(reference) {
  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/bills/${reference}`,
      flwFetchOptions({
        method: "GET",
        headers: { Authorization: `Bearer ${getSecretKey()}` },
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error checking bill status: ${networkErr.message}`,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON checking bill status (HTTP ${response.status})`,
    };
  }

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error:
        json.message || `Bill status check failed (HTTP ${response.status})`,
    };
  }

  const d = json.data || {};
  // Flutterwave's status payload confirms the record exists and
  // returns its details (flw_ref, transaction_date, amount, product)
  // but does not carry an explicit SUCCESSFUL/FAILED enum the way
  // /v3/transfers/:id does. A populated transaction_date + flw_ref is
  // the strongest signal available that the bill was actually
  // processed; absence of those after a reasonable number of retries
  // is treated as still-pending by the caller, never assumed failed.
  // `failed` stays permanently false here (Flutterwave gives us no
  // reliable way to assert it) — present only so bills-worker.js's
  // pollAndFinalize() can check the same field name across providers;
  // see vtpass-service.js's getBillStatus() for a provider that CAN
  // set this meaningfully.
  return {
    success: true,
    data: {
      flw_ref: d.flw_ref || null,
      tx_ref: d.tx_ref || null,
      customer_reference: d.customer_reference || reference,
      amount: d.amount,
      product: d.product,
      network: d.network || null,
      transaction_date: d.transaction_date || null,
      confirmed: Boolean(d.flw_ref && d.transaction_date),
      failed: false,
      token: d.token || d.Token || null,
    },
    raw: json,
  };
}

/**
 * Pre-payment customer/meter/smartcard lookup.
 * GET /v3/bill-items/{item_code}/validate?customer={identifier}
 *
 * CONFIRMED as a real, documented Flutterwave endpoint (Bills ->
 * Validate customer details) — unlike most of the bill-payment shapes
 * elsewhere in this file, this path/query/auth shape came directly
 * from Flutterwave's own API reference, not a best-known guess.
 *
 * item_code is the SAME identifier listBillerItems() above now
 * captures as external_item_code — for a plan-based purchase (DATA/
 * CABLE) that's the specific plan's own item_code; for a category
 * with no live plan context (ELECTRICITY, or verifying before a plan
 * is chosen) the caller passes bill_providers.external_item_code
 * instead. Either way this function itself is item_code-agnostic — it
 * just validates whatever code it's given.
 *
 * Response shape (the `data` object's actual fields — customer name,
 * address, etc.) is NOT independently confirmed here; no live account
 * access from this environment. Returned verbatim rather than
 * remapped to named fields, since bills-service.js's
 * handleVerifyCustomer() already passes whatever comes back straight
 * to the frontend as label/value pairs — an unexpected field just
 * shows up as an extra row, it doesn't break anything. Worth checking
 * one real response against your account before trusting it blindly.
 */
async function validateCustomer({ itemCode, customerIdentifier }) {
  if (!itemCode) {
    return {
      success: false,
      error: "itemCode is required to validate a customer",
      retryable: false,
    };
  }

  let response;
  try {
    response = await fetch(
      `${FLW_BASE_URL}/bill-items/${encodeURIComponent(itemCode)}/validate?customer=${encodeURIComponent(customerIdentifier)}`,
      flwFetchOptions({
        method: "GET",
        headers: { Authorization: `Bearer ${getSecretKey()}` },
      }),
    );
  } catch (networkErr) {
    return {
      success: false,
      error: `Network error validating customer: ${networkErr.message}`,
      retryable: true,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      success: false,
      error: `Invalid JSON validating customer (HTTP ${response.status})`,
      retryable: true,
    };
  }

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error:
        json.message || `Customer validation failed (HTTP ${response.status})`,
      retryable: response.status >= 500,
      raw: json,
    };
  }

  return {
    success: true,
    data: json.data || {},
    raw: json,
  };
}

module.exports = {
  createVirtualAccount,
  verifyWebhookSignature,
  verifyTransaction,
  initiateTransfer,
  getTransferStatus,
  purchaseAirtime,
  purchaseData,
  payElectricity,
  payCable,
  payBetting,
  listBillerItems,
  getBillStatus,
  validateCustomer,
};