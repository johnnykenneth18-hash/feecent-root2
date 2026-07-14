// flutterwave-service.js
// The ONLY module that talks to Flutterwave for virtual account creation.
// No route, controller, or worker should call the Flutterwave API directly —
// they all go through the functions exported here.

const FLW_BASE_URL = "https://api.flutterwave.com/v3";

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
async function purchaseAirtime({ phoneNumber, amount, reference }) {
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
        body: JSON.stringify({
          country: "NG",
          customer: phoneNumber,
          amount,
          recurrence: "ONCE",
          type: "AIRTIME",
          reference,
        }),
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

  if (!response.ok || json.status !== "success") {
    return {
      success: false,
      error:
        json.message || `Flutterwave bills error (HTTP ${response.status})`,
      retryable: response.status >= 500,
      raw: json,
    };
  }

  const d = json.data || {};
  return {
    success: true,
    // Flutterwave's create-bill response doesn't always carry an
    // explicit final status field the way transfers do — a 200 here
    // means "accepted", not necessarily "delivered". The caller
    // should still confirm via getBillStatus() before treating this
    // as a completed purchase.
    data: {
      flw_ref: d.flw_ref || null,
      tx_ref: d.tx_ref || reference,
      network: d.network || null,
      phone_number: d.phone_number || phoneNumber,
      amount: d.amount || amount,
    },
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
    },
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
  getBillStatus,
};
