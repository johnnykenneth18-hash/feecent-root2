// monnify-service.js
// The ONLY module that talks to the Monnify API. Nothing outside
// monnify-provider.js should import this directly — same rule as
// flutterwave-service.js / paystack-service.js.
//
// Implements everything Monnify's public API actually offers that
// this codebase has a use for: reserved (dedicated) virtual accounts,
// disbursements (transfers), transfer/transaction status checks, and
// webhook signature verification. Which of these is actually LIVE for
// a given service is an admin-panel / service_routing decision — this
// file does not restrict what Monnify is allowed to do.
//
// HONEST GAP (not an oversight): Monnify (Moniepoint's collections +
// disbursement platform) has no airtime/data/electricity/cable/
// betting bill-payment API in its public documentation — it is a
// collections/disbursement platform, not a bills aggregator.
// monnify-provider.js does NOT implement purchaseAirtime/purchaseData/
// payElectricity/payCable/payBetting for this reason — same reasoning
// as paystack-service.js's header note.
//
// Monnify's auth model is different from Flutterwave/Paystack's static
// secret key: you exchange MONNIFY_API_KEY + MONNIFY_SECRET_KEY for a
// short-lived bearer token via Basic Auth, then use that token on every
// call. Token caching below keeps this to roughly one login call per
// ~55 minutes rather than one per request.
//
// CONFIRM before relying on this in production: written from Monnify's
// documented API shapes, not run against a live account from here (no
// network egress to api.monnify.com in this environment). In
// particular, MONNIFY_CONTRACT_CODE is required for reserved-account
// creation and is specific to your Monnify merchant account — get it
// from your Monnify dashboard, it is not a made-up value.

const crypto = require("crypto");

const MONNIFY_BASE_URL =
  process.env.MONNIFY_BASE_URL || "https://api.monnify.com";

let cachedToken = null;
let cachedTokenExpiresAt = 0;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

async function getAccessToken() {
  if (cachedToken && Date.now() < cachedTokenExpiresAt) {
    return cachedToken;
  }

  const apiKey = requireEnv("MONNIFY_API_KEY");
  const secretKey = requireEnv("MONNIFY_SECRET_KEY");
  const basicAuth = Buffer.from(`${apiKey}:${secretKey}`).toString("base64");

  const response = await fetch(`${MONNIFY_BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { Authorization: `Basic ${basicAuth}` },
  });
  const json = await response.json();
  if (!response.ok || !json.requestSuccessful) {
    throw new Error(
      json.responseMessage || `Monnify login failed (HTTP ${response.status})`,
    );
  }

  cachedToken = json.responseBody.accessToken;
  // Monnify tokens are valid ~1hr; refresh 5 minutes early to avoid a
  // request racing against expiry mid-call.
  cachedTokenExpiresAt =
    Date.now() + (json.responseBody.expiresIn - 300) * 1000;
  return cachedToken;
}

async function monnifyFetch(path, options = {}) {
  let token;
  try {
    token = await getAccessToken();
  } catch (authErr) {
    return { networkError: `Monnify auth failed: ${authErr.message}` };
  }

  let response;
  try {
    response = await fetch(`${MONNIFY_BASE_URL}${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
  } catch (networkErr) {
    return {
      networkError: `Network error contacting Monnify: ${networkErr.message}`,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      networkError: `Invalid JSON from Monnify (HTTP ${response.status})`,
    };
  }

  return {
    ok: response.ok && json.requestSuccessful,
    status: response.status,
    json,
  };
}

/**
 * Creates a reserved (dedicated) virtual account.
 * MONNIFY_CONTRACT_CODE identifies your merchant contract — required,
 * see header note. accountReference (txRef) is echoed back on every
 * subsequent deposit webhook for this account — same mechanism
 * flutterwave-service.js relies on for matching deposits to accounts.
 */
async function createVirtualAccount({
  email,
  bvn,
  firstname,
  lastname,
  txRef,
}) {
  if (!bvn || !/^\d{11}$/.test(bvn)) {
    return { success: false, error: "Invalid or missing BVN" };
  }

  let contractCode;
  try {
    contractCode = requireEnv("MONNIFY_CONTRACT_CODE");
  } catch (err) {
    return { success: false, error: err.message };
  }

  const result = await monnifyFetch("/api/v2/bank-transfer/reserved-accounts", {
    method: "POST",
    body: JSON.stringify({
      accountReference: txRef,
      accountName: `${firstname} ${lastname}`,
      currencyCode: "NGN",
      contractCode,
      customerEmail: email,
      customerName: `${firstname} ${lastname}`,
      bvn,
      getAllAvailableBanks: true,
    }),
  });
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.responseMessage ||
        `Monnify reserved account error (HTTP ${result.status})`,
      raw: result.json,
    };
  }

  const d = result.json.responseBody;
  const firstAccount = Array.isArray(d.accounts) ? d.accounts[0] : null;
  return {
    success: true,
    data: {
      provider_account_id: d.accountReference,
      account_number: firstAccount?.accountNumber || null,
      bank_name: firstAccount?.bankName || null,
      bank_code: firstAccount?.bankCode || null,
    },
    raw: result.json,
  };
}

/**
 * Initiates a single disbursement (payout). sourceAccountNumber is
 * your Monnify wallet/settlement account funding the transfer —
 * required by Monnify's disbursement API, set via
 * MONNIFY_SOURCE_ACCOUNT_NUMBER.
 */
async function initiateTransfer({
  accountBank,
  accountNumber,
  amount,
  narration,
  reference,
  beneficiaryName,
}) {
  let sourceAccountNumber;
  try {
    sourceAccountNumber = requireEnv("MONNIFY_SOURCE_ACCOUNT_NUMBER");
  } catch (err) {
    return { success: false, error: err.message, retryable: false };
  }

  const result = await monnifyFetch("/api/v2/disbursements/single", {
    method: "POST",
    body: JSON.stringify({
      amount,
      reference,
      narration: narration || `Transfer to ${beneficiaryName}`,
      destinationBankCode: accountBank,
      destinationAccountNumber: accountNumber,
      currency: "NGN",
      sourceAccountNumber,
    }),
  });
  if (result.networkError)
    return { success: false, error: result.networkError, retryable: true };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.responseMessage ||
        `Monnify disbursement error (HTTP ${result.status})`,
      retryable: result.status >= 500,
      raw: result.json,
    };
  }

  const d = result.json.responseBody;
  return {
    success: true,
    data: {
      flw_id: d.reference, // kept as flw_id for shape-compatibility with the PaymentProvider interface — it's Monnify's own reference, not a Flutterwave one
      status: mapMonnifyStatus(d.status),
      reference: d.reference,
    },
    raw: result.json,
  };
}

/**
 * Checks a previously-initiated disbursement's current status.
 */
async function getTransferStatus(reference) {
  const result = await monnifyFetch(
    `/api/v2/disbursements/single/summary?reference=${encodeURIComponent(reference)}`,
    { method: "GET" },
  );
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.responseMessage ||
        `Monnify status check error (HTTP ${result.status})`,
    };
  }
  const d = result.json.responseBody;
  return {
    success: true,
    data: {
      id: d.reference,
      reference: d.reference,
      amount: d.amount,
      status: mapMonnifyStatus(d.status),
      complete_message: d.status,
    },
    raw: result.json,
  };
}

/**
 * Verifies a collection (deposit) transaction directly with Monnify —
 * never trust a webhook body alone. Used by monnify-webhook-handler.js
 * before crediting a wallet.
 */
async function verifyTransaction(transactionReference) {
  const result = await monnifyFetch(
    `/api/v2/transactions/${encodeURIComponent(transactionReference)}`,
    { method: "GET" },
  );
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.responseMessage ||
        `Monnify transaction verify error (HTTP ${result.status})`,
      raw: result.json,
    };
  }
  const d = result.json.responseBody;
  return {
    success: true,
    data: {
      id: d.transactionReference,
      status: d.paymentStatus === "PAID" ? "successful" : d.paymentStatus,
      amount: d.amountPaid,
      currency: d.currencyCode || "NGN",
      // accountReference is the same value we set as txRef at account
      // creation (FEECENT-VA-<accountId>) — matches
      // flutterwave-service.js's tx_ref convention exactly, see
      // monnify-webhook-handler.js for the match logic.
      tx_ref: d.product?.reference || null,
      narration: d.paymentDescription || null,
      sender_name: d.payerName || null,
      sender_account: d.paymentSourceInformation?.[0]?.accountNumber || null,
      sender_bank: d.paymentSourceInformation?.[0]?.bankCode || null,
    },
    raw: result.json,
  };
}

// Monnify's own status vocabulary (PENDING/SUCCESS/FAILED/REVERSED) is
// mapped to the SUCCESSFUL/FAILED/NEW vocabulary the rest of the
// codebase (external-transfer-worker.js, transfer-webhook-handler.js)
// already expects from Flutterwave, so those files don't need
// per-provider branching on status strings.
function mapMonnifyStatus(monnifyStatus) {
  switch (monnifyStatus) {
    case "SUCCESS":
      return "SUCCESSFUL";
    case "FAILED":
    case "REVERSED":
      return "FAILED";
    default:
      return "NEW";
  }
}

/**
 * Verifies Monnify's webhook signature. Monnify signs webhook payloads
 * with an HMAC-SHA512 hash of the raw request body using your CLIENT
 * SECRET (MONNIFY_SECRET_KEY), sent in the `monnify-signature` header —
 * CONFIRM this exact header name and hashing input against your
 * Monnify dashboard's webhook documentation before relying on it;
 * Monnify has historically documented this slightly differently across
 * API versions and this is not verified against a live callback here.
 */
function verifyWebhookSignature(rawBody, signatureHeader) {
  if (!signatureHeader) return false;
  const secretKey = requireEnv("MONNIFY_SECRET_KEY");
  const hash = crypto
    .createHmac("sha512", secretKey)
    .update(rawBody)
    .digest("hex");
  return hash === signatureHeader;
}

module.exports = {
  createVirtualAccount,
  initiateTransfer,
  getTransferStatus,
  verifyTransaction,
  verifyWebhookSignature,
};
