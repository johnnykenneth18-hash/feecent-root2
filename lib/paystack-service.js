// paystack-service.js
// The ONLY module that talks to the Paystack API. Nothing outside
// paystack-provider.js should import this directly — same rule as
// flutterwave-service.js.
//
// Implements everything Paystack's public API actually offers that
// this codebase has a use for: Dedicated Virtual Accounts, bank
// account resolution, transfers (recipient creation + payout +
// status), transaction verification, and webhook signature
// verification. Which of these is actually LIVE for a given service
// is an admin-panel / service_routing decision (see
// service-registry-admin-service.js) — this file does not restrict
// what Paystack is allowed to do, it implements what Paystack's API
// can do.
//
// HONEST GAP (not an oversight): Paystack has no airtime/data/
// electricity/cable/betting bill-payment API in its public
// documentation — it is a payments/transfers/virtual-account
// platform, not a bills aggregator like Flutterwave or a VTU
// provider. paystack-provider.js does NOT implement purchaseAirtime/
// purchaseData/payElectricity/payCable/payBetting for this reason —
// inventing endpoints that don't exist would mean this code calling a
// URL that 404s the first time a real user's bill payment hit it.
// If Paystack later ships a bills product, or you want to route bills
// through a dedicated aggregator under Paystack's name, that's new
// code, not a flag to flip here.
//
// CONFIRM before relying on this in production: written from Paystack's
// documented API shapes, not run against a live account from here (no
// network egress to api.paystack.co in this environment). Test each
// function against your Paystack test/live keys before routing real
// traffic to it — same caveat flutterwave-service.js carries for its
// less-common endpoints.

const crypto = require("crypto");

const PAYSTACK_BASE_URL =
  process.env.PAYSTACK_BASE_URL || "https://api.paystack.co";

function getSecretKey() {
  const key = process.env.PAYSTACK_SECRET_KEY;
  if (!key) {
    throw new Error("PAYSTACK_SECRET_KEY is not set");
  }
  return key;
}

async function paystackFetch(path, options = {}) {
  let response;
  try {
    response = await fetch(`${PAYSTACK_BASE_URL}${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${getSecretKey()}`,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
  } catch (networkErr) {
    return {
      ok: false,
      networkError: `Network error contacting Paystack: ${networkErr.message}`,
    };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      ok: false,
      networkError: `Invalid JSON from Paystack (HTTP ${response.status})`,
    };
  }

  return {
    ok: response.ok && json.status === true,
    status: response.status,
    json,
  };
}

/**
 * Paystack requires a Customer to exist before a Dedicated Virtual
 * Account can be created for them. Safe to call repeatedly with the
 * same email — Paystack returns the existing customer rather than
 * erroring on a duplicate.
 */
async function createOrFetchCustomer({
  email,
  firstname,
  lastname,
  phonenumber,
}) {
  const result = await paystackFetch("/customer", {
    method: "POST",
    body: JSON.stringify({
      email,
      first_name: firstname,
      last_name: lastname,
      phone: phonenumber,
    }),
  });
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message ||
        `Paystack customer error (HTTP ${result.status})`,
      raw: result.json,
    };
  }
  return {
    success: true,
    data: { customer_code: result.json.data.customer_code },
    raw: result.json,
  };
}

/**
 * Creates a permanent Dedicated Virtual Account. Requires the
 * customer to have passed Paystack's BVN validation for a permanent
 * (non-expiring) account on most preferred_bank options — CONFIRM your
 * account's exact KYC requirement before relying on this end-to-end;
 * Paystack's validation requirements have changed over time per their
 * docs.
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

  const customerResult = await createOrFetchCustomer({
    email,
    firstname,
    lastname,
    phonenumber,
  });
  if (!customerResult.success) return customerResult;

  const result = await paystackFetch("/dedicated_account", {
    method: "POST",
    body: JSON.stringify({
      customer: customerResult.data.customer_code,
      preferred_bank: process.env.PAYSTACK_PREFERRED_BANK || "wema-bank",
    }),
  });
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message ||
        `Paystack dedicated account error (HTTP ${result.status})`,
      raw: result.json,
    };
  }

  const d = result.json.data;
  return {
    success: true,
    data: {
      provider_account_id: String(d.id),
      account_number: d.account_number,
      bank_name: d.bank?.name || null,
      bank_code: d.bank?.slug || null,
    },
    raw: result.json,
  };
}

/**
 * Resolves an account number + bank code to the account holder's
 * name. Backs the "Bank Account Resolution" service.
 */
async function resolveAccount({ accountNumber, bankCode }) {
  const result = await paystackFetch(
    `/bank/resolve?account_number=${encodeURIComponent(accountNumber)}&bank_code=${encodeURIComponent(bankCode)}`,
    { method: "GET" },
  );
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message ||
        `Paystack account resolution error (HTTP ${result.status})`,
      raw: result.json,
    };
  }
  return {
    success: true,
    data: {
      account_name: result.json.data.account_name,
      account_number: result.json.data.account_number,
    },
    raw: result.json,
  };
}

/**
 * Verifies a charge (deposit) directly with Paystack — never trust a
 * webhook body alone. Used both by the live webhook path and its
 * retry worker, same pattern as flutterwaveService.verifyTransaction.
 */
async function verifyTransaction(reference) {
  const result = await paystackFetch(
    `/transaction/verify/${encodeURIComponent(reference)}`,
    {
      method: "GET",
    },
  );
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message ||
        `Paystack transaction verify error (HTTP ${result.status})`,
      raw: result.json,
    };
  }
  const d = result.json.data;
  return {
    success: true,
    data: {
      id: d.id,
      reference: d.reference,
      status: d.status, // "success" | "failed" | "abandoned"
      amount: d.amount / 100, // Paystack amounts are in kobo
      currency: d.currency,
      // Dedicated virtual account deposits carry the receiving account
      // number here — this is how paystack-webhook-handler.js matches
      // the deposit to a Feecent account, since Paystack DVA creation
      // (unlike Flutterwave/Monnify) doesn't accept a caller-supplied
      // reference to echo back.
      receiver_account_number:
        d.authorization?.receiver_bank_account_number || null,
      sender_name:
        d.authorization?.sender_bank_account_name ||
        d.customer?.first_name ||
        null,
      sender_account: d.authorization?.sender_bank_account_number || null,
      sender_bank: d.authorization?.sender_bank || null,
      narration: d.gateway_response || null,
    },
    raw: result.json,
  };
}

/**
 * Creates (or reuses) a transfer recipient — required before any
 * transfer can be sent. Paystack recipient creation is idempotent per
 * account_number+bank_code+currency in practice, but we don't cache
 * recipient_code across calls here since Paystack has no documented
 * "get or create" endpoint for recipients; each transfer call creates
 * one. CONFIRM whether your volume warrants caching this — not done
 * here to avoid a stale/deleted recipient_code silently breaking
 * transfers.
 */
async function createTransferRecipient({
  accountNumber,
  bankCode,
  beneficiaryName,
}) {
  const result = await paystackFetch("/transferrecipient", {
    method: "POST",
    body: JSON.stringify({
      type: "nuban",
      name: beneficiaryName,
      account_number: accountNumber,
      bank_code: bankCode,
      currency: "NGN",
    }),
  });
  if (result.networkError)
    return { success: false, error: result.networkError, retryable: true };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message ||
        `Paystack recipient creation error (HTTP ${result.status})`,
      retryable: result.status >= 500,
      raw: result.json,
    };
  }
  return {
    success: true,
    data: { recipient_code: result.json.data.recipient_code },
    raw: result.json,
  };
}

/**
 * Initiates a payout. Paystack requires a recipient_code (created
 * above) rather than accepting raw bank details on the transfer call
 * itself — the only real shape difference from Flutterwave/Monnify's
 * single-call transfer.
 */
async function initiateTransfer({
  accountBank,
  accountNumber,
  amount,
  narration,
  reference,
  beneficiaryName,
}) {
  const recipientResult = await createTransferRecipient({
    accountNumber,
    bankCode: accountBank,
    beneficiaryName,
  });
  if (!recipientResult.success) return recipientResult;

  const result = await paystackFetch("/transfer", {
    method: "POST",
    body: JSON.stringify({
      source: "balance",
      amount: Math.round(amount * 100), // Paystack transfers are also in kobo
      recipient: recipientResult.data.recipient_code,
      reason: narration || `Transfer to ${beneficiaryName}`,
      reference,
    }),
  });
  if (result.networkError)
    return { success: false, error: result.networkError, retryable: true };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message ||
        `Paystack transfer error (HTTP ${result.status})`,
      retryable: result.status >= 500,
      raw: result.json,
    };
  }

  const d = result.json.data;
  return {
    success: true,
    data: {
      flw_id: d.transfer_code, // kept as flw_id for shape-compatibility with the PaymentProvider interface — it's Paystack's own transfer_code, not a Flutterwave one
      status: mapPaystackTransferStatus(d.status),
      reference: d.reference,
    },
    raw: result.json,
  };
}

/**
 * Checks a previously-initiated transfer's current status directly
 * with Paystack, by transfer_code or numeric id.
 */
async function getTransferStatus(transferCodeOrId) {
  const result = await paystackFetch(
    `/transfer/${encodeURIComponent(transferCodeOrId)}`,
    {
      method: "GET",
    },
  );
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message ||
        `Paystack transfer status error (HTTP ${result.status})`,
    };
  }
  const d = result.json.data;
  return {
    success: true,
    data: {
      id: d.transfer_code,
      reference: d.reference,
      amount: d.amount / 100,
      status: mapPaystackTransferStatus(d.status),
      complete_message: d.status,
    },
    raw: result.json,
  };
}

// Paystack's own status vocabulary (success/failed/reversed/pending/
// otp/received) mapped to the SUCCESSFUL/FAILED/NEW vocabulary the
// rest of the codebase already expects from Flutterwave, so
// external-transfer-worker.js / transfer-webhook-handler.js don't need
// per-provider branching on status strings.
function mapPaystackTransferStatus(paystackStatus) {
  switch (paystackStatus) {
    case "success":
      return "SUCCESSFUL";
    case "failed":
    case "reversed":
      return "FAILED";
    default:
      return "NEW";
  }
}

/**
 * Verifies Paystack's webhook signature. Paystack signs the RAW
 * (unparsed) request body with HMAC-SHA512 using your secret key —
 * this requires the route to have access to the raw body, which
 * Express's default json() body-parser does NOT retain. Wire this
 * route with express.raw({ type: "application/json" }) (or a verify
 * callback on json() that captures req.rawBody) BEFORE the global
 * json() parser reaches it — same kind of requirement Flutterwave's
 * verif-hash header check does not need, but Paystack's HMAC scheme
 * does. See paystack-webhook-handler.js's mount comment.
 */
function verifyWebhookSignature(rawBody, signatureHeader) {
  if (!signatureHeader) return false;
  const hash = crypto
    .createHmac("sha512", getSecretKey())
    .update(rawBody)
    .digest("hex");
  return hash === signatureHeader;
}

module.exports = {
  createVirtualAccount,
  resolveAccount,
  verifyTransaction,
  initiateTransfer,
  getTransferStatus,
  verifyWebhookSignature,
};
