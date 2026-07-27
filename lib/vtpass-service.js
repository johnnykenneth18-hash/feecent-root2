// vtpass-service.js
// The ONLY module that talks to the VTpass API. Nothing outside
// vtpass-provider.js should import this directly — same rule as
// flutterwave-service.js / paystack-service.js / monnify-service.js.
//
// Implements every bill category this codebase models: airtime, data,
// electricity, cable TV, and betting wallet funding — VTpass supports
// all five under one uniform API shape (GET /service-variations to
// list plans, POST /pay to purchase, POST /requery for status), unlike
// Flutterwave where airtime/electricity/cable each had slightly
// different parameter conventions. VTpass also has education (WAEC/
// JAMB pins) and insurance products — NOT implemented here because
// this codebase's bill_categories schema doesn't model those two
// categories yet (see bills-catalog-service.js). Add them as new
// bill_categories rows + corresponding provider methods if you want
// them — this file's pattern extends cleanly to that.
//
// KEY DIFFERENCE from Flutterwave that matters for your admin setup:
// VTpass has NO generic "AIRTIME, network auto-detected" endpoint —
// every purchase (including airtime) requires an explicit serviceID
// identifying the exact network/biller (e.g. "mtn", "mtn-data",
// "ikeja-electric", "dstv", "bet9ja"). That serviceID is exactly what
// belongs in each bill_providers row's External Biller Code field —
// so for VTpass you'll need one bill_providers row per network even
// under AIRTIME, not one generic row the way Flutterwave allowed.
//
// AUTH: GET requests (service categories/variations) use a
// "public-key" header. POST requests (pay/requery) use "api-key" +
// "secret-key" headers. CONFIRM this exact auth split against your
// VTpass dashboard docs before relying on it — VTpass's documented
// auth scheme has evolved across versions and this is not run against
// a live account from here (no network egress to vtpass.com/
// sandbox.vtpass.com in this environment).

const crypto = require("crypto");

const VTPASS_BASE_URL = process.env.VTPASS_BASE_URL; //|| "https://vtpass.com/api";

function getKeys() {
  const apiKey = process.env.VTPASS_API_KEY;
  const secretKey = process.env.VTPASS_SECRET_KEY;
  const publicKey = process.env.VTPASS_PUBLIC_KEY;
  if (!apiKey || !secretKey || !publicKey) {
    throw new Error(
      "VTPASS_API_KEY, VTPASS_SECRET_KEY, and VTPASS_PUBLIC_KEY must all be set",
    );
  }
  return { apiKey, secretKey, publicKey };
}

/**
 * VTpass's requery/status check is keyed by THEIR OWN request_id, but
 * bills-worker.js's pollAndFinalize() always calls getBillStatus()
 * with only bill_transactions.provider_tx_ref (our own reference) —
 * it never has access to whatever VTpass returned at purchase time.
 * So the request_id sent to VTpass at purchase MUST be independently
 * re-derivable from that same reference string alone, with no other
 * stored state, both now and on any later status check. A
 * deterministic hash of `reference` satisfies that.
 *
 * CONFIRM VTpass's exact request_id format/length rules against their
 * current docs — their convention has historically favored a
 * date-prefixed id, which this deliberately does NOT do (a date
 * prefix based on "now" would differ between purchase time and a
 * later status check, breaking the one property that actually
 * matters here). If VTpass rejects this format, that surfaces as an
 * immediate, visible purchase-time error — never a silent stuck
 * state — so it's safe to try as-is and adjust if needed.
 */
function referenceToRequestId(reference) {
  return (
    "FC" + crypto.createHash("md5").update(reference).digest("hex").slice(0, 18)
  );
}

async function vtpassGet(path) {
  const { publicKey } = getKeys();
  let response;
  try {
    response = await fetch(`${VTPASS_BASE_URL}${path}`, {
      method: "GET",
      headers: { "public-key": publicKey },
    });
  } catch (networkErr) {
    return {
      networkError: `Network error contacting VTpass: ${networkErr.message}`,
    };
  }
  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      networkError: `Invalid JSON from VTpass (HTTP ${response.status})`,
    };
  }
  return { ok: response.ok, status: response.status, json };
}

async function vtpassPost(path, body) {
  const { apiKey, secretKey } = getKeys();
  let response;
  try {
    response = await fetch(`${VTPASS_BASE_URL}${path}`, {
      method: "POST",
      headers: {
        "api-key": apiKey,
        "secret-key": secretKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch (networkErr) {
    return {
      networkError: `Network error contacting VTpass: ${networkErr.message}`,
    };
  }
  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return {
      networkError: `Invalid JSON from VTpass (HTTP ${response.status})`,
    };
  }
  return { ok: response.ok, status: response.status, json };
}

/**
 * Lists purchasable variations (data bundles, cable packages, or
 * prepaid/postpaid for electricity) under a given serviceID. Backs
 * "Refresh Plans" in bills-admin-service.js via
 * PaymentGateway.listBillerItems({ providerCode: 'vtpass', billerCode }).
 * Returns the exact shape refreshPlansFromProvider() expects:
 * { success, items: [{ external_plan_code, display_name, provider_cost }] }.
 */
async function listBillerItems(serviceID) {
  const result = await vtpassGet(
    `/service-variations?serviceID=${encodeURIComponent(serviceID)}`,
  );
  if (result.networkError)
    return { success: false, error: result.networkError };
  if (!result.ok || result.json.response_description !== "000") {
    return {
      success: false,
      error:
        result.json?.response_description ||
        `VTpass service-variations error (HTTP ${result.status})`,
      raw: result.json,
    };
  }
  const variations =
    result.json.content?.varations || result.json.content?.variations || [];
  return {
    success: true,
    items: variations.map((v) => ({
      external_plan_code: v.variation_code,
      display_name: v.name,
      provider_cost: Number(v.variation_amount) || 0,
    })),
    raw: result.json,
  };
}

/**
 * Shared purchase call — every VTpass bill type (airtime, data,
 * electricity, cable, betting) goes through the same POST /pay shape;
 * only which fields are populated differs, which is why
 * vtpass-provider.js's five category methods all just call this with
 * different arguments rather than needing five different HTTP calls
 * the way flutterwave-service.js does.
 */
async function vtpassPay({
  serviceID,
  billersCode,
  variationCode,
  amount,
  phone,
  reference,
}) {
  if (!serviceID) {
    return {
      success: false,
      error: "serviceID (VTpass's biller/network identifier) is required",
      retryable: false,
    };
  }
  const requestId = referenceToRequestId(reference);

  const body = {
    request_id: requestId,
    serviceID,
    billersCode,
    amount,
    phone,
  };
  if (variationCode) body.variation_code = variationCode;

  const result = await vtpassPost("/pay", body);
  if (result.networkError)
    return { success: false, error: result.networkError, retryable: true };

  const json = result.json || {};
  // VTpass's own response_description codes: "000" = successful,
  // "099" = pending/processing, anything else = a real rejection.
  // See mapVtpassStatus() below for the same vocabulary reused by
  // getBillStatus() so bills-worker.js doesn't need VTpass-specific
  // branching.
  const code = json.code || json.response_description;
  if (!result.ok || (code && code !== "000" && code !== "099")) {
    return {
      success: false,
      error:
        json.response_description || `VTpass pay error (HTTP ${result.status})`,
      retryable: result.status >= 500,
      raw: { request: body, response: json },
    };
  }

  return {
    success: true,
    data: {
      // Reused as bill_transactions.provider_reference by
      // bills-worker.js — see the header note above for why this MUST
      // be the same value getBillStatus()'s requery will recompute.
      flw_ref: requestId,
      tx_ref: reference,
      network: json.content?.transactions?.network || null,
      phone_number: phone,
      amount: json.content?.transactions?.amount || amount,
    },
    raw: { request: body, response: json },
  };
}

async function purchaseAirtime({ phoneNumber, amount, reference, billerCode }) {
  return vtpassPay({
    serviceID: billerCode, // e.g. "mtn" | "glo" | "airtel" | "etisalat" — VTpass has no network-agnostic airtime endpoint
    billersCode: phoneNumber,
    amount,
    phone: phoneNumber,
    reference,
  });
}

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
        "planCode (VTpass's variation_code) is required for data purchases",
      retryable: false,
    };
  }
  return vtpassPay({
    serviceID: billerCode, // e.g. "mtn-data" | "glo-data" | "airtel-data" | "etisalat-data" | "smile-direct" | "spectranet"
    billersCode: customerIdentifier,
    variationCode: planCode,
    amount,
    phone: customerIdentifier,
    reference,
  });
}

async function payElectricity({
  customerIdentifier,
  amount,
  reference,
  billerCode,
  itemCode,
}) {
  // itemCode carries "prepaid"/"postpaid" here — same convention
  // flutterwave-service.js's payElectricity already uses for meter
  // type, matching the existing bills-worker.js dispatch shape.
  return vtpassPay({
    serviceID: billerCode, // e.g. "ikeja-electric" | "eko-electric" | ...
    billersCode: customerIdentifier, // meter number
    variationCode: itemCode,
    amount,
    phone: customerIdentifier,
    reference,
  });
}

async function payCable({
  customerIdentifier,
  amount,
  reference,
  planCode,
  billerCode,
}) {
  return vtpassPay({
    serviceID: billerCode, // e.g. "dstv" | "gotv" | "startimes"
    billersCode: customerIdentifier, // smartcard/IUC number
    variationCode: planCode,
    amount,
    phone: customerIdentifier,
    reference,
  });
}

async function payBetting({
  customerIdentifier,
  amount,
  reference,
  billerCode,
}) {
  return vtpassPay({
    serviceID: billerCode, // e.g. "bet9ja" | "nairabet" | "merrybet"
    billersCode: customerIdentifier, // customer's account ID on the betting platform
    amount,
    phone: customerIdentifier,
    reference,
  });
}

function mapVtpassStatus(json) {
  const status = json?.content?.transactions?.status;
  if (status === "delivered") return { confirmed: true, failed: false };
  if (status === "failed" || status === "reversed")
    return { confirmed: false, failed: true };
  return { confirmed: false, failed: false }; // pending/initiated — keep polling
}

/**
 * Status check via VTpass's requery endpoint, keyed by the SAME
 * deterministic request_id purchase used (see referenceToRequestId).
 * Returns `failed: true` explicitly when VTpass reports a definitive
 * failure/reversal — see the matching fix in bills-worker.js's
 * pollAndFinalize(), which previously had no way to act on a
 * provider's definitive failure signal and could poll forever even
 * after a provider clearly said "failed".
 */
async function getBillStatus(reference) {
  const requestId = referenceToRequestId(reference);
  const result = await vtpassPost("/requery", { request_id: requestId });
  if (result.networkError)
    return { success: false, error: result.networkError };

  const json = result.json || {};
  if (!result.ok) {
    return {
      success: false,
      error:
        json.response_description ||
        `VTpass requery error (HTTP ${result.status})`,
    };
  }

  const { confirmed, failed } = mapVtpassStatus(json);
  const txn = json.content?.transactions || {};
  return {
    success: true,
    data: {
      flw_ref: requestId,
      tx_ref: reference,
      customer_reference: reference,
      amount: txn.amount,
      product: txn.product_name || null,
      network: txn.network || null,
      transaction_date: txn.transaction_date || null,
      confirmed,
      failed,
      failure_reason: failed
        ? json.response_description ||
          "VTpass reported this transaction as failed"
        : null,
    },
    raw: json,
  };
}

module.exports = {
  listBillerItems,
  purchaseAirtime,
  purchaseData,
  payElectricity,
  payCable,
  payBetting,
  getBillStatus,
};
