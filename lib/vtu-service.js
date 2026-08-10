// vtu-service.js
// The ONLY module that talks to the VTU.ng API. Nothing outside
// vtu-provider.js should import this directly — same rule as every
// other *-service.js in this codebase.
//
// VTU.ng (operated by FraNKAPPWeb Technologies, CAC BN 2384195) is a
// bills aggregator like Flutterwave/VTpass, not a payments/virtual-
// account platform like Paystack/Monnify — it implements all five
// bill categories this codebase models: airtime, data, electricity,
// cable, betting. It additionally offers ePINs (recharge card
// printing), NOT implemented here — same reason as VTpass's WAEC/
// insurance gap: this codebase's bill_categories schema doesn't model
// that category yet.
//
// Written directly from VTU.ng's own API reference (https://vtu.ng/api/)
// — every endpoint, param, and response shape below came from that
// document, not a guess.
//
// AUTH — important operational note. VTU.ng issues exactly ONE active
// JWT per account at a time: "only the latest token remains active —
// generating a new token invalidates older ones." This app runs
// multiple concurrent serverless instances (Vercel/Fly.io/Render, per
// your existing infra) with no shared memory between them. Caching the
// token in a local JS variable the way monnify-service.js does would
// mean every cold-started instance logging in fresh silently
// invalidates every OTHER instance's still-cached token — causing
// intermittent 403s under real concurrent traffic, not a hypothetical
// edge case. So this uses cache-service.js's shared cache (already
// relied on elsewhere, e.g. bills-catalog-service.js) instead of a
// local variable, so every instance shares one token rather than
// racing each other for fresh logins. CONFIRM cache-service.js is
// backed by something genuinely shared across all your deployed
// instances (Redis/Upstash/a DB table, not per-instance memory) before
// relying on this — if it isn't, this exact race condition still
// happens, just one layer down.
//
// CONFIRM before relying on this in production: shapes below are
// transcribed faithfully from VTU.ng's docs, not run against a live
// account from here (no network egress to vtu.ng in this environment).

const crypto = require("crypto");
const { cacheGet, cacheSet, cacheDel } = require("./cache-service");

const VTU_BASE_URL = process.env.VTU_BASE_URL || "https://vtu.ng/wp-json";
const TOKEN_CACHE_KEY = "vtu_ng:jwt_token";
// Docs say tokens are valid 7 days; refresh at 6.5 days to leave a
// safety margin rather than racing expiry mid-call.
const TOKEN_TTL_SECONDS = 6.5 * 24 * 60 * 60;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

// Data/TV variation lists are fetched live (public endpoints).
// Electricity's variation_id is a fixed 2-value enum (prepaid/postpaid
// — VTU.ng has no fetch endpoint for this, it's just two known
// values) and betting has no variation_id concept at all. See
// listBillerItems() below for how each service_id is classified.
// Lists transcribed directly from VTU.ng's documented service_id
// enums.
const DATA_SERVICE_IDS = new Set(["mtn", "glo", "airtel", "9mobile", "smile"]);
const TV_SERVICE_IDS = new Set(["dstv", "gotv", "startimes", "showmax"]);
const ELECTRICITY_SERVICE_IDS = new Set([
  "ikeja-electric", "eko-electric", "kano-electric", "portharcourt-electric",
  "jos-electric", "ibadan-electric", "kaduna-electric", "abuja-electric",
  "enugu-electric", "benin-electric", "aba-electric", "yola-electric",
]);
// Case-SENSITIVE exactly as documented — unlike every other category's
// service_id, VTU.ng's betting service_ids are mixed-case
// (e.g. "Bet9ja", "SportyBet"). Must be entered into
// bill_providers.external_biller_code with this exact casing.
const BETTING_SERVICE_IDS = new Set([
  "1xBet", "BangBet", "Bet9ja", "BetKing", "BetLand", "BetLion", "BetWay",
  "CloudBet", "LiveScoreBet", "MerryBet", "NaijaBet", "NairaBet",
  "SportyBet", "SupaBet",
]);

/**
 * VTU.ng's requery is keyed by the SAME request_id sent at purchase
 * time. bills-worker.js's pollAndFinalize() only ever has
 * bill_transactions.provider_tx_ref (our own reference) available — it
 * never carries forward whatever VTU.ng returned at purchase. So, same
 * requirement and same fix as vtpass-service.js's
 * referenceToRequestId(): a deterministic hash of `reference` alone,
 * independently re-derivable both at purchase time and any later
 * status check. Capped under VTU.ng's documented 50-char max.
 */
function referenceToRequestId(reference) {
  return (
    "FC" + crypto.createHash("md5").update(reference).digest("hex").slice(0, 20)
  );
}

async function getAccessToken() {
  const cached = await cacheGet(TOKEN_CACHE_KEY);
  if (cached?.token) return cached.token;

  const username = requireEnv("VTU_USERNAME");
  const password = requireEnv("VTU_PASSWORD");

  const response = await fetch(`${VTU_BASE_URL}/jwt-auth/v1/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const json = await response.json();
  if (!response.ok || !json.token) {
    throw new Error(
      json.message || `VTU.ng login failed (HTTP ${response.status})`,
    );
  }

  await cacheSet(TOKEN_CACHE_KEY, { token: json.token }, TOKEN_TTL_SECONDS);
  return json.token;
}

async function vtuFetch(path, options = {}, { auth = true } = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };

  if (auth) {
    let token;
    try {
      token = await getAccessToken();
    } catch (authErr) {
      return { networkError: `VTU.ng auth failed: ${authErr.message}` };
    }
    headers.Authorization = `Bearer ${token}`;
  }

  let response;
  try {
    response = await fetch(`${VTU_BASE_URL}${path}`, { ...options, headers });
  } catch (networkErr) {
    return { networkError: `Network error contacting VTU.ng: ${networkErr.message}` };
  }

  let json;
  try {
    json = await response.json();
  } catch (parseErr) {
    return { networkError: `Invalid JSON from VTU.ng (HTTP ${response.status})` };
  }

  // A 403 here might mean the shared token got invalidated by another
  // instance logging in concurrently (see header note) rather than a
  // genuine credentials failure — clear the cached token so the NEXT
  // call re-authenticates instead of every subsequent call retrying
  // against a token we now know is dead.
  if (response.status === 403 && auth) {
    await cacheDel(TOKEN_CACHE_KEY);
  }

  return { ok: response.ok && json.code === "success", status: response.status, json };
}

/**
 * Lists purchasable variations for a service_id. Data/TV variations
 * are fetched live (public endpoints, no auth needed). Electricity's
 * "variations" are a fixed enum synthesized here so the admin panel's
 * "Fetch Item Code" picker (bills-admin-service.js's
 * fetchProviderItemCodes) has something to show without a special
 * case. Betting has no variation_id concept at all (see purchase
 * params below) — returns an empty list, not an error.
 */
async function listBillerItems(serviceID) {
  if (ELECTRICITY_SERVICE_IDS.has(serviceID)) {
    return {
      success: true,
      items: [
        { external_item_code: "prepaid", display_name: "Prepaid", provider_cost: null },
        { external_item_code: "postpaid", display_name: "Postpaid", provider_cost: null },
      ],
    };
  }
  if (BETTING_SERVICE_IDS.has(serviceID)) {
    return { success: true, items: [] };
  }

  let path;
  if (DATA_SERVICE_IDS.has(serviceID)) {
    path = `/api/v2/variations/data?service_id=${encodeURIComponent(serviceID)}`;
  } else if (TV_SERVICE_IDS.has(serviceID)) {
    path = `/api/v2/variations/tv?service_id=${encodeURIComponent(serviceID)}`;
  } else {
    return {
      success: false,
      error: `'${serviceID}' is not a recognized VTU.ng service_id — check External Biller Code against VTU.ng's documented list.`,
    };
  }

  const result = await vtuFetch(path, { method: "GET" }, { auth: false });
  if (result.networkError) return { success: false, error: result.networkError };
  if (!result.ok) {
    return {
      success: false,
      error: result.json?.message || `VTU.ng variations error (HTTP ${result.status})`,
      raw: result.json,
    };
  }

  const items = Array.isArray(result.json.data) ? result.json.data : [];
  return {
    success: true,
    items: items.map((item) => ({
      external_plan_code: String(item.variation_id),
      external_item_code: null,
      display_name:
        (item.data_plan || item.package_bouquet || item.service_name || "") +
        (item.availability && item.availability !== "Available" ? " (Unavailable)" : ""),
      provider_cost: item.price != null ? Number(item.price) : null,
      raw: item,
    })),
    raw: result.json,
  };
}

// Codes worth retrying on backoff: wallet_busy is transient by
// definition; duplicate_order (409, "duplicate order within 3
// minutes") is VTU.ng's own anti-fraud lockout, which naturally
// clears once enough backoff time has passed, so failing it
// permanently would incorrectly kill a purchase that would have gone
// through fine 3 minutes later.
const RETRYABLE_CODES = new Set(["wallet_busy", "duplicate_order", "rate_limit_exceeded"]);

/**
 * Shared purchase call — VTU.ng uses a different endpoint per product
 * (unlike VTpass's single /pay), but the request_id/requery pattern is
 * identical across all of them, so this centralizes that.
 */
async function vtuPurchase(path, body, reference) {
  const requestId = referenceToRequestId(reference);
  const result = await vtuFetch(path, {
    method: "POST",
    body: JSON.stringify({ request_id: requestId, ...body }),
  });

  if (result.networkError) {
    return { success: false, error: result.networkError, retryable: true };
  }

  const json = result.json || {};

  // duplicate_request_id specifically means VTU.ng already has an
  // order under this exact request_id — from a PRIOR attempt at this
  // same bill_transaction we never got a confirmed response for
  // (network drop, function timeout, etc). Blindly retrying the
  // purchase call again would just get this same rejection forever.
  // VTU.ng's own integration guidelines point at requery for exactly
  // this case, so fall through to it and report ITS actual outcome as
  // this call's result rather than a bare failure.
  if (!result.ok && json.code === "duplicate_request_id") {
    return requeryAsPurchaseResult(requestId, reference);
  }

  if (!result.ok) {
    const retryable =
      RETRYABLE_CODES.has(json.code) || result.status === 429 || result.status >= 500;
    return {
      success: false,
      error: json.message || `VTU.ng purchase error (HTTP ${result.status})`,
      retryable,
      raw: { request: body, response: json },
    };
  }

  return {
    success: true,
    data: {
      // Reused as bill_transactions.provider_reference by
      // bills-worker.js — MUST match what getBillStatus()'s requery
      // recomputes, see referenceToRequestId() above.
      flw_ref: requestId,
      tx_ref: reference,
      order_id: json.data?.order_id,
      status: json.data?.status, // processing-api | completed-api | refunded, etc — see mapVtuStatus()
      network: json.data?.service_name || null,
      // Confirmed present directly on a completed electricity purchase
      // response per VTU.ng's docs (not nested) — see
      // getBillStatus()'s fallback chain for the requery equivalent,
      // which ISN'T shown for electricity in their docs and is
      // therefore unconfirmed.
      token: json.data?.token || null,
      units: json.data?.units || null,
    },
    raw: { request: body, response: json },
  };
}

async function requeryAsPurchaseResult(requestId, reference) {
  const result = await vtuFetch("/api/v2/requery", {
    method: "POST",
    body: JSON.stringify({ request_id: requestId }),
  });
  if (result.networkError) {
    return { success: false, error: result.networkError, retryable: true };
  }

  const json = result.json || {};
  if (!result.ok) {
    return {
      success: false,
      error: json.message || `VTU.ng requery error (HTTP ${result.status})`,
      retryable: result.status >= 500,
    };
  }

  const d = json.data || {};
  const { failed } = mapVtuStatus(d.status);
  if (failed) {
    return {
      success: false,
      error: `VTU.ng order status: ${d.status}`,
      retryable: false,
      raw: json,
    };
  }

  return {
    success: true,
    data: {
      flw_ref: requestId,
      tx_ref: reference,
      order_id: d.order_id,
      status: d.status,
      network: d.meta_data?.network || null,
      token: d.token || d.meta_data?.token || null,
      units: d.units || d.meta_data?.units || null,
    },
    raw: json,
  };
}

async function purchaseAirtime({ phoneNumber, amount, reference, billerCode }) {
  return vtuPurchase(
    "/api/v2/airtime",
    { phone: phoneNumber, service_id: billerCode, amount },
    reference,
  );
}

async function purchaseData({ customerIdentifier, amount, reference, planCode, billerCode }) {
  if (!planCode) {
    return {
      success: false,
      error: "planCode (VTU.ng's variation_id) is required for data purchases",
      retryable: false,
    };
  }
  return vtuPurchase(
    "/api/v2/data",
    { phone: customerIdentifier, service_id: billerCode, variation_id: planCode },
    reference,
  );
}

async function payElectricity({ customerIdentifier, amount, reference, billerCode, itemCode }) {
  if (!itemCode) {
    return {
      success: false,
      error: "itemCode (prepaid/postpaid) is required for electricity purchases",
      retryable: false,
    };
  }
  return vtuPurchase(
    "/api/v2/electricity",
    { customer_id: customerIdentifier, service_id: billerCode, variation_id: itemCode, amount },
    reference,
  );
}

async function payCable({ customerIdentifier, amount, reference, planCode, billerCode }) {
  if (!planCode) {
    return {
      success: false,
      error: "planCode (VTU.ng's variation_id) is required for cable purchases",
      retryable: false,
    };
  }
  // amount is optional per VTU.ng's docs — defaults to the package
  // price for subscription_type "change" (VTU.ng's own default, used
  // here since this codebase has no UI concept of "renew" pricing,
  // which needs the verify-customer response's renewal_amount fed
  // back in — not wired up).
  return vtuPurchase(
    "/api/v2/tv",
    { customer_id: customerIdentifier, service_id: billerCode, variation_id: planCode },
    reference,
  );
}

async function payBetting({ customerIdentifier, amount, reference, billerCode }) {
  // No variation_id for betting — matches VTU.ng's documented params
  // exactly (request_id, customer_id, service_id, amount only).
  return vtuPurchase(
    "/api/v2/betting",
    { customer_id: customerIdentifier, service_id: billerCode, amount },
    reference,
  );
}

/**
 * Pre-payment customer lookup — confirmed real endpoint
 * (POST /api/v2/verify-customer), confirmed response shape too (both
 * from docs and from a live test — see conversation). variation_id
 * (prepaid/postpaid) is required for electricity only, per VTU.ng's
 * docs; omitted for cable/betting.
 */
async function validateCustomer({ customerIdentifier, billerCode, itemCode }) {
  const body = { customer_id: customerIdentifier, service_id: billerCode };
  if (ELECTRICITY_SERVICE_IDS.has(billerCode)) {
    if (!itemCode) {
      return {
        success: false,
        error: "itemCode (prepaid/postpaid) is required to verify an electricity customer",
        retryable: false,
      };
    }
    body.variation_id = itemCode;
  }

  const result = await vtuFetch("/api/v2/verify-customer", {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (result.networkError) {
    return { success: false, error: result.networkError, retryable: true };
  }
  if (!result.ok) {
    return {
      success: false,
      error:
        result.json?.message || `VTU.ng customer verification failed (HTTP ${result.status})`,
      retryable: result.status >= 500,
      raw: result.json,
    };
  }
  return { success: true, data: result.json.data || {}, raw: result.json };
}

function mapVtuStatus(status) {
  if (status === "completed-api") return { confirmed: true, failed: false };
  if (["refunded", "cancelled", "failed"].includes(status)) {
    return { confirmed: false, failed: true };
  }
  return { confirmed: false, failed: false }; // initiated-api/processing-api/queued-api/pending/on-hold — keep polling
}

/**
 * Status check via VTU.ng's requery, keyed by the SAME deterministic
 * request_id purchase used.
 */
async function getBillStatus(reference) {
  const requestId = referenceToRequestId(reference);
  const result = await vtuFetch("/api/v2/requery", {
    method: "POST",
    body: JSON.stringify({ request_id: requestId }),
  });
  if (result.networkError) return { success: false, error: result.networkError };

  const json = result.json || {};
  if (!result.ok) {
    return {
      success: false,
      error: json.message || `VTU.ng requery error (HTTP ${result.status})`,
    };
  }

  const d = json.data || {};
  const { confirmed, failed } = mapVtuStatus(d.status);
  return {
    success: true,
    data: {
      flw_ref: requestId,
      tx_ref: reference,
      amount: d.amount,
      network: d.meta_data?.network || null,
      // NOT CONFIRMED for electricity specifically — VTU.ng's docs
      // only show requery samples for Data/ePINs/Airtime, none for
      // Electricity. The direct purchase response puts token/units at
      // the top level of `data` (confirmed); this checks both that
      // shape AND a meta_data-nested one as a fallback until a real
      // electricity requery response is available to check against.
      token: d.token || d.meta_data?.token || null,
      units: d.units || d.meta_data?.units || null,
      transaction_date: d.date_updated || null,
      confirmed,
      failed,
      failure_reason: failed ? `VTU.ng order status: ${d.status}` : null,
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
  validateCustomer,
  getBillStatus,
};