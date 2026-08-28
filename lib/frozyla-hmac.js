// frozyla-hmac.js
//
// HMAC request signing/verification shared by both sides of the
// FEECENT <-> Frozyla integration. Not an npm package — the two apps
// are separate repos, so copy this file into both. Keep the two
// copies byte-identical; if the signing scheme ever changes, change
// both at once or every request fails verification on whichever side
// didn't get the update.
//
// Signed string is:
//   `${method}.${path}.${timestamp}.${nonce}.${rawBody}`
// HMAC-SHA256, hex digest.
//
// method + path are bound into the signature (not just timestamp/nonce
// + body) so a captured, still-valid-window signature for one endpoint
// can't be pointed at a different endpoint/resource — this matters
// most for GET requests with an empty body, where the body alone
// carries no information about which resource is being requested.
//
// rawBody must be the EXACT bytes sent over the wire (the JSON string,
// not a re-serialized object — key ordering differences between two
// independent JSON.stringify calls would break this). For GET
// requests with no body, use the empty string "".
//
// path is the request path only, no query string, no host — e.g.
// "/api/v1/integrations/feecent/frozyla/credit". Both sides must
// agree on this exactly; if a proxy/base-path prefix differs between
// what the sender signs and what the receiver sees, verification
// fails. Normalize before signing/verifying, not after.

const crypto = require("crypto");

const REPLAY_WINDOW_SECONDS = 300; // 5 minutes — matches the nonce table's prune interval

function sign({ secret, method, path, timestamp, nonce, rawBody }) {
  return crypto
    .createHmac("sha256", secret)
    .update(`${method.toUpperCase()}.${path}.${timestamp}.${nonce}.${rawBody}`)
    .digest("hex");
}

function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}

// Returns { valid: true } or { valid: false, reason } — reason is for
// server-side logs only, never echo it back to the caller.
function verify({ secret, method, path, timestamp, nonce, rawBody, signature }) {
  if (!method || !path || !timestamp || !nonce || rawBody === undefined || !signature) {
    return { valid: false, reason: "MISSING_FIELDS" };
  }

  const tsNum = Number(timestamp);
  if (!Number.isFinite(tsNum)) {
    return { valid: false, reason: "INVALID_TIMESTAMP" };
  }
  const ageSeconds = Math.abs(Date.now() / 1000 - tsNum);
  if (ageSeconds > REPLAY_WINDOW_SECONDS) {
    return { valid: false, reason: "TIMESTAMP_OUT_OF_WINDOW" };
  }

  const expected = sign({ secret, method, path, timestamp, nonce, rawBody });

  // Constant-time comparison. A length mismatch is treated as
  // "not valid" without calling timingSafeEqual (which requires equal
  // lengths) — checking length first leaks nothing useful, unlike
  // comparing unequal-length buffers naively would.
  const expectedBuf = Buffer.from(expected, "hex");
  const givenBuf = Buffer.from(String(signature), "hex");
  if (expectedBuf.length !== givenBuf.length) {
    return { valid: false, reason: "SIGNATURE_MISMATCH" };
  }
  if (!crypto.timingSafeEqual(expectedBuf, givenBuf)) {
    return { valid: false, reason: "SIGNATURE_MISMATCH" };
  }

  return { valid: true };
}

module.exports = { sign, verify, generateNonce, REPLAY_WINDOW_SECONDS };