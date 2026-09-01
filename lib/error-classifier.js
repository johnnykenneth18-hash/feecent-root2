// lib/sms/error-classifier.js
//
// Turns whatever an adapter throws/returns into one of four buckets
// the router acts on (section 15):
//
//   RETRYABLE                  -> try the next provider in priority order now
//   NON_RETRYABLE               -> stop; another provider can't fix a bad phone number
//   UNKNOWN                     -> the request may or may not have reached the
//                                  network/provider (timeout, connection reset).
//                                  Router treats this as "assume it might have
//                                  gone through" — see sms-router.js's UNKNOWN
//                                  handling and section 14.
//   PROVIDER_CONFIGURATION_ERROR -> auth/credentials are wrong; failing over
//                                  won't help either, and this should page
//                                  whoever owns provider config, not just log.
//
// Each adapter calls classify(err) from its own catch block and
// attaches the result to the error it throws (err.category), rather
// than the router trying to interpret raw HTTP/axios errors itself —
// only the adapter actually knows what a given status/error code from
// ITS provider means.

const RETRYABLE = "RETRYABLE";
const NON_RETRYABLE = "NON_RETRYABLE";
const UNKNOWN = "UNKNOWN";
const CONFIG_ERROR = "PROVIDER_CONFIGURATION_ERROR";

// Generic HTTP-status-based classification, used as the default inside
// each adapter's normalizeError() before provider-specific error-code
// overrides are applied.
function classifyHttpError(err) {
  // No response at all -> timeout / connection reset / DNS failure.
  // We genuinely don't know whether the provider received the request.
  if (!err.response) {
    if (err.code === "ECONNABORTED" || /timeout/i.test(err.message || "")) {
      return UNKNOWN;
    }
    return UNKNOWN;
  }

  const status = err.response.status;

  if (status === 401 || status === 403) return CONFIG_ERROR;
  if (status === 429) return RETRYABLE; // rate-limited by provider, not our fault
  if (status >= 500 && status < 600) return RETRYABLE;
  if (status === 408) return UNKNOWN; // provider itself reported a timeout
  if (status >= 400 && status < 500) return NON_RETRYABLE; // bad number, bad sender id, malformed payload, etc.

  return UNKNOWN;
}

module.exports = {
  RETRYABLE,
  NON_RETRYABLE,
  UNKNOWN,
  CONFIG_ERROR,
  classifyHttpError,
};
