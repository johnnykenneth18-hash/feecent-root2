// bill-payment-engine.js
// Validates a bill payment request and dispatches it to the right
// processor. Each processor knows the rules for its own bill type
// (min/max amount, identifier format) — the engine's job is routing
// and giving a clear, honest error for anything not built yet.
//
// Phase 1: AIRTIME is the only real processor. DATA / ELECTRICITY /
// CABLE / BETTING are declared (so the shape of the eventual system is
// visible) but return NOT_SUPPORTED_YET rather than pretending to work
// — see the note on this in payment-provider.js.

const PROCESSORS = {
  AIRTIME: {
    minAmount: 50,
    maxAmount: 50000,
    validate({ customer_identifier, amount }) {
      if (!customer_identifier || !/^0\d{10}$/.test(customer_identifier)) {
        return "A valid 11-digit Nigerian phone number is required (e.g. 08012345678)";
      }
      const numericAmount = Number(amount);
      if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
        return "Invalid amount";
      }
      if (numericAmount < PROCESSORS.AIRTIME.minAmount) {
        return `Minimum airtime purchase is ₦${PROCESSORS.AIRTIME.minAmount}`;
      }
      if (numericAmount > PROCESSORS.AIRTIME.maxAmount) {
        return `Maximum airtime purchase is ₦${PROCESSORS.AIRTIME.maxAmount.toLocaleString()}`;
      }
      return null; // no error
    },
  },
  DATA: { supported: false },
  ELECTRICITY: { supported: false },
  CABLE: { supported: false },
  BETTING: { supported: false },
};

function getProcessor(serviceType) {
  const processor = PROCESSORS[serviceType];
  if (!processor) {
    return {
      error: `Unknown service type '${serviceType}'`,
      code: "UNKNOWN_SERVICE_TYPE",
    };
  }
  if (processor.supported === false) {
    return {
      error: `${serviceType} payments are not available yet`,
      code: "NOT_SUPPORTED_YET",
    };
  }
  return { processor };
}

function validateBillRequest({ service_type, customer_identifier, amount }) {
  const { processor, error, code } = getProcessor(service_type);
  if (error) return { valid: false, error, code };

  const validationError = processor.validate({ customer_identifier, amount });
  if (validationError) {
    return { valid: false, error: validationError, code: "VALIDATION_FAILED" };
  }
  return { valid: true };
}

module.exports = { validateBillRequest, getProcessor, PROCESSORS };
