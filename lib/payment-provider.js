// payment-provider.js
// The contract every payment provider must implement. Nothing outside
// providers/*-provider.js should ever import flutterwave-service.js (or
// a future paystack-service.js) directly — everything goes through an
// object shaped like this, obtained from payment-gateway.js.
//
// Phase 1 reality check: only the methods actually backed by working
// code (createVirtualAccount, initiateTransfer, verifyTransaction,
// purchaseAirtime, getBillStatus) are implemented on FlutterwaveProvider.
// Everything else defined here throws NotImplementedError — loudly and
// immediately, not silently succeeding with fake data. That's the
// honest state of the system today: better to fail a request clearly
// than to pretend a data/electricity/cable purchase happened.

class NotImplementedError extends Error {
  constructor(providerName, methodName) {
    super(`${providerName} does not implement ${methodName}() yet`);
    this.name = "NotImplementedError";
    this.code = "PROVIDER_METHOD_NOT_IMPLEMENTED";
  }
}

class PaymentProvider {
  get code() {
    throw new Error("PaymentProvider subclasses must implement get code()");
  }

  async createCustomer(_params) {
    throw new NotImplementedError(this.code, "createCustomer");
  }

  async createVirtualAccount(_params) {
    throw new NotImplementedError(this.code, "createVirtualAccount");
  }

  async verifyAccount(_params) {
    throw new NotImplementedError(this.code, "verifyAccount");
  }

  async initiateTransfer(_params) {
    throw new NotImplementedError(this.code, "initiateTransfer");
  }

  async verifyTransfer(_params) {
    throw new NotImplementedError(this.code, "verifyTransfer");
  }

  async verifyTransaction(_params) {
    throw new NotImplementedError(this.code, "verifyTransaction");
  }

  async purchaseAirtime(_params) {
    throw new NotImplementedError(this.code, "purchaseAirtime");
  }

  async purchaseData(_params) {
    throw new NotImplementedError(this.code, "purchaseData");
  }

  async payElectricity(_params) {
    throw new NotImplementedError(this.code, "payElectricity");
  }

  async payCable(_params) {
    throw new NotImplementedError(this.code, "payCable");
  }

  async payBetting(_params) {
    throw new NotImplementedError(this.code, "payBetting");
  }

  async getBillStatus(_params) {
    throw new NotImplementedError(this.code, "getBillStatus");
  }

  async reverseTransaction(_params) {
    throw new NotImplementedError(this.code, "reverseTransaction");
  }

  async refund(_params) {
    throw new NotImplementedError(this.code, "refund");
  }
}

module.exports = { PaymentProvider, NotImplementedError };