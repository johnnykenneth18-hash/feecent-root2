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
//
// CHANGE (bills v3 metadata/secret-data upgrade): added verifyCustomer()
// for the pre-payment customer-lookup step (spec sections 10-11) — meter
// number -> customer name, smartcard -> current bouquet, etc. Same
// honest-stub treatment as everything else here: no provider implements
// it yet (Flutterwave's real bill-validation endpoint hasn't been
// confirmed against your live account, so it's not being guessed at),
// and bills-service.js's handleVerifyCustomer() treats
// PROVIDER_METHOD_NOT_IMPLEMENTED as "let the user proceed without a
// confirmed name," not as a hard failure — verification is a UX
// nicety, not something the payment itself depends on.

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

  // Pre-payment customer/meter/smartcard lookup — e.g.
  // { customerIdentifier, billerCode, itemCode, categoryCode } ->
  // { customer_name, meter_address, current_bouquet, ... } depending
  // on category. Shape is intentionally provider- and
  // category-dependent; bills-service.js passes whatever comes back
  // straight through to the frontend as a flat object of label/value
  // pairs. itemCode is required by Flutterwave's implementation
  // (flutterwave-provider.js) — resolved by bills-service.js from
  // bill_providers.external_item_code before this is ever called; a
  // provider whose lookup doesn't need one can just ignore the param.
  async verifyCustomer(_params) {
    throw new NotImplementedError(this.code, "verifyCustomer");
  }

  async getBillStatus(_params) {
    throw new NotImplementedError(this.code, "getBillStatus");
  }

  async listBillerItems(_params) {
    throw new NotImplementedError(this.code, "listBillerItems");
  }

  async reverseTransaction(_params) {
    throw new NotImplementedError(this.code, "reverseTransaction");
  }

  async refund(_params) {
    throw new NotImplementedError(this.code, "refund");
  }
}

module.exports = { PaymentProvider, NotImplementedError };