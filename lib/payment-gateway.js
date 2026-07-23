// payment-gateway.js
// Backward-compatible facade over service-registry.js. Kept so
// existing callers — bills-worker.js, bills-admin-service.js — don't
// need to change their import or call shape while the routing engine
// underneath is generalized to every service category, not just
// payments. New code should call ServiceRegistry.getProvider(serviceCode)
// from service-registry.js directly instead of adding more methods here.
//
// CAPABILITY_TO_SERVICE below is the only place left that still knows
// the old capability strings ('virtual_account', 'transfer', 'airtime')
// that predate the general registry.
//
// Bug fix included in this rewrite: the previous version of this file
// only defined createVirtualAccount / initiateTransfer / verifyTransfer
// / verifyTransaction / purchaseAirtime / getBillStatus / listBillerItems.
// bills-worker.js's CATEGORY_GATEWAY_METHOD map dispatches DATA/
// ELECTRICITY/CABLE_TV/BETTING jobs to PaymentGateway.purchaseData /
// payElectricity / payCable / payBetting — none of which existed on
// this object, so every non-airtime, non-plan... wait, every non-AIRTIME
// bill category job was throwing "PaymentGateway.<method> is not a
// function" the moment a worker tried to process it. Those four
// methods are added below.
//
// ProviderRouter is kept as an export purely for source compatibility
// with anything that imported it (nothing in the current codebase
// does) — it's a deprecated alias for ServiceRegistry, not a second
// routing implementation.

const {
  ServiceRegistry,
  NoProviderConfiguredError,
} = require("./service-registry");

const CAPABILITY_TO_SERVICE = {
  virtual_account: "virtual_account",
  transfer: "external_transfer",
  airtime: "airtime",
};

const PaymentGateway = {
  async createVirtualAccount(params) {
    const provider = await ServiceRegistry.getProvider(
      CAPABILITY_TO_SERVICE.virtual_account,
    );
    return provider.createVirtualAccount(params);
  },

  async initiateTransfer(params) {
    const { implementation, providerCode } = await ServiceRegistry.resolve(
      CAPABILITY_TO_SERVICE.transfer,
    );
    const result = await implementation.initiateTransfer(params);
    return { ...result, providerCode };
  },

  async verifyTransfer({ providerCode, ...params }) {
    const provider = ServiceRegistry.getProviderByCode(providerCode);
    return provider.verifyTransfer(params);
  },

  async verifyTransaction({ providerCode, ...params }) {
    const provider = ServiceRegistry.getProviderByCode(providerCode);
    return provider.verifyTransaction(params);
  },

  async purchaseAirtime(params) {
    const { implementation, providerCode } = await ServiceRegistry.resolve(
      CAPABILITY_TO_SERVICE.airtime,
    );
    const result = await implementation.purchaseAirtime(params);
    return { ...result, providerCode };
  },

  // --- Added: these four were missing before, see header note. ---
  async purchaseData(params) {
    const { implementation, providerCode } = await ServiceRegistry.resolve(
      "data",
    );
    const result = await implementation.purchaseData(params);
    return { ...result, providerCode };
  },

  async payElectricity(params) {
    const { implementation, providerCode } = await ServiceRegistry.resolve(
      "electricity",
    );
    const result = await implementation.payElectricity(params);
    return { ...result, providerCode };
  },

  async payCable(params) {
    const { implementation, providerCode } = await ServiceRegistry.resolve(
      "cable_tv",
    );
    const result = await implementation.payCable(params);
    return { ...result, providerCode };
  },

  async payBetting(params) {
    const { implementation, providerCode } = await ServiceRegistry.resolve(
      "betting_wallet_funding",
    );
    const result = await implementation.payBetting(params);
    return { ...result, providerCode };
  },
  // --- end added methods ---

  async getBillStatus({ providerCode, ...params }) {
    const provider = ServiceRegistry.getProviderByCode(providerCode);
    return provider.getBillStatus(params);
  },

  async listBillerItems({ providerCode, ...params }) {
    const provider = ServiceRegistry.getProviderByCode(providerCode);
    return provider.listBillerItems(params);
  },
};

module.exports = {
  PaymentGateway,
  // Deprecated alias — see header note.
  ProviderRouter: ServiceRegistry,
  NoProviderConfiguredError,
};