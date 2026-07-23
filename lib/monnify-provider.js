// monnify-provider.js
// Implements PaymentProvider by wrapping monnify-service.js — same
// pattern as flutterwave-provider.js.
//
// CAPABILITIES lists everything Monnify's API genuinely supports and
// this file implements: external_transfer, virtual_account,
// deposit_verification. Which of these is actually routed live for a
// given service is decided in the admin panel (service_routing /
// manual override) — not restricted here. The bills-related services
// are deliberately absent because Monnify has no public API for them
// — see monnify-service.js's header for why that's not an oversight.

const { PaymentProvider } = require("./payment-provider");
const monnifyService = require("./monnify-service");

const CAPABILITIES = ["external_transfer", "virtual_account", "deposit_verification"];

class MonnifyProvider extends PaymentProvider {
  get code() {
    return "monnify";
  }

  async createVirtualAccount(params) {
    return monnifyService.createVirtualAccount(params);
  }

  async initiateTransfer(params) {
    return monnifyService.initiateTransfer(params);
  }

  async verifyTransfer(params) {
    return monnifyService.getTransferStatus(params.flwTransferId);
  }

  async verifyTransaction(reference) {
    return monnifyService.verifyTransaction(reference);
  }

  // Not implemented — see monnify-service.js header: Monnify has no
  // bills/airtime API. purchaseAirtime/purchaseData/payElectricity/
  // payCable/payBetting/listBillerItems/getBillStatus all fall through
  // to PaymentProvider's default NotImplementedError.
}

module.exports = new MonnifyProvider();
module.exports.MonnifyProvider = MonnifyProvider;
module.exports.CAPABILITIES = CAPABILITIES;