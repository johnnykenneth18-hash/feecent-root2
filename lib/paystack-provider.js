// paystack-provider.js
// Implements PaymentProvider by wrapping paystack-service.js — same
// pattern as flutterwave-provider.js.
//
// CAPABILITIES lists everything Paystack's API genuinely supports and
// this file implements: virtual_account, bank_account_resolution,
// external_transfer, deposit_verification. Which of these is actually
// routed live for a given service is decided in the admin panel
// (service_routing / manual override) — not restricted here. The
// bills-related services (airtime/data/electricity/cable/betting) are
// deliberately absent because Paystack has no public API for them —
// see paystack-service.js's header for why that's not an oversight.

const { PaymentProvider } = require("./payment-provider");
const paystackService = require("./paystack-service");

const CAPABILITIES = [
  "virtual_account",
  "bank_account_resolution",
  "external_transfer",
  "deposit_verification",
];

class PaystackProvider extends PaymentProvider {
  get code() {
    return "paystack";
  }

  async createVirtualAccount(params) {
    return paystackService.createVirtualAccount(params);
  }

  async verifyAccount({ accountNumber, bankCode }) {
    return paystackService.resolveAccount({ accountNumber, bankCode });
  }

  async initiateTransfer(params) {
    return paystackService.initiateTransfer(params);
  }

  async verifyTransfer(params) {
    // Matches the shape external-transfer-worker.js/transfer-webhook-
    // handler.js call every provider with: { flwTransferId }. For
    // Paystack that value is the transfer_code returned from
    // initiateTransfer(), stored in flutterwave_transfers.flutterwave_reference
    // regardless of which provider produced it (column name is legacy,
    // value is provider-agnostic — see 011_service_registry.sql).
    return paystackService.getTransferStatus(params.flwTransferId);
  }

  async verifyTransaction(reference) {
    return paystackService.verifyTransaction(reference);
  }

  // Not implemented — see paystack-service.js header: Paystack has no
  // bills/airtime API. purchaseAirtime/purchaseData/payElectricity/
  // payCable/payBetting/listBillerItems/getBillStatus all fall through
  // to PaymentProvider's default NotImplementedError.
}

module.exports = new PaystackProvider();
module.exports.PaystackProvider = PaystackProvider;
module.exports.CAPABILITIES = CAPABILITIES;
