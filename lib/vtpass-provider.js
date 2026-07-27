// vtpass-provider.js
// Implements PaymentProvider by wrapping vtpass-service.js — same
// pattern as flutterwave-provider.js.
//
// CAPABILITIES: unlike Paystack/Monnify (which have NO bills API at
// all — see their own header notes), VTpass is a bills aggregator
// exactly like Flutterwave, so it declares all five bill categories
// this codebase models. Which of these is actually routed live for a
// given category (or a specific network within a category, since
// bill_providers rows are per-network) is an admin-panel /
// service_routing decision — not restricted here.

const { PaymentProvider } = require("./payment-provider");
const vtpassService = require("./vtpass-service");

const CAPABILITIES = ["airtime", "data", "electricity", "cable_tv", "betting_wallet_funding"];

class VtpassProvider extends PaymentProvider {
  get code() {
    return "vtpass";
  }

  async purchaseAirtime({ phoneNumber, amount, reference, billerCode }) {
    return vtpassService.purchaseAirtime({ phoneNumber, amount, reference, billerCode });
  }

  async purchaseData({ customerIdentifier, amount, reference, planCode, billerCode }) {
    return vtpassService.purchaseData({ customerIdentifier, amount, reference, planCode, billerCode });
  }

  async payElectricity({ customerIdentifier, amount, reference, billerCode, itemCode }) {
    return vtpassService.payElectricity({ customerIdentifier, amount, reference, billerCode, itemCode });
  }

  async payCable({ customerIdentifier, amount, reference, planCode, billerCode }) {
    return vtpassService.payCable({ customerIdentifier, amount, reference, planCode, billerCode });
  }

  async payBetting({ customerIdentifier, amount, reference, billerCode }) {
    return vtpassService.payBetting({ customerIdentifier, amount, reference, billerCode });
  }

  async listBillerItems(params) {
    // bills-admin-service.js's refreshPlansFromProvider() calls this
    // as listBillerItems({ billerCode }) — VTpass's variations
    // endpoint is keyed by serviceID, which IS what external_biller_code
    // holds for a VTpass-routed bill_providers row.
    const serviceID = typeof params === "string" ? params : params.billerCode;
    return vtpassService.listBillerItems(serviceID);
  }

  async getBillStatus(params) {
    const reference = typeof params === "string" ? params : params.reference;
    return vtpassService.getBillStatus(reference);
  }

  // Not implemented — VTpass has no virtual account, transfer, or bank
  // resolution API; it is purely a bills aggregator. createVirtualAccount/
  // initiateTransfer/verifyTransfer/verifyAccount all fall through to
  // PaymentProvider's default NotImplementedError.
}

module.exports = new VtpassProvider();
module.exports.VtpassProvider = VtpassProvider;
module.exports.CAPABILITIES = CAPABILITIES;