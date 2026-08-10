// vtu-provider.js
// Implements PaymentProvider by wrapping vtu-service.js — same
// pattern as vtpass-provider.js.
//
// CAPABILITIES: like VTpass, VTU.ng is a full bills aggregator (not a
// payments/virtual-account platform like Paystack/Monnify), so it
// declares all five bill categories this codebase models. Which of
// these is actually routed live for a given category (or specific
// network within a category, since bill_providers rows are
// per-network) is an admin-panel / service_routing decision — not
// restricted here.

const { PaymentProvider } = require("./payment-provider");
const vtuService = require("./vtu-service");

const CAPABILITIES = ["airtime", "data", "electricity", "cable_tv", "betting_wallet_funding"];

class VtuProvider extends PaymentProvider {
  get code() {
    return "vtu";
  }

  async purchaseAirtime({ phoneNumber, amount, reference, billerCode }) {
    return vtuService.purchaseAirtime({ phoneNumber, amount, reference, billerCode });
  }

  async purchaseData({ customerIdentifier, amount, reference, planCode, billerCode }) {
    return vtuService.purchaseData({ customerIdentifier, amount, reference, planCode, billerCode });
  }

  async payElectricity({ customerIdentifier, amount, reference, billerCode, itemCode }) {
    return vtuService.payElectricity({ customerIdentifier, amount, reference, billerCode, itemCode });
  }

  async payCable({ customerIdentifier, amount, reference, planCode, billerCode }) {
    return vtuService.payCable({ customerIdentifier, amount, reference, planCode, billerCode });
  }

  async payBetting({ customerIdentifier, amount, reference, billerCode }) {
    return vtuService.payBetting({ customerIdentifier, amount, reference, billerCode });
  }

  async listBillerItems(params) {
    // bills-admin-service.js's refreshPlansFromProvider() and
    // fetchProviderItemCodes() both call this as
    // listBillerItems({ billerCode }) — VTU.ng's service_id IS what
    // external_biller_code holds for a VTU.ng-routed bill_providers
    // row, same convention as VTpass.
    const serviceID = typeof params === "string" ? params : params.billerCode;
    return vtuService.listBillerItems(serviceID);
  }

  async getBillStatus(params) {
    const reference = typeof params === "string" ? params : params.reference;
    return vtuService.getBillStatus(reference);
  }

  // Real, confirmed endpoint (see vtu-service.js's validateCustomer()
  // header) AND confirmed response shape — for electricity, both from
  // VTU.ng's own docs and from a live test against a real account (see
  // conversation history). Unlike Flutterwave's implementation, none
  // of this is a guess.
  async verifyCustomer({ customerIdentifier, billerCode, itemCode }) {
    const result = await vtuService.validateCustomer({
      customerIdentifier,
      billerCode,
      itemCode,
    });
    if (!result.success) {
      const err = new Error(result.error || "Customer validation failed");
      err.retryable = result.retryable;
      throw err;
    }
    return result.data;
  }

  // Not implemented — VTU.ng has no virtual account, transfer, or bank
  // resolution API; it is purely a bills aggregator, same as VTpass.
  // createVirtualAccount/initiateTransfer/verifyTransfer/verifyAccount
  // all fall through to PaymentProvider's default NotImplementedError.
  // ePINs (recharge card printing) is also not implemented — this
  // codebase's bill_categories schema doesn't model that category yet,
  // same reason vtpass-service.js's header gives for WAEC/insurance.
}

module.exports = new VtuProvider();
module.exports.VtuProvider = VtuProvider;
module.exports.CAPABILITIES = CAPABILITIES;