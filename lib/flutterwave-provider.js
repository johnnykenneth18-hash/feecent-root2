// flutterwave-provider.js
// Implements PaymentProvider by wrapping flutterwave-service.js — the
// existing, already-battle-tested module that owns every raw HTTP call
// to Flutterwave. This file adapts that module's shapes to the standard
// provider interface; it deliberately contains no fetch() calls of its
// own.

const { PaymentProvider, NotImplementedError } = require("./payment-provider");
const flutterwaveService = require("./flutterwave-service");

class FlutterwaveProvider extends PaymentProvider {
  get code() {
    return "flutterwave";
  }

  async createVirtualAccount(params) {
    const result = await flutterwaveService.createVirtualAccount(params);
    return result;
  }

  async initiateTransfer(params) {
    const result = await flutterwaveService.initiateTransfer(params);
    return result;
  }

  async verifyTransfer(params) {
    const result = await flutterwaveService.getTransferStatus(
      params.flwTransferId,
    );
    return result;
  }

  async verifyTransaction(params) {
    const result = await flutterwaveService.verifyTransaction(
      params.transactionId,
    );
    return result;
  }

  async purchaseAirtime({ phoneNumber, amount, reference }) {
    return flutterwaveService.purchaseAirtime({
      phoneNumber,
      amount,
      reference,
    });
  }

  // See the CONFIRM-before-relying-on-this notes in flutterwave-service.js's
  // purchaseData/payElectricity/payCable/payBetting — the `type` values
  // and biller/item code requirements are my best-known convention, not
  // verified against your live Flutterwave account.
  async purchaseData({ customerIdentifier, amount, reference, planCode }) {
    return flutterwaveService.purchaseData({
      customerIdentifier,
      amount,
      reference,
      planCode,
    });
  }

  async payElectricity({
    customerIdentifier,
    amount,
    reference,
    billerCode,
    itemCode,
  }) {
    return flutterwaveService.payElectricity({
      customerIdentifier,
      amount,
      reference,
      billerCode,
      itemCode,
    });
  }

  async payCable({ customerIdentifier, amount, reference, planCode }) {
    return flutterwaveService.payCable({
      customerIdentifier,
      amount,
      reference,
      planCode,
    });
  }

  async payBetting({ customerIdentifier, amount, reference, billerCode }) {
    return flutterwaveService.payBetting({
      customerIdentifier,
      amount,
      reference,
      billerCode,
    });
  }

  async listBillerItems({ billerCode, country }) {
    return flutterwaveService.listBillerItems(billerCode, { country });
  }

  async getBillStatus({ reference }) {
    return flutterwaveService.getBillStatus(reference);
  }

  // Still not built — createCustomer, verifyAccount, reverseTransaction,
  // refund. Listed explicitly so it's obvious at a glance what
  // Flutterwave is NOT wired for in this codebase yet.
}

module.exports = new FlutterwaveProvider();
module.exports.FlutterwaveProvider = FlutterwaveProvider;
