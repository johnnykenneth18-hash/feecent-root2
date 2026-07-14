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
    const result = await flutterwaveService.getTransferStatus(params.flwTransferId);
    return result;
  }

  async verifyTransaction(params) {
    const result = await flutterwaveService.verifyTransaction(params.transactionId);
    return result;
  }

  async purchaseAirtime({ phoneNumber, amount, reference }) {
    return flutterwaveService.purchaseAirtime({ phoneNumber, amount, reference });
  }

  async getBillStatus({ reference }) {
    return flutterwaveService.getBillStatus(reference);
  }

  // Not yet built — see payment-provider.js header. Explicitly listed
  // here (rather than just inherited silently) so it's obvious at a
  // glance which capabilities Flutterwave is wired for in this codebase
  // today: purchaseData, payElectricity, payCable, payBetting,
  // reverseTransaction, refund, createCustomer, verifyAccount.
}

module.exports = new FlutterwaveProvider();
module.exports.FlutterwaveProvider = FlutterwaveProvider;