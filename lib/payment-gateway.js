// payment-gateway.js
// The ONLY module that business logic (bills-service.js, bills-worker.js,
// external-transfer-*.js, virtual-account-worker.js once migrated) should
// import to reach a payment provider. Nothing above this file should know
// Flutterwave exists.
//
// Contains two logical pieces in one file for now:
//   - ProviderRouter: picks which provider handles a given capability,
//     reading from the `providers` table (not a hardcoded if/else) so
//     adding a second provider is a data change, not a code change.
//   - PaymentGateway: the facade — one method per capability, each of
//     which asks the router for a provider then calls the matching
//     method on it.
//
// Split ProviderRouter into its own file once there's a second provider
// and routing logic (e.g. "try provider A, fall back to B on failure")
// actually needs to grow past a single active-row lookup — no need to
// pre-build that complexity for one provider.

const { createClient } = require("@supabase/supabase-js");
const flutterwaveProvider = require("./flutterwave-provider");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Registry of provider implementations available in this codebase.
// Adding a provider means: implement PaymentProvider, add it here, add
// its row (with supported_capabilities) to the `providers` table via
// migration. PaymentGateway's methods below never change.
const PROVIDER_IMPLEMENTATIONS = {
  flutterwave: flutterwaveProvider,
};

class ProviderRouter {
  /**
   * Returns the active provider implementation for a capability,
   * preferring lowest `priority` when more than one provider supports
   * it. Throws a clear error if nothing is configured — callers should
   * not have to guess why a payment silently didn't happen.
   */
  async selectProvider(capability) {
    const { data: candidates, error } = await supabase
      .from("providers")
      .select("code, name, priority")
      .eq("is_active", true)
      .contains("supported_capabilities", [capability])
      .order("priority", { ascending: true });

    if (error) {
      throw new Error(`Provider routing lookup failed: ${error.message}`);
    }
    if (!candidates || candidates.length === 0) {
      throw new Error(`No active provider supports capability '${capability}'`);
    }

    const chosen = candidates[0];
    const implementation = PROVIDER_IMPLEMENTATIONS[chosen.code];
    if (!implementation) {
      throw new Error(
        `Provider '${chosen.code}' is configured active in the database but has no implementation registered in payment-gateway.js`,
      );
    }
    return implementation;
  }

  /**
   * Returns a specific provider by code, bypassing capability routing.
   * Used for anything that must go back to the exact provider that
   * processed the original transaction (status checks, verification,
   * reversal) — routing those by capability again could hand a
   * follow-up call to a different provider once more than one is
   * configured for the same capability, which would silently query
   * the wrong system.
   */
  selectProviderByCode(code) {
    const implementation = PROVIDER_IMPLEMENTATIONS[code];
    if (!implementation) {
      throw new Error(
        `No provider implementation registered for code '${code}'`,
      );
    }
    return implementation;
  }
}

const router = new ProviderRouter();

const PaymentGateway = {
  async createVirtualAccount(params) {
    const provider = await router.selectProvider("virtual_account");
    return provider.createVirtualAccount(params);
  },

  async initiateTransfer(params) {
    const provider = await router.selectProvider("transfer");
    return provider.initiateTransfer(params);
  },

  async verifyTransfer({ providerCode, ...params }) {
    const provider = router.selectProviderByCode(providerCode);
    return provider.verifyTransfer(params);
  },

  async verifyTransaction({ providerCode, ...params }) {
    const provider = router.selectProviderByCode(providerCode);
    return provider.verifyTransaction(params);
  },

  async purchaseAirtime(params) {
    const provider = await router.selectProvider("airtime");
    const result = await provider.purchaseAirtime(params);
    return { ...result, providerCode: provider.code };
  },

  async getBillStatus({ providerCode, ...params }) {
    const provider = router.selectProviderByCode(providerCode);
    return provider.getBillStatus(params);
  },

  async listBillerItems({ providerCode, ...params }) {
    const provider = router.selectProviderByCode(providerCode);
    return provider.listBillerItems(params);
  },
};

module.exports = { PaymentGateway, ProviderRouter };
