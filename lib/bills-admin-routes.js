// bills-admin-routes.js
// Admin "Bills Management" API. Coarse gating (authenticate +
// authorizeAdmin) happens at the mount point in index.js, same as
// every other /api/sys/* route. Granular per-action enforcement is
// now done HERE, server-side, via requirePermission() — it used to be
// "handled client-side by admin-permissions.js", which meant it wasn't
// enforced at all (DevTools could call any of these directly). The
// permission keys below match admin-permissions.js's ACTIONS_REGISTRY
// under "bills-management" 1:1 — if that registry changes, update here.
//
// Mount in index.js:
//   const billsAdminRouter = require("./bills-admin-routes")(requirePermission);
//   app.use("/api/sys/bills", authenticate, authorizeAdmin, billsAdminRouter);

const express = require("express");
const adminService = require("./bills-admin-service");
const catalog = require("./bills-catalog-service");

function handleError(res, err, fallbackMessage) {
  if (err.code === "NOT_IMPLEMENTED") {
    return res
      .status(501)
      .json({ success: false, error: err.message, code: err.code });
  }
  if (err.code === "NOT_FOUND") {
    return res
      .status(404)
      .json({ success: false, error: err.message, code: err.code });
  }
  if (
    err.code === "MISSING_BILLER_CODE" ||
    err.code === "PROVIDER_FETCH_FAILED"
  ) {
    return res
      .status(400)
      .json({ success: false, error: err.message, code: err.code });
  }
  console.error(`[BILLS-ADMIN] ${fallbackMessage}:`, err);
  res.status(500).json({ success: false, error: fallbackMessage });
}

// Factory: takes the shared requirePermission(key) middleware from
// index.js (avoids guessing this file's relative path back to
// middleware/auth.js — index.js already knows the right path).
module.exports = function (requirePermission) {
  const router = express.Router();
  const perm = (actionId) => requirePermission(`bills-management:${actionId}`);

  // ---------------- Categories ----------------
  router.get("/categories", perm("view-bills-catalog"), async (req, res) => {
    try {
      res.json({ success: true, data: await adminService.listCategoriesAdmin() });
    } catch (err) {
      handleError(res, err, "Failed to load categories");
    }
  });

  router.post("/categories", perm("manage-categories"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.createCategory(req.user.id, req, req.body),
      });
    } catch (err) {
      handleError(res, err, "Failed to create category");
    }
  });

  router.put("/categories/:id", perm("manage-categories"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.updateCategory(
          req.user.id,
          req,
          req.params.id,
          req.body,
        ),
      });
    } catch (err) {
      handleError(res, err, "Failed to update category");
    }
  });

  router.delete("/categories/:id", perm("manage-categories"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.deleteCategory(req.user.id, req, req.params.id),
      });
    } catch (err) {
      handleError(res, err, "Failed to delete category");
    }
  });

  // ---------------- Providers ----------------
  router.get("/providers/:categoryId", perm("view-bills-catalog"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.listProvidersAdmin(req.params.categoryId),
      });
    } catch (err) {
      handleError(res, err, "Failed to load providers");
    }
  });

  router.post("/providers", perm("manage-providers"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.createProvider(req.user.id, req, req.body),
      });
    } catch (err) {
      handleError(res, err, "Failed to create provider");
    }
  });

  router.put("/providers/:id", perm("manage-providers"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.updateProvider(
          req.user.id,
          req,
          req.params.id,
          req.body,
        ),
      });
    } catch (err) {
      handleError(res, err, "Failed to update provider");
    }
  });

  router.delete("/providers/:id", perm("manage-providers"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.deleteProvider(req.user.id, req, req.params.id),
      });
    } catch (err) {
      handleError(res, err, "Failed to delete provider");
    }
  });

  // Preview-only — fetches a biller's available item_codes without
  // saving anything. Backs the "Fetch Item Code" picker in the provider
  // modal (admin-bills-management.js), for providers whose category has
  // no plan-selection flow to source one from otherwise (ELECTRICITY).
  router.get("/providers/:id/items", perm("manage-providers"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.fetchProviderItemCodes(req.params.id),
      });
    } catch (err) {
      handleError(res, err, "Failed to fetch item codes");
    }
  });

  // ---------------- Plans ----------------
  router.get("/plans/:providerId", perm("view-bills-catalog"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.listPlansAdmin(req.params.providerId),
      });
    } catch (err) {
      handleError(res, err, "Failed to load plans");
    }
  });

  router.post("/plans", perm("manage-plans"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.createPlan(req.user.id, req, req.body),
      });
    } catch (err) {
      handleError(res, err, "Failed to create plan");
    }
  });

  router.put("/plans/:id", perm("manage-plans"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.updatePlan(
          req.user.id,
          req,
          req.params.id,
          req.body,
        ),
      });
    } catch (err) {
      handleError(res, err, "Failed to update plan");
    }
  });

  router.delete("/plans/:id", perm("manage-plans"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.deletePlan(req.user.id, req, req.params.id),
      });
    } catch (err) {
      handleError(res, err, "Failed to delete plan");
    }
  });

  router.post("/plans/:providerId/refresh", perm("manage-plans"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.refreshPlansFromProvider(
          req.user.id,
          req,
          req.params.providerId,
        ),
      });
    } catch (err) {
      handleError(res, err, "Failed to refresh plans");
    }
  });

  // ---------------- Pricing ----------------
  router.post("/pricing", perm("manage-pricing"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.upsertPricingRule(req.user.id, req, req.body),
      });
    } catch (err) {
      handleError(res, err, "Failed to update pricing");
    }
  });

  // ---------------- Settings ----------------
  router.get("/settings/:key", perm("view-bills-catalog"), async (req, res) => {
    try {
      const setting = await adminService.getSetting(req.params.key);
      if (!setting)
        return res
          .status(404)
          .json({ success: false, error: "Setting not found" });
      res.json({ success: true, data: setting });
    } catch (err) {
      handleError(res, err, "Failed to load setting");
    }
  });

  router.post("/settings", perm("manage-bills-settings"), async (req, res) => {
    try {
      const { key, value } = req.body;
      if (!key || value === undefined) {
        return res
          .status(400)
          .json({ success: false, error: "key and value are required" });
      }
      res.json({
        success: true,
        data: await adminService.setSetting(req.user.id, req, key, value),
      });
    } catch (err) {
      handleError(res, err, "Failed to update setting");
    }
  });

  // ---------------- Analytics ----------------
  router.get("/analytics", perm("view-bills-analytics"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.getCategoryAnalytics(),
      });
    } catch (err) {
      handleError(res, err, "Failed to load analytics");
    }
  });

  // ---------------- Frozyla integration monitoring ----------------
  router.get("/frozyla/transactions", perm("view-frozyla-transactions"), async (req, res) => {
    try {
      const { status, reconciliation_status, limit, offset } = req.query;
      res.json({
        success: true,
        data: await adminService.listFrozylaTransactions({
          status,
          reconciliation_status,
          limit: limit ? Math.min(parseInt(limit, 10) || 50, 200) : 50,
          offset: offset ? parseInt(offset, 10) || 0 : 0,
        }),
      });
    } catch (err) {
      handleError(res, err, "Failed to load Frozyla transactions");
    }
  });

  router.get("/frozyla/transactions/:id", perm("view-frozyla-transactions"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.getFrozylaTransactionDetail(req.params.id),
      });
    } catch (err) {
      handleError(res, err, "Failed to load Frozyla transaction detail");
    }
  });

  router.post(
    "/frozyla/transactions/:id/resolve",
    perm("resolve-frozyla-mismatch"),
    async (req, res) => {
      try {
        res.json({
          success: true,
          data: await adminService.resolveFrozylaMismatch(
            req.user.id,
            req,
            req.params.id,
            req.body,
          ),
        });
      } catch (err) {
        if (err.code === "REASON_REQUIRED") {
          return res.status(400).json({ success: false, error: err.message, code: err.code });
        }
        handleError(res, err, "Failed to resolve Frozyla reconciliation entry");
      }
    },
  );

  router.post("/frozyla/reconcile", perm("trigger-frozyla-reconciliation"), async (req, res) => {
    try {
      res.json({
        success: true,
        data: await adminService.triggerFrozylaReconciliation(req.user.id, req),
      });
    } catch (err) {
      handleError(res, err, "Failed to run Frozyla reconciliation sweep");
    }
  });

  return router;
};