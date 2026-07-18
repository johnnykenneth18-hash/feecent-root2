// bills-admin-routes.js
// Admin "Bills Management" API. Gated the same way every other
// /api/sys/* route in this codebase is (authenticate + authorizeAdmin
// — coarse "is this an admin" check; granular per-action permission
// enforcement follows the existing pattern of being handled
// client-side by admin-permissions.js/admin-permissions-bridge.js, not
// introducing a new server-side model this codebase doesn't otherwise
// use).
//
// Mount in index.js:
//   const billsAdminRouter = require("./bills-admin-routes");
//   app.use("/api/sys/bills", authenticate, authorizeAdmin, billsAdminRouter);

const express = require("express");
const router = express.Router();
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

// ---------------- Categories ----------------
router.get("/categories", async (req, res) => {
  try {
    res.json({ success: true, data: await adminService.listCategoriesAdmin() });
  } catch (err) {
    handleError(res, err, "Failed to load categories");
  }
});

router.post("/categories", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.createCategory(req.user.id, req, req.body),
    });
  } catch (err) {
    handleError(res, err, "Failed to create category");
  }
});

router.put("/categories/:id", async (req, res) => {
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

router.delete("/categories/:id", async (req, res) => {
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
router.get("/providers/:categoryId", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.listProvidersAdmin(req.params.categoryId),
    });
  } catch (err) {
    handleError(res, err, "Failed to load providers");
  }
});

router.post("/providers", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.createProvider(req.user.id, req, req.body),
    });
  } catch (err) {
    handleError(res, err, "Failed to create provider");
  }
});

router.put("/providers/:id", async (req, res) => {
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

router.delete("/providers/:id", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.deleteProvider(req.user.id, req, req.params.id),
    });
  } catch (err) {
    handleError(res, err, "Failed to delete provider");
  }
});

// ---------------- Plans ----------------
router.get("/plans/:providerId", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.listPlansAdmin(req.params.providerId),
    });
  } catch (err) {
    handleError(res, err, "Failed to load plans");
  }
});

router.post("/plans", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.createPlan(req.user.id, req, req.body),
    });
  } catch (err) {
    handleError(res, err, "Failed to create plan");
  }
});

router.put("/plans/:id", async (req, res) => {
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

router.delete("/plans/:id", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.deletePlan(req.user.id, req, req.params.id),
    });
  } catch (err) {
    handleError(res, err, "Failed to delete plan");
  }
});

router.post("/plans/:providerId/refresh", async (req, res) => {
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
router.post("/pricing", async (req, res) => {
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
router.get("/settings/:key", async (req, res) => {
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

router.post("/settings", async (req, res) => {
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
router.get("/analytics", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await adminService.getCategoryAnalytics(),
    });
  } catch (err) {
    handleError(res, err, "Failed to load analytics");
  }
});

module.exports = router;
