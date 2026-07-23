// service-registry-admin-routes.js
// Admin "Service Registry" API — same gating as every other /api/sys/*
// route (authenticate + authorizeAdmin; granular permission enforcement
// stays client-side via admin-permissions.js, matching bills-admin-routes.js).
//
// Mount in index.js:
//   const serviceRegistryAdminRouter = require("./service-registry-admin-routes");
//   app.use("/api/sys/service-registry", authenticate, authorizeAdmin, serviceRegistryAdminRouter);

const express = require("express");
const router = express.Router();
const registryAdmin = require("./service-registry-admin-service");

function handleError(res, err, fallbackMessage) {
  if (err.code === "NO_IMPLEMENTATION" || err.code === "CAPABILITY_NOT_DECLARED") {
    return res.status(400).json({ success: false, error: err.message, code: err.code });
  }
  if (err.code === "ROUTING_DEPENDS_ON_CAPABILITY") {
    return res.status(409).json({ success: false, error: err.message, code: err.code });
  }
  console.error(`[REGISTRY-ADMIN] ${fallbackMessage}:`, err);
  res.status(500).json({ success: false, error: fallbackMessage });
}

// ---------------- Categories & services (read-only) ----------------
router.get("/categories", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.listCategories() });
  } catch (err) {
    handleError(res, err, "Failed to load categories");
  }
});

router.get("/services", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.listServices({ categoryId: req.query.category_id }) });
  } catch (err) {
    handleError(res, err, "Failed to load services");
  }
});

// ---------------- Providers ----------------
router.get("/providers", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.listProviders({ categoryId: req.query.category_id }) });
  } catch (err) {
    handleError(res, err, "Failed to load providers");
  }
});

router.post("/providers", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.createProvider(req.user.id, req, req.body) });
  } catch (err) {
    handleError(res, err, "Failed to create provider");
  }
});

router.put("/providers/:id", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await registryAdmin.updateProvider(req.user.id, req, req.params.id, req.body),
    });
  } catch (err) {
    handleError(res, err, "Failed to update provider");
  }
});

router.post("/providers/:code/health", async (req, res) => {
  try {
    const { status, note } = req.body;
    res.json({
      success: true,
      data: await registryAdmin.setProviderHealth(req.user.id, req, req.params.code, status, note),
    });
  } catch (err) {
    handleError(res, err, "Failed to update provider health");
  }
});

// ---------------- Capabilities ----------------
router.get("/providers/:id/capabilities", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.listCapabilities(req.params.id) });
  } catch (err) {
    handleError(res, err, "Failed to load capabilities");
  }
});

router.post("/providers/:id/capabilities", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await registryAdmin.addCapability(req.user.id, req, req.params.id, req.body.service_code),
    });
  } catch (err) {
    handleError(res, err, "Failed to add capability");
  }
});

router.delete("/providers/:id/capabilities/:serviceCode", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await registryAdmin.removeCapability(req.user.id, req, req.params.id, req.params.serviceCode),
    });
  } catch (err) {
    handleError(res, err, "Failed to remove capability");
  }
});

// ---------------- Routing ----------------
router.get("/routing/:serviceCode", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.listRouting(req.params.serviceCode) });
  } catch (err) {
    handleError(res, err, "Failed to load routing");
  }
});

router.get("/routing/:serviceCode/eligible-providers", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.listEligibleProviders(req.params.serviceCode) });
  } catch (err) {
    handleError(res, err, "Failed to load eligible providers");
  }
});

router.post("/routing", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.upsertRouting(req.user.id, req, req.body) });
  } catch (err) {
    handleError(res, err, "Failed to update routing");
  }
});

router.delete("/routing/:id", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.removeRouting(req.user.id, req, req.params.id) });
  } catch (err) {
    handleError(res, err, "Failed to remove routing");
  }
});

// ---------------- Manual override ----------------
router.get("/override/:serviceCode", async (req, res) => {
  try {
    res.json({ success: true, data: await registryAdmin.getOverrideStatus(req.params.serviceCode) });
  } catch (err) {
    handleError(res, err, "Failed to load override status");
  }
});

router.post("/override/:serviceCode", async (req, res) => {
  try {
    const { provider_id, reason } = req.body;
    res.json({
      success: true,
      data: await registryAdmin.setManualOverride(req.user.id, req, req.params.serviceCode, provider_id, reason),
    });
  } catch (err) {
    handleError(res, err, "Failed to set manual override");
  }
});

router.delete("/override/:serviceCode", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await registryAdmin.clearManualOverride(req.user.id, req, req.params.serviceCode),
    });
  } catch (err) {
    handleError(res, err, "Failed to clear manual override");
  }
});

module.exports = router;