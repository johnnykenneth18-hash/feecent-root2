// vat-admin-routes.js
// Admin VAT config API — same gating as every other /api/sys/* route
// (authenticate + authorizeAdmin; granular permission enforcement
// stays client-side via admin-permissions.js — see the "fee-management"
// action added for this: "manage-vat").
//
// Mount in index.js:
//   const vatAdminRouter = require("./vat-admin-routes");
//   app.use("/api/sys/vat-config", authenticate, authorizeAdmin, vatAdminRouter);

const express = require("express");
const router = express.Router();
const vatAdmin = require("./vat-admin-service");

function handleError(res, err, fallbackMessage) {
  if (err.code === "INVALID_VAT_PERCENTAGE") {
    return res.status(400).json({ success: false, error: err.message, code: err.code });
  }
  console.error(`[VAT-ADMIN] ${fallbackMessage}:`, err);
  res.status(500).json({ success: false, error: fallbackMessage });
}

router.get("/", async (req, res) => {
  try {
    res.json({ success: true, data: await vatAdmin.getVatConfig() });
  } catch (err) {
    handleError(res, err, "Failed to load VAT config");
  }
});

router.put("/", async (req, res) => {
  try {
    res.json({ success: true, data: await vatAdmin.updateVatConfig(req.user.id, req, req.body) });
  } catch (err) {
    handleError(res, err, "Failed to update VAT config");
  }
});

router.get("/pending", async (req, res) => {
  try {
    res.json({ success: true, data: await vatAdmin.listPendingVat(req.query) });
  } catch (err) {
    handleError(res, err, "Failed to load pending VAT charges");
  }
});

module.exports = router;