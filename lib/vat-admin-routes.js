// vat-admin-routes.js
// Admin VAT config API. Coarse gating (authenticate + authorizeAdmin)
// happens at the mount point in index.js. Granular enforcement is done
// HERE via requirePermission("fee-management:manage-vat"), matching the
// "fee-management" section in admin-permissions.js's ACTIONS_REGISTRY.
//
// Mount in index.js:
//   const vatAdminRouter = require("./vat-admin-routes")(requirePermission);
//   app.use("/api/sys/vat-config", authenticate, authorizeAdmin, vatAdminRouter);

const express = require("express");
const vatAdmin = require("./vat-admin-service");

function handleError(res, err, fallbackMessage) {
  if (err.code === "INVALID_VAT_PERCENTAGE") {
    return res.status(400).json({ success: false, error: err.message, code: err.code });
  }
  console.error(`[VAT-ADMIN] ${fallbackMessage}:`, err);
  res.status(500).json({ success: false, error: fallbackMessage });
}

module.exports = function (requirePermission) {
  const router = express.Router();
  const perm = requirePermission("fee-management:manage-vat");

  router.get("/", perm, async (req, res) => {
    try {
      res.json({ success: true, data: await vatAdmin.getVatConfig() });
    } catch (err) {
      handleError(res, err, "Failed to load VAT config");
    }
  });

  router.put("/", perm, async (req, res) => {
    try {
      res.json({ success: true, data: await vatAdmin.updateVatConfig(req.user.id, req, req.body) });
    } catch (err) {
      handleError(res, err, "Failed to update VAT config");
    }
  });

  router.get("/pending", perm, async (req, res) => {
    try {
      res.json({ success: true, data: await vatAdmin.listPendingVat(req.query) });
    } catch (err) {
      handleError(res, err, "Failed to load pending VAT charges");
    }
  });

  return router;
};