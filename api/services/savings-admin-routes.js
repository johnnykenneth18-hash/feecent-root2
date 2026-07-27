// savings-admin-routes.js
// Admin "Savings Management" API — same gating as every other
// /api/sys/* route (authenticate + authorizeAdmin; granular permission
// enforcement stays client-side via admin-permissions.js).
//
// Mount in index.js:
//   const savingsAdminRouter = require("./savings-admin-routes");
//   app.use("/api/sys/savings", authenticate, authorizeAdmin, savingsAdminRouter);

const express = require("express");
const router = express.Router();
const savingsAdmin = require("./savings-admin-service");

function handleError(res, err, fallbackMessage) {
  if (err.code === "NOT_FOUND") {
    return res
      .status(404)
      .json({ success: false, error: err.message, code: err.code });
  }
  if (
    ["MISSING_FIELD", "CANNOT_DELETE_BUILT_IN", "HAS_ENROLLMENTS"].includes(
      err.code,
    )
  ) {
    return res
      .status(400)
      .json({ success: false, error: err.message, code: err.code });
  }
  console.error(`[SAVINGS-ADMIN] ${fallbackMessage}:`, err);
  res.status(500).json({ success: false, error: fallbackMessage });
}

// ---------------- Products ----------------
router.get("/products", async (req, res) => {
  try {
    res.json({ success: true, data: await savingsAdmin.listProducts() });
  } catch (err) {
    handleError(res, err, "Failed to load savings products");
  }
});

router.get("/products/:id", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await savingsAdmin.getProduct(req.params.id),
    });
  } catch (err) {
    handleError(res, err, "Failed to load savings product");
  }
});

router.post("/products", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await savingsAdmin.createGenericProduct(req.user.id, req, req.body),
    });
  } catch (err) {
    handleError(res, err, "Failed to create savings product");
  }
});

router.put("/products/:id", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await savingsAdmin.updateProduct(
        req.user.id,
        req,
        req.params.id,
        req.body,
      ),
    });
  } catch (err) {
    handleError(res, err, "Failed to update savings product");
  }
});

router.delete("/products/:id", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await savingsAdmin.deleteProduct(req.user.id, req, req.params.id),
    });
  } catch (err) {
    handleError(res, err, "Failed to delete savings product");
  }
});

// ---------------- Status copy ----------------
router.get("/products/:id/status-copy", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await savingsAdmin.listStatusCopy(req.params.id),
    });
  } catch (err) {
    handleError(res, err, "Failed to load status copy");
  }
});

router.post("/status-copy", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await savingsAdmin.upsertStatusCopy(req.user.id, req, req.body),
    });
  } catch (err) {
    handleError(res, err, "Failed to update status copy");
  }
});

// ---------------- Global kill switch ----------------
router.get("/enabled", async (req, res) => {
  try {
    res.json({
      success: true,
      data: { savings_enabled: await savingsAdmin.getSavingsEnabled() },
    });
  } catch (err) {
    handleError(res, err, "Failed to load savings enabled status");
  }
});

router.post("/enabled", async (req, res) => {
  try {
    res.json({
      success: true,
      data: await savingsAdmin.setSavingsEnabled(
        req.user.id,
        req,
        req.body.enabled,
      ),
    });
  } catch (err) {
    handleError(res, err, "Failed to update savings enabled status");
  }
});

module.exports = router;
