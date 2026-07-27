// savings-catalog-routes.js
// User-facing read routes covering the FULL savings catalog — both
// built-in engines and generic products. Distinct from:
//   - savings-generic-routes.js's /products, which only ever returned
//     engine_type='generic' products (for the generic-start flow)
//   - savings-admin-routes.js, which is admin-only
// This file is what lets dashboard.js's existing 5 hardcoded types
// read their name/description/icon/status and admin-authored status
// wording from the catalog, instead of those being baked into JS
// string literals.
//
// Mount in index.js:
//   const savingsCatalogRouter = require("./savings-catalog-routes");
//   app.use("/api/user/savings/catalog", authenticate, savingsCatalogRouter);

const express = require("express");
const router = express.Router();
const catalog = require("./savings-catalog-service");

// GET /api/user/savings/catalog — every visible product, built-in and
// generic alike.
router.get("/", async (req, res) => {
  try {
    const products = await catalog.getProducts();
    res.json({ success: true, data: products });
  } catch (err) {
    console.error("[SAVINGS-CATALOG] GET / failed:", err);
    res.status(500).json({ success: false, error: "Failed to load savings catalog" });
  }
});

// GET /api/user/savings/catalog/:code — single product by its catalog
// code (e.g. "fixed", "harvest", or a generic product's code).
router.get("/:code", async (req, res) => {
  try {
    const product = await catalog.getProductByCode(req.params.code);
    if (!product) {
      return res.status(404).json({ success: false, error: "Unknown savings product" });
    }
    res.json({ success: true, data: product });
  } catch (err) {
    console.error("[SAVINGS-CATALOG] GET /:code failed:", err);
    res.status(500).json({ success: false, error: "Failed to load savings product" });
  }
});

// GET /api/user/savings/catalog/:code/status-copy/:statusKey — the
// admin-authored (or sensible default) title/body for a given product
// + computed status. dashboard.js's existing status computation
// (isMatured/isTargetReached/canWithdraw/isCompleted — all unchanged)
// decides WHICH statusKey to ask for; this only supplies the wording.
router.get("/:code/status-copy/:statusKey", async (req, res) => {
  try {
    const product = await catalog.getProductByCode(req.params.code);
    if (!product) {
      return res.status(404).json({ success: false, error: "Unknown savings product" });
    }
    const copy = await catalog.getStatusCopy(product.id, req.params.statusKey);
    res.json({ success: true, data: copy });
  } catch (err) {
    console.error("[SAVINGS-CATALOG] GET /:code/status-copy/:statusKey failed:", err);
    res.status(500).json({ success: false, error: "Failed to load status copy" });
  }
});

module.exports = router;