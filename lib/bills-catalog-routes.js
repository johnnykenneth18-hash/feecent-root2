// bills-catalog-routes.js
// Public (authenticated-user-facing) read routes for the bills
// catalog. These never write anything — POST /api/bills (the actual
// purchase) stays in bills-service.js, unchanged in shape from
// before.
//
// Mount in index.js alongside the other /api/user/* style routes:
//   const billsCatalogRouter = require("./bills-catalog-routes");
//   app.use("/api/bills", authenticate, billsCatalogRouter);
//
// (authenticate is applied at the mount point, matching how the rest
// of index.js wires per-route middleware — not repeated here per route.)

const express = require("express");
const router = express.Router();
const catalog = require("./bills-catalog-service");

// GET /api/bills/categories
// GET /api/bills/categories?featured=true
router.get("/categories", async (req, res) => {
  try {
    const featuredOnly = req.query.featured === "true";
    const [categories, billsEnabled] = await Promise.all([
      catalog.getCategories({ featuredOnly }),
      catalog.isBillsEnabled(),
    ]);
    res.json({ success: true, bills_enabled: billsEnabled, data: categories });
  } catch (err) {
    console.error("[BILLS-CATALOG] GET /categories failed:", err);
    res
      .status(500)
      .json({ success: false, error: "Failed to load bill categories" });
  }
});

// GET /api/bills/categories/:id
router.get("/categories/:id", async (req, res) => {
  try {
    const category = await catalog.getCategoryById(req.params.id);
    if (!category || category.status === "HIDDEN") {
      return res
        .status(404)
        .json({ success: false, error: "Category not found" });
    }
    res.json({ success: true, data: category });
  } catch (err) {
    console.error("[BILLS-CATALOG] GET /categories/:id failed:", err);
    res.status(500).json({ success: false, error: "Failed to load category" });
  }
});

// GET /api/bills/providers?category=DATA   (by category code)
router.get("/providers", async (req, res) => {
  try {
    const { category } = req.query;
    if (!category) {
      return res
        .status(400)
        .json({ success: false, error: "category query param is required" });
    }
    const categoryRow = await catalog.getCategoryByCode(category);
    if (!categoryRow) {
      return res
        .status(404)
        .json({ success: false, error: "Unknown category" });
    }
    const providers = await catalog.getProvidersForCategory(categoryRow.id);
    res.json({ success: true, data: providers });
  } catch (err) {
    console.error("[BILLS-CATALOG] GET /providers failed:", err);
    res.status(500).json({ success: false, error: "Failed to load providers" });
  }
});

// GET /api/bills/providers/:category  (path-param variant, as in the spec)
router.get("/providers/:category", async (req, res) => {
  try {
    const categoryRow = await catalog.getCategoryByCode(req.params.category);
    if (!categoryRow) {
      return res
        .status(404)
        .json({ success: false, error: "Unknown category" });
    }
    const providers = await catalog.getProvidersForCategory(categoryRow.id);
    res.json({ success: true, data: providers });
  } catch (err) {
    console.error("[BILLS-CATALOG] GET /providers/:category failed:", err);
    res.status(500).json({ success: false, error: "Failed to load providers" });
  }
});

// GET /api/bills/plans?provider_id=...
router.get("/plans", async (req, res) => {
  try {
    const { provider_id } = req.query;
    if (!provider_id) {
      return res
        .status(400)
        .json({ success: false, error: "provider_id query param is required" });
    }
    const plans = await catalog.getPlansForProvider(provider_id);
    res.json({ success: true, data: plans });
  } catch (err) {
    console.error("[BILLS-CATALOG] GET /plans failed:", err);
    res.status(500).json({ success: false, error: "Failed to load plans" });
  }
});

// GET /api/bills/plans/:provider  (provider_id as path param, as in the spec)
router.get("/plans/:provider", async (req, res) => {
  try {
    const plans = await catalog.getPlansForProvider(req.params.provider);
    res.json({ success: true, data: plans });
  } catch (err) {
    console.error("[BILLS-CATALOG] GET /plans/:provider failed:", err);
    res.status(500).json({ success: false, error: "Failed to load plans" });
  }
});

module.exports = router;
