// savings-generic-routes.js
// User-facing API for generic (admin-defined) savings products.
// Mirrors bills-catalog-routes.js's read-only-catalog-plus-action-route
// split — this file never contains the actual money-movement logic
// (that's savings-generic-engine.js); it only validates the request
// shape and calls into that engine.
//
// Mount in index.js:
//   const savingsGenericRouter = require("./savings-generic-routes");
//   app.use("/api/user/savings/generic", authenticate, savingsGenericRouter);
//
// Does NOT replace or duplicate any existing /api/user/savings* route
// for the 5 built-in engines — those stay exactly as they are in
// index.js today.

const express = require("express");
const router = express.Router();
const { createClient } = require("@supabase/supabase-js");
const catalog = require("./savings-catalog-service");
const engine = require("./savings-generic-engine");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// GET /api/user/savings/generic/products — catalog of generic
// products only (built-ins are still served by whatever existing
// route already lists them in index.js).
router.get("/products", async (req, res) => {
  try {
    const enabled = await catalog.isSavingsEnabled();
    if (!enabled) {
      return res.json({ success: true, savings_enabled: false, data: [] });
    }
    const products = (await catalog.getProducts()).filter((p) => p.engine_type === "generic");
    res.json({ success: true, savings_enabled: true, data: products });
  } catch (err) {
    console.error("[SAVINGS-GENERIC] GET /products failed:", err);
    res.status(500).json({ success: false, error: "Failed to load savings products" });
  }
});

// GET /api/user/savings/generic — this user's generic enrollments
router.get("/", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("savings_enrollments")
      .select("*, savings_products(code, name, icon, reward_type)")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    console.error("[SAVINGS-GENERIC] GET / failed:", err);
    res.status(500).json({ success: false, error: "Failed to load your savings plans" });
  }
});

// GET /api/user/savings/generic/:id — single enrollment detail, with
// the admin-authored status copy for its CURRENT status attached, so
// the frontend can show the right modal without its own switch/case.
router.get("/:id", async (req, res) => {
  try {
    const { data: enrollment, error } = await supabase
      .from("savings_enrollments")
      .select("*, savings_products(code, name, icon, reward_type)")
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .single();
    if (error || !enrollment) {
      return res.status(404).json({ success: false, error: "Savings plan not found" });
    }
    const statusCopy = await catalog.getStatusCopy(enrollment.product_id, enrollment.status);
    res.json({ success: true, data: { ...enrollment, status_copy: statusCopy } });
  } catch (err) {
    console.error("[SAVINGS-GENERIC] GET /:id failed:", err);
    res.status(500).json({ success: false, error: "Failed to load savings plan" });
  }
});

// POST /api/user/savings/generic/start
router.post("/start", async (req, res) => {
  try {
    if (!(await catalog.isSavingsEnabled())) {
      return res.status(503).json({ success: false, error: "Savings is temporarily unavailable", code: "SAVINGS_DISABLED" });
    }
    const { account_id, product_code, initial_amount, target_amount, target_date } = req.body;
    if (!account_id || !product_code || !initial_amount) {
      return res.status(400).json({
        success: false,
        error: "account_id, product_code, and initial_amount are required",
        code: "MISSING_FIELDS",
      });
    }

    const result = await engine.createEnrollment({
      userId: req.user.id,
      accountId: account_id,
      productCode: product_code,
      initialAmount: initial_amount,
      targetAmount: target_amount,
      targetDate: target_date,
    });

    if (!result.success) {
      const statusMap = { PRODUCT_MAINTENANCE: 501, PRODUCT_NOT_AVAILABLE: 501, INSUFFICIENT_BALANCE: 400 };
      return res.status(statusMap[result.code] || 400).json(result);
    }
    res.json({ success: true, data: result.enrollment });
  } catch (err) {
    console.error("[SAVINGS-GENERIC] POST /start failed:", err);
    res.status(500).json({ success: false, error: "Failed to start savings plan" });
  }
});

// PUT /api/user/savings/generic/:id/auto-save
router.put("/:id/auto-save", async (req, res) => {
  try {
    const { auto_save } = req.body;
    const { data, error } = await supabase
      .from("savings_enrollments")
      .update({ auto_save: Boolean(auto_save), updated_at: new Date().toISOString() })
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select()
      .single();
    if (error || !data) {
      return res.status(404).json({ success: false, error: "Savings plan not found" });
    }
    res.json({ success: true, data });
  } catch (err) {
    console.error("[SAVINGS-GENERIC] PUT /:id/auto-save failed:", err);
    res.status(500).json({ success: false, error: "Failed to update auto-save" });
  }
});

// POST /api/user/savings/generic/:id/withdraw
router.post("/:id/withdraw", async (req, res) => {
  try {
    const result = await engine.processWithdrawal({ enrollmentId: req.params.id, userId: req.user.id });
    if (!result.success) {
      return res.status(400).json(result);
    }
    res.json({ success: true, data: result });
  } catch (err) {
    console.error("[SAVINGS-GENERIC] POST /:id/withdraw failed:", err);
    res.status(500).json({ success: false, error: "Failed to process withdrawal" });
  }
});

module.exports = router;