// savings-status-route.js
// One tiny endpoint: whether the WHOLE Savings/Finance section is on
// or showing "Coming Soon" — checked once when the user opens that
// tab, before rendering anything (built-in types AND generic ones).
// Separate from savings-generic-routes.js's /products endpoint, which
// only ever concerned the generic catalog specifically.
//
// Mount in index.js:
//   const savingsStatusRouter = require("./savings-status-route");
//   app.use("/api/user/savings/status", authenticate, savingsStatusRouter);

const express = require("express");
const router = express.Router();
const catalog = require("./savings-catalog-service");

router.get("/", async (req, res) => {
  try {
    const enabled = await catalog.isSavingsEnabled();
    res.json({ success: true, savings_enabled: enabled });
  } catch (err) {
    console.error("[SAVINGS-STATUS] check failed:", err);
    // Fail OPEN for this one — if the check itself breaks, showing the
    // normal savings UI (today's existing behavior) is safer than
    // accidentally locking every user out of their own money.
    res.json({ success: true, savings_enabled: true });
  }
});

module.exports = router;