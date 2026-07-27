// api/cron/process-savings.js - Serverless function for Vercel cron
const { processAllSavings } = require("../services/savings-cron");
// NEW: processes ONLY engine_type='generic' (admin-defined) products —
// completely separate from the 5 existing engines processAllSavings()
// already handles above, which are untouched. Adjust this relative
// path to match wherever your other backend files actually live if
// your project uses `lib/` rather than `services/` — match whatever
// path convention this file's own processAllSavings import above uses.
const { processGenericSavings } = require("../services/savings-generic-engine");

export default async function handler(req, res) {
  // Verify cron secret
  /*const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }*/

  try {
    await processAllSavings();
    await processGenericSavings();
    res.status(200).json({
      success: true,
      message: "Savings processed successfully",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Cron job error:", error);
    res.status(500).json({
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
}