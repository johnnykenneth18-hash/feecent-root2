// api/cron/process-savings.js - Serverless function for Vercel cron
const { processAllSavings } = require("../services/savings-cron");

export default async function handler(req, res) {
  // Verify cron secret
  /*const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }*/

  try {
    await processAllSavings();
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
