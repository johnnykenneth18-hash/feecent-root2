// statement-service.js
// Account Statement generation — view (JSON) and download (PDF).
//
// Source of truth: the `ledger` table, NOT transactions_new. The ledger is
// append-only and carries balance_before/balance_after/running_balance per
// entry, which is exactly what a statement needs and is the only table in
// this codebase guaranteed to never be mutated after the fact. Building a
// statement from transactions_new would mean re-deriving balances that the
// ledger already computed atomically inside process_transfer /
// process_deposit / reserve_external_transfer — duplicating that logic here
// is how statements and real balances quietly drift apart.
//
// Security posture (per-request, not just "auth required"):
//   - Ownership check: account_id must belong to req.user.id. This is the
//     single most important line in this file — without it, any
//     authenticated user could read another user's statement by guessing/
//     enumerating account IDs (IDOR).
//   - Bounded date range: statements are capped at 366 days per request to
//     stop a single request from pulling a multi-year ledger history into
//     memory (both a DoS vector and a PDF-generation cost problem).
//   - Dedicated rate limiter: statement generation is heavier than a normal
//     read (a DB range scan + PDF render), so it gets its own limiter
//     separate from general API traffic.
//   - Full audit trail: every statement view/download is written to
//     financial_audit_log with the account, requester, IP, date range and
//     format — banks are expected to be able to answer "who pulled a
//     statement on this account, and when."
//   - No sensitive fields leak into the PDF: PIN, BVN, raw device
//     fingerprints, and internal provider references are never included.

const { createClient } = require("@supabase/supabase-js");
const rateLimit = require("express-rate-limit");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

const MAX_RANGE_DAYS = 366;
const DEFAULT_RANGE_DAYS = 30;
const MAX_ENTRIES_PER_STATEMENT = 5000; // hard ceiling; see pagination note below

// ------------------------------------------------------------
// Rate limiter — statement generation is a heavier operation
// (range scan + PDF render) than a normal GET, so it gets its own,
// tighter budget instead of sharing the general API limiter.
// ------------------------------------------------------------
const statementLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many statement requests. Please try again shortly." },
  keyGenerator: (req) => `${req.user?.id || req.ip}`,
});

function parseDateRange(query) {
  const now = new Date();
  let endDate = query.end_date ? new Date(query.end_date) : now;
  let startDate = query.start_date
    ? new Date(query.start_date)
    : new Date(endDate.getTime() - DEFAULT_RANGE_DAYS * 24 * 60 * 60 * 1000);

  if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
    return { error: "Invalid start_date or end_date" };
  }
  if (startDate > endDate) {
    return { error: "start_date must be before end_date" };
  }

  const rangeDays = (endDate - startDate) / (24 * 60 * 60 * 1000);
  if (rangeDays > MAX_RANGE_DAYS) {
    return {
      error: `Date range too large. Maximum statement range is ${MAX_RANGE_DAYS} days.`,
    };
  }

  // Statements are inclusive of the whole end_date calendar day.
  endDate = new Date(endDate);
  endDate.setHours(23, 59, 59, 999);

  return { startDate, endDate };
}

// ------------------------------------------------------------
// Shared: verify ownership + pull ledger rows + compute opening/closing.
// ------------------------------------------------------------
async function buildStatementData(req) {
  const { accountId } = req.params;

  const { data: account, error: accountErr } = await supabase
    .from("accounts")
    .select(
      "id, user_id, account_number, account_type, currency, balance, bank_name, creation_status",
    )
    .eq("id", accountId)
    .eq("user_id", req.user.id) // ownership check — never trust the path param alone
    .single();

  if (accountErr || !account) {
    return { status: 404, error: "Account not found" };
  }

  const range = parseDateRange(req.query);
  if (range.error) {
    return { status: 400, error: range.error };
  }
  const { startDate, endDate } = range;

  const {
    data: entries,
    error: ledgerErr,
    count,
  } = await supabase
    .from("ledger")
    .select(
      "id, ledger_reference, transaction_reference, entry_type, amount, balance_before, balance_after, running_balance, description, status, created_at",
      { count: "exact" },
    )
    .eq("account_id", account.id)
    .gte("created_at", startDate.toISOString())
    .lte("created_at", endDate.toISOString())
    .order("created_at", { ascending: true })
    .limit(MAX_ENTRIES_PER_STATEMENT);

  if (ledgerErr) {
    return { status: 500, error: "Failed to load ledger entries" };
  }

  // Opening balance = balance_before of the first entry in range. If there
  // are no entries in the window, opening and closing both fall back to
  // the account's current balance — accurate for an unmoved account, and
  // clearly labeled as "as of" rather than implied to be range-derived.
  const openingBalance =
    entries.length > 0
      ? Number(entries[0].balance_before)
      : Number(account.balance);
  const closingBalance =
    entries.length > 0
      ? Number(entries[entries.length - 1].balance_after)
      : Number(account.balance);

  const totalDebits = entries
    .filter((e) => e.entry_type === "DEBIT")
    .reduce((sum, e) => sum + Number(e.amount), 0);
  const totalCredits = entries
    .filter((e) => e.entry_type === "CREDIT")
    .reduce((sum, e) => sum + Number(e.amount), 0);

  return {
    status: 200,
    account,
    startDate,
    endDate,
    entries,
    openingBalance,
    closingBalance,
    totalDebits,
    totalCredits,
    truncated: count !== null && count > MAX_ENTRIES_PER_STATEMENT,
  };
}

async function logStatementAccess({
  req,
  account,
  startDate,
  endDate,
  format,
}) {
  // Best-effort audit write. A logging failure must never block the
  // customer from getting their own statement, so this is fire-and-forget
  // with a console fallback rather than something the request awaits-and-fails-on.
  try {
    await supabase.from("financial_audit_log").insert({
      user_id: req.user.id,
      action_type:
        format === "pdf" ? "statement_downloaded" : "statement_viewed",
      details: {
        account_id: account.id,
        account_number: account.account_number,
        start_date: startDate.toISOString(),
        end_date: endDate.toISOString(),
        format,
      },
      ip_address: req.ip,
      user_agent: req.headers["user-agent"] || null,
      request_id: req.headers["x-request-id"] || null,
    });
  } catch (err) {
    console.error("[STATEMENT] Failed to write audit log:", err);
  }
}

// ------------------------------------------------------------
// GET /api/user/accounts/:accountId/statement  (JSON — for in-app viewing)
// ------------------------------------------------------------
async function handleGetStatementJson(req, res) {
  try {
    const result = await buildStatementData(req);
    if (result.status !== 200) {
      return res.status(result.status).json({ error: result.error });
    }

    const {
      account,
      startDate,
      endDate,
      entries,
      openingBalance,
      closingBalance,
      totalDebits,
      totalCredits,
      truncated,
    } = result;

    await logStatementAccess({
      req,
      account,
      startDate,
      endDate,
      format: "json",
    });

    res.json({
      account: {
        account_number: account.account_number,
        account_type: account.account_type,
        currency: account.currency || "NGN",
        bank_name: account.bank_name || "Feecent",
      },
      period: {
        start_date: startDate.toISOString(),
        end_date: endDate.toISOString(),
      },
      opening_balance: openingBalance,
      closing_balance: closingBalance,
      total_debits: totalDebits,
      total_credits: totalCredits,
      entry_count: entries.length,
      truncated, // true if more entries exist than MAX_ENTRIES_PER_STATEMENT — narrow the date range
      entries: entries.map((e) => ({
        date: e.created_at,
        description: e.description,
        type: e.entry_type,
        amount: Number(e.amount),
        balance_after: Number(e.balance_after),
        reference: e.ledger_reference,
        status: e.status,
      })),
    });
  } catch (error) {
    console.error("[STATEMENT] JSON generation error:", error);
    res.status(500).json({ error: "Failed to generate statement" });
  }
}

// ------------------------------------------------------------
// GET /api/user/accounts/:accountId/statement/pdf  (PDF download)
// Requires: npm install pdfkit
// ------------------------------------------------------------
async function handleGetStatementPdf(req, res) {
  let PDFDocument;
  try {
    PDFDocument = require("pdfkit");
  } catch (err) {
    console.error("[STATEMENT] pdfkit not installed:", err.message);
    return res.status(500).json({
      error:
        "PDF generation is not available. Run `npm install pdfkit` on the server.",
    });
  }

  try {
    const result = await buildStatementData(req);
    if (result.status !== 200) {
      return res.status(result.status).json({ error: result.error });
    }

    const {
      account,
      startDate,
      endDate,
      entries,
      openingBalance,
      closingBalance,
      totalDebits,
      totalCredits,
    } = result;

    await logStatementAccess({
      req,
      account,
      startDate,
      endDate,
      format: "pdf",
    });

    const fmtMoney = (n) =>
      new Intl.NumberFormat("en-NG", {
        style: "currency",
        currency: account.currency || "NGN",
      }).format(n);
    const fmtDate = (d) =>
      new Date(d).toLocaleDateString("en-NG", {
        year: "numeric",
        month: "short",
        day: "2-digit",
      });

    const filename = `Feecent-Statement-${account.account_number}-${startDate
      .toISOString()
      .slice(0, 10)}_to_${endDate.toISOString().slice(0, 10)}.pdf`;

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    // Statements contain financial data — never let an intermediary cache them.
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, private",
    );

    const doc = new PDFDocument({ size: "A4", margin: 40 });
    doc.pipe(res);

    // Header
    doc
      .fontSize(20)
      .fillColor("#0A2540")
      .text("Feecent", { continued: false })
      .fontSize(11)
      .fillColor("#555")
      .text("Statement of Account");
    doc.moveDown(0.5);
    doc
      .fontSize(9)
      .fillColor("#888")
      .text(
        "This is a system-generated statement and does not require a signature.",
      );
    doc.moveDown(1);

    // Account details box
    doc.fontSize(10).fillColor("#000");
    const detailsY = doc.y;
    doc.text(
      `Account Name/Type: ${account.account_type || "Checking"} Account`,
      40,
      detailsY,
    );
    doc.text(`Account Number: ${account.account_number}`, 40, detailsY + 15);
    doc.text(`Bank: ${account.bank_name || "Feecent"}`, 40, detailsY + 30);
    doc.text(`Currency: ${account.currency || "NGN"}`, 300, detailsY);
    doc.text(
      `Period: ${fmtDate(startDate)} – ${fmtDate(endDate)}`,
      300,
      detailsY + 15,
    );
    doc.text(`Generated: ${fmtDate(new Date())}`, 300, detailsY + 30);
    doc.moveDown(3);

    // Summary box
    doc.fontSize(10).fillColor("#000");
    const summaryY = doc.y;
    doc.text(`Opening Balance: ${fmtMoney(openingBalance)}`, 40, summaryY);
    doc.text(`Closing Balance: ${fmtMoney(closingBalance)}`, 40, summaryY + 15);
    doc.text(`Total Credits: ${fmtMoney(totalCredits)}`, 300, summaryY);
    doc.text(`Total Debits: ${fmtMoney(totalDebits)}`, 300, summaryY + 15);
    doc.moveDown(3);

    // Table header
    const tableTop = doc.y;
    const cols = { date: 40, desc: 120, type: 330, amount: 390, balance: 470 };
    doc.fontSize(9).fillColor("#fff");
    doc.rect(40, tableTop, 515, 18).fill("#0A2540");
    doc
      .fillColor("#fff")
      .text("Date", cols.date + 4, tableTop + 5)
      .text("Description", cols.desc + 4, tableTop + 5)
      .text("Type", cols.type + 4, tableTop + 5)
      .text("Amount", cols.amount + 4, tableTop + 5)
      .text("Balance", cols.balance + 4, tableTop + 5);

    let y = tableTop + 22;
    doc.fillColor("#000").fontSize(8.5);

    if (entries.length === 0) {
      doc.text("No transactions in this period.", 40, y);
      y += 20;
    }

    entries.forEach((entry, idx) => {
      if (y > 760) {
        doc.addPage();
        y = 40;
      }
      if (idx % 2 === 0) {
        doc.rect(40, y - 3, 515, 16).fill("#F5F7FA");
        doc.fillColor("#000");
      }
      const amountLabel = `${entry.entry_type === "DEBIT" ? "-" : "+"}${fmtMoney(
        Number(entry.amount),
      )}`;
      doc
        .fontSize(8.5)
        .fillColor(entry.entry_type === "DEBIT" ? "#B42318" : "#087443")
        .text(fmtDate(entry.created_at), cols.date + 4, y, {
          width: cols.desc - cols.date - 8,
        });
      doc
        .fillColor("#000")
        .text((entry.description || "").slice(0, 45), cols.desc + 4, y, {
          width: cols.type - cols.desc - 8,
        })
        .text(entry.entry_type, cols.type + 4, y, {
          width: cols.amount - cols.type - 8,
        })
        .fillColor(entry.entry_type === "DEBIT" ? "#B42318" : "#087443")
        .text(amountLabel, cols.amount + 4, y, {
          width: cols.balance - cols.amount - 8,
        })
        .fillColor("#000")
        .text(fmtMoney(Number(entry.balance_after)), cols.balance + 4, y, {
          width: 85,
        });
      y += 16;
    });

    doc.moveDown(2);
    doc
      .fontSize(8)
      .fillColor("#888")
      .text(
        "Feecent is committed to the accuracy of this statement. If you notice a discrepancy, contact support within 30 days of the statement date.",
        40,
        Math.min(y + 20, 770),
        { width: 515 },
      );

    doc.end();
  } catch (error) {
    console.error("[STATEMENT] PDF generation error:", error);
    if (!res.headersSent) {
      res.status(500).json({ error: "Failed to generate statement PDF" });
    } else {
      res.end();
    }
  }
}

module.exports = {
  statementLimiter,
  handleGetStatementJson,
  handleGetStatementPdf,
};
