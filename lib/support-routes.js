// support-routes.js
//
// USER-FACING support/chat endpoints. Mount in index.js as:
//
//   const supportRoutes = require("./lib/support-routes");
//   app.use("/api/support", authenticate, supportRoutes);
//
// `authenticate` is your existing bank-auth middleware (../middleware/auth)
// — reused here ONLY to know who's asking (req.user.id / first_name /
// last_name / email, for pre-filling the escalation form and for the
// ownership check on ticket routes). Every single query in this file goes
// through `supportDb`, the isolated client from support-db.js — never the
// bank `supabase` client. No bank table (users, accounts, transactions,
// ledger, ...) is ever queried here.
//
// Ownership model: req.user.id (a bank user UUID) is stored as
// `bank_user_id` on the ticket, as a plain opaque value — not a foreign
// key (this DB has no users table to reference). All "my ticket" checks
// below compare against it directly.

const express = require("express");
const router = express.Router();

const { supportDb, withDbTimeout } = require("./support-db");
const {
  schemas,
  validate,
  createTicketLimiter,
  sendMessageLimiter,
  readLimiter,
} = require("./support-security");

const BOT_NAME = "FeeCent Assistant";

// GET /api/support/topics — the bot's menu of issue buttons.
router.get("/topics", readLimiter, async (req, res) => {
  try {
    const { data, error } = await withDbTimeout(
      supportDb
        .from("support_topics")
        .select("id, title, solution, display_order")
        .eq("is_active", true)
        .order("display_order", { ascending: true }),
    );
    if (error) throw error;
    res.json({ topics: data || [] });
  } catch (err) {
    console.error("[support] topics fetch error:", err);
    res.status(500).json({ error: "Failed to load support topics" });
  }
});

// GET /api/support/tickets — this user's tickets, newest first.
router.get("/tickets", readLimiter, async (req, res) => {
  try {
    const { data, error } = await withDbTimeout(
      supportDb
        .from("support_tickets")
        .select(
          "id, status, topic_title_snapshot, assigned_admin_name, created_at, updated_at, closed_at",
        )
        .eq("bank_user_id", req.user.id)
        .order("created_at", { ascending: false }),
    );
    if (error) throw error;
    res.json({ tickets: data || [] });
  } catch (err) {
    console.error("[support] tickets list error:", err);
    res.status(500).json({ error: "Failed to load your support tickets" });
  }
});

// POST /api/support/tickets — escalate to a human. Creates the ticket and
// seeds it with the bot's suggested solution (if a topic was picked) plus
// the user's own message explaining why it didn't help.
router.post(
  "/tickets",
  createTicketLimiter,
  validate(schemas.createTicket),
  async (req, res) => {
    try {
      const { full_name, email, topic_id, initial_message } = req.body;

      let topicTitleSnapshot = null;
      let topicSolution = null;
      if (topic_id) {
        const { data: topic } = await withDbTimeout(
          supportDb
            .from("support_topics")
            .select("title, solution")
            .eq("id", topic_id)
            .maybeSingle(),
        );
        if (topic) {
          topicTitleSnapshot = topic.title;
          topicSolution = topic.solution;
        }
      }

      const { data: ticket, error: ticketError } = await withDbTimeout(
        supportDb
          .from("support_tickets")
          .insert({
            bank_user_id: req.user.id,
            full_name,
            email,
            topic_id: topic_id || null,
            topic_title_snapshot: topicTitleSnapshot,
            status: "open",
            source: "bot_escalation",
          })
          .select()
          .single(),
      );
      if (ticketError) throw ticketError;

      const seedMessages = [];
      if (topicSolution) {
        seedMessages.push({
          ticket_id: ticket.id,
          sender_type: "bot",
          sender_name: BOT_NAME,
          message: `Suggested solution for "${topicTitleSnapshot}": ${topicSolution}`,
        });
      }
      seedMessages.push({
        ticket_id: ticket.id,
        sender_type: "user",
        sender_name: full_name,
        message: initial_message,
      });

      const { error: msgError } = await withDbTimeout(
        supportDb.from("support_messages").insert(seedMessages),
      );
      if (msgError) throw msgError;

      res.json({ message: "Ticket created", ticket });
    } catch (err) {
      console.error("[support] ticket creation error:", err);
      res.status(500).json({ error: "Failed to create support ticket" });
    }
  },
);

// Shared ownership check, used by the three routes below.
async function loadOwnedTicket(req, res) {
  const { ticketId } = req.params;
  const { data: ticket, error } = await withDbTimeout(
    supportDb
      .from("support_tickets")
      .select("*")
      .eq("id", ticketId)
      .eq("bank_user_id", req.user.id)
      .maybeSingle(),
  );
  if (error) throw error;
  if (!ticket) {
    res.status(404).json({ error: "Ticket not found" });
    return null;
  }
  return ticket;
}

// GET /api/support/tickets/:ticketId/messages — combined ticket + messages,
// so the widget can poll a single endpoint to pick up new admin replies AND
// notice status changes (e.g. an admin closed the ticket).
router.get("/tickets/:ticketId/messages", readLimiter, async (req, res) => {
  try {
    const ticket = await loadOwnedTicket(req, res);
    if (!ticket) return;

    const { data: messages, error } = await withDbTimeout(
      supportDb
        .from("support_messages")
        .select("id, sender_type, sender_name, message, created_at")
        .eq("ticket_id", ticket.id)
        .order("created_at", { ascending: true }),
    );
    if (error) throw error;

    res.json({ ticket, messages: messages || [] });
  } catch (err) {
    console.error("[support] messages fetch error:", err);
    res.status(500).json({ error: "Failed to load messages" });
  }
});

// POST /api/support/tickets/:ticketId/messages — user sends a follow-up.
router.post(
  "/tickets/:ticketId/messages",
  sendMessageLimiter,
  validate(schemas.sendMessage),
  async (req, res) => {
    try {
      const ticket = await loadOwnedTicket(req, res);
      if (!ticket) return;

      if (ticket.status === "closed") {
        return res
          .status(409)
          .json({ error: "This conversation is closed. Please start a new request." });
      }

      const { data: chatMessage, error } = await withDbTimeout(
        supportDb
          .from("support_messages")
          .insert({
            ticket_id: ticket.id,
            sender_type: "user",
            sender_name: ticket.full_name,
            message: req.body.message,
          })
          .select()
          .single(),
      );
      if (error) throw error;

      await withDbTimeout(
        supportDb
          .from("support_tickets")
          .update({ updated_at: new Date().toISOString() })
          .eq("id", ticket.id),
      );

      res.json({ message: "Message sent", chatMessage });
    } catch (err) {
      console.error("[support] send message error:", err);
      res.status(500).json({ error: "Failed to send message" });
    }
  },
);

// POST /api/support/tickets/:ticketId/close — user ends their own ticket.
router.post("/tickets/:ticketId/close", readLimiter, async (req, res) => {
  try {
    const ticket = await loadOwnedTicket(req, res);
    if (!ticket) return;

    const { error } = await withDbTimeout(
      supportDb
        .from("support_tickets")
        .update({
          status: "closed",
          closed_at: new Date().toISOString(),
          closed_by: "user",
        })
        .eq("id", ticket.id),
    );
    if (error) throw error;

    res.json({ message: "Ticket closed" });
  } catch (err) {
    console.error("[support] close ticket error:", err);
    res.status(500).json({ error: "Failed to close ticket" });
  }
});

module.exports = router;