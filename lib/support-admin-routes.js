// support-admin-routes.js
//
// ADMIN-FACING support/chat endpoints. Coarse gating (authenticate +
// authorizeAdmin) happens at the mount point in index.js:
//
//   const supportAdminRoutes = require("./support-admin-routes")(requirePermission);
//   app.use("/api/sys/support", authenticate, authorizeAdmin, supportAdminRoutes);
//
// Granular enforcement is done HERE via requirePermission(), matching
// admin-permissions.js's ACTIONS_REGISTRY under "support-management" 1:1.
//
// Same isolation rule as support-routes.js: every query here goes through
// `supportDb` (the separate support Supabase project), never the bank
// `supabase` client. The only bank-side data this file ever touches is
// `req.user.first_name` / `req.user.id` of the ADMIN who is logged in
// (read from the JWT `authenticate` middleware already decoded — no extra
// bank DB query), used purely to label chat replies with a human name and
// to log who closed what. No customer banking data is read or written.

const express = require("express");

const { supportDb, withDbTimeout } = require("./support-db");
const { schemas, validate, sendMessageLimiter, readLimiter } = require("./support-security");

module.exports = function (requirePermission) {
  const router = express.Router();
  const perm = (actionId) => requirePermission(`support-management:${actionId}`);

  // ============================================================================
  // Topics — the issue buttons + canned solutions the bot shows to users
  // ============================================================================

  // GET /api/sys/support/topics — all topics, including inactive ones, for
  // the admin management screen.
  router.get("/topics", perm("manage-topics"), readLimiter, async (req, res) => {
    try {
      const { data, error } = await withDbTimeout(
        supportDb
          .from("support_topics")
          .select("*")
          .order("display_order", { ascending: true }),
      );
      if (error) throw error;
      res.json({ topics: data || [] });
    } catch (err) {
      console.error("[support-admin] topics list error:", err);
      res.status(500).json({ error: "Failed to load topics" });
    }
  });

  router.post(
    "/topics",
    perm("manage-topics"),
    validate(schemas.createTopic),
    async (req, res) => {
      try {
        const { data, error } = await withDbTimeout(
          supportDb
            .from("support_topics")
            .insert({
              title: req.body.title,
              solution: req.body.solution,
              display_order: req.body.display_order ?? 0,
              is_active: req.body.is_active ?? true,
            })
            .select()
            .single(),
        );
        if (error) throw error;
        res.json({ message: "Topic created", topic: data });
      } catch (err) {
        console.error("[support-admin] topic create error:", err);
        res.status(500).json({ error: "Failed to create topic" });
      }
    },
  );

  router.put(
    "/topics/:topicId",
    perm("manage-topics"),
    validate(schemas.updateTopic),
    async (req, res) => {
      try {
        const { data, error } = await withDbTimeout(
          supportDb
            .from("support_topics")
            .update(req.body)
            .eq("id", req.params.topicId)
            .select()
            .maybeSingle(),
        );
        if (error) throw error;
        if (!data) return res.status(404).json({ error: "Topic not found" });
        res.json({ message: "Topic updated", topic: data });
      } catch (err) {
        console.error("[support-admin] topic update error:", err);
        res.status(500).json({ error: "Failed to update topic" });
      }
    },
  );

  router.delete("/topics/:topicId", perm("manage-topics"), async (req, res) => {
    try {
      const { error } = await withDbTimeout(
        supportDb.from("support_topics").delete().eq("id", req.params.topicId),
      );
      if (error) throw error;
      res.json({ message: "Topic deleted" });
    } catch (err) {
      console.error("[support-admin] topic delete error:", err);
      res.status(500).json({ error: "Failed to delete topic" });
    }
  });

  // ============================================================================
  // Tickets
  // ============================================================================

  // GET /api/sys/support/tickets?status=open|closed — the ticket queue.
  router.get("/tickets", perm("view-ticket"), readLimiter, async (req, res) => {
    try {
      const status = ["open", "closed"].includes(req.query.status) ? req.query.status : null;

      let query = supportDb
        .from("support_tickets")
        .select("id, full_name, email, topic_title_snapshot, status, assigned_admin_name, created_at, updated_at, closed_at")
        .order("updated_at", { ascending: false })
        .limit(200);

      if (status) query = query.eq("status", status);

      const { data, error } = await withDbTimeout(query);
      if (error) throw error;
      res.json({ tickets: data || [] });
    } catch (err) {
      console.error("[support-admin] tickets list error:", err);
      res.status(500).json({ error: "Failed to load tickets" });
    }
  });

  // GET /api/sys/support/tickets/:ticketId/messages — full thread for one ticket.
  router.get(
    "/tickets/:ticketId/messages",
    perm("view-ticket"),
    readLimiter,
    async (req, res) => {
      try {
        const { data: ticket, error: ticketError } = await withDbTimeout(
          supportDb
            .from("support_tickets")
            .select("*")
            .eq("id", req.params.ticketId)
            .maybeSingle(),
        );
        if (ticketError) throw ticketError;
        if (!ticket) return res.status(404).json({ error: "Ticket not found" });

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
        console.error("[support-admin] messages fetch error:", err);
        res.status(500).json({ error: "Failed to load messages" });
      }
    },
  );

  // POST /api/sys/support/tickets/:ticketId/reply — admin sends a reply.
  // Replying to a closed ticket automatically reopens it (an admin following
  // up is a deliberate action; leaving it closed would just hide their own
  // message from the user).
  router.post(
    "/tickets/:ticketId/reply",
    perm("reply-ticket"),
    sendMessageLimiter,
    validate(schemas.adminReply),
    async (req, res) => {
      try {
        const { data: ticket, error: ticketError } = await withDbTimeout(
          supportDb
            .from("support_tickets")
            .select("id, status")
            .eq("id", req.params.ticketId)
            .maybeSingle(),
        );
        if (ticketError) throw ticketError;
        if (!ticket) return res.status(404).json({ error: "Ticket not found" });

        const adminName = req.user.first_name || "Support Agent";

        const { data: chatMessage, error } = await withDbTimeout(
          supportDb
            .from("support_messages")
            .insert({
              ticket_id: ticket.id,
              sender_type: "admin",
              sender_name: adminName,
              message: req.body.message,
            })
            .select()
            .single(),
        );
        if (error) throw error;

        await withDbTimeout(
          supportDb
            .from("support_tickets")
            .update({
              assigned_admin_name: adminName,
              status: "open",
              updated_at: new Date().toISOString(),
            })
            .eq("id", ticket.id),
        );

        res.json({ message: "Reply sent", chatMessage });
      } catch (err) {
        console.error("[support-admin] reply error:", err);
        res.status(500).json({ error: "Failed to send reply" });
      }
    },
  );

  // POST /api/sys/support/tickets/:ticketId/close
  router.post(
    "/tickets/:ticketId/close",
    perm("close-ticket"),
    readLimiter,
    async (req, res) => {
      try {
        const { data, error } = await withDbTimeout(
          supportDb
            .from("support_tickets")
            .update({
              status: "closed",
              closed_at: new Date().toISOString(),
              closed_by: "admin",
            })
            .eq("id", req.params.ticketId)
            .select()
            .maybeSingle(),
        );
        if (error) throw error;
        if (!data) return res.status(404).json({ error: "Ticket not found" });
        res.json({ message: "Ticket closed", ticket: data });
      } catch (err) {
        console.error("[support-admin] close ticket error:", err);
        res.status(500).json({ error: "Failed to close ticket" });
      }
    },
  );

  return router;
};