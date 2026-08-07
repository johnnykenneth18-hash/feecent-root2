// support-security.js
//
// All input validation, sanitization, and rate limiting for the support/
// chat system, in one place. Same approach as validation.js: Zod schemas
// server-side (client-side checks in the widget are UX only, never trust),
// plus a couple of chat-specific defenses:
//
//   - XSS: we do NOT trust that every future admin tool will render chat
//     text safely, so on write we strip anything that looks like markup
//     (tags, event-handler-style attributes) rather than just relying on
//     "always use textContent" at render time. Both layers exist —
//     defense in depth — but the frontend widgets ALSO must use
//     textContent/escapeHtml when rendering (see support-widget.js /
//     admin-support-management.js). Never re-introduce innerHTML with raw
//     message text.
//
//   - SQL injection: N/A by construction — every query in
//     support-routes.js / support-admin-routes.js goes through the
//     Supabase client's query builder (.eq(), .insert(), etc.), which
//     parameterizes values under the hood. Nowhere in this module is a
//     query ever built by concatenating a string. Keep it that way — never
//     add a raw `.rpc()`/SQL string that interpolates user input.
//
//   - Enumeration / abuse: rate limits below on ticket creation and
//     message sending, keyed by IP (+ email where relevant) so one IP
//     can't flood the queue or spam an admin's inbox.

const { z } = require("zod");
const rateLimit = require("express-rate-limit");

// ----------------------------------------------------------------------------
// Sanitization
// ----------------------------------------------------------------------------

// Strips HTML tags, `javascript:`/`data:` scheme prefixes, and control
// characters. This is intentionally aggressive — support chat is plain
// text, it never needs to carry markup, so there is no legitimate case
// where a `<`, `>` pair should survive. This runs BEFORE the message is
// stored, so even a compromised or future careless render path (some admin
// tool that does `innerHTML = message` instead of `textContent`) sees
// inert text, not a live payload.
function stripDangerousMarkup(input) {
  return String(input)
    .replace(/<[^>]*>/g, "") // strip all tags
    .replace(/javascript:/gi, "")
    .replace(/data:text\/html/gi, "")
    // strip control chars except \n and \t
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .trim();
}

// A conservative HTML-escaper, exported for any server-rendered surface
// (e.g. admin notification emails) that needs to embed a message inside
// actual HTML rather than plain text.
function escapeHtml(input) {
  return String(input)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ----------------------------------------------------------------------------
// Zod schemas
// ----------------------------------------------------------------------------

const messageText = z
  .string()
  .trim()
  .min(1, "Message cannot be empty")
  .max(4000, "Message is too long")
  .transform(stripDangerousMarkup)
  .refine((v) => v.length > 0, "Message cannot be empty");

const fullName = z
  .string()
  .trim()
  .min(1, "Name is required")
  .max(150)
  .regex(/^[a-zA-Z\s'.-]+$/, "Only letters, spaces, hyphens and apostrophes allowed")
  .transform(stripDangerousMarkup);

const email = z.string().trim().toLowerCase().email("Invalid email address").max(254);

const uuid = z.string().uuid("Invalid ID format");

const schemas = {
  createTicket: z.object({
    full_name: fullName,
    email,
    topic_id: uuid.optional().nullable(),
    initial_message: messageText,
  }),

  sendMessage: z.object({
    message: messageText,
  }),

  closeTicket: z.object({
    reason: z.string().trim().max(500).transform(stripDangerousMarkup).optional(),
  }),

  createTopic: z.object({
    title: z.string().trim().min(1).max(150).transform(stripDangerousMarkup),
    solution: z.string().trim().min(1).max(4000).transform(stripDangerousMarkup),
    display_order: z.number().int().min(0).max(10000).optional(),
    is_active: z.boolean().optional(),
  }),

  updateTopic: z.object({
    title: z.string().trim().min(1).max(150).transform(stripDangerousMarkup).optional(),
    solution: z.string().trim().min(1).max(4000).transform(stripDangerousMarkup).optional(),
    display_order: z.number().int().min(0).max(10000).optional(),
    is_active: z.boolean().optional(),
  }),

  adminReply: z.object({
    message: messageText,
  }),
};

// Generic validation middleware, same shape as validation.js's `validate()`.
function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        error: "Invalid request",
        details: result.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      });
    }
    req.body = result.data;
    next();
  };
}

// ----------------------------------------------------------------------------
// Rate limiters
// ----------------------------------------------------------------------------

// New tickets: cap per IP+email so one person/bot can't flood the admin
// queue. Escalating to a human is meant to be occasional, not spammable.
const createTicketLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many support requests. Please try again later." },
  keyGenerator: (req) => `${req.ip}:${(req.body?.email || "").toLowerCase()}`,
});

// Chat messages: generous enough for a real conversation, tight enough to
// stop a scripted flood.
const sendMessageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "You're sending messages too quickly. Please slow down." },
  keyGenerator: (req) => `${req.ip}:${req.user?.id || req.params?.ticketId || "anon"}`,
});

// Public topic list / polling reads — light touch, just anti-abuse.
const readLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please slow down." },
});

module.exports = {
  schemas,
  validate,
  stripDangerousMarkup,
  escapeHtml,
  createTicketLimiter,
  sendMessageLimiter,
  readLimiter,
};