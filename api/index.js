const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();
const router = express.Router();
const nodemailer = require("nodemailer");
const webpush = require("web-push");
const crypto = require("crypto");

// Several routes (adjust-balance, /user/transfer, ...) feed
// req.headers["idempotency-key"] straight into a UUID-typed RPC parameter
// (p_request_id). backend-config.js on the client now always sends a real
// UUID there, but this stays as a backstop against any caller — an old
// cached mobile build, a curl test, a future integration — that sends a
// non-UUID value. Without it, a bad header crashes the RPC with Postgres
// 22P02 instead of just minting a fresh server-side UUID and moving on.
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function safeRequestId(headerValue) {
  return headerValue && UUID_RE.test(headerValue)
    ? headerValue
    : crypto.randomUUID();
}

// Ledger rows include real balance movements (DEBIT/CREDIT, and the
// WALLET_DEBIT/WALLET_CREDIT variant reserve_internal_transfer_as_external
// writes) alongside pure audit/memo rows (WALLET_DEBIT_RESERVED,
// WALLET_DEBIT_RESERVE_RELEASE) whose balance_before === balance_after by
// design — they document that a reservation happened, they don't move
// money. Reconciliation code must ignore the memo rows entirely (0, not a
// debit) or every reserve-then-complete transfer gets debited twice. This
// mirrors derive_ledger_balance()'s CASE/ELSE 0 in setup.sql, extended to
// also recognize the WALLET_ prefixed variant so real credits on that path
// aren't miscounted as debits.
const LEDGER_CREDIT_TYPES = new Set(["CREDIT", "WALLET_CREDIT"]);
const LEDGER_DEBIT_TYPES = new Set(["DEBIT", "WALLET_DEBIT"]);
function ledgerEntryDelta(entry) {
  if (LEDGER_CREDIT_TYPES.has(entry.entry_type)) return entry.amount;
  if (LEDGER_DEBIT_TYPES.has(entry.entry_type)) return -entry.amount;
  return 0;
}
const axios = require("axios");

// ONLY NOW declare app
const app = express();

const rateLimit = require("express-rate-limit");
//const helmet = require('helmet');

// Store failed attempts in memory (use Redis in production)
const failedAttempts = new Map();
const suspiciousActivities = new Map();

// Enhanced rate limiting
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many requests. Please try again later." },
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.ip + (req.body.email || "");
  },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many authentication attempts. Try again later." },
  skipSuccessfulRequests: true,
});

const transferLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: "Transfer limit reached. Try again later." },
});

// Enhanced security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com",
        ],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          "https://cdnjs.cloudflare.com",
          "https://cdn.jsdelivr.net",
        ],
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com",
          "https://cdnjs.cloudflare.com",
        ],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: [
          "'self'",
          "https://bank-backend-blush.vercel.app",
          "https://*.supabase.co",
        ],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  }),
);

// Security middleware FIRST (after app is declared)
//app.use(helmet());

// Then cors
/*app.use(
  cors({
    origin: (origin, callback) => {
      const allowed = [
        "http://127.0.0.1:5501",
        "http://localhost",
        "https://localhost",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "https://zivarabank.vercel.app",
        "https://paystora.com",
        "www.paystora.com",
        "paystora.com",
        "*",
      ];
      if (
        !origin ||
        allowed.includes(origin) ||
        allowed.some((a) => origin?.startsWith(a))
      ) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    optionsSuccessStatus: 204,
  }),
);*/

app.use(
  cors({
    origin: (origin, callback) => {
      const allowed = [
        "http://127.0.0.1:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5500",
        "http://localhost:5501",
        "https://localhost:5500",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "https://bank-backend-blush.vercel.app",
        "https://zivarabank.vercel.app",
        "https://paystora.com",
        "http://paystora.com",
        "https://www.paystora.com",
        "http://www.paystora.com",
        "capacitor://localhost",
        "capacitor://localhost:8080",
        "ionic://localhost",
        "http://localhost",
        "https://localhost",
        "http://localhost:8080",
        "http://localhost:3000",
        /\.vercel\.app$/, // Allow all vercel.app subdomains
      ];

      // Allow any origin in development
      if (!origin || process.env.NODE_ENV === "development") {
        callback(null, false);
        return;
      }

      // Check against allowed origins
      const isAllowed = allowed.some((allowedOrigin) => {
        if (allowedOrigin instanceof RegExp) {
          return allowedOrigin.test(origin);
        }
        return allowedOrigin === origin;
      });

      if (isAllowed) {
        callback(null, true);
      } else {
        console.log(`CORS blocked origin: ${origin}`);
        callback(null, false); // Still allow but log - change to false in production if needed
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Accept",
      "Origin",
      "X-Device-ID",
      "X-Device-Fingerprint",
      "X-Device-Integrity",
      "X-Ops-Request",
      "x-request-id",
      "x-Request-id",
      "X-Client-Version",
      "X-client-Version",
      "x-device-id", // Add lowercase version
      "X-Device-Id", // Add alternative case
      "device-fingerprint",
      "X-Session-ID",
      "Idempotency-Key",
      "idempotency-key",
    ],
    exposedHeaders: ["Authorization"],
    optionsSuccessStatus: 204,
  }),
);

app.use(express.json());
app.use(morgan("combined"));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Hard timeout wrapper for Supabase/Postgres calls. Without this, a stalled
// query (paused project, connection issue, degraded query) hangs the whole
// request indefinitely — Express has no built-in server-side timeout, so
// the client eventually gives up on its own, but the server-side handler
// just sits there the entire time. Uses Supabase's built-in .abortSignal()
// support so the underlying HTTP request is actually cancelled on timeout,
// not just abandoned while it keeps running in the background.
// Usage: await withDbTimeout(supabase.from("users").select("id").eq(...), 8000)
function withDbTimeout(queryBuilder, ms = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  const builder =
    typeof queryBuilder.abortSignal === "function"
      ? queryBuilder.abortSignal(controller.signal)
      : queryBuilder;
  return Promise.resolve(builder).finally(() => clearTimeout(timer));
}

// Virtual account provisioning (Flutterwave) — see flutterwave-service.js
// and virtual-account-worker.js
const virtualAccountWorker = require("../lib/virtual-account-worker");

// Incoming deposit webhooks (Flutterwave) — see deposit-webhook-service.js
const depositWebhookService = require("../lib/deposit-webhook-service");

// Redis cache layer (cache-aside, fail-open) — see cache-service.js
// header for the full design rationale before wiring more routes to
// this. Currently applied to: GET /api/user/notifications.
const {
  cacheware,
  getUserCacheVersion,
  bumpUserCacheVersion,
} = require("../lib/cache-service");

// Cron sweep: retries any create_virtual_account jobs the fast path missed,
// on their exponential backoff schedule. Wire this to Vercel Cron in
// vercel.json — see the deployment notes.
app.get("/api/cron/virtual-accounts", virtualAccountWorker.cronHandler);

// Deposit webhook endpoint — intentionally NOT behind the authenticate
// middleware, Flutterwave calls this directly.

const statementService = require("../lib/statement-service");

app.post(
  "/api/webhooks/flutterwave",
  depositWebhookService.handleFlutterwaveWebhook,
);

const billsCatalogRouter = require("../lib/bills-catalog-routes");
const billsAdminRouter = require("../lib/bills-admin-routes");

const { sendToToken, sendToTokens } = require("../lib/fcm-service");

// Cron sweep: retries any deposit webhooks that failed verification or
// crediting on their first attempt.
app.get("/api/cron/deposit-webhooks", depositWebhookService.cronHandler);

app.post("/api/webhooks/monnify", monnifyWebhookHandler.handleMonnifyWebhook);

app.post("/api/webhooks/paystack",
     express.raw({ type: "application/json" }),
     (req, res) => {
       req.rawBody = req.body; // Buffer — needed for signature chec       req.body = JSON.parse(req.body.toString("utf8"));
       paystackWebhookHandler.handlePaystackWebhook(req, res);
    });

 const serviceRegistryAdminRouter = require("../lib/service-registry-admin-routes");
 app.use("/api/sys/service-registry", authenticate, authorizeAdmin, serviceRegistryAdminRouter);

   const vatAdminRouter = require("../lib/vat-admin-routes");
   app.use("/api/sys/vat-config", authenticate, authorizeAdmin, vatAdminRouter);


// Configure VAPID for web push - ADD THIS SECTION
webpush.setVapidDetails(
  process.env.VAPID_SUBJECT || "mailto:support@paystora.com",
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY,
);

const {
  authenticate,
  authorizeAdmin,
  checkAccountFrozen,
  logAdminAction,
  otpRateLimiter,
  preventConcurrentTransfer,
  releaseTransactionLock,
  startLockCleanup,
  generateSessionId, // Add this
  getDeviceInfo,
  invalidateAllUserSessions,
  checkSingleDeviceSession, // Add this
  createUserSession,
  checkSessionValidity, // Add this
  getUserActiveSessions, // Add this
  revokeSession,
  revokeCurrentSession, // Add this
} = require("../middleware/auth"); // ← relative path from api/index.js

// Start the lock cleanup
startLockCleanup();

let cleanupInterval = null;

// index.js - Add at the top with other imports
const http = require("http");
const socketIo = require("socket.io");

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.IO with CORS
const io = socketIo(server, {
  cors: {
    origin: [
      "http://127.0.0.1:5500",
      "http://127.0.0.1:5501",
      "http://localhost:5500",
      "http://localhost:5501",
      "https://bank-backend-blush.vercel.app",
      "https://zivarabank.vercel.app",
      "https://paystora.com",
      "capacitor://localhost",
      "capacitor://localhost:8080",
      "ionic://localhost",
      "http://localhost",
      "http://localhost:8080",
      "http://localhost:3000",
      /\.vercel\.app$/,
    ],
    credentials: true,
    methods: ["GET", "POST"],
  },
});

// Store connected users and their socket IDs
const connectedUsers = new Map(); // userId -> { socketId, deviceInfo }
const userUnreadCounts = new Map(); // userId -> unread count for admin

// Socket.IO authentication middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentication required"));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data: user, error } = await supabase
      .from("users")
      .select("id, role, first_name, last_name, email")
      .eq("id", decoded.userId)
      .single();

    if (error || !user) {
      return next(new Error("User not found"));
    }

    socket.user = user;
    next();
  } catch (err) {
    next(new Error("Invalid token"));
  }
});

// Socket.IO connection handler
io.on("connection", (socket) => {
  console.log(`User connected: ${socket.user.id} (${socket.user.role})`);

  // Store connected user
  connectedUsers.set(socket.user.id, {
    socketId: socket.id,
    user: socket.user,
    connectedAt: new Date(),
  });

  // Join user to their personal room
  socket.join(`user_${socket.user.id}`);

  // If admin, join admin room
  if (socket.user.role === "admin" || socket.user.role === "super_admin") {
    socket.join("admin_room");

    // Send initial unread counts to admin
    sendUnreadCountsToAdmin();

    // Send list of active conversations
    sendActiveConversationsToAdmin();
  }

  // Handle sending a message
  socket.on("send_message", async (data) => {
    try {
      const { message, toUserId } = data;

      if (!message || !message.trim()) {
        return socket.emit("error", { message: "Message cannot be empty" });
      }

      const isAdmin =
        socket.user.role === "admin" || socket.user.role === "super_admin";
      const fromUserId = socket.user.id;
      const toUser = isAdmin ? toUserId : null;

      // Insert message into database
      const { data: messageRecord, error } = await supabase
        .from("live_support_messages")
        .insert({
          user_id: isAdmin ? toUserId : fromUserId,
          admin_id: isAdmin ? fromUserId : null,
          message: message.trim(),
          is_from_admin: isAdmin,
          status: "sent",
          created_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (error) throw error;

      // Determine recipient
      const recipientId = isAdmin ? toUserId : "admin_room";

      // Emit to recipient
      if (recipientId === "admin_room") {
        // Send to all admins
        io.to("admin_room").emit("new_message", {
          message: messageRecord,
          fromUser: {
            id: fromUserId,
            name: `${socket.user.first_name || ""} ${socket.user.last_name || ""}`.trim(),
            email: socket.user.email,
            isAdmin: false,
          },
        });

        // Increment unread count for this user in admin view
        const currentCount = userUnreadCounts.get(fromUserId) || 0;
        userUnreadCounts.set(fromUserId, currentCount + 1);

        // Update unread counts for all admins
        sendUnreadCountsToAdmin();

        // Update conversation list
        sendActiveConversationsToAdmin();
      } else {
        // Send to specific user
        const recipientSocket = connectedUsers.get(recipientId);
        if (recipientSocket) {
          io.to(recipientSocket.socketId).emit("new_message", {
            message: messageRecord,
            fromUser: {
              id: fromUserId,
              name: `${socket.user.first_name || ""} ${socket.user.last_name || ""}`.trim(),
              isAdmin: isAdmin,
            },
          });
        }
      }

      // Emit back to sender for confirmation
      socket.emit("message_sent", messageRecord);
    } catch (error) {
      console.error("Send message error:", error);
      socket.emit("error", { message: "Failed to send message" });
    }
  });

  // Handle marking messages as read (when admin views a chat)
  socket.on("mark_conversation_read", async (data) => {
    const { userId } = data;

    if (socket.user.role !== "admin" && socket.user.role !== "super_admin") {
      return;
    }

    // Reset unread count for this user
    userUnreadCounts.set(userId, 0);

    // Update database - mark messages as read
    await supabase
      .from("live_support_messages")
      .update({
        status: "read",
        read_at: new Date().toISOString(),
      })
      .eq("user_id", userId)
      .eq("is_from_admin", false)
      .eq("status", "sent");

    // Send updated counts to all admins
    sendUnreadCountsToAdmin();
    sendActiveConversationsToAdmin();
  });

  // Handle typing indicator
  socket.on("typing", (data) => {
    const { toUserId, isTyping } = data;
    const isAdmin =
      socket.user.role === "admin" || socket.user.role === "super_admin";

    const recipientId = isAdmin ? toUserId : "admin_room";

    if (recipientId === "admin_room") {
      socket.to("admin_room").emit("user_typing", {
        userId: socket.user.id,
        userName:
          `${socket.user.first_name || ""} ${socket.user.last_name || ""}`.trim(),
        isTyping,
      });
    } else {
      const recipientSocket = connectedUsers.get(recipientId);
      if (recipientSocket) {
        io.to(recipientSocket.socketId).emit("user_typing", {
          userId: socket.user.id,
          isTyping,
        });
      }
    }
  });

  // Handle disconnection
  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.user.id}`);
    connectedUsers.delete(socket.user.id);

    // Update admin view
    if (socket.user.role !== "admin") {
      sendActiveConversationsToAdmin();
    }
  });
});

// Helper function to send unread counts to all admins
async function sendUnreadCountsToAdmin() {
  // Get all users who have sent messages
  const { data: allMessages } = await supabase
    .from("live_support_messages")
    .select("user_id, status")
    .eq("is_from_admin", false)
    .eq("status", "sent")
    .order("created_at", { ascending: false });

  // Calculate unread counts per user
  const unreadCounts = {};
  for (const msg of allMessages || []) {
    unreadCounts[msg.user_id] = (unreadCounts[msg.user_id] || 0) + 1;
  }

  // Update our map
  for (const [userId, count] of Object.entries(unreadCounts)) {
    userUnreadCounts.set(userId, count);
  }

  // Send to all admins
  io.to("admin_room").emit(
    "unread_counts",
    Object.fromEntries(userUnreadCounts),
  );
}

// Helper function to send active conversations to admin
async function sendActiveConversationsToAdmin() {
  // Get all users who have sent messages, with their latest message
  const { data: conversations } = await supabase
    .from("live_support_messages")
    .select(
      `
      user_id,
      users!live_support_messages_user_id_fkey (
        id,
        first_name,
        last_name,
        email
      ),
      message,
      created_at,
      is_from_admin,
      status
    `,
    )
    .order("created_at", { ascending: false });

  // Group by user and get latest message
  const userConversations = new Map();

  for (const msg of conversations || []) {
    if (!userConversations.has(msg.user_id)) {
      const unreadCount = userUnreadCounts.get(msg.user_id) || 0;
      userConversations.set(msg.user_id, {
        user_id: msg.user_id,
        user_name: msg.users
          ? `${msg.users.first_name || ""} ${msg.users.last_name || ""}`.trim()
          : "Unknown User",
        user_email: msg.users?.email || "",
        last_message: msg.message,
        last_message_time: msg.created_at,
        last_message_is_from_admin: msg.is_from_admin,
        unread_count: unreadCount,
        status: msg.status,
      });
    }
  }

  // Convert to array and sort: unread first, then by last message time
  const sortedConversations = Array.from(userConversations.values()).sort(
    (a, b) => {
      // Unread conversations first
      if (a.unread_count > 0 && b.unread_count === 0) return -1;
      if (a.unread_count === 0 && b.unread_count > 0) return 1;
      // Then by last message time (newest first)
      return new Date(b.last_message_time) - new Date(a.last_message_time);
    },
  );

  io.to("admin_room").emit("active_conversations", sortedConversations);
}

// Replace app.listen with server.listen
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Socket.IO enabled for real-time chat`);
});

// Function to send push notification to user
async function sendPushNotificationToUser(userId, title, body, data = {}) {
  try {
    // Get user's push tokens
    const { data: tokens, error } = await supabase
      .from("user_push_tokens")
      .select("push_token, platform")
      .eq("user_id", userId)
      .eq("is_active", true);

    if (error || !tokens || tokens.length === 0) {
      console.log("No push tokens found for user:", userId);
      return false;
    }

    let sent = false;
        for (const token of tokens) {
          if (token.platform === "android" || token.platform === "ios") {
            const result = await sendToToken(token.push_token, { title, body, data });
            if (result.success) sent = true;
          } else {
        // Web push
        const { webpush } = require("web-push");
        try {
          await webpush.sendNotification(
            JSON.parse(token.push_token),
            JSON.stringify({
              title,
              body,
              data,
              icon: "/icons/icon-192x192.png",
            }),
          );
          sent = true;
        } catch (err) {
          console.error("Web push error:", err);
        }
      }
    }

    return sent;
  } catch (error) {
    console.error("Send push error:", error);
    return false;
  }
}

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_PORT == 465, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Test transporter on startup (silent fail)
async function testEmailConfig() {
  try {
    await transporter.verify();
    console.log("✅ Brevo SMTP configured successfully");
  } catch (error) {
    console.error("⚠️ Brevo SMTP configuration error:", error.message);
    console.log("Email will still work - check your SMTP credentials");
  }
}
testEmailConfig();

// Send push notification to user's device when in-app notification is created
async function sendPushNotificationForInAppNotification(
  userId,
  title,
  message,
  notificationId,
  type = "info",
) {
  try {
    // Get user's push tokens
    const { data: tokens, error } = await supabase
      .from("user_push_tokens")
      .select("push_token, platform")
      .eq("user_id", userId)
      .eq("is_active", true);

    if (error || !tokens || tokens.length === 0) {
      console.log("No push tokens found for user:", userId);
      return false;
    }

    // Check if user has push notifications enabled
    const { data: settings } = await supabase
      .from("user_push_settings")
      .select(
        "notifications_enabled, transfers, savings, security, promotions, bills",
      )
      .eq("user_id", userId)
      .single();

    if (!settings || !settings.notifications_enabled) {
      console.log("Push notifications disabled for user:", userId);
      return false;
    }

    // Check if this notification type is enabled
    let typeEnabled = true;
    if (type === "transfer") typeEnabled = settings.transfers !== false;
    else if (type === "savings") typeEnabled = settings.savings !== false;
    else if (type === "security") typeEnabled = settings.security !== false;
    else if (type === "promotion") typeEnabled = settings.promotions === true;
    else if (type === "bill") typeEnabled = settings.bills !== false;

    if (!typeEnabled) {
      console.log(`Push type ${type} disabled for user:`, userId);
      return false;
    }

    // Prepare payload
    const payload = {
      title: title,
      body: message,
      data: {
        notificationId: notificationId,
        type: type,
        timestamp: new Date().toISOString(),
        url: "/dashboard.html",
      },
      icon: "/icons/icon-192x192.png",
      badge: "/icons/badge-72x72.png",
      vibrate: [200, 100, 200],
      sound: "default",
      priority: "high",
    };

    let sent = false;

    // Send to all active tokens
    /*for (const token of tokens) {
      try {
        if (token.platform === "android") {
          // For Capacitor Android, we need to send via FCM
          // The Capacitor PushNotifications plugin handles this automatically
          // We just need to store the notification
          console.log(
            "Android push token found, notification will be delivered by Capacitor",
          );
          sent = true;
        } else if (token.platform === "web") {
          // For web PWA
          try {
            const webpush = require("web-push");
            await webpush.sendNotification(
              JSON.parse(token.push_token),
              JSON.stringify(payload),
            );
            sent = true;
          } catch (err) {
            console.error("Web push error:", err);
          }
        } else {
          sent = true;
        }
      } catch (err) {
        console.error(`Push send error for token ${token.id}:`, err);
      }
    }*/

    // Send to all active tokens
    for (const token of tokens) {
      try {
        if (token.platform === "android" || token.platform === "ios") {
          const result = await sendToToken(token.push_token, {
            title: payload.title,
            body: payload.body,
            data: payload.data,
          });
          if (result.success) {
            sent = true;
          } else if (result.invalidToken) {
            // Dead token — deactivate it so future sends don't waste
            // time retrying something FCM has already told us is gone.
            await supabase
              .from("user_push_tokens")
              .update({ is_active: false })
              .eq("push_token", token.push_token);
          }
        } else if (token.platform === "web") {
          // For web PWA
          try {
            const webpush = require("web-push");
            await webpush.sendNotification(
              JSON.parse(token.push_token),
              JSON.stringify(payload),
            );
            sent = true;
          } catch (err) {
            console.error("Web push error:", err);
          }
        } else {
          sent = true;
        }
      } catch (err) {
        console.error(`Push send error for token ${token.id}:`, err);
      }
    }

    return sent;
  } catch (error) {
    console.error("Send push notification error:", error);
    return false;
  }
}

// ==================== DEVICE TRUST & TRANSFER HISTORY ====================

// Track user's trusted devices
async function updateDeviceTrust(userId, deviceFingerprint, userAgent, ip) {
  try {
    // Check if device exists
    const { data: existingDevice } = await supabase
      .from("trusted_devices")
      .select("*")
      .eq("user_id", userId)
      .eq("device_fingerprint", deviceFingerprint)
      .single();

    const now = new Date().toISOString();

    if (existingDevice) {
      // Update last used timestamp
      await supabase
        .from("trusted_devices")
        .update({
          last_used_at: now,
          usage_count: (existingDevice.usage_count || 0) + 1,
          ip_address: ip,
          user_agent: userAgent,
        })
        .eq("id", existingDevice.id);

      return {
        isNewDevice: false,
        deviceAge: Math.floor(
          (Date.now() - new Date(existingDevice.first_seen_at)) /
            (1000 * 60 * 60 * 24),
        ),
        trustLevel: existingDevice.trust_level || "standard",
      };
    } else {
      // Register new device
      await supabase.from("trusted_devices").insert({
        user_id: userId,
        device_fingerprint: deviceFingerprint,
        device_name: deviceFingerprint.substring(0, 20),
        first_seen_at: now,
        last_used_at: now,
        usage_count: 1,
        trust_level: "new",
        ip_address: ip,
        user_agent: userAgent,
      });

      return {
        isNewDevice: true,
        deviceAge: 0,
        trustLevel: "new",
      };
    }
  } catch (error) {
    console.error("Update device trust error:", error);
    return { isNewDevice: false, deviceAge: 0, trustLevel: "standard" };
  }
}

// Get user's transfer threshold based on device trust and history
async function getUserTransferThreshold(userId, deviceFingerprint) {
  try {
    // Get device info
    const { data: device } = await supabase
      .from("trusted_devices")
      .select("first_seen_at, usage_count, trust_level")
      .eq("user_id", userId)
      .eq("device_fingerprint", deviceFingerprint)
      .single();

    if (!device) {
      return { threshold: 50000, reason: "new_device", level: "new" };
    }

    const deviceAge = Math.floor(
      (Date.now() - new Date(device.first_seen_at)) / (1000 * 60 * 60 * 24),
    );

    // Calculate threshold based on device age
    // Day 0-1: ₦500,000
    // Day 2-6: ₦2,000,000
    // Day 7+: ₦10,000,000 (effectively unlimited for most users)

    if (deviceAge < 2) {
      return {
        threshold: 500000,
        reason: "new_device",
        level: "new",
        deviceAge,
      };
    } else if (deviceAge < 7) {
      return {
        threshold: 2000000,
        reason: "trusted_device",
        level: "trusted",
        deviceAge,
      };
    } else {
      return {
        threshold: 9999999999,
        reason: "fully_trusted",
        level: "full",
        deviceAge,
      };
    }
  } catch (error) {
    console.error("Get threshold error:", error);
    return { threshold: 500000, reason: "default", level: "standard" };
  }
}

// Check if user has transferred to this recipient before
async function hasTransferredToBefore(userId, recipientAccountNumber) {
  try {
    // First get recipient's user_id from account number
    const { data: recipientAccount } = await supabase
      .from("accounts")
      .select("user_id")
      .eq("account_number", recipientAccountNumber)
      .single();

    if (!recipientAccount) return false;

    // Check transaction history
    const { data: existingTransfer, error } = await supabase
      .from("transactions_new")
      .select("id, created_at, amount")
      .eq("sender_user_id", userId)
      .eq("receiver_user_id", recipientAccount.user_id)
      .eq("status", "completed")
      .limit(1);

    return existingTransfer && existingTransfer.length > 0;
  } catch (error) {
    console.error("Check transfer history error:", error);
    return false;
  }
}

// Get recent beneficiaries for a user (last 5 unique recipients)
async function getRecentBeneficiaries(userId) {
  try {
    const { data: transactions } = await supabase
      .from("transactions_new")
      .select(
        `
        receiver_user_id,
        receiver_account_id,
        amount,
        created_at,
        accounts:receiver_account_id (account_number),
        users:receiver_user_id (first_name, last_name, email)
      `,
      )
      .eq("sender_user_id", userId)
      .eq("status", "completed")
      .order("created_at", { ascending: false });

    // Get unique recipients
    const uniqueRecipients = new Map();

    for (const tx of transactions || []) {
      if (!uniqueRecipients.has(tx.receiver_user_id) && tx.users) {
        uniqueRecipients.set(tx.receiver_user_id, {
          user_id: tx.receiver_user_id,
          name: `${tx.users.first_name || ""} ${tx.users.last_name || ""}`.trim(),
          account_number: tx.accounts?.account_number || "N/A",
          last_transfer: tx.created_at,
          amount: tx.amount,
        });
      }
      if (uniqueRecipients.size >= 5) break;
    }

    return Array.from(uniqueRecipients.values());
  } catch (error) {
    console.error("Get beneficiaries error:", error);
    return [];
  }
}

// Security logging function
async function logSecurityEvent(userId, eventType, details = {}) {
  try {
    await withDbTimeout(
      supabase.from("security_logs").insert({
        user_id: userId,
        event_type: eventType,
        details: details,
        ip_address: details.ip || null,
        timestamp: new Date().toISOString(),
      }),
    );
  } catch (error) {
    console.error("Security logging error:", error);
  }
}

// Notification function - WITH PUSH NOTIFICATIONS
async function createNotification(userId, title, message, type = "info") {
  try {
    // Insert into database
    const { data: notification, error } = await supabase
      .from("notifications")
      .insert({
        user_id: userId,
        title: title,
        message: message,
        type: type,
        created_at: new Date().toISOString(),
        is_read: false,
      })
      .select()
      .single();

    if (error) {
      console.error("Notification insert error:", error);
      return null;
    }

    // SEND PUSH NOTIFICATION TO DEVICE
    await sendPushNotificationForInAppNotification(
      userId,
      title,
      message,
      notification.id,
      type,
    );

    return notification;
  } catch (error) {
    console.error("Notification error:", error);
    return null;
  }
}

// ==================== SMS CONFIGURATION (AFRICA'S TALKING) ====================
// Single initialization, guarded by env vars actually being present.
// The previous version called require("africastalking")(...) unconditionally
// on this line AND tried to call the result as a function again a few lines
// below — that second call was invoking an already-initialized client
// object, not the factory, which is exactly "africastalking is not a
// function". One factory call, one guard, one variable used everywhere.
let africasTalkingClient = null;
try {
  if (
    process.env.AFRICASTALKING_API_KEY &&
    process.env.AFRICASTALKING_USERNAME
  ) {
    africasTalkingClient = require("africastalking")({
      apiKey: process.env.AFRICASTALKING_API_KEY,
      username: process.env.AFRICASTALKING_USERNAME,
    });
    console.log("✅ Africa's Talking initialized for SMS");
  } else {
    console.log("⚠️ Africa's Talking credentials missing - SMS disabled");
  }
} catch (error) {
  console.error("❌ Africa's Talking initialization error:", error.message);
}

// Send SMS using Africa's Talking
async function sendOTPSMS(phoneNumber, otp) {
  // Skip if client not initialized
  if (!africasTalkingClient) {
    console.log(
      `⚠️ SMS not sent - Africa's Talking not configured. Would send OTP ${otp} to ${phoneNumber}`,
    );
    return false;
  }

  // Format phone number (ensure it has country code)
  let formattedNumber = phoneNumber.trim();
  if (!formattedNumber.startsWith("+")) {
    // Add Nigeria country code if not present
    if (formattedNumber.startsWith("0")) {
      formattedNumber = "+234" + formattedNumber.substring(1);
    } else if (!formattedNumber.startsWith("234")) {
      formattedNumber = "+234" + formattedNumber;
    }
  }

  console.log(
    `📱 Attempting to send SMS to ${formattedNumber} with OTP ${otp}`,
  );

  try {
    const result = await africasTalkingClient.SMS.send({
      to: formattedNumber,
      message: `Your FEECENT verification code is: ${otp}. Valid for 10 minutes. DO NOT share this code with anyone.`,
      from: process.env.AFRICASTALKING_SENDER_ID || "FEECENT",
    });

    console.log("✅ SMS sent successfully:", result);

    // Check if SMS was actually sent (Africa's Talking returns array of results)
    if (result && result.SMSMessageData && result.SMSMessageData.Recipients) {
      const recipient = result.SMSMessageData.Recipients[0];
      if (recipient.status === "Success") {
        console.log(`✅ SMS delivered to ${recipient.number}`);
        return true;
      } else {
        console.error(
          `❌ SMS failed: ${recipient.status} - ${recipient.statusCode}`,
        );
        return false;
      }
    }

    return true;
  } catch (error) {
    console.error("❌ SMS error details:", {
      message: error.message,
      code: error.code,
      response: error.response?.data || error.response,
    });
    return false;
  }
}

// Alternative: Send OTP via SMS with fallback to email
async function sendOTPWithFallback(user, otp) {
  let smsSent = false;
  let emailSent = false;

  // Try SMS first if user has phone
  if (user.phone && user.phone.trim()) {
    smsSent = await sendOTPSMS(user.phone, otp);
  }

  // Always send email as backup (or primary if SMS failed)
  emailSent = await sendOTPEmail(user.email, otp);

  return {
    sms_sent: smsSent,
    email_sent: emailSent,
    method: smsSent ? "sms" : "email",
  };
}

// ==================== TRANSFER LIMIT HELPER FUNCTIONS ====================

// Get user's tier limits
async function getUserTierLimits(userId) {
  try {
    // Get user's current tier
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("account_tier")
      .eq("id", userId)
      .single();

    if (userError) throw userError;

    const userTier = user?.account_tier || 1;

    // Get tier limits
    const { data: limits, error: limitsError } = await supabase
      .from("account_tier_limits")
      .select("*")
      .eq("tier", userTier)
      .single();

    if (limitsError || !limits) {
      // Fallback limits
      const fallbackLimits = {
        1: {
          daily_transfer_limit: 150000,
          single_transfer_limit: 150000,
          max_balance: 500000,
        },
        2: {
          daily_transfer_limit: 250000,
          single_transfer_limit: 250000,
          max_balance: 800000,
        },
        3: {
          daily_transfer_limit: 999999999,
          single_transfer_limit: 999999999,
          max_balance: 999999999,
        },
      };
      return {
        daily_limit: fallbackLimits[userTier]?.daily_transfer_limit || 150000,
        single_limit: fallbackLimits[userTier]?.single_transfer_limit || 150000,
        max_balance: fallbackLimits[userTier]?.max_balance || 500000,
        tier: userTier,
      };
    }

    return {
      daily_limit: limits.daily_transfer_limit,
      single_limit: limits.single_transfer_limit,
      max_balance: limits.max_balance,
      tier: userTier,
      tier_name: limits.tier_name,
    };
  } catch (error) {
    console.error("Get tier limits error:", error);
    // Safe defaults
    return {
      daily_limit: 150000,
      single_limit: 150000,
      max_balance: 500000,
      tier: 1,
    };
  }
}

// Check daily transfer limit
async function checkDailyTransferLimit(userId, amount, userTier = null) {
  try {
    // Get tier limits
    const limits = await getUserTierLimits(userId);

    // Get today's date (start of day)
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Get today's total transfers from this user
    const { data: todayTransfers, error: txError } = await supabase
      .from("transactions_new")
      .select("amount")
      .eq("sender_user_id", userId)
      .eq("status", "completed")
      .gte("created_at", today.toISOString());

    if (txError) {
      console.error("Daily limit check error:", txError);
      return { allowed: true }; // Allow on error
    }

    const dailyUsed =
      todayTransfers?.reduce((sum, t) => sum + t.amount, 0) || 0;
    const remainingDaily = limits.daily_limit - dailyUsed;

    if (amount > remainingDaily) {
      return {
        allowed: false,
        reason: `Daily transfer limit exceeded. You have ₦${dailyUsed.toLocaleString()} of ₦${limits.daily_limit.toLocaleString()} used today. This transfer of ₦${amount.toLocaleString()} would exceed your limit by ₦${(amount - remainingDaily).toLocaleString()}.`,
        daily_limit: limits.daily_limit,
        daily_used: dailyUsed,
        remaining: remainingDaily,
        tier: limits.tier,
      };
    }

    return {
      allowed: true,
      daily_used: dailyUsed,
      daily_limit: limits.daily_limit,
      remaining: remainingDaily,
    };
  } catch (error) {
    console.error("Daily limit check error:", error);
    return { allowed: true };
  }
}

// Check single transfer limit
async function checkSingleTransferLimit(userId, amount, userTier = null) {
  try {
    const limits = await getUserTierLimits(userId);

    if (amount > limits.single_limit) {
      return {
        allowed: false,
        reason: `Single transfer limit is ₦${limits.single_limit.toLocaleString()}. Your transfer of ₦${amount.toLocaleString()} exceeds this limit.`,
        single_limit: limits.single_limit,
        tier: limits.tier,
      };
    }

    return { allowed: true, single_limit: limits.single_limit };
  } catch (error) {
    console.error("Single limit check error:", error);
    return { allowed: true };
  }
}

// ==================== SECURITY MONITORING ENDPOINTS ====================

// Log security events
app.post("/api/security/events", authenticate, async (req, res) => {
  try {
    const { events } = req.body;

    if (!events || !Array.isArray(events)) {
      return res.status(400).json({ error: "Invalid events data" });
    }

    // Log each event to security_logs table
    for (const event of events) {
      await supabase.from("security_logs").insert({
        user_id: req.user.id,
        event_type: event.type,
        details: event.details,
        ip_address: req.ip,
        user_agent: event.userAgent || req.headers["user-agent"],
        timestamp: new Date(event.timestamp || Date.now()),
      });
    }

    res.json({ success: true, logged: events.length });
  } catch (error) {
    console.error("Security events error:", error);
    // Always return 200 to avoid client-side errors
    res.json({ success: false, error: error.message });
  }
});

// Send heartbeat (keep session alive)
app.post("/api/security/heartbeat", authenticate, async (req, res) => {
  try {
    // Update last activity timestamp in user_sessions table
    const sessionToken = req.headers.authorization?.split(" ")[1];

    if (sessionToken) {
      await supabase
        .from("user_sessions")
        .update({ last_activity: new Date().toISOString() })
        .eq("session_token", sessionToken)
        .eq("user_id", req.user.id)
        .eq("is_active", true);
    }

    res.json({ success: true, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error("Heartbeat error:", error);
    res.json({ success: false });
  }
});

// Check if session is compromised
app.get("/api/security/check-session", authenticate, async (req, res) => {
  try {
    const sessionToken = req.headers.authorization?.split(" ")[1];

    if (!sessionToken) {
      return res.json({ isCompromised: false });
    }

    // Check for multiple active sessions from different IPs/UserAgents
    const { data: sessions, error } = await supabase
      .from("user_sessions")
      .select("id, ip_address, user_agent, created_at")
      .eq("user_id", req.user.id)
      .eq("is_active", true)
      .neq("session_token", sessionToken);

    if (error) {
      console.error("Session check error:", error);
      return res.json({ isCompromised: false });
    }

    // If there are multiple active sessions from different locations within a short time
    const suspicious = sessions && sessions.length > 2;

    res.json({
      isCompromised: suspicious,
      active_sessions_count: sessions?.length || 0,
    });
  } catch (error) {
    console.error("Session check error:", error);
    res.json({ isCompromised: false });
  }
});

// Get user's security events (for their own dashboard)
app.get("/api/user/security-events", authenticate, async (req, res) => {
  try {
    const { limit = 50 } = req.query;

    const { data: events, error } = await supabase
      .from("security_logs")
      .select("*")
      .eq("user_id", req.user.id)
      .order("timestamp", { ascending: false })
      .limit(parseInt(limit));

    if (error) throw error;

    res.json({ events: events || [] });
  } catch (error) {
    console.error("Security events fetch error:", error);
    res.status(500).json({ error: "Failed to fetch security events" });
  }
});

// Revoke all other sessions
app.post(
  "/api/security/revoke-other-sessions",
  authenticate,
  async (req, res) => {
    try {
      const currentToken = req.headers.authorization?.split(" ")[1];

      // Get current session ID
      const { data: currentSession } = await supabase
        .from("user_sessions")
        .select("id")
        .eq("session_token", currentToken)
        .single();

      // Revoke all other sessions
      await supabase
        .from("user_sessions")
        .update({
          is_active: false,
          expires_at: new Date().toISOString(),
          invalidated_reason: "User revoked all other sessions",
        })
        .eq("user_id", req.user.id)
        .neq("id", currentSession?.id);

      res.json({ success: true });
    } catch (error) {
      console.error("Revoke sessions error:", error);
      res.status(500).json({ error: "Failed to revoke sessions" });
    }
  },
);

// Validate session endpoint
app.get("/api/auth/validate-session", authenticate, async (req, res) => {
  try {
    // Check if user still exists and is active
    const { data: user, error } = await supabase
      .from("users")
      .select("id, is_active, is_frozen")
      .eq("id", req.user.id)
      .single();

    if (error || !user || !user.is_active || user.is_frozen) {
      return res.status(401).json({ error: "Session invalid" });
    }

    res.json({ valid: true });
  } catch (error) {
    res.status(401).json({ error: "Session validation failed" });
  }
});

// Report device compromise (from root-detection.js)
app.post("/api/security/report-compromise", async (req, res) => {
  try {
    const { detection_results, compromise_level, device_info } = req.body;

    // Get token if available (for authenticated users)
    let userId = null;
    const authHeader = req.header("Authorization");
    if (authHeader) {
      try {
        const token = authHeader.replace("Bearer ", "");
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.userId;
      } catch (e) {}
    }

    // Log to security_compromises table
    const { error } = await supabase.from("security_compromises").insert({
      user_id: userId,
      detection_results: detection_results,
      compromise_level: compromise_level,
      device_info: device_info,
      ip_address: req.ip,
      user_agent: req.headers["user-agent"],
      created_at: new Date().toISOString(),
    });

    if (error) console.error("Compromise report error:", error);

    // Always return 200 to avoid client errors
    res.json({ success: true });
  } catch (error) {
    console.error("Report compromise error:", error);
    res.json({ success: false });
  }
});

// ==================== API CONNECTION TEST ENDPOINT ====================
// Simple test endpoint to verify API is running and properly deployed
app.get("/api/test-connection", (req, res) => {
  console.log("Test connection endpoint hit at:", new Date().toISOString());

  res.json({
    success: true,
    message: "API is connected and working properly! ✅",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    api_version: "1.0.0",
    endpoints_available: {
      auth: "/api/auth/*",
      user: "/api/user/*",
      admin: "/api/sys/*",
      savings: "/api/user/savings/*",
      test: "/api/test-connection",
    },
  });
});

// Also add a POST version for testing with body
app.post("/api/test-connection", (req, res) => {
  console.log("POST test connection hit at:", new Date().toISOString());
  console.log("Request body:", req.body);

  res.json({
    success: true,
    message: "POST test successful! ✅",
    received_data: req.body,
    timestamp: new Date().toISOString(),
  });
});

// ==================== AUTHENTICATION ROUTES ====================

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      email,
      password,
      first_name,
      last_name,
      middle_name,
      phone,
      country,
      state,
      city,
      address,
      postal_code,
      date_of_birth,
      gender,
      marital_status,
      occupation,
      referral_code,
      age,
      security_question_1,
      security_answer_1,
      security_question_2,
      security_answer_2,
      passcode,
      face_images,
      bvn,
    } = req.body;

    console.log("Registration attempt for:", email);
    console.log("Face images received:", face_images ? face_images.length : 0);

    // Validation
    if (age && (age < 18 || age > 120)) {
      return res.status(400).json({ error: "Age must be between 18 and 120" });
    }

    // Validate passcode (6 digits)
    if (passcode && !/^\d{6}$/.test(passcode)) {
      return res
        .status(400)
        .json({ error: "Passcode must be exactly 6 digits" });
    }

    // Validate BVN (required — needed to create a permanent Flutterwave
    // dedicated virtual account immediately after registration)
    if (!bvn || !/^\d{11}$/.test(bvn)) {
      return res
        .status(400)
        .json({ error: "A valid 11-digit BVN is required" });
    }

    // Check if user exists
    const { data: existingUser } = await withDbTimeout(
      supabase.from("users").select("email").eq("email", email).single(),
    );

    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Hash passcode if provided
    let hashedPasscode = null;
    if (passcode) {
      hashedPasscode = await bcrypt.hash(passcode, 10);
    }

    // Hash security answers
    const hashedAnswer1 = await bcrypt.hash(
      security_answer_1?.toLowerCase().trim() || "",
      10,
    );
    const hashedAnswer2 = await bcrypt.hash(
      security_answer_2?.toLowerCase().trim() || "",
      10,
    );

    // Calculate age from date_of_birth if not provided
    let calculatedAge = age;
    if (!calculatedAge && date_of_birth) {
      const birthDate = new Date(date_of_birth);
      const today = new Date();
      calculatedAge = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      if (
        monthDiff < 0 ||
        (monthDiff === 0 && today.getDate() < birthDate.getDate())
      ) {
        calculatedAge--;
      }
    }

    // Create user with all fields - NO ID FIELDS
    const { data: user, error } = await withDbTimeout(
      supabase
        .from("users")
        .insert({
          email,
          password_hash: hashedPassword,
          first_name,
          last_name,
          middle_name: middle_name || null,
          phone,
          country: country || null,
          state: state || null,
          city: city || null,
          address: address || null,
          postal_code: postal_code || null,
          date_of_birth: date_of_birth || null,
          gender: gender || null,
          marital_status: marital_status || null,
          occupation: occupation || null,
          referral_code: referral_code || null,
          age: calculatedAge || null,
          bvn,
          security_question_1,
          security_answer_1: hashedAnswer1,
          security_question_2,
          security_answer_2: hashedAnswer2,
          passcode_hash: hashedPasscode,
          passcode_set_at: hashedPasscode ? new Date().toISOString() : null,
          face_verified: !!face_images && face_images.length > 0,
          face_verification_date:
            face_images && face_images.length > 0
              ? new Date().toISOString()
              : null,
          role: "user",
          kyc_status: "pending",
          is_active: true,
          is_frozen: false,
          account_tier: 1, // ALL NEW USERS START AT TIER 1
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .select()
        .single(),
      12000, // account creation is heavier than a lookup - a bit more headroom
    );

    if (error) {
      console.error("Supabase insert error:", error);
      throw error;
    }

    console.log("User created with ID:", user.id);

    // ==================== PRODUCTION-GRADE FACE STORAGE ====================
    if (face_images && face_images.length > 0) {
      console.log(
        `[FACE] Processing ${face_images.length} face images for user ${user.id}`,
      );

      const faceDescriptorVectors = req.body.face_descriptors || [];
      const faceQualityScores = req.body.face_quality_scores || [];

      // ── Step 1: Collect all valid 128-D vectors ─────────────────────────────
      const validFrames = []; // { vector, quality, image, index }
      for (let i = 0; i < face_images.length; i++) {
        const vector = faceDescriptorVectors[i];
        const quality = faceQualityScores[i] || 0.8;
        if (vector && Array.isArray(vector) && vector.length === 128) {
          validFrames.push({
            vector,
            quality,
            image: face_images[i],
            index: i,
          });
        }
      }
      console.log(
        `[FACE] ${validFrames.length}/${face_images.length} frames have valid 128-D vectors`,
      );

      // ── Step 2: Compute averaged canonical embedding ─────────────────────────
      // Averaging all captures is more robust than picking one frame.
      let canonicalVector = null;
      let bestQuality = 0;
      let bestImage = null;

      if (validFrames.length > 0) {
        const avg = new Array(128).fill(0);
        for (const frame of validFrames) {
          for (let j = 0; j < 128; j++)
            avg[j] += frame.vector[j] / validFrames.length;
        }
        canonicalVector = avg;

        // Also track the single highest-quality frame for reference
        const bestFrame = validFrames.reduce((a, b) =>
          b.quality > a.quality ? b : a,
        );
        bestQuality = bestFrame.quality;
        bestImage = bestFrame.image;
      }

      // ── Step 3: Clean slate — remove old descriptors for this user ──────────
      const { error: deleteError } = await supabase
        .from("face_descriptors")
        .delete()
        .eq("user_id", user.id);
      if (deleteError)
        console.error("[FACE] Error clearing old descriptors:", deleteError);

      // ── Step 4: Insert one PRIMARY row with the clean flat canonical vector ──
      // This is what getUserFaceDescriptor() reads. Storing as a plain array
      // (not nested in an object) means all three extraction paths in that
      // function will find it reliably.
      if (canonicalVector) {
        const { error: primaryErr } = await supabase
          .from("face_descriptors")
          .insert({
            user_id: user.id,
            descriptor: canonicalVector, // flat 128-number array → JSONB
            is_primary: true,
            is_active: true,
            quality_score: bestQuality,
            version: 1,
            created_at: new Date().toISOString(),
          });

        if (primaryErr) {
          console.error(
            "[FACE] Failed to insert primary descriptor:",
            primaryErr,
          );
        } else {
          console.log(
            "[FACE] ✅ Inserted primary (averaged) descriptor into face_descriptors",
          );
        }

        // ── Step 5: Insert individual frame rows (audit / re-train use) ─────────
        // These are stored with the nested format {image, vector, angle} for
        // forensic purposes. They are NOT the ones used for verification lookup.
        let frameInsertCount = 0;
        for (const frame of validFrames) {
          const { error: frameErr } = await supabase
            .from("face_descriptors")
            .insert({
              user_id: user.id,
              descriptor: {
                vector: frame.vector, // nested — for audit only
                image: frame.image,
                angle: frame.index,
                quality: frame.quality,
                timestamp: new Date().toISOString(),
                is_valid: true,
              },
              is_primary: false,
              is_active: true,
              quality_score: frame.quality,
              version: 1,
              created_at: new Date().toISOString(),
            });
          if (!frameErr) frameInsertCount++;
          else
            console.error(
              `[FACE] Frame ${frame.index} insert error:`,
              frameErr,
            );
        }
        console.log(
          `[FACE] Inserted ${frameInsertCount}/${validFrames.length} frame rows`,
        );

        // ── Step 6: Store canonical embedding in users table ────────────────────
        // users.face_embedding is the fastest lookup path (no join needed).
        // Always store as a flat JSON array string so parsing is unambiguous.
        const { error: updateError } = await supabase
          .from("users")
          .update({
            face_embedding: JSON.stringify(canonicalVector), // flat array string
            face_verified: true,
            face_quality_score: bestQuality,
            face_image: bestImage || null,
            face_verification_date: new Date().toISOString(),
            face_embedding_version: 1,
            updated_at: new Date().toISOString(),
          })
          .eq("id", user.id);

        if (updateError) {
          console.error(
            "[FACE] Failed to update users.face_embedding:",
            updateError,
          );
        } else {
          console.log(
            "[FACE] ✅ users.face_embedding updated with canonical vector",
          );
        }
      } else {
        // Images received but no valid 128-D descriptor vectors were sent
        console.warn(
          "[FACE] No valid face vectors in payload — face_verified stays false",
        );
        await supabase
          .from("users")
          .update({ face_verified: false, face_verification_date: null })
          .eq("id", user.id);
      }
    }

    // ========== CREATE CHECKING ACCOUNT ==========
    // Create checking account for user. The DB trigger still stamps a
    // placeholder ACC number synchronously so account_number stays
    // NOT NULL/UNIQUE everywhere else in the app that reads it. The real
    // Flutterwave permanent virtual account number replaces it once the
    // background job below completes (creation_status: PENDING -> ACTIVE).
    const { data: newAccount, error: accountError } = await supabase
      .from("accounts")
      .insert({
        user_id: user.id,
        account_type: "checking",
        currency: "NGN",
        balance: 0.0,
        available_balance: 0.0,
        status: "active",
        creation_status: "PENDING",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (accountError) {
      console.error("Account creation error:", accountError);
    }

    // ========== ENQUEUE VIRTUAL ACCOUNT CREATION JOB ==========
    // Never call Flutterwave inline here — registration must succeed
    // regardless of Flutterwave's availability. A worker picks this up
    // separately (immediately via fire-and-forget below, and again on the
    // cron sweep if that attempt is lost).
    let enqueuedJobId = null;
    if (newAccount && !accountError) {
      const { data: job, error: jobError } = await supabase
        .from("background_jobs")
        .insert({
          job_type: "create_virtual_account",
          payload: {
            user_id: user.id,
            account_id: newAccount.id,
            email: user.email,
            bvn,
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
          },
          status: "pending",
          priority: 100,
        })
        .select()
        .single();

      if (jobError) {
        console.error("Failed to enqueue virtual account job:", jobError);
      } else {
        enqueuedJobId = job.id;
      }
    }

    // ========== PRODUCTION SESSION MANAGEMENT FOR REGISTRATION ==========

    // Get device info
    const deviceInfo = getDeviceInfo(req);
    const sessionVersion = Math.floor(Date.now() / 1000);
    const sessionId = generateSessionId();

    // STEP 1: Get ALL existing active sessions for this user (should be none for new user)
    const { data: existingSessions } = await withDbTimeout(
      supabase
        .from("user_sessions")
        .select("id, session_id, device_name, session_token")
        .eq("user_id", user.id)
        .eq("is_active", true),
    );

    // STEP 2: Generate token with session info (MATCHES LOGIN FORMAT)
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId: sessionId,
        sessionVersion: sessionVersion,
        issuedAt: Date.now(),
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || "7d" },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // STEP 3: Insert the new session (MATCHES LOGIN)
    const { error: sessionError } = await withDbTimeout(
      supabase.from("user_sessions").insert({
        user_id: user.id,
        session_token: token,
        session_id: sessionId,
        device_fingerprint: deviceInfo.device_name,
        device_name: deviceInfo.device_name,
        ip_address: deviceInfo.ip_address,
        user_agent: deviceInfo.user_agent,
        expires_at: expiresAt.toISOString(),
        is_active: true,
        is_current: true,
        session_version: sessionVersion,
        created_at: new Date().toISOString(),
        last_activity: new Date().toISOString(),
      }),
    );

    if (sessionError) {
      console.error("Session insert error during registration:", sessionError);
      // Don't fail registration, just log it
    }

    // STEP 4: Update user record with active session (MATCHES LOGIN)
    await withDbTimeout(
      supabase
        .from("users")
        .update({
          active_session_id: sessionId,
          last_active_device: deviceInfo.device_name,
          active_session_started_at: new Date().toISOString(),
          last_login: new Date().toISOString(),
          session_version: sessionVersion,
        })
        .eq("id", user.id),
    );

    // STEP 5: Invalidate any existing sessions (should be none, but safe)
    if (existingSessions && existingSessions.length > 0) {
      console.log(
        `Invalidating ${existingSessions.length} existing session(s) for new user ${user.id}`,
      );

      await withDbTimeout(
        supabase
          .from("user_sessions")
          .update({
            is_active: false,
            is_current: false,
            invalidated_reason: `New registration from ${deviceInfo.device_name}`,
            expires_at: new Date().toISOString(),
          })
          .in(
            "id",
            existingSessions.map((s) => s.id),
          ),
      );
    }

    // STEP 6: Log successful registration
    await logSecurityEvent(user.id, "user_registered", {
      ip: req.ip,
      device: deviceInfo.device_name,
      session_id: sessionId,
    });

    // Kick off virtual account creation immediately, without making the
    // user wait for Flutterwave. On Vercel's Node.js runtime, a plain
    // fire-and-forget async call can be killed the instant the response
    // is sent, so this uses waitUntil() to keep the function alive until
    // the job attempt finishes (requires `npm install @vercel/functions`).
    // If this attempt fails for any reason, the cron sweep in
    // virtual-account-worker.js retries it on the normal backoff schedule
    // — registration success never depends on this succeeding.
    if (enqueuedJobId) {
      try {
        const { waitUntil } = require("@vercel/functions");
        waitUntil(virtualAccountWorker.processOne(enqueuedJobId));
      } catch (waitUntilErr) {
        // @vercel/functions not installed / not running on Vercel — fall
        // back to plain fire-and-forget; the cron sweep still covers it.
        virtualAccountWorker
          .processOne(enqueuedJobId)
          .catch((e) => console.error("processOne fallback failed:", e));
      }
    }

    // Return response with token and session info
    res.status(201).json({
      message: "User created successfully",
      token: token,
      session: {
        id: sessionId,
        device: deviceInfo.device_name,
        logged_in_at: new Date().toISOString(),
      },
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        middle_name: user.middle_name,
        role: user.role,
        phone: user.phone,
        country: user.country,
        state: user.state,
        city: user.city,
        age: user.age,
        gender: user.gender,
        marital_status: user.marital_status,
        occupation: user.occupation,
        has_passcode: !!user.passcode_hash,
        face_verified: user.face_verified,
        face_images_count: face_images ? face_images.length : 0,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed: " + error.message });
  }
});

// In index.js - REPLACE the login endpoint with this stricter version

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password, fingerprint } = req.body;
    const ip = req.ip;

    // Failed attempts check (keep your existing code)
    const attemptsKey = `${ip}:${email}`;
    const attempts = failedAttempts.get(attemptsKey) || {
      count: 0,
      firstAttempt: Date.now(),
    };

    if (Date.now() - attempts.firstAttempt > 15 * 60 * 1000) {
      attempts.count = 0;
      attempts.firstAttempt = Date.now();
    }

    if (attempts.count >= 5) {
      return res.status(429).json({
        error: "Too many failed attempts. Account temporarily locked.",
      });
    }

    // Fetch user
    const { data: user, error } = await withDbTimeout(
      supabase.from("users").select("*").eq("email", email).single(),
    );

    if (error || !user) {
      attempts.count++;
      failedAttempts.set(attemptsKey, attempts);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Password check
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      attempts.count++;
      failedAttempts.set(attemptsKey, attempts);
      await logSecurityEvent(user.id, "failed_login", { ip, fingerprint });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Account status checks
    if (!user.is_active) {
      return res.status(403).json({ error: "Account is deactivated" });
    }

    if (user.is_frozen) {
      return res.status(403).json({
        error: "Account frozen",
        freeze_reason: user.freeze_reason,
        unfreeze_method: user.unfreeze_method,
      });
    }

    // Clear failed attempts
    failedAttempts.delete(attemptsKey);

    // ========== CHECK IF 2FA IS ENABLED ==========
    if (user.two_factor_enabled) {
      // Generate OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

      // Store OTP with user_id
      await withDbTimeout(
        supabase.from("otps").insert({
          user_id: user.id,
          otp_code: otpCode,
          otp_type: "login_2fa",
          expires_at: expiresAt,
          is_used: false,
        }),
      );

      // Send email
      await sendOTPEmail(user.email, otpCode, "2fa");

      // Generate TEMPORARY token (short-lived, only for 2FA verification)
      const tempToken = jwt.sign(
        {
          userId: user.id,
          email: user.email,
          role: user.role,
          tempAuth: true, // Flag to indicate this is a temporary token
          purpose: "2fa_verification",
          issuedAt: Date.now(),
        },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }, // Short expiry for 2FA step
      );

      return res.json({
        requiresTwoFactor: true,
        tempToken: tempToken,
        userId: user.id,
        message: "Verification code sent to your email",
      });
    }

    // ========== STRICT SESSION MANAGEMENT ==========
    const deviceInfo = getDeviceInfo(req);
    const sessionVersion = Math.floor(Date.now() / 1000);
    const sessionId = generateSessionId();

    // STEP 1: Get ALL existing active sessions for this user
    const { data: existingSessions } = await withDbTimeout(
      supabase
        .from("user_sessions")
        .select("id, session_id, device_name, session_token")
        .eq("user_id", user.id)
        .eq("is_active", true),
    );

    // STEP 2: Generate new token with session info
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId: sessionId,
        sessionVersion: sessionVersion,
        issuedAt: Date.now(),
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || "7d" },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // STEP 3: Insert the new session
    const { error: sessionError } = await withDbTimeout(
      supabase.from("user_sessions").insert({
        user_id: user.id,
        session_token: token,
        session_id: sessionId,
        device_fingerprint: deviceInfo.device_name,
        device_name: deviceInfo.device_name,
        ip_address: deviceInfo.ip_address,
        user_agent: deviceInfo.user_agent,
        expires_at: expiresAt.toISOString(),
        is_active: true,
        is_current: true,
        session_version: sessionVersion,
        created_at: new Date().toISOString(),
        last_activity: new Date().toISOString(),
      }),
    );

    if (sessionError) {
      console.error("Session insert error:", sessionError);
    }

    // STEP 4: Update user record with new active session
    await withDbTimeout(
      supabase
        .from("users")
        .update({
          active_session_id: sessionId,
          last_active_device: deviceInfo.device_name,
          active_session_started_at: new Date().toISOString(),
          last_login: new Date().toISOString(),
          session_version: sessionVersion,
        })
        .eq("id", user.id),
    );

    // STEP 5: Invalidate ALL existing sessions (excluding the new one)
    if (existingSessions && existingSessions.length > 0) {
      console.log(
        `Invalidating ${existingSessions.length} old session(s) for user ${user.id}`,
      );

      // Get the IDs of sessions to invalidate
      const oldSessionIds = existingSessions.map((s) => s.id);

      await withDbTimeout(
        supabase
          .from("user_sessions")
          .update({
            is_active: false,
            is_current: false,
            invalidated_reason: `New login from ${deviceInfo.device_name}`,
            expires_at: new Date().toISOString(),
          })
          .in("id", oldSessionIds),
      );

      // Send notifications for each old session
      for (const oldSession of existingSessions) {
        try {
          await withDbTimeout(
            supabase.from("notifications").insert({
              user_id: user.id,
              title: "New Device Login",
              message: `Your account was accessed from: ${deviceInfo.device_name}. Your session on ${oldSession.device_name || "another device"} was terminated. If this wasn't you, log in and change your password immediately.`,
              type: "security",
              created_at: new Date().toISOString(),
            }),
          );
        } catch (err) {
          console.error("Notification error:", err);
          // Don't throw - notification failure shouldn't break login
        }
      }
    }

    // Log successful login
    await logSecurityEvent(user.id, "successful_login", {
      ip,
      fingerprint,
      device: deviceInfo.device_name,
      session_id: sessionId,
    });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
        admin_role: user.admin_role,
        admin_permissions: user.admin_permissions,
        is_frozen: user.is_frozen,
        kyc_status: user.kyc_status,
      },
      session: {
        id: sessionId,
        device: deviceInfo.device_name,
        logged_in_at: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed: " + error.message });
  }
});

// ==================== THEME PREFERENCE ROUTES ====================

// Get user's theme preference
app.get("/api/user/theme", authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("theme_preference")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    res.json({ theme_preference: user?.theme_preference || "system" });
  } catch (error) {
    console.error("Get theme error:", error);
    res.json({ theme_preference: "system" });
  }
});

// Update user's theme preference
app.put("/api/user/theme", authenticate, async (req, res) => {
  try {
    const { theme_preference } = req.body;

    if (!["light", "dark", "system"].includes(theme_preference)) {
      return res.status(400).json({ error: "Invalid theme preference" });
    }

    const { error } = await supabase
      .from("users")
      .update({
        theme_preference: theme_preference,
        updated_at: new Date().toISOString(),
      })
      .eq("id", req.user.id);

    if (error) throw error;

    res.json({ success: true, theme_preference });
  } catch (error) {
    console.error("Update theme error:", error);
    res.status(500).json({ error: "Failed to update theme preference" });
  }
});

// ==================== TWO-FACTOR AUTHENTICATION ROUTES ====================

// Get 2FA status
app.get("/api/user/2fa/status", authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("two_factor_enabled")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    res.json({ enabled: user?.two_factor_enabled || false });
  } catch (error) {
    console.error("2FA status error:", error);
    res.status(500).json({ error: "Failed to get 2FA status" });
  }
});

// Send setup OTP
app.post("/api/user/2fa/send-setup-otp", authenticate, async (req, res) => {
  try {
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const requestId = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await supabase.from("otps").insert({
      id: requestId,
      user_id: req.user.id,
      otp_code: otpCode,
      otp_type: "2fa_setup",
      expires_at: expiresAt,
      is_used: false,
    });

    await sendOTPEmail(req.user.email, otpCode, "2fa");

    res.json({ success: true, request_id: requestId });
  } catch (error) {
    console.error("Send setup OTP error:", error);
    res.status(500).json({ error: "Failed to send verification code" });
  }
});

// Resend setup OTP
app.post("/api/user/2fa/resend-setup-otp", authenticate, async (req, res) => {
  try {
    const { request_id } = req.body;

    // Mark old OTP as used
    await supabase.from("otps").update({ is_used: true }).eq("id", request_id);

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const newRequestId = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await supabase.from("otps").insert({
      id: newRequestId,
      user_id: req.user.id,
      otp_code: otpCode,
      otp_type: "2fa_setup",
      expires_at: expiresAt,
      is_used: false,
    });

    await sendOTPEmail(req.user.email, otpCode, "2fa");

    res.json({ success: true, request_id: newRequestId });
  } catch (error) {
    console.error("Resend setup OTP error:", error);
    res.status(500).json({ error: "Failed to resend code" });
  }
});

// Enable 2FA
app.post("/api/user/2fa/enable", authenticate, async (req, res) => {
  try {
    const { otp_code, request_id } = req.body;

    // Verify OTP
    const { data: otpRecord, error: otpError } = await supabase
      .from("otps")
      .select("*")
      .eq("id", request_id)
      .eq("user_id", req.user.id)
      .eq("otp_code", otp_code)
      .eq("otp_type", "2fa_setup")
      .eq("is_used", false)
      .single();

    if (otpError || !otpRecord) {
      return res.status(401).json({ error: "Invalid verification code" });
    }

    if (new Date(otpRecord.expires_at) < new Date()) {
      return res.status(401).json({ error: "Code has expired" });
    }

    // Mark OTP as used
    await supabase.from("otps").update({ is_used: true }).eq("id", request_id);

    // Enable 2FA
    await supabase
      .from("users")
      .update({ two_factor_enabled: true })
      .eq("id", req.user.id);

    res.json({ success: true, message: "2FA enabled successfully" });
  } catch (error) {
    console.error("Enable 2FA error:", error);
    res.status(500).json({ error: "Failed to enable 2FA" });
  }
});

// Disable 2FA
app.post("/api/user/2fa/disable", authenticate, async (req, res) => {
  try {
    await supabase
      .from("users")
      .update({ two_factor_enabled: false })
      .eq("id", req.user.id);

    res.json({ success: true, message: "2FA disabled" });
  } catch (error) {
    console.error("Disable 2FA error:", error);
    res.status(500).json({ error: "Failed to disable 2FA" });
  }
});

// ==================== 2FA VERIFICATION ENDPOINT (GATE ONLY) ====================

let twoFactorAttempts = new Map(); // Track OTP attempts per user

app.post("/api/auth/verify-2fa", async (req, res) => {
  try {
    const { tempToken, otp_code } = req.body;
    const ip = req.ip;

    // Step 1: Verify the temporary token
    let decoded;
    try {
      decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({
        error: "Invalid or expired session. Please login again.",
        code: "SESSION_EXPIRED",
      });
    }

    // Verify this is a temporary 2FA token
    if (!decoded.tempAuth || decoded.purpose !== "2fa_verification") {
      return res.status(401).json({
        error: "Invalid verification session",
        code: "INVALID_SESSION",
      });
    }

    const userId = decoded.userId;

    // Step 2: Check OTP attempts limit
    const attemptsKey = `${ip}:${userId}`;
    const attempts = twoFactorAttempts.get(attemptsKey) || {
      count: 0,
      firstAttempt: Date.now(),
    };

    // Reset attempts after 15 minutes
    if (Date.now() - attempts.firstAttempt > 15 * 60 * 1000) {
      attempts.count = 0;
      attempts.firstAttempt = Date.now();
    }

    if (attempts.count >= 5) {
      return res.status(429).json({
        error: "Too many incorrect OTP attempts. Please login again.",
        code: "TOO_MANY_ATTEMPTS",
      });
    }

    // Step 3: Verify OTP
    const { data: otpRecord, error: otpError } = await supabase
      .from("otps")
      .select("*")
      .eq("user_id", userId)
      .eq("otp_code", otp_code)
      .eq("otp_type", "login_2fa")
      .eq("is_used", false)
      .single();

    if (otpError || !otpRecord) {
      // Increment failed attempts
      attempts.count++;
      twoFactorAttempts.set(attemptsKey, attempts);

      const remaining = 5 - attempts.count;
      return res.status(401).json({
        error: "Invalid verification code",
        attempts_remaining: remaining,
        code: "INVALID_OTP",
      });
    }

    // Check expiry
    if (new Date(otpRecord.expires_at) < new Date()) {
      return res.status(401).json({
        error: "Verification code has expired. Please login again.",
        code: "OTP_EXPIRED",
      });
    }

    // Step 4: Mark OTP as used
    await supabase
      .from("otps")
      .update({ is_used: true })
      .eq("id", otpRecord.id);

    // Step 5: Clear failed attempts on success
    twoFactorAttempts.delete(attemptsKey);

    // Step 6: Get fresh user data
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("*")
      .eq("id", userId)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Step 7: CREATE FULL SESSION (same as successful login)
    const deviceInfo = getDeviceInfo(req);
    const sessionVersion = Math.floor(Date.now() / 1000);
    const sessionId = generateSessionId();

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId: sessionId,
        sessionVersion: sessionVersion,
        issuedAt: Date.now(),
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || "7d" },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Get existing sessions to invalidate
    const { data: existingSessions } = await supabase
      .from("user_sessions")
      .select("id, session_id, device_name")
      .eq("user_id", user.id)
      .eq("is_active", true);

    // Insert new session
    await supabase.from("user_sessions").insert({
      user_id: user.id,
      session_token: token,
      session_id: sessionId,
      device_fingerprint: deviceInfo.device_name,
      device_name: deviceInfo.device_name,
      ip_address: deviceInfo.ip_address,
      user_agent: deviceInfo.user_agent,
      expires_at: expiresAt.toISOString(),
      is_active: true,
      is_current: true,
      session_version: sessionVersion,
      created_at: new Date().toISOString(),
      last_activity: new Date().toISOString(),
    });

    // Update user record
    await supabase
      .from("users")
      .update({
        active_session_id: sessionId,
        last_active_device: deviceInfo.device_name,
        active_session_started_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
        session_version: sessionVersion,
      })
      .eq("id", user.id);

    // Invalidate old sessions
    if (existingSessions && existingSessions.length > 0) {
      await supabase
        .from("user_sessions")
        .update({
          is_active: false,
          is_current: false,
          invalidated_reason: `New 2FA login from ${deviceInfo.device_name}`,
          expires_at: new Date().toISOString(),
        })
        .in(
          "id",
          existingSessions.map((s) => s.id),
        );

      // Send notifications
      for (const oldSession of existingSessions) {
        try {
          await supabase.from("notifications").insert({
            user_id: user.id,
            title: "New Device Login",
            message: `Your account was accessed from: ${deviceInfo.device_name}. Your session on ${oldSession.device_name || "another device"} was terminated.`,
            type: "security",
            created_at: new Date().toISOString(),
          });
        } catch (err) {
          console.error("Notification error:", err);
          // Don't throw - notification failure shouldn't break login
        }
      }
    }

    // Log successful 2FA verification
    await logSecurityEvent(user.id, "successful_2fa_verification", {
      ip,
      device: deviceInfo.device_name,
      session_id: sessionId,
    });

    // Return full login response
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
        admin_role: user.admin_role,
        admin_permissions: user.admin_permissions,
        is_frozen: user.is_frozen,
        kyc_status: user.kyc_status,
      },
      session: {
        id: sessionId,
        device: deviceInfo.device_name,
        logged_in_at: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("2FA verification error:", error);
    res.status(500).json({ error: "Verification failed: " + error.message });
  }
});

// Resend 2FA OTP endpoint
app.post("/api/auth/resend-2fa-otp", async (req, res) => {
  try {
    const { tempToken } = req.body;

    // Verify temporary token
    let decoded;
    try {
      decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({
        error: "Invalid session. Please login again.",
        code: "SESSION_EXPIRED",
      });
    }

    if (!decoded.tempAuth || decoded.purpose !== "2fa_verification") {
      return res.status(401).json({ error: "Invalid verification session" });
    }

    const userId = decoded.userId;

    // Get user email
    const { data: user } = await supabase
      .from("users")
      .select("email")
      .eq("id", userId)
      .single();

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Invalidate old OTPs
    await supabase
      .from("otps")
      .update({ is_used: true })
      .eq("user_id", userId)
      .eq("otp_type", "login_2fa")
      .eq("is_used", false);

    // Generate new OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await supabase.from("otps").insert({
      user_id: userId,
      otp_code: otpCode,
      otp_type: "login_2fa",
      expires_at: expiresAt,
      is_used: false,
    });

    await sendOTPEmail(user.email, otpCode, "2fa");

    res.json({ success: true, message: "New code sent to your email" });
  } catch (error) {
    console.error("Resend 2FA OTP error:", error);
    res.status(500).json({ error: "Failed to resend code" });
  }
});

// Add to index.js - Logout endpoint
app.post("/api/user/logout", authenticate, async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    // Invalidate the session
    await supabase
      .from("user_sessions")
      .update({
        is_active: false,
        is_current: false,
        invalidated_reason: "User logged out",
        expires_at: new Date().toISOString(),
      })
      .eq("session_token", token)
      .eq("user_id", req.user.id);

    // Clear user's active session if it matches
    await supabase
      .from("users")
      .update({ active_session_id: null })
      .eq("id", req.user.id)
      .eq("active_session_id", req.sessionId);

    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Failed to logout" });
  }
});

// ==================== SESSION MANAGEMENT ENDPOINTS ====================

// In index.js - Update the check-session endpoint

app.get("/api/auth/check-session", authenticate, async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // If token has no sessionId, it's invalid - force logout
    if (!decoded.sessionId) {
      return res.json({
        valid: false,
        reason: "Invalid session format",
        code: "SESSION_EXPIRED",
      });
    }

    // Check session validity in database
    const { data: dbSession, error: sessionError } = await supabase
      .from("user_sessions")
      .select("session_id, is_active, invalidated_reason")
      .eq("session_token", token)
      .single();

    if (sessionError || !dbSession || !dbSession.is_active) {
      return res.json({
        valid: false,
        reason: dbSession?.invalidated_reason || "Session not found",
        code: "SESSION_EXPIRED",
      });
    }

    // Compare session IDs
    if (dbSession.session_id !== decoded.sessionId) {
      return res.json({
        valid: false,
        reason: "Session ID mismatch - another device logged in",
        code: "SESSION_REPLACED",
        device_name: "another device",
      });
    }

    // Check user's active_session_id
    const { data: user } = await supabase
      .from("users")
      .select("active_session_id, last_active_device")
      .eq("id", req.user.id)
      .single();

    if (
      user &&
      user.active_session_id &&
      user.active_session_id !== decoded.sessionId
    ) {
      return res.json({
        valid: false,
        reason: "Another device has taken over this session",
        code: "SESSION_REPLACED",
        device_name: user.last_active_device || "another device",
      });
    }

    res.json({ valid: true });
  } catch (error) {
    console.error("Session check error:", error);
    res.json({ valid: false, code: "SESSION_EXPIRED", reason: error.message });
  }
});

// Get current user's active sessions
app.get("/api/user/sessions", authenticate, async (req, res) => {
  try {
    const sessions = await getUserActiveSessions(req.user.id);

    // Get current session token
    const currentToken = req.headers.authorization?.split(" ")[1];

    // Find which session is current
    const { data: currentSession } = await supabase
      .from("user_sessions")
      .select("id")
      .eq("session_token", currentToken)
      .eq("user_id", req.user.id)
      .single();

    const formattedSessions = sessions.map((session) => ({
      id: session.id,
      device_name: session.device_fingerprint,
      ip_address: session.ip_address,
      last_active: session.last_activity,
      created_at: session.created_at,
      is_current: currentSession?.id === session.id,
    }));

    res.json({ sessions: formattedSessions });
  } catch (error) {
    console.error("Get sessions error:", error);
    res.status(500).json({ error: "Failed to fetch sessions" });
  }
});

// Revoke all other sessions (keep current only)
app.post("/api/user/sessions/revoke-others", authenticate, async (req, res) => {
  try {
    const currentToken = req.headers.authorization?.split(" ")[1];

    if (!currentToken) {
      return res.status(400).json({ error: "Invalid session" });
    }

    // Get current session ID
    const { data: currentSession } = await supabase
      .from("user_sessions")
      .select("id")
      .eq("session_token", currentToken)
      .eq("user_id", req.user.id)
      .single();

    if (!currentSession) {
      return res.status(404).json({ error: "Current session not found" });
    }

    // Revoke all other sessions
    const { error } = await supabase
      .from("user_sessions")
      .update({
        is_active: false,
        invalidated_reason: "User revoked all other sessions",
        expires_at: new Date(),
      })
      .eq("user_id", req.user.id)
      .neq("id", currentSession.id)
      .eq("is_active", true);

    if (error) throw error;

    // Create security notification
    await supabase.from("notifications").insert({
      user_id: req.user.id,
      title: "Security: Other Sessions Revoked",
      message:
        "You have successfully revoked all other active sessions. Only your current device remains logged in.",
      type: "security",
      created_at: new Date(),
    });

    res.json({
      success: true,
      message: "All other sessions have been revoked",
    });
  } catch (error) {
    console.error("Revoke sessions error:", error);
    res.status(500).json({ error: "Failed to revoke sessions" });
  }
});

// Revoke specific session
app.post(
  "/api/user/sessions/:sessionId/revoke",
  authenticate,
  async (req, res) => {
    try {
      const { sessionId } = req.params;

      // Cannot revoke current session
      const currentToken = req.headers.authorization?.split(" ")[1];
      const { data: currentSession } = await supabase
        .from("user_sessions")
        .select("id")
        .eq("session_token", currentToken)
        .eq("user_id", req.user.id)
        .single();

      if (currentSession?.id === sessionId) {
        return res
          .status(400)
          .json({ error: "Cannot revoke your current session" });
      }

      await revokeSession(
        sessionId,
        req.user.id,
        "User revoked specific session",
      );

      res.json({ success: true, message: "Session revoked successfully" });
    } catch (error) {
      console.error("Revoke session error:", error);
      res.status(500).json({ error: "Failed to revoke session" });
    }
  },
);

// ==================== PASSCODE AUTHENTICATION ROUTES ====================

// Check if user has passcode set - IMPROVED phone number matching
app.post("/api/auth/check-passcode", async (req, res) => {
  try {
    const { identifier } = req.body;

    if (!identifier || typeof identifier !== "string") {
      return res.status(400).json({ error: "Identifier is required" });
    }

    console.log(`Check passcode for identifier: ${identifier}`);

    let query = supabase
      .from("users")
      .select("id, email, first_name, last_name, passcode_hash, phone");

    if (identifier.includes("@")) {
      // Email login
      query = query.eq("email", identifier.toLowerCase());
    } else {
      // Phone number login - try multiple formats
      const cleanPhone = identifier.trim().replace(/\s/g, "");

      // Try exact match first
      let { data: user, error } = await withDbTimeout(
        query.eq("phone", cleanPhone).single(),
      );

      if (!user) {
        // Try with +234 prefix (Nigeria)
        let withPrefix = cleanPhone;
        if (!cleanPhone.startsWith("+")) {
          if (cleanPhone.startsWith("0")) {
            withPrefix = "+234" + cleanPhone.substring(1);
          } else if (!cleanPhone.startsWith("234")) {
            withPrefix = "+234" + cleanPhone;
          } else {
            withPrefix = "+" + cleanPhone;
          }
        }

        const { data: userWithPrefix } = await withDbTimeout(
          supabase
            .from("users")
            .select("id, email, first_name, last_name, passcode_hash, phone")
            .eq("phone", withPrefix)
            .single(),
        );

        if (userWithPrefix) {
          user = userWithPrefix;
        } else {
          // Try without country code
          let withoutPrefix = cleanPhone;
          if (cleanPhone.startsWith("+234")) {
            withoutPrefix = "0" + cleanPhone.substring(4);
          } else if (cleanPhone.startsWith("234")) {
            withoutPrefix = "0" + cleanPhone.substring(3);
          }

          const { data: userWithoutPrefix } = await withDbTimeout(
            supabase
              .from("users")
              .select("id, email, first_name, last_name, passcode_hash, phone")
              .eq("phone", withoutPrefix)
              .single(),
          );

          if (userWithoutPrefix) {
            user = userWithoutPrefix;
          }
        }
      }

      if (!user) {
        console.log(`No user found for phone: ${cleanPhone}`);
        return res.status(404).json({ error: "Account not found" });
      }

      const hasPasscode = !!(user.passcode_hash && user.passcode_hash !== null);

      return res.json({
        has_passcode: hasPasscode,
        user: {
          id: user.id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
        },
      });
    }

    const { data: user, error } = await withDbTimeout(query.single());

    if (error || !user) {
      console.log(`No user found for identifier: ${identifier}`);
      return res.status(404).json({ error: "Account not found" });
    }

    const hasPasscode = !!(user.passcode_hash && user.passcode_hash !== null);

    res.json({
      has_passcode: hasPasscode,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
      },
    });
  } catch (error) {
    console.error("Check passcode error:", error);
    if (error.message && error.message.includes("aborted")) {
      return res
        .status(504)
        .json({ error: "Database is not responding, please try again" });
    }
    res.status(500).json({ error: "Failed to check passcode" });
  }
});

// index.js - REPLACE the entire /api/auth/verify-passcode endpoint

app.post("/api/auth/verify-passcode", async (req, res) => {
  try {
    const { user_id, passcode } = req.body;

    // Get IP address properly
    const ip =
      req.ip ||
      req.connection?.remoteAddress ||
      req.headers["x-forwarded-for"] ||
      "unknown";
    const userAgent = req.headers["user-agent"] || "unknown";

    if (!passcode || passcode.length !== 6 || !/^\d{6}$/.test(passcode)) {
      return res.status(400).json({ error: "Invalid passcode format" });
    }

    const { data: user, error } = await withDbTimeout(
      supabase.from("users").select("*").eq("id", user_id).single(),
    );

    if (error || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (!user.is_active) {
      return res.status(403).json({ error: "Account is deactivated" });
    }

    if (user.is_frozen) {
      return res.status(403).json({ error: "Account is frozen" });
    }

    const maxAttempts = 5;
    const attemptWindow = 15 * 60 * 1000;

    if (user.passcode_attempts >= maxAttempts) {
      const lastAttempt = new Date(user.last_passcode_attempt);
      if (Date.now() - lastAttempt < attemptWindow) {
        return res
          .status(429)
          .json({ error: "Too many incorrect attempts. Try again later." });
      } else {
        await withDbTimeout(
          supabase
            .from("users")
            .update({ passcode_attempts: 0 })
            .eq("id", user_id),
        );
      }
    }

    const isValid = await bcrypt.compare(passcode, user.passcode_hash);

    if (!isValid) {
      const newAttempts = (user.passcode_attempts || 0) + 1;
      await withDbTimeout(
        supabase
          .from("users")
          .update({
            passcode_attempts: newAttempts,
            last_passcode_attempt: new Date(),
          })
          .eq("id", user_id),
      );
      return res.status(401).json({
        error: "Invalid passcode",
        attempts_remaining: maxAttempts - newAttempts,
      });
    }

    // Reset attempts on success
    await withDbTimeout(
      supabase
        .from("users")
        .update({
          passcode_attempts: 0,
          last_passcode_attempt: null,
          last_login: new Date(),
        })
        .eq("id", user_id),
    );

    // ========== STRICT SESSION MANAGEMENT (SAME AS EMAIL LOGIN) ==========
    const deviceInfo = getDeviceInfo(req);
    const sessionVersion = Math.floor(Date.now() / 1000);
    const sessionId = generateSessionId();

    // STEP 1: Get ALL existing active sessions for this user
    const { data: existingSessions } = await withDbTimeout(
      supabase
        .from("user_sessions")
        .select("id, session_id, device_name, session_token")
        .eq("user_id", user.id)
        .eq("is_active", true),
    );

    // STEP 2: Generate new token with session info
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId: sessionId,
        sessionVersion: sessionVersion,
        issuedAt: Date.now(),
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || "7d" },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // STEP 3: Insert the new session
    const { error: sessionError } = await withDbTimeout(
      supabase.from("user_sessions").insert({
        user_id: user.id,
        session_token: token,
        session_id: sessionId,
        device_fingerprint: deviceInfo.device_name,
        device_name: deviceInfo.device_name,
        ip_address: deviceInfo.ip_address,
        user_agent: deviceInfo.user_agent,
        expires_at: expiresAt.toISOString(),
        is_active: true,
        is_current: true,
        session_version: sessionVersion,
        created_at: new Date().toISOString(),
        last_activity: new Date().toISOString(),
      }),
    );

    if (sessionError) {
      console.error("Session insert error:", sessionError);
    }

    // STEP 4: Update user record with new active session
    await withDbTimeout(
      supabase
        .from("users")
        .update({
          active_session_id: sessionId,
          last_active_device: deviceInfo.device_name,
          active_session_started_at: new Date().toISOString(),
          last_login: new Date().toISOString(),
          session_version: sessionVersion,
        })
        .eq("id", user.id),
    );

    // STEP 5: Invalidate ALL existing sessions (excluding the new one)
    if (existingSessions && existingSessions.length > 0) {
      console.log(
        `[Passcode Login] Invalidating ${existingSessions.length} old session(s) for user ${user.id}`,
      );

      // Get the IDs of sessions to invalidate
      const oldSessionIds = existingSessions.map((s) => s.id);

      await withDbTimeout(
        supabase
          .from("user_sessions")
          .update({
            is_active: false,
            is_current: false,
            invalidated_reason: `New passcode login from ${deviceInfo.device_name}`,
            expires_at: new Date().toISOString(),
          })
          .in("id", oldSessionIds),
      );

      // Send notifications for each old session
      for (const oldSession of existingSessions) {
        try {
          await withDbTimeout(
            supabase.from("notifications").insert({
              user_id: user.id,
              title: "New Device Login",
              message: `Your account was accessed from: ${deviceInfo.device_name}. Your session on ${oldSession.device_name || "another device"} was terminated. If this wasn't you, log in and change your password immediately.`,
              type: "security",
              created_at: new Date().toISOString(),
            }),
          );
        } catch (err) {
          console.error("Notification error:", err);
          // Don't throw - notification failure shouldn't break login
        }
      }
    }

    // Log successful login
    await logSecurityEvent(user.id, "successful_passcode_login", {
      ip,
      device: deviceInfo.device_name,
      session_id: sessionId,
    });

    // Return response
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
        admin_role: user.admin_role,
        admin_permissions: user.admin_permissions,
        is_frozen: user.is_frozen,
        kyc_status: user.kyc_status,
      },
      session: {
        id: sessionId,
        device: deviceInfo.device_name,
        logged_in_at: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("Passcode verification error:", error);
    res.status(500).json({ error: "Verification failed: " + error.message });
  }
});

// Set/Update passcode (user)
app.post("/api/user/set-passcode", authenticate, async (req, res) => {
  try {
    const { passcode } = req.body;

    if (!passcode || passcode.length !== 6 || !/^\d{6}$/.test(passcode)) {
      return res
        .status(400)
        .json({ error: "Passcode must be exactly 6 digits" });
    }

    const hashedPasscode = await bcrypt.hash(passcode, 10);

    const { error } = await supabase
      .from("users")
      .update({
        passcode_hash: hashedPasscode,
        passcode_set_at: new Date(),
        passcode_attempts: 0,
        updated_at: new Date(),
      })
      .eq("id", req.user.id);

    if (error) throw error;

    res.json({ success: true, message: "Passcode set successfully" });
  } catch (error) {
    console.error("Set passcode error:", error);
    res.status(500).json({ error: "Failed to set passcode" });
  }
});

// Change passcode (requires current passcode verification)
app.post("/api/user/change-passcode", authenticate, async (req, res) => {
  try {
    const { current_passcode, new_passcode } = req.body;

    if (
      !new_passcode ||
      new_passcode.length !== 6 ||
      !/^\d{6}$/.test(new_passcode)
    ) {
      return res
        .status(400)
        .json({ error: "New passcode must be exactly 6 digits" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("passcode_hash")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    // If user has a passcode, verify current one
    if (user.passcode_hash) {
      if (!current_passcode) {
        return res.status(400).json({ error: "Current passcode required" });
      }

      const isValid = await bcrypt.compare(
        current_passcode,
        user.passcode_hash,
      );
      if (!isValid) {
        return res.status(401).json({ error: "Current passcode is incorrect" });
      }
    }

    const hashedPasscode = await bcrypt.hash(new_passcode, 10);

    await supabase
      .from("users")
      .update({
        passcode_hash: hashedPasscode,
        passcode_set_at: new Date(),
        passcode_attempts: 0,
        updated_at: new Date(),
      })
      .eq("id", req.user.id);

    res.json({ success: true, message: "Passcode changed successfully" });
  } catch (error) {
    console.error("Change passcode error:", error);
    res.status(500).json({ error: "Failed to change passcode" });
  }
});

// ==================== GET FACE DESCRIPTOR (PRODUCTION VERSION) ====================
app.get("/api/user/face-descriptor", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log(`[FACE] Fetching face descriptor for user: ${userId}`);

    const result = await getUserFaceDescriptor(userId);

    if (!result || !result.vector) {
      return res.status(400).json({
        error: "No face registered",
        message: "Please complete face registration first",
        code: "NO_FACE_REGISTERED",
      });
    }

    // Float32Array serialises to {"0":x,"1":y,...} in JSON — must convert to plain array first
    res.json({
      face_descriptor: Array.from(result.vector),
      source: result.source,
      version: result.version,
    });
  } catch (err) {
    console.error("[FACE] Error in face-descriptor endpoint:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== ROBUST FACE DESCRIPTOR RETRIEVAL ====================
async function getUserFaceDescriptor(userId) {
  // ── Helper: extract a 128-D float array from whatever shape a value is ──
  function extractVector(raw) {
    if (!raw) return null;

    // Already a plain JS array of numbers
    if (
      Array.isArray(raw) &&
      raw.length === 128 &&
      typeof raw[0] === "number"
    ) {
      return raw;
    }

    // Stored as a JSON string — parse first
    if (typeof raw === "string") {
      try {
        raw = JSON.parse(raw);
      } catch (e) {
        return null;
      }
      // After parsing it might now be a plain array
      if (Array.isArray(raw) && raw.length === 128) return raw;
    }

    // Nested object formats written by old code paths
    if (raw?.vector && Array.isArray(raw.vector) && raw.vector.length === 128)
      return raw.vector;
    if (
      raw?.descriptor &&
      Array.isArray(raw.descriptor) &&
      raw.descriptor.length === 128
    )
      return raw.descriptor;

    return null;
  }

  // ── Source 1: users.face_embedding (fastest — no join) ─────────────────
  const { data: user, error: userError } = await supabase
    .from("users")
    .select("face_embedding, face_verified, face_embedding_version")
    .eq("id", userId)
    .single();

  if (!userError && user?.face_embedding) {
    const vector = extractVector(user.face_embedding);
    if (vector) {
      console.log(
        `[FACE] ✅ Source=users_table  length=${vector.length}  sample=${vector[0].toFixed(4)}`,
      );
      return {
        vector: new Float32Array(vector),
        source: "users_table",
        version: user.face_embedding_version || 1,
      };
    }
    console.warn(
      "[FACE] users.face_embedding exists but could not extract 128-D vector — falling through to face_descriptors",
    );
  }

  // ── Source 2: face_descriptors table ────────────────────────────────────
  // Prioritise: primary=true first, then highest quality_score.
  // We fetch up to 10 rows and try each until we find a valid vector,
  // because some rows may have the nested {image,vector} format instead of
  // a flat array, or may have been inserted with bad data.
  const { data: descriptors, error: descError } = await supabase
    .from("face_descriptors")
    .select("id, descriptor, quality_score, is_primary, created_at")
    .eq("user_id", userId)
    .eq("is_active", true)
    .order("is_primary", { ascending: false })
    .order("quality_score", { ascending: false })
    .limit(10);

  if (!descError && descriptors && descriptors.length > 0) {
    for (const row of descriptors) {
      const vector = extractVector(row.descriptor);
      if (vector) {
        console.log(
          `[FACE] ✅ Source=face_descriptors  is_primary=${row.is_primary}  length=${vector.length}`,
        );

        // Auto-sync back to users table so next call hits Source 1 immediately
        const syncStr = JSON.stringify(vector);
        const { error: syncErr } = await supabase
          .from("users")
          .update({
            face_embedding: syncStr,
            face_verified: true,
            face_quality_score: row.quality_score || 0.8,
            face_embedding_version: 1,
            updated_at: new Date().toISOString(),
          })
          .eq("id", userId);

        if (syncErr)
          console.error("[FACE] Auto-sync to users table failed:", syncErr);
        else
          console.log("[FACE] Auto-synced descriptor to users.face_embedding");

        return {
          vector: new Float32Array(vector),
          source: "face_descriptors",
          version: 1,
        };
      }
    }
    console.warn(
      `[FACE] ${descriptors.length} rows in face_descriptors but none yielded a valid 128-D vector`,
    );
  }

  console.error(`[FACE] ❌ No usable face vector found for user ${userId}`);
  return null;
}

// ── 2. POST /api/auth/face/audit ──────────────────────────────────────────────
app.post("/api/auth/face/audit", authenticate, async (req, res) => {
  try {
    const { matched, distance, similarity } = req.body;
    const userId = req.user.id || req.user.userId;

    // Log to face_audit_log table using Supabase
    const { error: insertError } = await supabase
      .from("face_audit_log")
      .insert({
        user_id: userId,
        matched: matched,
        distance: distance,
        similarity: similarity,
        ip_address:
          req.headers["x-forwarded-for"] || req.socket?.remoteAddress || null,
        created_at: new Date().toISOString(),
      });

    if (insertError) {
      // Table might not exist, log but don't fail
      console.warn(
        "[face-audit] Could not insert to face_audit_log:",
        insertError.message,
      );
    }

    return res.json({ ok: true });
  } catch (err) {
    // Audit failure must never break the client
    console.error("[face-audit] Error:", err);
    return res.json({ ok: false });
  }
});

// ==================== FACE DATA DEBUG ENDPOINT ====================

async function getCurrentVersion(userId) {
  const { data: user } = await supabase
    .from("users")
    .select("face_embedding_version")
    .eq("id", userId)
    .single();
  return user?.face_embedding_version || 0;
}

// ==================== FACE MANAGEMENT API ENDPOINTS ====================

// GET face management data (admin)
app.get(
  "/api/sys/face-management",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { page = 1, limit = 20, search = "", status = "all" } = req.query;
      const offset = (parseInt(page) - 1) * parseInt(limit);

      console.log(
        `[FaceManagement] Fetching users - page: ${page}, search: ${search}, status: ${status}`,
      );

      let query = supabase.from("users").select(
        `
        id,
        email,
        first_name,
        last_name,
        phone,
        face_verified,
        face_quality_score,
        face_verification_date,
        face_reset_requested,
        created_at
      `,
        { count: "exact" },
      );

      // Apply search filter
      if (search) {
        query = query.or(
          `first_name.ilike.%${search}%,last_name.ilike.%${search}%,email.ilike.%${search}%`,
        );
      }

      // Apply status filter
      if (status === "verified") {
        query = query.eq("face_verified", true);
      } else if (status === "unverified") {
        query = query.eq("face_verified", false);
      }

      const {
        data: users,
        error,
        count,
      } = await query
        .order("created_at", { ascending: false })
        .range(offset, offset + parseInt(limit) - 1);

      if (error) throw error;

      // Get face image counts for each user
      const userIds = users.map((u) => u.id);
      let faceCounts = {};

      if (userIds.length > 0) {
        const { data: faceData } = await supabase
          .from("face_descriptors")
          .select("user_id")
          .in("user_id", userIds)
          .eq("is_active", true);

        faceCounts = (faceData || []).reduce((acc, f) => {
          acc[f.user_id] = (acc[f.user_id] || 0) + 1;
          return acc;
        }, {});
      }

      // Get stats
      const { count: verifiedCount } = await supabase
        .from("users")
        .select("*", { count: "exact", head: true })
        .eq("face_verified", true);

      const { count: totalRecords } = await supabase
        .from("face_descriptors")
        .select("*", { count: "exact", head: true });

      const { data: avgQuality } = await supabase
        .from("users")
        .select("face_quality_score")
        .not("face_quality_score", "is", null);

      const avgQualityScore =
        avgQuality && avgQuality.length > 0
          ? Math.round(
              (avgQuality.reduce(
                (sum, u) => sum + (u.face_quality_score || 0),
                0,
              ) /
                avgQuality.length) *
                100,
            )
          : 0;

      const usersWithCounts = users.map((user) => ({
        ...user,
        face_images_count: faceCounts[user.id] || 0,
      }));

      res.json({
        users: usersWithCounts,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / parseInt(limit)),
        },
        stats: {
          verified_count: verifiedCount || 0,
          pending_reenroll: 0,
          total_records: totalRecords || 0,
          avg_quality: avgQualityScore,
        },
      });
    } catch (error) {
      console.error("Face management error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== DEBUG: GET FULL FACE DATA FOR USER ====================
app.get(
  "/api/sys/debug/face-data/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      console.log(`[DEBUG] Fetching face data for user: ${userId}`);

      // 1. Get user basic info
      const { data: user, error: userError } = await supabase
        .from("users")
        .select(
          `
        id,
        email,
        first_name,
        last_name,
        face_verified,
        face_embedding,
        face_quality_score,
        face_verification_date,
        face_embedding_version,
        created_at
      `,
        )
        .eq("id", userId)
        .single();

      if (userError) {
        console.error("User fetch error:", userError);
        return res
          .status(404)
          .json({ error: "User not found", details: userError });
      }

      // 2. Get all face descriptors
      const { data: descriptors, error: descError } = await supabase
        .from("face_descriptors")
        .select(
          `
        id,
        descriptor,
        is_primary,
        is_active,
        quality_score,
        version,
        created_at,
        updated_at
      `,
        )
        .eq("user_id", userId)
        .order("is_primary", { ascending: false })
        .order("created_at", { ascending: true });

      if (descError) {
        console.error("Descriptors fetch error:", descError);
        // Non-fatal: continue with empty array so the rest of the response still works
      }
      const safeDescriptors = descriptors || [];

      // 3. Analyze user's face_embedding
      const analyzeDescriptor = (desc) => {
        if (!desc) return { exists: false };

        const result = {
          exists: true,
          type: typeof desc,
          is_128_array: false,
          array_length: 0,
          first_few_values: null,
          structure: null,
        };

        // Handle different types
        if (typeof desc === "string") {
          try {
            const parsed = JSON.parse(desc);
            if (Array.isArray(parsed)) {
              result.is_128_array = parsed.length === 128;
              result.array_length = parsed.length;
              if (result.is_128_array) {
                result.first_few_values = parsed.slice(0, 5);
              }
            } else if (parsed && typeof parsed === "object") {
              result.structure = Object.keys(parsed);
              if (parsed.vector && Array.isArray(parsed.vector)) {
                result.is_128_array = parsed.vector.length === 128;
                result.array_length = parsed.vector.length;
                if (result.is_128_array) {
                  result.first_few_values = parsed.vector.slice(0, 5);
                }
              }
            }
          } catch (e) {}
        }

        if (typeof desc === "object" && desc !== null) {
          result.structure = Object.keys(desc);
          if (desc.vector && Array.isArray(desc.vector)) {
            result.is_128_array = desc.vector.length === 128;
            result.array_length = desc.vector.length;
            if (result.is_128_array) {
              result.first_few_values = desc.vector.slice(0, 5);
            }
          } else if (desc.descriptor && Array.isArray(desc.descriptor)) {
            result.is_128_array = desc.descriptor.length === 128;
            result.array_length = desc.descriptor.length;
            if (result.is_128_array) {
              result.first_few_values = desc.descriptor.slice(0, 5);
            }
          } else if (Array.isArray(desc)) {
            result.is_128_array = desc.length === 128;
            result.array_length = desc.length;
            if (result.is_128_array) {
              result.first_few_values = desc.slice(0, 5);
            }
          }
        }

        return result;
      };

      // Analyze user's face_embedding
      const userEmbeddingAnalysis = analyzeDescriptor(user.face_embedding);

      // Analyze each descriptor
      const descriptorsAnalysis = (descriptors || []).map((desc) => ({
        id: desc.id,
        is_primary: desc.is_primary,
        is_active: desc.is_active,
        quality_score: desc.quality_score,
        version: desc.version,
        created_at: desc.created_at,
        analysis: analyzeDescriptor(desc.descriptor),
      }));

      // Build recommendation
      let recommendation = "";
      let canVerify = false;
      let needsSync = false;

      if (userEmbeddingAnalysis.is_128_array) {
        recommendation =
          "✅ User has valid face descriptor in users table. Face verification should work.";
        canVerify = true;
      } else if (descriptorsAnalysis.some((d) => d.analysis.is_128_array)) {
        recommendation =
          "⚠️ User has valid face descriptor in face_descriptors table but NOT in users table. Run sync to fix.";
        canVerify = true;
        needsSync = true;
      } else if (descriptorsAnalysis.length > 0) {
        recommendation =
          "❌ User has face descriptors but none are valid 128-length arrays. Data format is incorrect.";
        canVerify = false;
      } else {
        recommendation =
          "❌ No face data found for this user. User needs to complete face registration.";
        canVerify = false;
      }

      res.json({
        user: {
          id: user.id,
          email: user.email,
          name: `${user.first_name} ${user.last_name}`,
          face_verified: user.face_verified,
          face_quality_score: user.face_quality_score,
          face_verification_date: user.face_verification_date,
          face_embedding_version: user.face_embedding_version || 0,
        },
        user_face_embedding: {
          exists: !!user.face_embedding,
          analysis: userEmbeddingAnalysis,
          raw_preview: user.face_embedding
            ? JSON.stringify(user.face_embedding).substring(0, 200)
            : null,
        },
        descriptors_count: descriptors?.length || 0,
        descriptors: descriptorsAnalysis,
        verification_status: {
          can_verify: canVerify,
          recommendation: recommendation,
          needs_sync: needsSync,
          needs_registration: descriptorsAnalysis.length === 0,
        },
      });
    } catch (error) {
      console.error("Debug face data error:", error);
      res.status(500).json({ error: error.message, stack: error.stack });
    }
  },
);

// ==================== SYNC FACE DATA FROM DESCRIPTORS TO USERS TABLE ====================
app.post(
  "/api/sys/debug/sync-face-data/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      console.log(`[SYNC] Syncing face data for user: ${userId}`);

      // Find the best descriptor (primary first, then any active, then any)
      const { data: descriptors, error: fetchError } = await supabase
        .from("face_descriptors")
        .select("descriptor, is_primary, quality_score")
        .eq("user_id", userId)
        .eq("is_active", true)
        .order("is_primary", { ascending: false })
        .order("quality_score", { ascending: false });

      if (fetchError || !descriptors || descriptors.length === 0) {
        return res
          .status(404)
          .json({ error: "No face descriptors found for this user" });
      }

      let bestVector = null;
      let bestQuality = 0;

      for (const desc of descriptors) {
        let vector = null;

        // Try to extract vector from different formats
        if (desc.descriptor) {
          // Format: { vector: [...] }
          if (
            desc.descriptor.vector &&
            Array.isArray(desc.descriptor.vector) &&
            desc.descriptor.vector.length === 128
          ) {
            vector = desc.descriptor.vector;
          }
          // Format: { descriptor: [...] }
          else if (
            desc.descriptor.descriptor &&
            Array.isArray(desc.descriptor.descriptor) &&
            desc.descriptor.descriptor.length === 128
          ) {
            vector = desc.descriptor.descriptor;
          }
          // Format: direct array
          else if (
            Array.isArray(desc.descriptor) &&
            desc.descriptor.length === 128
          ) {
            vector = desc.descriptor;
          }
          // Format: string that parses to array
          else if (typeof desc.descriptor === "string") {
            try {
              const parsed = JSON.parse(desc.descriptor);
              if (Array.isArray(parsed) && parsed.length === 128) {
                vector = parsed;
              } else if (
                parsed.vector &&
                Array.isArray(parsed.vector) &&
                parsed.vector.length === 128
              ) {
                vector = parsed.vector;
              }
            } catch (e) {}
          }
        }

        if (vector) {
          bestVector = vector;
          bestQuality = desc.quality_score || 0;
          break; // Use the first valid one (already ordered by primary then quality)
        }
      }

      if (!bestVector) {
        return res.status(400).json({
          error: "No valid 128-length face vector found in descriptors",
          debug: descriptors.map((d) => ({
            has_descriptor: !!d.descriptor,
            type: typeof d.descriptor,
            keys: d.descriptor ? Object.keys(d.descriptor) : [],
          })),
        });
      }

      // Get current version
      const { data: currentUser } = await supabase
        .from("users")
        .select("face_embedding_version")
        .eq("id", userId)
        .single();

      const newVersion = (currentUser?.face_embedding_version || 0) + 1;

      // Update users table
      const { error: updateError } = await supabase
        .from("users")
        .update({
          face_embedding: bestVector,
          face_verified: true,
          face_quality_score: bestQuality || 0.8,
          face_embedding_version: newVersion,
          face_verification_date: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq("id", userId);

      if (updateError) throw updateError;

      // Log the sync action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "sync_face_data",
        target_user_id: userId,
        details: {
          vector_length: bestVector.length,
          quality_score: bestQuality,
          version: newVersion,
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      console.log(
        `[SYNC] Successfully synced face data for user ${userId}, version ${newVersion}`,
      );

      res.json({
        success: true,
        message: "Face data synced successfully",
        vector_length: bestVector.length,
        vector_preview: bestVector.slice(0, 10),
        version: newVersion,
      });
    } catch (error) {
      console.error("Sync face data error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== GET USER FACE IMAGES ====================
app.get(
  "/api/sys/users/:userId/face-images",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      console.log(`[FaceImages] Fetching face images for user: ${userId}`);

      const { data: descriptors, error } = await supabase
        .from("face_descriptors")
        .select("descriptor, is_primary, quality_score, created_at")
        .eq("user_id", userId)
        .eq("is_active", true)
        .order("is_primary", { ascending: false })
        .order("created_at", { ascending: true });

      if (error) throw error;

      const images = (descriptors || [])
        .map((desc, index) => {
          let imageData = null;
          let angle = null;

          // Extract image from different formats
          if (desc.descriptor) {
            if (desc.descriptor.image) {
              imageData = desc.descriptor.image;
              angle = desc.descriptor.angle;
            } else if (
              typeof desc.descriptor === "string" &&
              desc.descriptor.startsWith("data:image")
            ) {
              imageData = desc.descriptor;
            }
          }

          return {
            image: imageData,
            angle: angle || index + 1,
            is_primary: desc.is_primary || false,
            quality_score: desc.quality_score,
            created_at: desc.created_at,
          };
        })
        .filter((img) => img.image); // Only return entries with actual images

      res.json({ images });
    } catch (error) {
      console.error("Get face images error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== TEST ENDPOINT FOR CURRENT USER (DEBUG) ====================
app.get("/api/user/debug-my-face", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    console.log(`[DEBUG-ME] User ${userId} debugging their own face data`);

    // Get from users table
    const { data: user, error: userError } = await supabase
      .from("users")
      .select(
        "id, email, first_name, last_name, face_verified, face_embedding, face_quality_score",
      )
      .eq("id", userId)
      .single();

    if (userError) {
      return res
        .status(404)
        .json({ error: "User not found", details: userError });
    }

    // Get from face_descriptors
    const { data: descriptors, error: descError } = await supabase
      .from("face_descriptors")
      .select("id, is_primary, is_active, quality_score")
      .eq("user_id", userId)
      .eq("is_active", true);

    // Analyze face_embedding
    let hasValidVector = false;
    let vectorLength = 0;

    if (user.face_embedding) {
      try {
        let embedding = user.face_embedding;
        if (typeof embedding === "string") embedding = JSON.parse(embedding);
        if (Array.isArray(embedding)) {
          vectorLength = embedding.length;
          hasValidVector = embedding.length === 128;
        } else if (embedding.vector && Array.isArray(embedding.vector)) {
          vectorLength = embedding.vector.length;
          hasValidVector = embedding.vector.length === 128;
        }
      } catch (e) {}
    }

    res.json({
      user_id: userId,
      email: user.email,
      name: `${user.first_name} ${user.last_name}`,
      face_verified: user.face_verified,
      has_face_embedding: !!user.face_embedding,
      has_valid_128_vector: hasValidVector,
      vector_length: vectorLength,
      face_quality_score: user.face_quality_score,
      descriptors_count: descriptors?.length || 0,
      can_verify: hasValidVector,
      message: hasValidVector
        ? "✅ Your face data is valid. Verification should work."
        : "❌ Your face data is invalid or missing. Please contact support.",
    });
  } catch (error) {
    console.error("Debug my face error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== FIX MISSING FACE DATA (Admin Utility) ====================
app.post(
  "/api/sys/fix-missing-face-data",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Find users who have face_descriptors but no face_embedding in users table
      const { data: usersWithDescriptors, error: fetchError } = await supabase
        .from("face_descriptors")
        .select("user_id")
        .eq("is_active", true)
        .not("descriptor", "is", null);

      if (fetchError) throw fetchError;

      const uniqueUserIds = [
        ...new Set(usersWithDescriptors.map((u) => u.user_id)),
      ];
      let fixed = 0;
      let failed = 0;

      for (const userId of uniqueUserIds) {
        try {
          // Get the user's current face_embedding status
          const { data: user } = await supabase
            .from("users")
            .select("face_embedding")
            .eq("id", userId)
            .single();

          // Skip if already has face_embedding
          if (user?.face_embedding) continue;

          // Get best descriptor
          const { data: descriptors } = await supabase
            .from("face_descriptors")
            .select("descriptor, quality_score")
            .eq("user_id", userId)
            .eq("is_active", true)
            .order("quality_score", { ascending: false })
            .limit(1);

          if (descriptors && descriptors.length > 0) {
            let vector = null;
            const desc = descriptors[0].descriptor;

            if (
              desc.vector &&
              Array.isArray(desc.vector) &&
              desc.vector.length === 128
            ) {
              vector = desc.vector;
            } else if (
              desc.descriptor &&
              Array.isArray(desc.descriptor) &&
              desc.descriptor.length === 128
            ) {
              vector = desc.descriptor;
            } else if (Array.isArray(desc) && desc.length === 128) {
              vector = desc;
            }

            if (vector) {
              await supabase
                .from("users")
                .update({
                  face_embedding: vector,
                  face_verified: true,
                  face_quality_score: descriptors[0].quality_score || 0.8,
                  updated_at: new Date().toISOString(),
                })
                .eq("id", userId);
              fixed++;
            }
          }
        } catch (err) {
          console.error(`Failed to fix user ${userId}:`, err);
          failed++;
        }
      }

      res.json({
        success: true,
        message: `Fixed ${fixed} users, failed ${failed}`,
        fixed,
        failed,
        total_users_processed: uniqueUserIds.length,
      });
    } catch (error) {
      console.error("Fix missing face data error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// Resend OTP
app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const { identifier } = req.body;

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email")
      .eq("email", identifier)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate new OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // Delete old OTPs
    await supabase
      .from("otps")
      .delete()
      .eq("user_id", user.id)
      .eq("otp_type", "login");

    // Create new OTP
    await supabase.from("otps").insert({
      user_id: user.id,
      otp_code: otpCode,
      otp_type: "login",
      expires_at: expiresAt,
    });

    // Send email
    await sendOTPEmail(user.email, otpCode);

    res.json({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    console.error("Resend OTP error:", error);
    res.status(500).json({ error: "Failed to resend OTP" });
  }
});

// Verify OTP for login
app.post("/api/auth/verify-otp-login", async (req, res) => {
  try {
    const { identifier, otp_code, transaction_id } = req.body;

    // Find user
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", identifier)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Verify OTP
    const { data: otpRecord, error: otpError } = await supabase
      .from("otps")
      .select("*")
      .eq("user_id", user.id)
      .eq("otp_code", otp_code)
      .eq("otp_type", "login")
      .eq("is_used", false)
      .single();

    if (otpError || !otpRecord) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    if (new Date(otpRecord.expires_at) < new Date()) {
      return res.status(401).json({ error: "OTP has expired" });
    }

    // Mark OTP as used
    await supabase
      .from("otps")
      .update({ is_used: true })
      .eq("id", otpRecord.id);

    // Update last login
    await supabase
      .from("users")
      .update({ last_login: new Date() })
      .eq("id", user.id);

    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE },
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("OTP verification error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// Helper function for Euclidean distance
function calculateEuclideanDistance(desc1, desc2) {
  let sum = 0;
  for (let i = 0; i < desc1.length; i++) {
    sum += Math.pow(desc1[i] - desc2[i], 2);
  }
  return Math.sqrt(sum);
}

// Check if user has passcode (for settings page)
app.get("/api/user/has-passcode", authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("passcode_hash")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    res.json({
      has_passcode: !!(user.passcode_hash && user.passcode_hash !== null),
    });
  } catch (error) {
    console.error("Has passcode error:", error);
    res.status(500).json({ error: "Failed to check passcode status" });
  }
});

// Helper function for Euclidean distance
function calculateEuclideanDistance(desc1, desc2) {
  let sum = 0;
  for (let i = 0; i < desc1.length; i++) {
    sum += Math.pow(desc1[i] - desc2[i], 2);
  }
  return Math.sqrt(sum);
}

// ==================== PASSCODE OTP ROUTES ====================

// Send OTP for passcode change/set - EMAIL FIRST
app.post("/api/user/send-passcode-otp", authenticate, async (req, res) => {
  try {
    const { method = "email" } = req.body; // Default to email, but accept method param

    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, phone")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    // Generate OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const requestId = uuidv4();

    // Store OTP request
    const { data: otpRequest, error: insertError } = await supabase
      .from("passcode_otp_requests")
      .insert({
        id: requestId,
        user_id: req.user.id,
        otp_code: otpCode,
        expires_at: expiresAt,
        is_used: false,
      })
      .select()
      .single();

    if (insertError) throw insertError;

    // Send OTP based on requested method (default to email)
    let sentMethod = "email";
    let contact = user.email;
    let sent = false;

    if (method === "sms" && user.phone && user.phone.trim()) {
      try {
        await sendOTPSMS(user.phone, otpCode);
        sent = true;
        sentMethod = "sms";
        contact = maskPhoneNumber(user.phone);
        console.log(`OTP sent via SMS to ${user.phone}`);
      } catch (smsError) {
        console.error("SMS send failed, falling back to email:", smsError);
        await sendOTPEmail(user.email, otpCode);
        sentMethod = "email";
        contact = maskEmail(user.email);
      }
    } else {
      // Default to email
      const emailSent = await sendOTPEmail(user.email, otpCode);
      if (emailSent) {
        sentMethod = "email";
        contact = maskEmail(user.email);
        console.log(`OTP sent via email to ${user.email}`);
      } else {
        // If email fails, try SMS as fallback
        if (user.phone && user.phone.trim()) {
          try {
            await sendOTPSMS(user.phone, otpCode);
            sentMethod = "sms";
            contact = maskPhoneNumber(user.phone);
            console.log(`OTP sent via SMS fallback to ${user.phone}`);
          } catch (smsError) {
            console.error("SMS fallback also failed:", smsError);
            throw new Error("Failed to send OTP via any method");
          }
        } else {
          throw new Error(
            "Failed to send OTP via email and no phone available",
          );
        }
      }
    }

    res.json({
      success: true,
      request_id: requestId,
      method: sentMethod,
      contact: contact,
      message: `Verification code sent to your ${sentMethod}`,
    });
  } catch (error) {
    console.error("Send passcode OTP error:", error);
    res
      .status(500)
      .json({ error: "Failed to send verification code: " + error.message });
  }
});

// Resend passcode OTP - UPDATED to accept method parameter
app.post("/api/user/resend-passcode-otp", authenticate, async (req, res) => {
  try {
    const { request_id, method = "email" } = req.body;

    // Invalidate old request
    await supabase
      .from("passcode_otp_requests")
      .update({ is_used: true })
      .eq("id", request_id)
      .eq("user_id", req.user.id);

    // Get user
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, phone")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    // Generate new OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    const newRequestId = uuidv4();

    const { data: otpRequest, error: insertError } = await supabase
      .from("passcode_otp_requests")
      .insert({
        id: newRequestId,
        user_id: req.user.id,
        otp_code: otpCode,
        expires_at: expiresAt,
        is_used: false,
      })
      .select()
      .single();

    if (insertError) throw insertError;

    // Send OTP based on requested method
    let sentMethod = "email";
    let contact = user.email;
    let sent = false;

    if (method === "sms" && user.phone && user.phone.trim()) {
      try {
        await sendOTPSMS(user.phone, otpCode);
        sent = true;
        sentMethod = "sms";
        contact = maskPhoneNumber(user.phone);
      } catch (smsError) {
        console.error("SMS send failed, falling back to email:", smsError);
        await sendOTPEmail(user.email, otpCode);
        sentMethod = "email";
        contact = maskEmail(user.email);
      }
    } else {
      await sendOTPEmail(user.email, otpCode);
      sentMethod = "email";
      contact = maskEmail(user.email);
    }

    res.json({
      success: true,
      request_id: newRequestId,
      method: sentMethod,
      contact: contact,
    });
  } catch (error) {
    console.error("Resend passcode OTP error:", error);
    res.status(500).json({ error: "Failed to resend code" });
  }
});

// Set passcode with OTP verification
app.post("/api/user/set-passcode-with-otp", authenticate, async (req, res) => {
  try {
    const { passcode, otp_code, request_id } = req.body;

    if (!passcode || passcode.length !== 6 || !/^\d{6}$/.test(passcode)) {
      return res
        .status(400)
        .json({ error: "Passcode must be exactly 6 digits" });
    }

    // Verify OTP
    const { data: otpRequest, error: otpError } = await supabase
      .from("passcode_otp_requests")
      .select("*")
      .eq("id", request_id)
      .eq("user_id", req.user.id)
      .eq("otp_code", otp_code)
      .eq("is_used", false)
      .single();

    if (otpError || !otpRequest) {
      return res
        .status(401)
        .json({ error: "Invalid or expired verification code" });
    }

    if (new Date(otpRequest.expires_at) < new Date()) {
      return res.status(401).json({ error: "Verification code has expired" });
    }

    // Mark OTP as used
    await supabase
      .from("passcode_otp_requests")
      .update({ is_used: true })
      .eq("id", request_id);

    // Hash and save passcode
    const hashedPasscode = await bcrypt.hash(passcode, 10);

    await supabase
      .from("users")
      .update({
        passcode_hash: hashedPasscode,
        passcode_set_at: new Date(),
        passcode_attempts: 0,
      })
      .eq("id", req.user.id);

    // Send confirmation
    await createNotification(
      req.user.id,
      "Passcode Set",
      "Your transaction passcode has been set successfully.",
      "success",
    );

    res.json({ success: true, message: "Passcode set successfully" });
  } catch (error) {
    console.error("Set passcode with OTP error:", error);
    res.status(500).json({ error: "Failed to set passcode" });
  }
});

// Change passcode with OTP verification
app.post(
  "/api/user/change-passcode-with-otp",
  authenticate,
  async (req, res) => {
    try {
      const { current_passcode, new_passcode, otp_code, request_id } = req.body;

      if (
        !new_passcode ||
        new_passcode.length !== 6 ||
        !/^\d{6}$/.test(new_passcode)
      ) {
        return res
          .status(400)
          .json({ error: "New passcode must be exactly 6 digits" });
      }

      // Get user's current passcode
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("passcode_hash")
        .eq("id", req.user.id)
        .single();

      if (userError) throw userError;

      // Verify current passcode if exists
      if (user.passcode_hash) {
        if (!current_passcode) {
          return res.status(400).json({ error: "Current passcode required" });
        }
        const isValid = await bcrypt.compare(
          current_passcode,
          user.passcode_hash,
        );
        if (!isValid) {
          return res
            .status(401)
            .json({ error: "Current passcode is incorrect" });
        }
      }

      // Verify OTP
      const { data: otpRequest, error: otpError } = await supabase
        .from("passcode_otp_requests")
        .select("*")
        .eq("id", request_id)
        .eq("user_id", req.user.id)
        .eq("otp_code", otp_code)
        .eq("is_used", false)
        .single();

      if (otpError || !otpRequest) {
        return res
          .status(401)
          .json({ error: "Invalid or expired verification code" });
      }

      if (new Date(otpRequest.expires_at) < new Date()) {
        return res.status(401).json({ error: "Verification code has expired" });
      }

      // Mark OTP as used
      await supabase
        .from("passcode_otp_requests")
        .update({ is_used: true })
        .eq("id", request_id);

      // Hash and save new passcode
      const hashedPasscode = await bcrypt.hash(new_passcode, 10);

      await supabase
        .from("users")
        .update({
          passcode_hash: hashedPasscode,
          passcode_set_at: new Date(),
          passcode_attempts: 0,
        })
        .eq("id", req.user.id);

      // Send confirmation
      await createNotification(
        req.user.id,
        "Passcode Changed",
        "Your transaction passcode has been changed successfully.",
        "success",
      );

      res.json({ success: true, message: "Passcode changed successfully" });
    } catch (error) {
      console.error("Change passcode with OTP error:", error);
      res.status(500).json({ error: "Failed to change passcode" });
    }
  },
);

// Helper functions for masking
function maskEmail(email) {
  if (!email) return email;
  const [local, domain] = email.split("@");
  if (local.length <= 2) return email;
  const maskedLocal = local[0] + "***" + local[local.length - 1];
  return `${maskedLocal}@${domain}`;
}

function maskPhoneNumber(phone) {
  if (!phone) return phone;
  if (phone.length <= 4) return phone;
  const start = phone.substring(0, 3);
  const end = phone.substring(phone.length - 2);
  return `${start}****${end}`;
}

// NOTE: a second `function sendOTPSMS` used to be declared here, calling
// the raw `africastalking` client directly with no null-guard and
// re-throwing on any error. Since both declarations shared the same
// function name in the same scope, this one silently overrode the safer
// version defined earlier (the one with phone number formatting, a
// null-guard, and graceful `return false` on failure) for every call site
// in the file, with no warning from Node. Removed — there is now exactly
// one sendOTPSMS, defined once, near the Africa's Talking initialization.

// Check and freeze account if balance exceeds tier limit
async function checkAndFreezeIfBalanceExceeds(userId) {
  try {
    // Get user's tier
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("account_tier, is_frozen")
      .eq("id", userId)
      .single();

    if (userError) return;

    // Get tier limits
    const { data: limits, error: limitsError } = await supabase
      .from("account_tier_limits")
      .select("max_balance")
      .eq("tier", user.account_tier)
      .single();

    if (limitsError) return;

    // Get user's total balance
    const { data: accounts } = await supabase
      .from("accounts")
      .select("balance")
      .eq("user_id", userId);

    const totalBalance =
      accounts?.reduce((sum, acc) => sum + (acc.balance || 0), 0) || 0;

    // Check if balance exceeds limit
    if (totalBalance > limits.max_balance && !user.is_frozen) {
      await supabase
        .from("users")
        .update({
          is_frozen: true,
          freeze_reason: `Your balance (₦${totalBalance.toLocaleString()}) exceeds your Tier ${user.account_tier} limit of ₦${limits.max_balance.toLocaleString()}. Please upgrade your account to continue.`,
          freeze_reason_type: "balance_exceeded",
          unfreeze_method: "upgrade",
          updated_at: new Date(),
        })
        .eq("id", userId);

      await bumpUserCacheVersion("authuser", userId);

      await supabase.from("notifications").insert({
        user_id: userId,
        title: "Account Frozen - Balance Limit Exceeded",
        message: `Your balance (₦${totalBalance.toLocaleString()}) exceeds your Tier ${user.account_tier} limit of ₦${limits.max_balance.toLocaleString()}. Please upgrade your account to continue using our services.`,
        type: "error",
        created_at: new Date(),
      });
    }
    // If balance is back within limit and account was frozen for balance reason, unfreeze
    else if (
      totalBalance <= limits.max_balance &&
      user.is_frozen &&
      user.freeze_reason_type === "balance_exceeded"
    ) {
      await supabase
        .from("users")
        .update({
          is_frozen: false,
          freeze_reason: null,
          freeze_reason_type: null,
          unfreeze_method: null,
          updated_at: new Date(),
        })
        .eq("id", userId);

      await bumpUserCacheVersion("authuser", userId);
    }
  } catch (error) {
    console.error("Balance check error:", error);
  }
}

// Modify transfer route to check daily limits based on tier
// Add this inside the transfer route before processing

// Check tier-based daily limit
async function checkTierTransferLimit(userId, amount) {
  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("account_tier")
      .eq("id", userId)
      .single();

    if (userError) return { allowed: true };

    const { data: limits, error: limitsError } = await supabase
      .from("account_tier_limits")
      .select("daily_transfer_limit, single_transfer_limit")
      .eq("tier", user.account_tier)
      .single();

    if (limitsError) return { allowed: true };

    // Check single transfer limit
    if (amount > limits.single_transfer_limit) {
      return {
        allowed: false,
        error: `Single transfer limit for your tier is ₦${limits.single_transfer_limit.toLocaleString()}`,
        limit: limits.single_transfer_limit,
      };
    }

    // Get today's total transfers
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const { data: todayTransfers } = await supabase
      .from("transactions_new")
      .select("amount")
      .eq("sender_user_id", userId)
      .eq("status", "completed")
      .gte("created_at", today.toISOString());

    const todayTotal =
      todayTransfers?.reduce((sum, t) => sum + t.amount, 0) || 0;

    if (todayTotal + amount > limits.daily_transfer_limit) {
      return {
        allowed: false,
        error: `Daily transfer limit for your tier is ₦${limits.daily_transfer_limit.toLocaleString()}. You have ₦${(limits.daily_transfer_limit - todayTotal).toLocaleString()} remaining today.`,
        limit: limits.daily_transfer_limit,
        remaining: limits.daily_transfer_limit - todayTotal,
      };
    }

    return { allowed: true };
  } catch (error) {
    console.error("Tier limit check error:", error);
    return { allowed: true };
  }
}

// ==================== FORGOT PASSWORD ROUTES (EMAIL ONLY) ====================

app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email required" });
  }

  const normalizedEmail = email.trim().toLowerCase();

  console.log(`📧 Password reset requested for: ${normalizedEmail}`);

  try {
    // STEP 1: Check if user exists FIRST
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, email, first_name")
      .eq("email", normalizedEmail)
      .maybeSingle();

    // IMPORTANT: If user doesn't exist, return generic message (don't reveal that email doesn't exist)
    if (!user) {
      console.log(`User not found: ${normalizedEmail}`);
      // Still return success to prevent email enumeration
      return res.json({
        success: true,
        message: "If your email is registered, you will receive a reset code.",
      });
    }

    // STEP 2: User exists - generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    console.log(`Generated OTP ${otp} for user ${user.id}`);

    // Mark any existing OTPs as used
    await supabase
      .from("password_resets")
      .update({ used: true })
      .eq("email", normalizedEmail)
      .eq("used", false);

    // Insert new OTP
    const { error: insertError } = await supabase
      .from("password_resets")
      .insert({
        email: normalizedEmail,
        otp: otp,
        expires_at: expiresAt.toISOString(),
        used: false,
        created_at: new Date().toISOString(),
      });

    if (insertError) {
      console.error("Insert OTP error:", insertError);
      return res.status(500).json({ error: "Failed to generate reset code" });
    }

    // STEP 3: Send email with OTP
    const emailSent = await sendOTPEmail(normalizedEmail, otp, "reset");

    if (!emailSent) {
      console.error(`Failed to send email to ${normalizedEmail}`);
      // Still return success to user (don't reveal email failure)
      return res.json({
        success: true,
        message: "If your email is registered, you will receive a reset code.",
      });
    }

    console.log(`✅ Reset email sent to ${normalizedEmail}`);
    res.json({
      success: true,
      message:
        "Reset code sent to your email. Please check your inbox and spam folder.",
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

// Step 2: Verify OTP
app.post("/api/auth/verify-reset-otp", async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Email and code required" });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedOtp = otp.trim();

  console.log(`Verifying OTP for ${normalizedEmail}`);

  try {
    const { data: record, error } = await supabase
      .from("password_resets")
      .select("*")
      .eq("email", normalizedEmail)
      .eq("otp", normalizedOtp)
      .eq("used", false)
      .single();

    if (error || !record) {
      console.log("Invalid OTP:", error);
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    if (new Date(record.expires_at) < new Date()) {
      console.log("Expired OTP for:", normalizedEmail);
      return res
        .status(400)
        .json({ error: "Code has expired. Please request a new one." });
    }

    // Mark as used
    await supabase
      .from("password_resets")
      .update({ used: true })
      .eq("id", record.id);

    console.log(`✅ OTP verified successfully for ${normalizedEmail}`);
    res.json({ valid: true });
  } catch (error) {
    console.error("Verify OTP error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// Step 3: Reset Password
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, otp, new_password } = req.body;

  if (!email || !otp || !new_password) {
    return res.status(400).json({ error: "All fields required" });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedOtp = otp.trim();

  console.log(`Resetting password for ${normalizedEmail}`);

  try {
    // Verify OTP again (must be used = true from previous step)
    const { data: record, error } = await supabase
      .from("password_resets")
      .select("*")
      .eq("email", normalizedEmail)
      .eq("otp", normalizedOtp)
      .eq("used", true)
      .single();

    if (error || !record) {
      console.log("Invalid reset session:", error);
      return res
        .status(400)
        .json({ error: "Invalid or expired reset session" });
    }

    if (new Date(record.expires_at) < new Date()) {
      return res.status(400).json({
        error: "Reset session has expired. Please request a new code.",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(new_password, 10);

    // Update user password
    const { error: updateError } = await supabase
      .from("users")
      .update({
        password_hash: hashedPassword,
        updated_at: new Date().toISOString(),
      })
      .eq("email", normalizedEmail);

    if (updateError) {
      console.error("Password update error:", updateError);
      return res.status(500).json({ error: "Failed to update password" });
    }

    // Delete the used OTP record (cleanup)
    await supabase.from("password_resets").delete().eq("id", record.id);

    console.log(`✅ Password reset successfully for ${normalizedEmail}`);
    res.json({
      message:
        "Password reset successful. You can now login with your new password.",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// ==================== SIMPLIFIED EMAIL FUNCTION ====================

// Enhanced sendOTPEmail function that supports different email types
async function sendOTPEmail(email, otp, type = "reset") {
  console.log(
    `📧 Attempting to send ${type} email to ${email}${otp ? ` with OTP: ${otp}` : ""}`,
  );

  // Check SMTP configuration
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS
  ) {
    console.error("❌ SMTP credentials missing. Email not sent.");
    return false;
  }

  try {
    let subject = "";
    let htmlContent = "";

    if (type === "upgrade") {
      subject = "FEECENT - Account Upgrade Verification";
      htmlContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>FEECENT Account Upgrade Verification</title>
                </head>
                <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5;">
                    <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden;">
                        <div style="background: #6b21a8; padding: 20px; text-align: center;">
                            <h1 style="color: white; margin: 0;">FEECENT</h1>
                            <p style="color: #d8b4fe; margin: 5px 0 0;">Account Upgrade Verification</p>
                        </div>
                        <div style="padding: 30px 20px;">
                            <h2 style="color: #333; margin-top: 0;">Verify Your Email</h2>
                            <p style="color: #666;">You requested to upgrade your FEECENT account. Please use the verification code below to continue:</p>
                            <div style="background: #f8fafc; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                                <span style="font-size: 42px; font-weight: bold; letter-spacing: 8px; color: #6b21a8; font-family: monospace;">${otp}</span>
                            </div>
                            <p style="color: #666; font-size: 14px;">This code expires in <strong>10 minutes</strong>.</p>
                            <p style="color: #999; font-size: 12px; margin-top: 20px;">If you didn't request this, please ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
            `;
    } else if (type === "2fa") {
      subject = "FEECENT - Two-Factor Authentication Code";
      htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>FEECENT 2FA Code</title>
    </head>
    <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5;">
        <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden;">
            <div style="background: #6b21a8; padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">FEECENT</h1>
                <p style="color: #d8b4fe; margin: 5px 0 0;">Two-Factor Authentication</p>
            </div>
            <div style="padding: 30px 20px;">
                <h2 style="color: #333; margin-top: 0;">Verification Code</h2>
                <p style="color: #666;">Use the following code to complete your login:</p>
                <div style="background: #f8fafc; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                    <span style="font-size: 42px; font-weight: bold; letter-spacing: 8px; color: #6b21a8; font-family: monospace;">${otp}</span>
                </div>
                <p style="color: #666; font-size: 14px;">This code expires in <strong>10 minutes</strong>.</p>
                <p style="color: #999; font-size: 12px; margin-top: 20px;">If you didn't request this, please ignore this email.</p>
            </div>
        </div>
    </body>
    </html>
  `;
    } else if (type === "verified") {
      subject = "FEECENT - Email Verified Successfully";
      htmlContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Email Verified - FEECENT</title>
                </head>
                <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5;">
                    <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden;">
                        <div style="background: #10b981; padding: 20px; text-align: center;">
                            <i class="fas fa-check-circle" style="font-size: 48px; color: white;"></i>
                            <h1 style="color: white; margin: 10px 0 0;">Email Verified!</h1>
                        </div>
                        <div style="padding: 30px 20px;">
                            <p style="color: #333; font-size: 16px;">Your email has been successfully verified.</p>
                            <p style="color: #666;">You can now proceed with your account upgrade by submitting your identification documents.</p>
                            <p style="color: #999; font-size: 12px; margin-top: 20px;">Thank you for choosing FEECENT.</p>
                        </div>
                    </div>
                </body>
                </html>
            `;
    } else {
      // Default password reset email
      subject = "FEECENT Password Reset Code";
      htmlContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>FEECENT Verification</title>
                </head>
                <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5;">
                    <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden;">
                        <div style="background: #6b21a8; padding: 20px; text-align: center;">
                            <h1 style="color: white; margin: 0;">FEECENT</h1>
                            <p style="color: #d8b4fe; margin: 5px 0 0;">Password Reset</p>
                        </div>
                        <div style="padding: 30px 20px;">
                            <h2 style="color: #333; margin-top: 0;">Password Reset</h2>
                            <p style="color: #666;">Your verification code is:</p>
                            <div style="background: #f8fafc; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                                <span style="font-size: 42px; font-weight: bold; letter-spacing: 8px; color: #6b21a8; font-family: monospace;">${otp}</span>
                            </div>
                            <p style="color: #666; font-size: 14px;">This code expires in <strong>10 minutes</strong>.</p>
                            <p style="color: #999; font-size: 12px; margin-top: 20px;">If you didn't request this, please ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
            `;
    }

    const mailOptions = {
      from: `"FEECENT" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
      to: email,
      subject: subject,
      html: htmlContent,
      text:
        type === "upgrade"
          ? `Your FEECENT account upgrade verification code is: ${otp}. Valid for 10 minutes.`
          : `Your FEECENT password reset code is: ${otp}. Valid for 10 minutes.`,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(
      `✅ ${type} email sent to ${email}, Message ID: ${info.messageId}`,
    );
    return true;
  } catch (error) {
    console.error(`❌ Email error (${type}):`, error.message);
    return false;
  }
}

// TEMPORARY DEBUG ROUTE - Put this FIRST
app.get("/api/test", (req, res) => {
  res.json({ message: "Server is working!", time: new Date().toISOString() });
});

// ==================== USER DASHBOARD ROUTES ====================

// Get user profile - Updated with all fields
app.get("/api/user/profile", authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select(
        `
        id,
        email,
        first_name,
        last_name,
        middle_name,
        phone,
        date_of_birth,
        age,
        gender,
        marital_status,
        occupation,
        referral_code,
        address,
        city,
        state,
        country,
        postal_code,
        identification_type,
        identification_number,
        kyc_status,
        role,
        admin_role,
        admin_permissions,
        two_factor_enabled,
        is_frozen,
        freeze_reason,
        face_verified,
        face_verification_date,
        created_at,
        updated_at
      `,
      )
      .eq("id", req.user.id)
      .single();

    if (error) {
      console.error("Profile fetch error:", error);
      return res.status(500).json({ error: "Failed to fetch profile" });
    }

    // Get face descriptor count (for UI display)
    const { count: faceCount, error: faceCountError } = await supabase
      .from("face_descriptors")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.user.id)
      .eq("is_active", true);

    if (faceCountError) {
      console.error("Face count error:", faceCountError);
    }

    // Check if user has passcode set
    const { data: passcodeCheck, error: passcodeError } = await supabase
      .from("users")
      .select("passcode_hash")
      .eq("id", req.user.id)
      .single();

    const hasPasscode = passcodeCheck && passcodeCheck.passcode_hash !== null;

    console.log("Profile fetched for user:", user.id);
    console.log("Face verified:", user.face_verified);
    console.log("Has passcode:", hasPasscode);

    res.json({
      ...user,
      has_passcode: hasPasscode,
      face_descriptor_count: faceCount || 0,
    });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// Update profile
app.put("/api/user/profile", authenticate, async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      phone,
      address,
      city,
      country,
      postal_code,
    } = req.body;

    const { data: user, error } = await supabase
      .from("users")
      .update({
        first_name,
        last_name,
        phone,
        address,
        city,
        country,
        postal_code,
        updated_at: new Date(),
      })
      .eq("id", req.user.id)
      .select()
      .single();

    if (error) throw error;

    res.json({ message: "Profile updated successfully", user });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// Change password

app.post("/api/user/change-password", authenticate, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    console.log("=== CHANGE PASSWORD REQUEST ===");
    console.log("User ID:", req.user?.id);
    console.log("User email:", req.user?.email);

    // IMPORTANT: Fetch fresh user data from database to ensure we have the password hash
    const { data: user, error: fetchError } = await supabase
      .from("users")
      .select("id, email, password_hash, first_name, last_name")
      .eq("id", req.user.id)
      .single();

    if (fetchError || !user) {
      console.error("User fetch error:", fetchError);
      return res.status(404).json({ error: "User not found" });
    }

    console.log("User found, has password hash:", !!user.password_hash);

    // Verify current password
    if (!user.password_hash) {
      console.error("No password hash found for user");
      return res.status(500).json({ error: "Account setup incomplete" });
    }

    const validPassword = await bcrypt.compare(
      current_password,
      user.password_hash,
    );
    if (!validPassword) {
      console.log("Current password incorrect for user:", user.email);
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(new_password, 10);

    // Update password
    const { error: updateError } = await supabase
      .from("users")
      .update({
        password_hash: hashedPassword,
        updated_at: new Date().toISOString(),
      })
      .eq("id", req.user.id);

    if (updateError) {
      console.error("Password update error:", updateError);
      return res.status(500).json({ error: "Failed to update password" });
    }

    console.log("Password changed successfully for user:", user.email);
    res.json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Password change error:", error);
    res
      .status(500)
      .json({ error: "Failed to change password: " + error.message });
  }
});

// Enable 2FA
app.post("/api/user/enable-2fa", authenticate, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({
      name: `BankApp:${req.user.email}`,
    });

    // Save secret to user
    await supabase
      .from("users")
      .update({ two_factor_secret: secret.base32 })
      .eq("id", req.user.id);

    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    res.json({ secret: secret.base32, qrCode });
  } catch (error) {
    console.error("2FA enable error:", error);
    res.status(500).json({ error: "Failed to enable 2FA" });
  }
});

// Verify and activate 2FA
app.post("/api/user/verify-enable-2fa", authenticate, async (req, res) => {
  try {
    const { token } = req.body;

    const verified = speakeasy.totp.verify({
      secret: req.user.two_factor_secret,
      encoding: "base32",
      token,
    });

    if (!verified) {
      return res.status(401).json({ error: "Invalid token" });
    }

    await supabase
      .from("users")
      .update({ two_factor_enabled: true })
      .eq("id", req.user.id);

    res.json({ message: "2FA enabled successfully" });
  } catch (error) {
    console.error("2FA verification error:", error);
    res.status(500).json({ error: "Failed to verify 2FA" });
  }
});

// Disable 2FA
app.post("/api/user/disable-2fa", authenticate, async (req, res) => {
  try {
    await supabase
      .from("users")
      .update({
        two_factor_enabled: false,
        two_factor_secret: null,
      })
      .eq("id", req.user.id);

    res.json({ message: "2FA disabled successfully" });
  } catch (error) {
    console.error("2FA disable error:", error);
    res.status(500).json({ error: "Failed to disable 2FA" });
  }
});

// Get accounts and balances (allow frozen users to see balance)
app.get("/api/user/accounts", authenticate, async (req, res) => {
  try {
    const { data: accounts, error } = await supabase
      .from("accounts")
      .select("*")
      .eq("user_id", req.user.id);

    if (error) throw error;

    res.json(accounts);
  } catch (error) {
    console.error("Accounts fetch error:", error);
    res.status(500).json({ error: "Failed to fetch accounts" });
  }
});

app.get(
  "/api/user/accounts/:accountId/statement",
  authenticate,
  statementService.statementLimiter,
  statementService.handleGetStatementJson,
);

app.get(
  "/api/user/accounts/:accountId/statement/pdf",
  authenticate,
  statementService.statementLimiter,
  statementService.handleGetStatementPdf,
);

// Get user transactions - FIXED VERSION
app.get(
  "/api/user/transactions",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { page = 1, limit = 20, start_date, end_date, type } = req.query;
      const offset = (parseInt(page) - 1) * parseInt(limit);

      // Get user's account IDs
      const { data: accounts, error: accountsError } = await supabase
        .from("accounts")
        .select("id")
        .eq("user_id", req.user.id);

      if (accountsError) throw accountsError;

      const accountIds = accounts.map((a) => a.id);

      if (accountIds.length === 0) {
        return res.json({
          transactions: [],
          pagination: { page: 1, limit: 20, total: 0, pages: 0 },
        });
      }

      // SIMPLE FIX: Get ALL transactions where user is sender OR receiver
      // But we'll filter out failed ones for receiver in JavaScript
      let query = supabase
        .from("transactions_new")
        .select(
          "id, transaction_reference, amount, description, transaction_type, status, created_at, completed_at, sender_account_id, receiver_account_id, sender_user_id, receiver_user_id, external_counterparty_name, external_counterparty_account, external_counterparty_bank",
          { count: "exact" },
        )
        .or(
          `sender_user_id.eq.${req.user.id},receiver_user_id.eq.${req.user.id}`,
        )
        .order("created_at", { ascending: false });

      // Apply filters
      if (start_date) {
        query = query.gte("created_at", start_date);
      }
      if (end_date) {
        query = query.lte("created_at", `${end_date}T23:59:59`);
      }
      if (type && type !== "all") {
        query = query.eq("transaction_type", type);
      }

      const {
        data: transactions,
        error,
        count,
      } = await query.range(offset, offset + parseInt(limit) - 1);

      if (error) {
        console.error("Transaction query error:", error);
        throw error;
      }

      // FILTER: Remove failed transactions from receiver's view
      const filteredTransactions = (transactions || []).filter((t) => {
        // If it's a failed/rejected transaction, only show to sender
        if (t.status === "failed" || t.status === "rejected") {
          return t.sender_user_id === req.user.id;
        }
        // For completed/pending, show to both
        return true;
      });

      // Get user details separately (only for displayed transactions)
      const userIds = new Set();
      filteredTransactions.forEach((t) => {
        if (t.sender_user_id) userIds.add(t.sender_user_id);
        if (t.receiver_user_id) userIds.add(t.receiver_user_id);
      });

      let userDetails = {};
      if (userIds.size > 0) {
        const { data: users } = await supabase
          .from("users")
          .select("id, first_name, last_name, email")
          .in("id", [...userIds]);

        userDetails = (users || []).reduce((acc, u) => {
          acc[u.id] = u;
          return acc;
        }, {});
      }

      // Get account details
      const accountIdsSet = new Set();
      filteredTransactions.forEach((t) => {
        if (t.sender_account_id) accountIdsSet.add(t.sender_account_id);
        if (t.receiver_account_id) accountIdsSet.add(t.receiver_account_id);
      });

      let accountDetails = {};
      if (accountIdsSet.size > 0) {
        const { data: accountsData } = await supabase
          .from("accounts")
          .select("id, account_number, account_type")
          .in("id", [...accountIdsSet]);

        accountDetails = (accountsData || []).reduce((acc, a) => {
          acc[a.id] = a;
          return acc;
        }, {});
      }

      // Combine data — include both the new sender_*/receiver_* names
      // and the old from_*/to_*/transaction_id aliases, since dashboard.js
      // reads the old names directly in several places.
      const enrichedTransactions = filteredTransactions.map((t) => ({
        ...t,
        transaction_id: t.transaction_reference,
        from_user_id: t.sender_user_id,
        to_user_id: t.receiver_user_id,
        from_account_id: t.sender_account_id,
        to_account_id: t.receiver_account_id,
        // No internal sender_user_id means the money came from outside
        // (e.g. a Flutterwave deposit) — fall back to the counterparty
        // fields captured on the transaction so the UI has a name to show
        // instead of blank/"Sender".
        from_user:
          userDetails[t.sender_user_id] ||
          (t.external_counterparty_name
            ? { first_name: t.external_counterparty_name, last_name: "" }
            : null),
        to_user: userDetails[t.receiver_user_id] || null,
        from_account: accountDetails[t.sender_account_id] || null,
        to_account: accountDetails[t.receiver_account_id] || null,
      }));

      res.json({
        transactions: enrichedTransactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / parseInt(limit)),
        },
      });
    } catch (error) {
      console.error("Transactions fetch error:", error);
      res
        .status(500)
        .json({ error: "Failed to fetch transactions: " + error.message });
    }
  },
);

// Get single transaction details for receipt viewing
app.get(
  "/api/user/transactions/:transactionId",
  authenticate,
  async (req, res) => {
    try {
      const { transactionId } = req.params;

      const { data: rawTransaction, error } = await supabase
        .from("transactions_new")
        .select(
          `
          *,
          from_account:accounts!transactions_new_sender_account_id_fkey(id, account_number),
          to_account:accounts!transactions_new_receiver_account_id_fkey(id, account_number),
          from_user:users!transactions_new_sender_user_id_fkey(id, first_name, last_name, email),
          to_user:users!transactions_new_receiver_user_id_fkey(id, first_name, last_name, email)
        `,
        )
        .eq("id", transactionId)
        .single();

      if (error) throw error;

      // Alias sender_*/receiver_* back to from_*/to_* for the frontend,
      // which reads these fields directly (receipt rendering, ownership checks).
      const transaction = {
        ...rawTransaction,
        transaction_id: rawTransaction.transaction_reference,
        from_user_id: rawTransaction.sender_user_id,
        to_user_id: rawTransaction.receiver_user_id,
        from_account_id: rawTransaction.sender_account_id,
        to_account_id: rawTransaction.receiver_account_id,
        // External counterparty (e.g. Flutterwave deposit sender, or an
        // external payout beneficiary) has no internal user row to join
        // against, so from_user/to_user come back null from the query
        // above. Fall back to the counterparty fields captured at credit
        // time so receipts show a real name instead of "Sender".
        from_user:
          rawTransaction.from_user ||
          (rawTransaction.external_counterparty_name
            ? {
                first_name: rawTransaction.external_counterparty_name,
                last_name: "",
              }
            : null),
        to_user: rawTransaction.to_user || null,
      };

      // SECURITY CHECK: Failed transactions only visible to sender
      if (
        transaction.status === "failed" ||
        transaction.status === "rejected"
      ) {
        if (transaction.from_user_id !== req.user.id) {
          return res.status(403).json({ error: "Access denied" });
        }
      } else {
        // For completed/pending, both parties can view
        if (
          transaction.from_user_id !== req.user.id &&
          transaction.to_user_id !== req.user.id
        ) {
          return res.status(403).json({ error: "Access denied" });
        }
      }

      res.json(transaction);
    } catch (error) {
      console.error("Transaction fetch error:", error);
      res.status(500).json({ error: "Failed to fetch transaction" });
    }
  },
);

// Download statement
app.get(
  "/api/user/statements",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { account_id, start_date, end_date, format = "csv" } = req.query;

      // Verify account belongs to user
      const { data: account } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", account_id)
        .eq("user_id", req.user.id)
        .single();

      if (!account) {
        return res.status(404).json({ error: "Account not found" });
      }

      // Get transactions
      const { data: transactions } = await supabase
        .from("transactions_new")
        .select("*")
        .or(
          `sender_account_id.eq.${account_id},receiver_account_id.eq.${account_id}`,
        )
        .gte("created_at", start_date)
        .lte("created_at", end_date)
        .order("created_at", { ascending: true });

      if (format === "csv") {
        // Generate CSV
        let csv = "Date,Description,Type,Amount,Balance\n";
        let balance = 0;

        transactions.forEach((t) => {
          const isCredit = t.receiver_account_id === account_id;
          const amount = isCredit ? t.amount : -t.amount;
          balance += amount;

          csv += `${t.created_at},${t.description},${isCredit ? "Credit" : "Debit"},${amount},${balance}\n`;
        });

        res.setHeader("Content-Type", "text/csv");
        res.setHeader(
          "Content-Disposition",
          "attachment; filename=statement.csv",
        );
        res.send(csv);
      } else {
        // Return JSON, aliased for frontend compatibility
        res.json(
          (transactions || []).map((t) => ({
            ...t,
            transaction_id: t.transaction_reference,
            from_account_id: t.sender_account_id,
            to_account_id: t.receiver_account_id,
            from_user_id: t.sender_user_id,
            to_user_id: t.receiver_user_id,
          })),
        );
      }
    } catch (error) {
      console.error("Statement generation error:", error);
      res.status(500).json({ error: "Failed to generate statement" });
    }
  },
);

// ============================================================
// ADD THIS TO YOUR index.js FILE
// ============================================================

// ==================== CHART OF ACCOUNTS API ====================

// GET all chart of accounts
app.get(
  "/api/sys/ledger/chart-of-accounts",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Fetch all active accounts from the chart_of_accounts table
      const { data: accounts, error } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .order("account_code", { ascending: true });

      if (error) {
        console.error("Error fetching chart of accounts:", error);
        return res.status(500).json({
          error: "Failed to fetch chart of accounts",
          details: error.message,
        });
      }

      // Return the accounts, or an empty array if none exist
      res.json({
        success: true,
        accounts: accounts || [],
      });
    } catch (error) {
      console.error("Chart of accounts error:", error);
      res.status(500).json({
        error: "Internal server error",
        details: error.message,
      });
    }
  },
);

// POST - Add a new account to chart of accounts
app.post(
  "/api/sys/ledger/chart-of-accounts",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        account_code,
        account_name,
        account_type,
        normal_balance,
        description,
        parent_account_id,
      } = req.body;

      // Validate required fields
      if (!account_code || !account_name || !account_type || !normal_balance) {
        return res.status(400).json({
          error:
            "Missing required fields: account_code, account_name, account_type, normal_balance",
        });
      }

      // Check if account code already exists
      const { data: existing, error: checkError } = await supabase
        .from("chart_of_accounts")
        .select("account_code")
        .eq("account_code", account_code)
        .maybeSingle();

      if (existing) {
        return res.status(409).json({
          error: "Account code already exists",
          account_code: account_code,
        });
      }

      // Insert new account
      const { data: account, error: insertError } = await supabase
        .from("chart_of_accounts")
        .insert({
          account_code,
          account_name,
          account_type,
          normal_balance,
          description: description || null,
          parent_account_id: parent_account_id || null,
          is_active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (insertError) {
        console.error("Error creating account:", insertError);
        return res.status(500).json({
          error: "Failed to create account",
          details: insertError.message,
        });
      }

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "create_chart_account",
        details: {
          account_code,
          account_name,
          account_type,
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.status(201).json({
        success: true,
        message: "Account created successfully",
        account: account,
      });
    } catch (error) {
      console.error("Create chart account error:", error);
      res.status(500).json({
        error: "Internal server error",
        details: error.message,
      });
    }
  },
);

// PUT - Update an existing chart of accounts entry
app.put(
  "/api/sys/ledger/chart-of-accounts/:accountCode",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { accountCode } = req.params;
      const {
        account_name,
        account_type,
        normal_balance,
        description,
        parent_account_id,
        is_active,
      } = req.body;

      // Check if account exists
      const { data: existing, error: checkError } = await supabase
        .from("chart_of_accounts")
        .select("account_code")
        .eq("account_code", accountCode)
        .maybeSingle();

      if (!existing) {
        return res.status(404).json({
          error: "Account not found",
          account_code: accountCode,
        });
      }

      // Update account
      const { data: account, error: updateError } = await supabase
        .from("chart_of_accounts")
        .update({
          account_name: account_name || existing.account_name,
          account_type: account_type || existing.account_type,
          normal_balance: normal_balance || existing.normal_balance,
          description:
            description !== undefined ? description : existing.description,
          parent_account_id:
            parent_account_id !== undefined
              ? parent_account_id
              : existing.parent_account_id,
          is_active: is_active !== undefined ? is_active : existing.is_active,
          updated_at: new Date().toISOString(),
        })
        .eq("account_code", accountCode)
        .select()
        .single();

      if (updateError) {
        console.error("Error updating account:", updateError);
        return res.status(500).json({
          error: "Failed to update account",
          details: updateError.message,
        });
      }

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "update_chart_account",
        details: {
          account_code: accountCode,
          updated_fields: Object.keys(req.body),
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Account updated successfully",
        account: account,
      });
    } catch (error) {
      console.error("Update chart account error:", error);
      res.status(500).json({
        error: "Internal server error",
        details: error.message,
      });
    }
  },
);

// DELETE - Deactivate (soft delete) a chart of accounts entry
app.delete(
  "/api/sys/ledger/chart-of-accounts/:accountCode",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { accountCode } = req.params;

      // Check if account exists
      const { data: existing, error: checkError } = await supabase
        .from("chart_of_accounts")
        .select("account_code, is_active")
        .eq("account_code", accountCode)
        .maybeSingle();

      if (!existing) {
        return res.status(404).json({
          error: "Account not found",
          account_code: accountCode,
        });
      }

      // Soft delete - set inactive instead of hard delete
      const { error: updateError } = await supabase
        .from("chart_of_accounts")
        .update({
          is_active: false,
          updated_at: new Date().toISOString(),
        })
        .eq("account_code", accountCode);

      if (updateError) {
        console.error("Error deleting account:", updateError);
        return res.status(500).json({
          error: "Failed to deactivate account",
          details: updateError.message,
        });
      }

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "delete_chart_account",
        details: {
          account_code: accountCode,
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Account deactivated successfully",
      });
    } catch (error) {
      console.error("Delete chart account error:", error);
      res.status(500).json({
        error: "Internal server error",
        details: error.message,
      });
    }
  },
);

// Enhanced transfer with device trust and recipient checking - WITH EARLY FAILURE RECORDING
app.post(
  "/api/user/transfer",
  authenticate,
  checkAccountFrozen,
  preventConcurrentTransfer, // 3. Acquire lock (prevents concurrent)
  releaseTransactionLock, // 4. Ensures lock is released
  transferLimiter,
  async (req, res) => {
    let failedRecordId = null;

    // (a) added transfer_auth_token
    const {
      from_account_id,
      to_account_number,
      amount,
      description,
      transfer_auth_token,
    } = req.body;
    // FIXED: same UUID-format issue as adjust-balance below — process_transfer's
    // p_request_id is UUID-typed too, so this route was equally exposed to
    // the auto-generated `${Date.now()}-${random}` Idempotency-Key header.
    const requestId = safeRequestId(
      req.headers["idempotency-key"] || req.body.requestId,
    );

    try {
      if (!from_account_id || !to_account_number || !amount || amount <= 0) {
        return res
          .status(400)
          .json({ error: "Missing or invalid fields", code: "INVALID_INPUT" });
      }

      // (b) NEW — enforce that a valid, matching, unused PIN authorization
      // exists for this exact transfer before touching any balances.
      if (!transfer_auth_token) {
        return res.status(401).json({
          error: "Transfer PIN verification required",
          code: "PIN_VERIFICATION_REQUIRED",
        });
      }

      const contextHash = hashTransferContext(
        from_account_id,
        to_account_number,
        amount,
      );

      const { data: authRecord, error: authError } = await supabase
        .from("transfer_authorizations")
        .select("id, used, expires_at, context_hash, user_id")
        .eq("token", transfer_auth_token)
        .single();

      if (
        authError ||
        !authRecord ||
        authRecord.used ||
        authRecord.user_id !== req.user.id ||
        authRecord.context_hash !== contextHash ||
        new Date(authRecord.expires_at) < new Date()
      ) {
        return res.status(401).json({
          error:
            "Invalid or expired transfer authorization. Please re-enter your PIN.",
          code: "PIN_VERIFICATION_REQUIRED",
        });
      }

      // Mark used immediately (single-use). Doing this before
      // process_transfer means a token can't be raced across two
      // concurrent requests even if preventConcurrentTransfer's lock has
      // any edge-case gap.
      await supabase
        .from("transfer_authorizations")
        .update({ used: true })
        .eq("id", authRecord.id);

      const {
        from_account_id,
        to_account_number,
        amount,
        description,
        device_fingerprint,
        skip_security_check = false,
        requires_otp = false,
      } = req.body;

      // Get user agent and IP for logging
      const userAgent = req.headers["user-agent"];
      const ip =
        req.ip ||
        req.connection.remoteAddress ||
        req.headers["x-forwarded-for"];

      // ========== STEP 1: CREATE INITIAL FAILED RECORD (in case anything fails) ==========
      const initialRecord = await createInitialFailedTransactionRecord(
        req.user.id,
        from_account_id,
        to_account_number,
        amount,
        description,
        ip,
        userAgent,
      );
      if (initialRecord) {
        failedRecordId = initialRecord.id;
      }

      // ========== VALIDATION CHECKS ==========

      // Validate amount
      if (!amount || amount <= 0) {
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            "Invalid amount",
            "validation_error",
          );
        }
        return res.status(400).json({ error: "Invalid amount" });
      }

      // Get source account
      const { data: fromAccount, error: fromError } = await supabase
        .from("accounts")
        .select("*, users!inner(id, email, first_name, last_name, phone)")
        .eq("id", from_account_id)
        .eq("user_id", req.user.id)
        .single();

      if (fromError || !fromAccount) {
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            "Source account not found",
            "account_error",
          );
        }
        return res.status(404).json({ error: "Source account not found" });
      }

      // ========== DAILY LIMIT CHECK (ADD THIS) ==========
      const dailyLimitCheck = await checkDailyTransferLimit(
        req.user.id,
        amount,
        fromAccount.users?.account_tier || 1,
      );

      if (!dailyLimitCheck.allowed) {
        const failureReason = dailyLimitCheck.reason;
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            failureReason,
            "daily_limit_exceeded",
            {
              daily_limit: dailyLimitCheck.daily_limit,
              daily_used: dailyLimitCheck.daily_used,
              amount_requested: amount,
              remaining: dailyLimitCheck.remaining,
              user_tier: fromAccount.users?.account_tier || 1,
            },
          );
        }
        return res.status(400).json({
          error: failureReason,
          failed_record_id: failedRecordId,
          limit_type: "daily",
          daily_limit: dailyLimitCheck.daily_limit,
          daily_used: dailyLimitCheck.daily_used,
          remaining: dailyLimitCheck.remaining,
        });
      }

      // ========== SINGLE TRANSFER LIMIT CHECK (ADD THIS) ==========
      const singleLimitCheck = await checkSingleTransferLimit(
        req.user.id,
        amount,
        fromAccount.users?.account_tier || 1,
      );

      if (!singleLimitCheck.allowed) {
        const failureReason = singleLimitCheck.reason;
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            failureReason,
            "single_limit_exceeded",
            {
              single_limit: singleLimitCheck.single_limit,
              amount_requested: amount,
              user_tier: fromAccount.users?.account_tier || 1,
            },
          );
        }
        return res.status(400).json({
          error: failureReason,
          failed_record_id: failedRecordId,
          limit_type: "single",
          single_limit: singleLimitCheck.single_limit,
        });
      }

      // ========== BALANCE CHECK WITH DIRECT DATABASE UPDATE ==========
      if (fromAccount.available_balance < amount) {
        console.log(
          `❌ INSUFFICIENT BALANCE: User ${req.user.id}, Available: ${fromAccount.available_balance}, Required: ${amount}`,
        );

        let finalTransactionUuid = null;
        const failureReason = `Insufficient balance. Available: ₦${fromAccount.available_balance.toLocaleString()}, Required: ₦${amount.toLocaleString()}`;

        // Check if we have a pending record ID from earlier
        if (failedRecordId) {
          console.log(`📝 Updating existing pending record: ${failedRecordId}`);

          // DIRECT UPDATE - NO HELPER FUNCTION
          const { error: updateError } = await supabase
            .from("transactions_new")
            .update({
              status: "failed",
              failed_reason: failureReason,
              failure_type: "balance_error",
              description: `Failed transfer - Insufficient funds. Available: ₦${fromAccount.available_balance.toLocaleString()}, Required: ₦${amount.toLocaleString()}`,
              completed_at: new Date().toISOString(),
            })
            .eq("id", failedRecordId);

          if (updateError) {
            console.error("❌ Update failed:", updateError);
          } else {
            console.log(
              `✅ Successfully updated record ${failedRecordId} with balance error`,
            );
            finalTransactionUuid = failedRecordId;

            // VERIFY the update worked
            const { data: verify } = await supabase
              .from("transactions_new")
              .select("failed_reason, status")
              .eq("id", failedRecordId)
              .single();

            console.log(
              `🔍 Verification - Status: ${verify?.status}, Reason: ${verify?.failed_reason}`,
            );
          }
        } else {
          // Create a brand new failed record
          console.log(`📝 Creating new failed record for balance error`);

          const transactionId = `FAIL${Date.now()}${Math.floor(Math.random() * 10000)}`;

          const { data: newRecord, error: insertError } = await supabase
            .from("transactions_new")
            .insert({
              transaction_id: transactionId,
              from_account_id: from_account_id,
              to_account_id: toAccount?.id || null,
              from_user_id: req.user.id,
              to_user_id: toAccount?.user_id || null,
              amount: amount,
              fee_amount: 0,
              description: description || `Transfer to ${to_account_number}`,
              transaction_type: "transfer",
              status: "failed",
              failed_reason: failureReason,
              failure_type: "balance_error",
              created_at: new Date().toISOString(),
              completed_at: new Date().toISOString(),
              ip_address: ip,
              user_agent: userAgent,
            })
            .select()
            .single();

          if (insertError) {
            console.error("❌ Failed to create failed record:", insertError);
          } else {
            console.log(`✅ Created new failed record: ${newRecord.id}`);
            finalTransactionUuid = newRecord.id;
          }
        }

        // Return the response with the record ID
        return res.status(400).json({
          error: "Insufficient funds",
          failed_record_id: finalTransactionUuid,
          failed_record_uuid: finalTransactionUuid,
          available_balance: fromAccount.available_balance,
          required_amount: amount,
        });
      }

      // Add this check in the transfer route after balance check
      const tierLimitCheck = await checkTierTransferLimit(req.user.id, amount);
      if (!tierLimitCheck.allowed) {
        return res
          .status(400)
          .json({ error: tierLimitCheck.error, tier_limit_exceeded: true });
      }

      // Get destination account
      const { data: toAccount, error: toError } = await supabase
        .from("accounts")
        .select("*, users!inner(id, email, first_name, last_name, is_frozen)")
        .eq("account_number", to_account_number)
        .single();

      if (toError || !toAccount) {
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            "Destination account not found",
            "account_error",
          );
        }
        return res.status(404).json({ error: "Destination account not found" });
      }

      // Update the failed record with correct to_account_id and to_user_id
      if (failedRecordId) {
        await supabase
          .from("transactions_new")
          .update({
            to_account_id: toAccount.id,
            to_user_id: toAccount.user_id,
          })
          .eq("id", failedRecordId);
      }

      // Prevent self-transfer
      if (toAccount.user_id === req.user.id) {
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            "Cannot transfer to own account",
            "validation_error",
          );
        }
        return res
          .status(400)
          .json({ error: "Cannot transfer to your own account" });
      }

      // Check if destination account is frozen
      if (toAccount.users?.is_frozen) {
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            "Destination account frozen",
            "account_frozen",
          );
        }
        return res.status(400).json({ error: "Destination account is frozen" });
      }

      // ========== SECURITY CHECKS ==========

      // 1. Update device trust tracking
      const deviceTrust = await updateDeviceTrust(
        req.user.id,
        device_fingerprint || req.headers["user-agent"],
        req.headers["user-agent"],
        req.ip,
      );

      // 2. Get user's current transfer threshold
      const userThreshold = await getUserTransferThreshold(
        req.user.id,
        device_fingerprint || req.headers["user-agent"],
      );

      // 3. Check if this is a large transfer (over ₦200,000)
      const isLargeTransfer = amount > 200000;

      // 4. Check if recipient is new (first time transfer)
      const isNewRecipient = !(await hasTransferredToBefore(
        req.user.id,
        to_account_number,
      ));

      // 5. Check if amount exceeds device threshold
      const exceedsThreshold = amount > userThreshold.threshold;

      // ========== SECURITY RESPONSES WITH FAILURE RECORDING ==========

      // Case 1: New device with amount above threshold
      if (
        !skip_security_check &&
        exceedsThreshold &&
        userThreshold.reason === "new_device"
      ) {
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            `New device limit: ₦${userThreshold.threshold.toLocaleString()}`,
            "security_new_device",
            {
              threshold: userThreshold.threshold,
              device_age: userThreshold.deviceAge,
            },
          );
        }

        return res.status(403).json({
          error: "new_device_limit",
          message: `This device is not yet trusted. For security, transfers are limited to ₦${userThreshold.threshold.toLocaleString()} on new devices.`,
          threshold: userThreshold.threshold,
          device_age: userThreshold.deviceAge,
          required_days: 2 - (userThreshold.deviceAge || 0),
          reason: "new_device",
          failed_record_id: failedRecordId,
        });
      }

      // Case 2: New recipient - require confirmation (not a failure yet)
      if (!skip_security_check && isNewRecipient) {
        // This is not a failure, just pending confirmation
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            "Awaiting new recipient confirmation",
            "pending_confirmation",
          );
        }

        return res.status(403).json({
          error: "new_recipient",
          message:
            "You haven't transferred to this recipient before. Please verify their details carefully.",
          recipient: {
            name: `${toAccount.users?.first_name || ""} ${toAccount.users?.last_name || ""}`.trim(),
            account_number: to_account_number,
          },
          require_confirmation: true,
          failed_record_id: failedRecordId,
        });
      }

      // Case 3: Large transfer - require confirmation
      if (!skip_security_check && isLargeTransfer) {
        if (failedRecordId) {
          await updateFailedTransactionRecord(
            failedRecordId,
            "Awaiting large transfer confirmation",
            "pending_confirmation",
          );
        }

        return res.status(403).json({
          error: "large_transfer",
          message: `You are about to transfer ₦${amount.toLocaleString()}. Please verify the recipient details carefully to avoid errors.`,
          recipient: {
            name: `${toAccount.users?.first_name || ""} ${toAccount.users?.last_name || ""}`.trim(),
            account_number: to_account_number,
          },
          amount: amount,
          require_confirmation: true,
          failed_record_id: failedRecordId,
        });
      }

      // ========== CONTINUE WITH NORMAL TRANSFER PROCESSING ==========

      // If we get here, delete the failed record since transfer will succeed
      if (failedRecordId) {
        await supabase
          .from("transactions_new")
          .delete()
          .eq("id", failedRecordId);
        failedRecordId = null;
      }

      // Internal transfers made from the dedicated Internal Transfer
      // button are free, full stop — no ₦50-over-₦10k fee, no tier
      // lookup. This is the ONLY free path in the app. Transfers that
      // land on a Feecent user via the external TRANSFER button still
      // go through reserve_internal_transfer_as_external() in
      // external-transfer-service.js and are charged the normal
      // external fee schedule — see the NOTE in that file.
      let feeAmount = 0;

      const totalDeduction = amount + feeAmount;

      // Final balance check
      if (fromAccount.available_balance < totalDeduction) {
        // Re-create failed record since balance check failed
        const newFailedRecord = await createInitialFailedTransactionRecord(
          req.user.id,
          from_account_id,
          to_account_number,
          amount,
          description,
          ip,
          userAgent,
        );
        if (newFailedRecord) {
          await updateFailedTransactionRecord(
            newFailedRecord.id,
            "Insufficient funds after fee calculation",
            "balance_error",
            {
              available_balance: fromAccount.available_balance,
              amount: totalDeduction,
              user_id: req.user.id,
            },
          );
        }
        return res.status(400).json({
          error: `Insufficient funds. Amount: ₦${amount} + Fee: ₦${feeAmount} = ₦${totalDeduction}`,
        });
      }

      // Generate transaction ID
      const transactionId = `TXN${Date.now()}${Math.floor(Math.random() * 10000)}`;

      // Create transaction record
      const transactionData = {
        transaction_id: transactionId,
        from_account_id,
        to_account_id: toAccount.id,
        from_user_id: req.user.id,
        to_user_id: toAccount.user_id,
        amount: amount,
        fee_amount: feeAmount,
        description: description || `Transfer to ${toAccount.account_number}`,
        transaction_type: "transfer",
        status: "pending",
        created_at: new Date().toISOString(),
      };

      // Check for OTP requirement
      const isLargeAmount = amount > 500000;
      const needsOTP = requires_otp || isLargeAmount;

      if (needsOTP && process.env.OTP_MODE === "on") {
        transactionData.requires_otp = true;

        const { data: transaction, error: txError } = await supabase
          .from("transactions_new")
          .insert(transactionData)
          .select()
          .single();

        if (txError) throw txError;

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        await supabase.from("otps").insert({
          user_id: req.user.id,
          transaction_id: transaction.id,
          otp_code: otpCode,
          otp_type: "transfer",
          expires_at: expiresAt,
        });

        await sendOTPEmail(fromAccount.users.email, otpCode);

        return res.json({
          message: "OTP required to complete transfer",
          requires_otp: true,
          transaction_id: transaction.id,
        });
      }

      // Process transfer immediately
      transactionData.status = "completed";
      transactionData.completed_at = new Date().toISOString();

      const { data: transaction, error: txError } = await supabase
        .from("transactions_new")
        .insert(transactionData)
        .select()
        .single();

      if (txError) throw txError;

      // Update balances
      const newSenderBalance = fromAccount.balance - totalDeduction;
      const newSenderAvailable = fromAccount.available_balance - totalDeduction;

      await supabase
        .from("accounts")
        .update({
          balance: newSenderBalance,
          available_balance: newSenderAvailable,
          updated_at: new Date().toISOString(),
        })
        .eq("id", from_account_id);

      const newReceiverBalance = toAccount.balance + amount;
      const newReceiverAvailable = toAccount.available_balance + amount;

      await supabase
        .from("accounts")
        .update({
          balance: newReceiverBalance,
          available_balance: newReceiverAvailable,
          updated_at: new Date().toISOString(),
        })
        .eq("id", toAccount.id);

      // ========== RECORD TO GENERAL LEDGER (DOUBLE ENTRY) ==========
      try {
        // Get the user data for sender and receiver
        const { data: fromUser } = await supabase
          .from("users")
          .select("id, email, first_name, last_name")
          .eq("id", req.user.id)
          .single();

        const { data: toUser } = await supabase
          .from("users")
          .select("id, email, first_name, last_name")
          .eq("id", toAccount.user_id)
          .single();

        // Record debit for sender
        await supabase.from("general_ledger").insert({
          transaction_id: transaction.id,
          user_id: req.user.id,
          account_code: "2000", // Customer Liabilities
          account_name: "Customer Liabilities",
          debit_amount: amount,
          credit_amount: 0,
          description: `Transfer to ${toAccount.account_number} (${toUser?.first_name || ""} ${toUser?.last_name || ""})`,
          reference: transaction.transaction_id,
          entry_date: new Date(),
          posted_by: null,
          posted_at: new Date(),
          is_reconciled: false,
        });

        // Record credit for receiver
        await supabase.from("general_ledger").insert({
          transaction_id: transaction.id,
          user_id: toAccount.user_id,
          account_code: "2000", // Customer Liabilities
          account_name: "Customer Liabilities",
          debit_amount: 0,
          credit_amount: amount,
          description: `Transfer from ${fromAccount.account_number} (${fromUser?.first_name || ""} ${fromUser?.last_name || ""})`,
          reference: transaction.transaction_id,
          entry_date: new Date(),
          posted_by: null,
          posted_at: new Date(),
          is_reconciled: false,
        });

        // Record fee if applicable
        if (feeAmount > 0) {
          await supabase.from("general_ledger").insert({
            transaction_id: transaction.id,
            user_id: null,
            account_code: "4020", // Transfer Fees
            account_name: "Transfer Fees",
            debit_amount: 0,
            credit_amount: feeAmount,
            description: `Transfer fee for transaction ${transaction.transaction_id}`,
            reference: transaction.transaction_id,
            entry_date: new Date(),
            posted_by: null,
            posted_at: new Date(),
            is_reconciled: false,
          });
        }

        console.log(
          "✅ Ledger entries recorded for transaction:",
          transaction.id,
        );
      } catch (ledgerError) {
        console.error("Ledger recording error:", ledgerError);
        // Don't fail the transaction, just log the error
      }

      // ========== RECORD TO SINGLE LEDGER ==========
      try {
        // Record for sender
        await supabase.from("single_ledger").insert({
          ledger_id: `SL${Date.now()}${Math.floor(Math.random() * 10000)}`,
          user_id: req.user.id,
          account_id: from_account_id,
          account_number: fromAccount.account_number,
          transaction_id: transaction.id,
          transaction_type: "transfer",
          amount: amount,
          balance_before: fromAccount.balance,
          balance_after: fromAccount.balance - (amount + feeAmount),
          description: description || `Transfer to ${toAccount.account_number}`,
          reference: transaction.transaction_id,
          direction: "Debit",
          created_at: new Date(),
        });

        // Record for receiver
        await supabase.from("single_ledger").insert({
          ledger_id: `SL${Date.now()}${Math.floor(Math.random() * 10000)}`,
          user_id: toAccount.user_id,
          account_id: toAccount.id,
          account_number: toAccount.account_number,
          transaction_id: transaction.id,
          transaction_type: "transfer",
          amount: amount,
          balance_before: toAccount.balance,
          balance_after: toAccount.balance + amount,
          description:
            description || `Transfer from ${fromAccount.account_number}`,
          reference: transaction.transaction_id,
          direction: "Credit",
          created_at: new Date(),
        });

        console.log("✅ Single ledger entries recorded");
      } catch (singleLedgerError) {
        console.error("Single ledger error:", singleLedgerError);
      }

      // Create notifications
      await createNotification(
        req.user.id,
        "Transfer Completed",
        `You transferred ₦${amount.toLocaleString()} to ${toAccount.account_number}. Fee: ₦${feeAmount}`,
        "success",
      );

      await createNotification(
        toAccount.user_id,
        "Money Received",
        `You received ₦${amount.toLocaleString()} from ${fromAccount.users.first_name} ${fromAccount.users.last_name}`,
        "success",
      );

      // Log successful transfer
      await logSecurityEvent(req.user.id, "transfer_completed", {
        amount,
        to_account: toAccount.account_number,
        transaction_id: transaction.id,
      });

      res.json({
        message: "Transfer completed successfully",
        transaction: {
          id: transaction.id,
          transaction_id: transaction.transaction_id,
          amount: amount,
          fee: feeAmount,
          total_deducted: totalDeduction,
          new_balance: newSenderAvailable,
          description: transaction.description,
          completed_at: transaction.completed_at,
        },
        recipient: {
          name: `${toAccount.users?.first_name || ""} ${toAccount.users?.last_name || ""}`.trim(),
          account_number: toAccount.account_number,
        },
      });
    } catch (error) {
      console.error("Transfer error:", error);

      // Update the failed record if it exists
      if (failedRecordId) {
        await updateFailedTransactionRecord(
          failedRecordId,
          error.message || "Internal server error",
          "server_error",
        );
      } else {
        // Create a new failed record
        const newFailedRecord = await createInitialFailedTransactionRecord(
          req.user.id,
          req.body.from_account_id,
          req.body.to_account_number,
          req.body.amount,
          req.body.description,
          req.ip,
          req.headers["user-agent"],
        );
        if (newFailedRecord) {
          await updateFailedTransactionRecord(
            newFailedRecord.id,
            error.message || "Internal server error",
            "server_error",
          );
        }
      }

      await logSecurityEvent(req.user.id, "transfer_failed", {
        error: error.message,
      });
      res.status(500).json({ error: "Transfer failed: " + error.message });
    }
  },
);

// ============================================================
// NEW TRANSFER ROUTE - Add to index.js
// ============================================================

/*const FinancialTransactionService = require("./services/FinancialTransactionService");
const transactionService = new FinancialTransactionService();

app.post(
  "/api/user/transfer",
  authenticate,
  checkAccountFrozen,
  preventConcurrentTransfer,
  releaseTransactionLock,
  async (req, res) => {
    const { from_account_id, to_account_number, amount, description } =
      req.body;
    const requestId =
      req.headers["idempotency-key"] ||
      req.body.requestId ||
      crypto.randomUUID();

    try {
      // Validate inputs
      if (!from_account_id || !to_account_number || !amount || amount <= 0) {
        return res.status(400).json({
          error: "Missing or invalid fields",
          code: "INVALID_INPUT",
        });
      }

      // Get source account
      const { data: fromAccount, error: fromError } = await supabase
        .from("accounts")
        .select("id, user_id, account_number, balance, available_balance")
        .eq("id", from_account_id)
        .eq("user_id", req.user.id)
        .single();

      if (fromError || !fromAccount) {
        return res.status(404).json({
          error: "Source account not found",
          code: "ACCOUNT_NOT_FOUND",
        });
      }

      // Get destination account
      const { data: toAccount, error: toError } = await supabase
        .from("accounts")
        .select("id, user_id, account_number")
        .eq("account_number", to_account_number)
        .single();

      if (toError || !toAccount) {
        return res.status(404).json({
          error: "Destination account not found",
          code: "ACCOUNT_NOT_FOUND",
        });
      }

      // Prevent self-transfer
      if (fromAccount.user_id === toAccount.user_id) {
        return res.status(400).json({
          error: "Cannot transfer to your own account",
          code: "SELF_TRANSFER",
        });
      }

      // Check if destination account is frozen
      const { data: toUser, error: userError } = await supabase
        .from("users")
        .select("is_frozen")
        .eq("id", toAccount.user_id)
        .single();

      if (toUser?.is_frozen) {
        return res.status(400).json({
          error: "Destination account is frozen",
          code: "ACCOUNT_FROZEN",
        });
      }

      // ========== SECURITY CHECKS ==========

      // 1. Update device trust tracking
      const deviceTrust = await updateDeviceTrust(
        req.user.id,
        device_fingerprint || req.headers["user-agent"],
        req.headers["user-agent"],
        req.ip,
      );

      // 2. Get user's current transfer threshold
      const userThreshold = await getUserTransferThreshold(
        req.user.id,
        device_fingerprint || req.headers["user-agent"],
      );

      // 3. Check if this is a large transfer (over ₦200,000)
      const isLargeTransfer = amount > 200000;

      // 4. Check if recipient is new (first time transfer)
      const isNewRecipient = !(await hasTransferredToBefore(
        req.user.id,
        to_account_number,
      ));

      // 5. Check if amount exceeds device threshold
      const exceedsThreshold = amount > userThreshold.threshold;

      // Calculate fee
      let feeAmount = 0;
      if (amount >= 10000) {
        feeAmount = 50;
      }

      // Get fee account ID from system settings
      const { data: feeAccountSetting } = await supabase
        .from("system_account_ids")
        .select("account_id")
        .eq("key", "FEE_ACCOUNT")
        .single();

      // Execute transaction atomically via process_transfer — one
      // Postgres function call, real FOR UPDATE row locking, real
      // all-or-nothing commit. Replaces the old
      // FinancialTransactionService.executeTransaction() path, which
      // could not actually guarantee atomicity across its separate
      // begin_transaction/rollback_transaction RPC calls.
      const { data: transferResult, error: transferError } = await supabase.rpc(
        "process_transfer",
        {
          p_request_id: requestId,
          p_user_id: req.user.id,
          p_from_account_id: fromAccount.id,
          p_to_account_id: toAccount.id,
          p_amount: amount,
          p_fee_amount: feeAmount,
          p_fee_account_id:
            feeAmount > 0 && feeAccountSetting
              ? feeAccountSetting.account_id
              : null,
          p_description:
            description || `Transfer to ${toAccount.account_number}`,
        },
      );

      if (transferError) {
        console.error("Transfer error:", transferError);

        if (
          transferError.message &&
          transferError.message.includes("Insufficient balance")
        ) {
          return res.status(400).json({
            error: "Insufficient balance",
            code: "INSUFFICIENT_BALANCE",
            message: transferError.message,
          });
        }

        if (transferError.message && transferError.message.includes("limit")) {
          return res.status(400).json({
            error: "Transfer limit exceeded",
            code: "LIMIT_EXCEEDED",
            message: transferError.message,
          });
        }

        return res.status(500).json({
          error: "Transfer failed",
          code: "TRANSFER_FAILED",
          message: transferError.message,
        });
      }

      res.json({
        success: true,
        message: transferResult.duplicate
          ? "Transfer already processed"
          : "Transfer completed successfully",
        transaction: {
          reference: transferResult.transaction_reference,
          amount: amount,
          fee: feeAmount,
          total_debited: amount + feeAmount,
          new_balance: transferResult.from_balance,
        },
      });
    } catch (error) {
      console.error("Transfer error:", error);
      res.status(500).json({
        error: "Transfer failed",
        code: "TRANSFER_FAILED",
        message: error.message,
      });
    }
  },
);*/

async function createInitialFailedTransactionRecord(
  userId,
  fromAccountId,
  toAccountNumber,
  amount,
  description,
  ip,
  userAgent,
) {
  try {
    // Get the source account details
    const { data: fromAccount } = await supabase
      .from("accounts")
      .select("account_number, user_id")
      .eq("id", fromAccountId)
      .single();

    // Try to get destination account info if it exists - BUT DON'T SET to_user_id for failed
    let toAccountId = null;
    let toUserId = null;
    let toAccountNumberDisplay = toAccountNumber;

    const { data: toAccount } = await supabase
      .from("accounts")
      .select("id, user_id, account_number")
      .eq("account_number", toAccountNumber)
      .maybeSingle();

    if (toAccount) {
      toAccountId = toAccount.id;
      // CRITICAL: DON'T set toUserId for failed transactions!
      // This ensures the failed transaction only shows for sender
      toUserId = null; // ← KEY FIX - don't set to_user_id for failed
      toAccountNumberDisplay = toAccount.account_number;
    }

    const transactionId = `FAIL${Date.now()}${Math.floor(Math.random() * 10000)}`;

    const transactionData = {
      transaction_id: transactionId,
      from_account_id: fromAccountId,
      to_account_id: toAccountId,
      from_user_id: userId,
      to_user_id: null, // ← CRITICAL FIX: Set to null for failed transactions
      amount: amount,
      fee_amount: 0,
      description:
        description || `Failed transfer to ${toAccountNumberDisplay}`,
      transaction_type: "transfer",
      status: "failed", // Set to failed directly
      failed_reason: null,
      failure_type: null,
      created_at: new Date().toISOString(),
      ip_address: ip,
      user_agent: userAgent,
    };

    const { data: inserted, error } = await supabase
      .from("transactions_new")
      .insert(transactionData)
      .select()
      .single();

    if (error) {
      console.error("Failed to create initial record:", error);
      return null;
    }

    try {
      await supabase.from("general_ledger").insert({
        transaction_id: failedRecordId,
        user_id: req.user.id,
        account_code: "1050", // Suspense Account for failed transactions
        account_name: "Suspense Account",
        debit_amount: 0,
        credit_amount: 0,
        description: `FAILED TRANSFER: ${failureReason.substring(0, 200)}`,
        reference: `FAIL_${Date.now()}`,
        entry_date: new Date(),
        posted_by: null,
        posted_at: new Date(),
        is_reconciled: false,
      });
    } catch (ledgerError) {
      console.error("Failed transaction ledger error:", ledgerError);
    }

    console.log(
      `📝 Created initial failed transaction record: ${transactionId}, Amount: ${amount}`,
    );
    return inserted;
  } catch (error) {
    console.error("Error creating initial record:", error);
    return null;
  }
}

async function updateFailedTransactionRecord(
  transactionRecordId,
  reason,
  failureType,
  details = {},
) {
  if (!transactionRecordId) {
    console.error(
      "No transactionRecordId provided to updateFailedTransactionRecord",
    );
    return false;
  }

  try {
    console.log(
      `🔄 Updating failed record ${transactionRecordId}: ${reason} (${failureType})`,
    );

    let finalReason = reason;
    let finalDescription = `Failed transfer - ${reason}`;

    // Build proper messages based on failure type
    if (failureType === "daily_limit_exceeded") {
      finalReason = `Daily limit exceeded. You have ₦${details.daily_used?.toLocaleString() || "N/A"} of ₦${details.daily_limit?.toLocaleString() || "N/A"} used. This transfer of ₦${details.amount_requested?.toLocaleString() || "N/A"} would exceed your limit. Remaining: ₦${details.remaining?.toLocaleString() || "N/A"}`;
      finalDescription = `Failed transfer - Daily limit exceeded. Tier ${details.user_tier || "N/A"} limit: ₦${details.daily_limit?.toLocaleString() || "N/A"}, Used today: ₦${details.daily_used?.toLocaleString() || "N/A"}, Attempted: ₦${details.amount_requested?.toLocaleString() || "N/A"}`;
    } else if (failureType === "single_limit_exceeded") {
      finalReason = `Single transfer limit is ₦${details.single_limit?.toLocaleString() || "N/A"}. Your transfer of ₦${details.amount_requested?.toLocaleString() || "N/A"} exceeds this limit.`;
      finalDescription = `Failed transfer - Single limit exceeded. Tier ${details.user_tier || "N/A"} limit: ₦${details.single_limit?.toLocaleString() || "N/A"}, Attempted: ₦${details.amount_requested?.toLocaleString() || "N/A"}`;
    } else if (failureType === "balance_error") {
      finalReason = `Insufficient balance. Available: ₦${details.available_balance?.toLocaleString() || "N/A"}, Required: ₦${details.required_amount?.toLocaleString() || "N/A"}`;
      finalDescription = `Failed transfer - Insufficient funds. Available: ₦${details.available_balance?.toLocaleString() || "N/A"}, Required: ₦${details.required_amount?.toLocaleString() || "N/A"}`;
    } else if (failureType === "validation_error") {
      finalReason = reason;
      finalDescription = `Failed transfer - ${reason}`;
    } else if (failureType === "account_error") {
      finalReason = reason;
      finalDescription = `Failed transfer - ${reason}`;
    } else if (failureType === "security_new_device") {
      finalReason = reason;
      finalDescription = `Failed transfer - ${reason}`;
    } else if (failureType === "account_frozen") {
      finalReason = reason;
      finalDescription = `Failed transfer - ${reason}`;
    } else if (failureType === "pin_error") {
      finalReason = reason;
      finalDescription = `Failed transfer - ${reason}`;
    }

    const updates = {
      failed_reason: finalReason,
      failure_type: failureType,
      description: finalDescription,
      status: "failed",
      // CRITICAL: Ensure to_user_id remains null for failed
      to_user_id: null,
      completed_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const { error } = await supabase
      .from("transactions_new")
      .update(updates)
      .eq("id", transactionRecordId);

    if (error) {
      console.error("Failed to update failed record:", error);
      return false;
    }

    console.log(`✅ Successfully updated failed record ${transactionRecordId}`);
    console.log(`   New failure_reason: ${finalReason}`);
    return true;
  } catch (error) {
    console.error("Error updating failed record:", error);
    return false;
  }
}

// Process fee income for admin (called by transfer route)
async function processFeeIncome(
  transaction,
  feeAmount,
  fromAccount,
  toAccount,
) {
  try {
    if (feeAmount <= 0) return;

    // Record fee as revenue
    const { error: feeError } = await supabase.from("transactions_new").insert({
      transaction_id: `FEE${Date.now()}${Math.floor(Math.random() * 1000)}`,
      from_account_id: fromAccount.id,
      to_account_id: null,
      from_user_id: fromAccount.user_id,
      to_user_id: null,
      amount: feeAmount,
      description: `Transfer fee for transaction ${transaction.transaction_id}`,
      transaction_type: "fee",
      status: "completed",
      completed_at: new Date().toISOString(),
      is_admin_adjusted: true,
      admin_note: "Auto-generated transfer fee",
    });

    if (feeError) {
      console.error("Fee transaction error:", feeError);
    }

    // Update fee income in ledger
    await supabase.from("general_ledger").insert({
      transaction_id: transaction.id,
      account_code: "4020", // Transfer Fees account
      account_name: "Transfer Fees",
      debit_amount: 0,
      credit_amount: feeAmount,
      description: `Transfer fee for transaction ${transaction.transaction_id}`,
      reference: transaction.transaction_id,
      entry_date: new Date().toISOString(),
      posted_by: null,
      posted_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Fee processing error:", error);
  }
}

// Get recipient name by account number (for transfer confirmation)
app.get("/api/accounts/recipient", authenticate, async (req, res) => {
  const { account_number } = req.query;

  if (
    !account_number ||
    typeof account_number !== "string" ||
    account_number.length < 8
  ) {
    return res.status(400).json({ error: "Invalid account number format" });
  }

  try {
    const { data, error } = await supabase
      .from("accounts")
      .select(
        `
        id,
        account_number,
        user_id,
        users!inner (
          first_name,
          last_name
        )
      `,
      )
      .eq("account_number", account_number)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: "Account not found" });
    }

    const fullName = `${data.users.first_name} ${data.users.last_name}`;

    res.json({
      success: true,
      name: fullName.trim(),
      account_id: data.id, // optional — useful later
      user_id: data.user_id,
    });
  } catch (err) {
    console.error("Recipient lookup error:", err);
    res.status(500).json({ error: "Failed to verify account" });
  }
});

// Get available fintech providers
/*app.get("/api/external/providers", authenticate, async (req, res) => {
  try {
    const providers = [
      {
        id: "paypal",
        name: "PayPal",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/paypal.svg",
        color: "#003087",
        fields: [
          {
            name: "recipient_email",
            label: "PayPal Email",
            type: "email",
            required: true,
          },
          {
            name: "recipient_name",
            label: "Full Name",
            type: "text",
            required: true,
          },
        ],
      },
      {
        id: "stripe",
        name: "Stripe",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/stripe.svg",
        color: "#635bff",
        fields: [
          {
            name: "recipient_email",
            label: "Stripe Account Email",
            type: "email",
            required: true,
          },
          {
            name: "recipient_name",
            label: "Business/Individual Name",
            type: "text",
            required: true,
          },
        ],
      },
      {
        id: "flutterwave",
        name: "Flutterwave",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/flutterwave.svg",
        color: "#f9a825",
        fields: [
          {
            name: "recipient_account",
            label: "Account Number",
            type: "text",
            required: true,
          },
          {
            name: "recipient_name",
            label: "Account Holder Name",
            type: "text",
            required: true,
          },
          {
            name: "recipient_email",
            label: "Email (Optional)",
            type: "email",
            required: false,
          },
        ],
      },
      {
        id: "paystack",
        name: "Paystack",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/paystack.svg",
        color: "#25c3f0",
        fields: [
          {
            name: "recipient_account",
            label: "Account Number",
            type: "text",
            required: true,
          },
          {
            name: "recipient_name",
            label: "Account Holder Name",
            type: "text",
            required: true,
          },
          {
            name: "recipient_phone",
            label: "Phone Number",
            type: "tel",
            required: true,
          },
        ],
      },
      {
        id: "wise",
        name: "Wise (TransferWise)",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/wise.svg",
        color: "#00b9b9",
        fields: [
          {
            name: "recipient_email",
            label: "Wise Email",
            type: "email",
            required: true,
          },
          {
            name: "recipient_name",
            label: "Recipient Name",
            type: "text",
            required: true,
          },
          {
            name: "recipient_account",
            label: "Account Number (if applicable)",
            type: "text",
            required: false,
          },
        ],
      },
      {
        id: "remitly",
        name: "Remitly",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/remitly.svg",
        color: "#00b9b9",
        fields: [
          {
            name: "recipient_name",
            label: "Recipient Name",
            type: "text",
            required: true,
          },
          {
            name: "recipient_phone",
            label: "Phone Number",
            type: "tel",
            required: true,
          },
          {
            name: "recipient_country",
            label: "Recipient Country",
            type: "text",
            required: true,
          },
        ],
      },
      {
        id: "worldremit",
        name: "WorldRemit",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/worldremit.svg",
        color: "#00b9b9",
        fields: [
          {
            name: "recipient_name",
            label: "Recipient Name",
            type: "text",
            required: true,
          },
          {
            name: "recipient_phone",
            label: "Phone Number",
            type: "tel",
            required: true,
          },
        ],
      },
      {
        id: "bank_transfer",
        name: "Bank Transfer",
        logo: "https://cdn.jsdelivr.net/gh/simple-icons/simple-icons/icons/bank.svg",
        color: "#4f46e5",
        fields: [
          {
            name: "bank_name",
            label: "Bank Name",
            type: "text",
            required: true,
          },
          {
            name: "recipient_account",
            label: "Account Number",
            type: "text",
            required: true,
          },
          {
            name: "recipient_name",
            label: "Account Holder Name",
            type: "text",
            required: true,
          },
          {
            name: "routing_number",
            label: "Routing Number",
            type: "text",
            required: true,
          },
          {
            name: "swift_code",
            label: "SWIFT/BIC Code",
            type: "text",
            required: false,
          },
        ],
      },
    ];

    res.json(providers);
  } catch (error) {
    console.error("Error fetching providers:", error);
    res.status(500).json({ error: "Failed to fetch providers" });
  }
});

// Create external transfer request
app.post(
  "/api/user/external-transfer",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    console.log("=== External Transfer Request Received ===");
    console.log("User ID:", req.user?.id);
    console.log("Request body:", req.body);

    try {
      const {
        from_account_id,
        provider_id,
        recipient_name,
        recipient_account,
        recipient_email,
        recipient_phone,
        amount,
        description,
        bank_name,
      } = req.body;

      console.log("Parsed data:", {
        from_account_id,
        provider_id,
        amount,
        bank_name,
      });

      // Validate amount
      if (!amount || amount <= 0) {
        console.log("Invalid amount:", amount);
        return res.status(400).json({ error: "Invalid amount" });
      }

      if (amount < 10000) {
        return res
          .status(400)
          .json({ error: "Minimum external transfer amount is ₦10,000" });
      }

      if (amount > 15000000) {
        return res
          .status(400)
          .json({ error: "Maximum external transfer amount is ₦15,000,000" });
      }

      // Get source account
      console.log("Fetching source account:", from_account_id);
      const { data: fromAccount, error: accountError } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", from_account_id)
        .eq("user_id", req.user.id)
        .single();

      if (accountError) {
        console.error("Account fetch error:", accountError);
        return res.status(404).json({
          error: "Source account not found",
          details: accountError.message,
        });
      }

      if (!fromAccount) {
        console.log("No account found for ID:", from_account_id);
        return res.status(404).json({ error: "Source account not found" });
      }

      console.log(
        "Source account found:",
        fromAccount.account_number,
        "Balance:",
        fromAccount.available_balance,
      );

      // Check sufficient funds
      if (fromAccount.available_balance < amount) {
        return res.status(400).json({ error: "Insufficient funds" });
      }

      // Get provider name
      let providerName = bank_name;
      if (provider_id) {
        const providers = {
          paypal: "PayPal",
          stripe: "Stripe",
          flutterwave: "Flutterwave",
          paystack: "Paystack",
          wise: "Wise",
          remitly: "Remitly",
          worldremit: "WorldRemit",
          bank_transfer: "Bank Transfer",
        };
        providerName = providers[provider_id] || bank_name || provider_id;
      }

      // Create external transfer record
      const transferData = {
        user_id: req.user.id,
        from_account_id: fromAccount.id,
        bank_name: providerName,
        recipient_name: recipient_name,
        recipient_account: recipient_account || null,
        recipient_email: recipient_email || null,
        recipient_phone: recipient_phone || null,
        amount: amount,
        description: description || `External transfer to ${providerName}`,
        status: "pending",
        created_at: new Date().toISOString(),
      };

      console.log("Inserting transfer record:", transferData);

      const { data: transfer, error: insertError } = await supabase
        .from("external_transfers")
        .insert(transferData)
        .select()
        .single();

      if (insertError) {
        console.error("Insert error:", insertError);
        return res.status(500).json({
          error: "Failed to create transfer record",
          details: insertError.message,
        });
      }

      console.log("Transfer record created:", transfer.id);

      // Immediately deduct amount from user balance
      const { error: updateError } = await supabase
        .from("accounts")
        .update({
          balance: fromAccount.balance - amount,
          available_balance: fromAccount.available_balance - amount,
          updated_at: new Date().toISOString(),
        })
        .eq("id", fromAccount.id);

      if (updateError) {
        console.error("Balance update error:", updateError);
        // Rollback would be ideal here, but for now log it
      }

      // Create transaction record for the deduction
      // NOTE: this /api/user/external-transfer route predates the
      // Flutterwave payout integration (/api/flutterwave/transfer) —
      // confirm whether it's still reachable from the frontend or safe
      // to remove, since it duplicates that flow.
      const { error: transError } = await supabase.from("transactions_new").insert({
        sender_account_id: fromAccount.id,
        sender_user_id: req.user.id,
        amount: amount,
        description: `External transfer to ${providerName} - ${recipient_name} (Pending approval)`,
        transaction_type: "external_transfer",
        status: "completed",
        completed_at: new Date().toISOString(),
        metadata: { is_admin_adjusted: false },
      });

      if (transError) {
        console.error("Transaction creation error:", transError);
      }

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: req.user.id,
        title: "External Transfer Initiated",
        message: `Your transfer of $${amount} to ${providerName} has been initiated. Funds have been deducted from your account and will be processed within 2-3 business days after approval.`,
        type: "info",
        created_at: new Date().toISOString(),
      });

      console.log("External transfer completed successfully");
      res.json({
        success: true,
        message:
          "External transfer initiated successfully. Funds will be processed within 2-3 business days.",
        transfer: transfer,
        estimated_completion: "2-3 business days",
      });
    } catch (error) {
      console.error("External transfer error - FULL DETAILS:", error);
      console.error("Error stack:", error.stack);
      res.status(500).json({
        error: "Failed to process external transfer",
        details: error.message,
        stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
      });
    }
  },
);

// Get user's external transfer history
app.get("/api/user/external-transfers", authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const offset = (page - 1) * limit;

    let query = supabase
      .from("external_transfers")
      .select("*", { count: "exact" })
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (status && status !== "all") {
      query = query.eq("status", status);
    }

    const {
      data: transfers,
      error,
      count,
    } = await query.range(offset, offset + limit - 1);

    if (error) throw error;

    res.json({
      transfers: transfers || [],
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching external transfers:", error);
    res.status(500).json({ error: "Failed to fetch external transfers" });
  }
});*/

// Verify OTP and complete transaction
app.post("/api/user/verify-otp", authenticate, async (req, res) => {
  try {
    const { transaction_id, otp_code } = req.body;

    // Get OTP record
    const { data: otpRecord } = await supabase
      .from("otps")
      .select("*")
      .eq("transaction_id", transaction_id)
      .eq("otp_code", otp_code)
      .eq("is_used", false)
      .single();

    if (!otpRecord || new Date(otpRecord.expires_at) < new Date()) {
      return res.status(401).json({ error: "Invalid or expired OTP" });
    }

    // Mark OTP as used
    await supabase
      .from("otps")
      .update({ is_used: true })
      .eq("id", otpRecord.id);

    // Get transaction
    const { data: transaction } = await supabase
      .from("transactions_new")
      .select("*")
      .eq("id", transaction_id)
      .single();

    // Get accounts
    const { data: fromAccount } = await supabase
      .from("accounts")
      .select("*")
      .eq("id", transaction.sender_account_id)
      .single();

    const { data: toAccount } = await supabase
      .from("accounts")
      .select("*")
      .eq("id", transaction.receiver_account_id)
      .single();

    // Update balances
    await supabase
      .from("accounts")
      .update({
        balance: fromAccount.balance - transaction.amount,
        available_balance: fromAccount.available_balance - transaction.amount,
      })
      .eq("id", transaction.sender_account_id);

    await supabase
      .from("accounts")
      .update({
        balance: toAccount.balance + transaction.amount,
        available_balance: toAccount.available_balance + transaction.amount,
      })
      .eq("id", transaction.receiver_account_id);

    // Update transaction status
    await supabase
      .from("transactions_new")
      .update({
        status: "completed",
        completed_at: new Date(),
        otp_verified: true,
      })
      .eq("id", transaction_id);

    res.json({ message: "Transaction completed successfully" });
  } catch (error) {
    console.error("OTP verification error:", error);
    res.status(500).json({ error: "OTP verification failed" });
  }
});

// Get cards
app.get(
  "/api/user/cards",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { data: cards, error } = await supabase
        .from("cards")
        .select("*, account:accounts(account_number)")
        .eq("user_id", req.user.id);

      if (error) throw error;

      res.json(cards);
    } catch (error) {
      console.error("Cards fetch error:", error);
      res.status(500).json({ error: "Failed to fetch cards" });
    }
  },
);

// Purchase card
app.post(
  "/api/user/purchase-card",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { card_type, is_virtual = false, purchase_method } = req.body;

      // Get card purchase settings
      const { data: settings } = await supabase
        .from("admin_settings")
        .select("setting_value")
        .eq("setting_key", "card_purchase_method")
        .single();

      const cardPrice = 3000; // Card price

      // Generate card details
      const cardNumber =
        "4" +
        Math.floor(Math.random() * 1000000000000000)
          .toString()
          .padStart(15, "0");
      const expiryDate = new Date();
      expiryDate.setFullYear(expiryDate.getFullYear() + 3);
      const cvv = Math.floor(100 + Math.random() * 900).toString();

      const { data: card, error } = await supabase
        .from("cards")
        .insert({
          user_id: req.user.id,
          account_id: null, // Will be linked after activation
          card_number: cardNumber,
          card_type,
          expiry_date: expiryDate,
          cvv,
          card_status: "inactive",
          is_virtual,
          purchase_method: purchase_method || settings?.setting_value,
          purchase_reference: uuidv4(),
        })
        .select()
        .single();

      if (error) throw error;

      res.json({
        message: "Card purchased successfully",
        card,
        payment_instructions: {
          method: purchase_method || settings?.setting_value,
          amount: cardPrice,
          reference: card.purchase_reference,
          // Add crypto payment details if applicable
          crypto_address:
            purchase_method === "crypto"
              ? "0x742d35Cc6634C0532925a3b844Bc1e7f9c5f5f5f"
              : null,
        },
      });
    } catch (error) {
      console.error("Card purchase error:", error);
      res.status(500).json({ error: "Failed to purchase card" });
    }
  },
);

// Activate card
app.post(
  "/api/user/activate-card/:cardId",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { cardId } = req.params;

      // Check if card is purchased and belongs to user
      const { data: card } = await supabase
        .from("cards")
        .select("*")
        .eq("id", cardId)
        .eq("user_id", req.user.id)
        .single();

      if (!card) {
        return res.status(404).json({ error: "Card not found" });
      }

      if (card.card_status !== "inactive") {
        return res.status(400).json({ error: "Card cannot be activated" });
      }

      // Get user's primary account
      const { data: account } = await supabase
        .from("accounts")
        .select("id")
        .eq("user_id", req.user.id)
        .eq("account_type", "checking")
        .single();

      // Activate card
      await supabase
        .from("cards")
        .update({
          card_status: "active",
          account_id: account.id,
        })
        .eq("id", cardId);

      res.json({ message: "Card activated successfully" });
    } catch (error) {
      console.error("Card activation error:", error);
      res.status(500).json({ error: "Failed to activate card" });
    }
  },
);

// Toggle card status (freeze/unfreeze)
app.post(
  "/api/user/toggle-card/:cardId",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { cardId } = req.params;
      const { action } = req.body; // 'freeze' or 'unfreeze'

      const newStatus = action === "freeze" ? "frozen" : "active";

      const { error } = await supabase
        .from("cards")
        .update({ card_status: newStatus })
        .eq("id", cardId)
        .eq("user_id", req.user.id);

      if (error) throw error;

      res.json({ message: `Card ${action}d successfully` });
    } catch (error) {
      console.error("Card toggle error:", error);
      res.status(500).json({ error: "Failed to update card status" });
    }
  },
);

// Report lost/stolen card
app.post(
  "/api/user/report-card/:cardId",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { cardId } = req.params;

      await supabase
        .from("cards")
        .update({ card_status: "lost" })
        .eq("id", cardId)
        .eq("user_id", req.user.id);

      // Create support ticket
      const { data: ticket } = await supabase
        .from("support_tickets")
        .insert({
          user_id: req.user.id,
          subject: "Lost/Stolen Card Report",
          message: `Card ID: ${cardId} reported as lost/stolen`,
          priority: "high",
        })
        .select()
        .single();

      res.json({
        message: "Card reported successfully. Support ticket created.",
        ticket,
      });
    } catch (error) {
      console.error("Card report error:", error);
      res.status(500).json({ error: "Failed to report card" });
    }
  },
);
//===================New beneficiafries rout =========================

// Get user's recent beneficiaries (for the transfer page)
app.get("/api/user/beneficiaries/recent", authenticate, async (req, res) => {
  try {
    const beneficiaries = await getRecentBeneficiaries(req.user.id);
    res.json({ beneficiaries });
  } catch (error) {
    console.error("Error fetching beneficiaries:", error);
    res.status(500).json({ error: "Failed to fetch beneficiaries" });
  }
});

// =========================Bills Sections =========================
// Get bills
/*app.get(
  "/api/user/bills",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { data: bills, error } = await supabase
        .from("bills")
        .select("*")
        .eq("user_id", req.user.id);

      if (error) throw error;

      res.json(bills);
    } catch (error) {
      console.error("Bills fetch error:", error);
      res.status(500).json({ error: "Failed to fetch bills" });
    }
  },
);

// Add bill
app.post(
  "/api/user/bills",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const {
        biller_name,
        biller_account,
        category,
        amount,
        due_date,
        is_recurring,
        recurring_frequency,
      } = req.body;

      const { data: bill, error } = await supabase
        .from("bills")
        .insert({
          user_id: req.user.id,
          biller_name,
          biller_account,
          category,
          amount,
          due_date,
          is_recurring,
          recurring_frequency,
        })
        .select()
        .single();

      if (error) throw error;

      res.json({ message: "Bill added successfully", bill });
    } catch (error) {
      console.error("Add bill error:", error);
      res.status(500).json({ error: "Failed to add bill" });
    }
  },
);*/

// Pay bill
/*app.post(
  "/api/user/pay-bill/:billId",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { billId } = req.params;
      const { account_id } = req.body;

      // Get bill
      const { data: bill } = await supabase
        .from("bills")
        .select("*")
        .eq("id", billId)
        .eq("user_id", req.user.id)
        .single();

      if (!bill) {
        return res.status(404).json({ error: "Bill not found" });
      }

      // Get account
      const { data: account } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", account_id)
        .eq("user_id", req.user.id)
        .single();

      if (!account) {
        return res.status(404).json({ error: "Account not found" });
      }

      if (account.available_balance < bill.amount) {
        return res.status(400).json({ error: "Insufficient funds" });
      }

      // Create transaction
      const { data: transaction } = await supabase
        .from("transactions_new")
        .insert({
          from_account_id: account_id,
          from_user_id: req.user.id,
          amount: bill.amount,
          description: `Bill payment to ${bill.biller_name}`,
          transaction_type: "bill_payment",
          status: "completed",
          completed_at: new Date(),
        })
        .select()
        .single();

      // Update account balance
      await supabase
        .from("accounts")
        .update({
          balance: account.balance - bill.amount,
          available_balance: account.available_balance - bill.amount,
        })
        .eq("id", account_id);

      // Update bill status
      await supabase.from("bills").update({ status: "paid" }).eq("id", billId);

      // If recurring, create next bill
      if (bill.is_recurring) {
        let nextDueDate = new Date(bill.due_date);
        switch (bill.recurring_frequency) {
          case "monthly":
            nextDueDate.setMonth(nextDueDate.getMonth() + 1);
            break;
          case "quarterly":
            nextDueDate.setMonth(nextDueDate.getMonth() + 3);
            break;
          case "yearly":
            nextDueDate.setFullYear(nextDueDate.getFullYear() + 1);
            break;
        }

        await supabase.from("bills").insert({
          user_id: req.user.id,
          biller_name: bill.biller_name,
          biller_account: bill.biller_account,
          category: bill.category,
          amount: bill.amount,
          due_date: nextDueDate,
          is_recurring: true,
          recurring_frequency: bill.recurring_frequency,
          status: "pending",
        });
      }

      res.json({ message: "Bill paid successfully", transaction });
    } catch (error) {
      console.error("Pay bill error:", error);
      res.status(500).json({ error: "Failed to pay bill" });
    }
  },
);*/

const billsService = require("../lib/bills-service");
const billsWorker = require("../lib/bills-worker");

app.use("/api/bills", authenticate, billsCatalogRouter);

app.use("/api/sys/bills", authenticate, authorizeAdmin, billsAdminRouter);

app.post(
  "/api/user/bills/verify-pin",
  authenticate,
  checkAccountFrozen,
  billsService.handleVerifyBillPaymentPin,
);
app.post(
  "/api/user/bills",
  authenticate,
  checkAccountFrozen,
  billsService.billPaymentLimiter,
  billsService.handleCreateBillPayment,
);
app.get("/api/cron/process-bills", billsWorker.cronHandler); // add to vercel.json cron config, same pattern as your other workers

// Get exchange rates
app.get("/api/user/exchange-rates", authenticate, async (req, res) => {
  try {
    const { data: rates, error } = await supabase
      .from("exchange_rates")
      .select("*");

    if (error) throw error;

    res.json(rates);
  } catch (error) {
    console.error("Exchange rates fetch error:", error);
    res.status(500).json({ error: "Failed to fetch exchange rates" });
  }
});

// Currency conversion
app.post(
  "/api/user/convert-currency",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { from_currency, to_currency, amount } = req.body;

      const { data: rate } = await supabase
        .from("exchange_rates")
        .select("rate")
        .eq("from_currency", from_currency)
        .eq("to_currency", to_currency)
        .single();

      if (!rate) {
        return res.status(404).json({ error: "Exchange rate not found" });
      }

      const convertedAmount = amount * rate.rate;

      res.json({
        from_currency,
        to_currency,
        amount,
        converted_amount: convertedAmount,
        rate: rate.rate,
      });
    } catch (error) {
      console.error("Currency conversion error:", error);
      res.status(500).json({ error: "Conversion failed" });
    }
  },
);

// Get budgets
app.get(
  "/api/user/budgets",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { month, year } = req.query;
      const currentDate = new Date();
      const queryMonth = month || currentDate.getMonth() + 1;
      const queryYear = year || currentDate.getFullYear();

      const { data: budgets, error } = await supabase
        .from("budgets")
        .select("*")
        .eq("user_id", req.user.id)
        .eq("month", queryMonth)
        .eq("year", queryYear);

      if (error) throw error;

      res.json(budgets);
    } catch (error) {
      console.error("Budgets fetch error:", error);
      res.status(500).json({ error: "Failed to fetch budgets" });
    }
  },
);

// Create or update budget
app.post(
  "/api/user/budgets",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { category, amount, month, year } = req.body;

      // Check if budget exists
      const { data: existingBudget } = await supabase
        .from("budgets")
        .select("id")
        .eq("user_id", req.user.id)
        .eq("category", category)
        .eq("month", month)
        .eq("year", year)
        .single();

      if (existingBudget) {
        // Update
        await supabase
          .from("budgets")
          .update({ amount })
          .eq("id", existingBudget.id);
      } else {
        // Create
        await supabase.from("budgets").insert({
          user_id: req.user.id,
          category,
          amount,
          month,
          year,
          spent: 0,
        });
      }

      res.json({ message: "Budget saved successfully" });
    } catch (error) {
      console.error("Budget save error:", error);
      res.status(500).json({ error: "Failed to save budget" });
    }
  },
);

// Get support tickets
app.get("/api/user/tickets", authenticate, async (req, res) => {
  try {
    const { data: tickets, error } = await supabase
      .from("support_tickets")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json(tickets);
  } catch (error) {
    console.error("Tickets fetch error:", error);
    res.status(500).json({ error: "Failed to fetch tickets" });
  }
});

// Create support ticket
app.post("/api/user/tickets", authenticate, async (req, res) => {
  try {
    const { subject, message, priority = "medium" } = req.body;

    const { data: ticket, error } = await supabase
      .from("support_tickets")
      .insert({
        user_id: req.user.id,
        subject,
        message,
        priority,
      })
      .select()
      .single();

    if (error) throw error;

    res.json({ message: "Ticket created successfully", ticket });
  } catch (error) {
    console.error("Ticket creation error:", error);
    res.status(500).json({ error: "Failed to create ticket" });
  }
});

// Get chat messages for ticket
app.get(
  "/api/user/tickets/:ticketId/messages",
  authenticate,
  async (req, res) => {
    try {
      const { ticketId } = req.params;

      // Verify ticket belongs to user
      const { data: ticket } = await supabase
        .from("support_tickets")
        .select("id")
        .eq("id", ticketId)
        .eq("user_id", req.user.id)
        .single();

      if (!ticket) {
        return res.status(404).json({ error: "Ticket not found" });
      }

      const { data: messages, error } = await supabase
        .from("chat_messages")
        .select("*, sender:sender_id(first_name, last_name, role)")
        .eq("ticket_id", ticketId)
        .order("created_at", { ascending: true });

      if (error) throw error;

      res.json(messages);
    } catch (error) {
      console.error("Messages fetch error:", error);
      res.status(500).json({ error: "Failed to fetch messages" });
    }
  },
);

// Send chat message
app.post(
  "/api/user/tickets/:ticketId/messages",
  authenticate,
  async (req, res) => {
    try {
      const { ticketId } = req.params;
      const { message } = req.body;

      // Verify ticket belongs to user
      const { data: ticket } = await supabase
        .from("support_tickets")
        .select("id")
        .eq("id", ticketId)
        .eq("user_id", req.user.id)
        .single();

      if (!ticket) {
        return res.status(404).json({ error: "Ticket not found" });
      }

      const { data: chatMessage, error } = await supabase
        .from("chat_messages")
        .insert({
          ticket_id: ticketId,
          sender_id: req.user.id,
          message,
          is_admin_reply: false,
        })
        .select()
        .single();

      if (error) throw error;

      res.json({ message: "Message sent successfully", chatMessage });
    } catch (error) {
      console.error("Message send error:", error);
      res.status(500).json({ error: "Failed to send message" });
    }
  },
);

// ==================== IMPROVED NOTIFICATION ROUTES ====================

// Get notifications with pagination and unread count
// Cache key: versioned per-user, so bumpUserCacheVersion("notif", userId)
// -- called from the three mutation routes below -- instantly
// invalidates every page/limit/filter variant this user has ever
// requested, without tracking each one down individually.
async function buildNotificationsCacheKey(req) {
  const { page = 1, limit = 20, unread_only = false } = req.query;
  const version = await getUserCacheVersion("notif", req.user.id);
  return `notif:v${version}:u:${req.user.id}:p:${page}:l:${limit}:uo:${unread_only}`;
}

// TTL is a safety net, not the primary invalidation mechanism -- this
// endpoint is polled every 10-30s from the dashboard, so even a fully
// missed invalidation call self-heals within one poll cycle.
app.get(
  "/api/user/notifications",
  authenticate,
  cacheware(buildNotificationsCacheKey, 20),
  async (req, res) => {
    try {
      const { page = 1, limit = 20, unread_only = false } = req.query;
      const offset = (parseInt(page) - 1) * parseInt(limit);

      // REMOVED: a "does the notifications table exist" check (select id
      // limit 1, then conditionally CREATE TABLE) used to run on every
      // single call to this route. The table has existed since initial
      // setup; this was a wasted extra round trip on literally every poll
      // (dashboard hits this endpoint every 10-30s per open session), for
      // a condition (42P01 — table missing) that in practice never fires
      // in a deployed app. createNotificationsTable() is still defined
      // below for one-off manual/migration use if ever genuinely needed.

      let query = supabase
        .from("notifications")
        .select("*", { count: "exact" })
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false });

      if (unread_only === "true") {
        query = query.eq("is_read", false);
      }

      const {
        data: notifications,
        error,
        count,
      } = await query.range(offset, offset + parseInt(limit) - 1);

      if (error) {
        console.error("Supabase notifications error:", error);
        // Return empty array instead of error
        return res.json({
          notifications: [],
          unread_count: 0,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: 0,
            pages: 0,
          },
        });
      }

      // FIXED: when the caller already asked for unread_only, `count`
      // above IS the unread count — a second exact COUNT(*) round trip
      // for the exact same rows was pure waste. Only fire the separate
      // query when the listing itself wasn't already scoped to unread,
      // i.e. when we genuinely need a different number than `count`.
      let unreadCount = count;
      if (unread_only !== "true") {
        const { count: uc, error: unreadError } = await supabase
          .from("notifications")
          .select("*", { count: "exact", head: true })
          .eq("user_id", req.user.id)
          .eq("is_read", false);

        if (unreadError) {
          console.error("Unread count error:", unreadError);
        }
        unreadCount = uc;
      }

      res.json({
        notifications: notifications || [],
        unread_count: unreadCount || 0,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / parseInt(limit)),
        },
      });
    } catch (error) {
      console.error("Notifications fetch error:", error);
      // Return empty array instead of error
      res.json({
        notifications: [],
        unread_count: 0,
        pagination: {
          page: 1,
          limit: 20,
          total: 0,
          pages: 0,
        },
      });
    }
  },
);

// Helper function to create notifications table if it doesn't exist
async function createNotificationsTable() {
  try {
    // Check if table exists
    const { error: checkError } = await supabase
      .from("notifications")
      .select("id")
      .limit(1);

    if (checkError && checkError.code === "42P01") {
      // Create the notifications table using raw SQL
      const createTableSQL = `
                CREATE TABLE IF NOT EXISTS notifications (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                    title VARCHAR(200) NOT NULL,
                    message TEXT NOT NULL,
                    type VARCHAR(50) DEFAULT 'info',
                    is_read BOOLEAN DEFAULT false,
                    read_at TIMESTAMP,
                    action_url TEXT,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
                
                CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
                CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
                CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);
            `;

      // Execute through Supabase's RPC if you have the function, or log to run manually
      console.log("Please run this SQL in your Supabase SQL editor:");
      console.log(createTableSQL);

      // Alternative: Try to insert a test record to see if table exists
      // If it fails, log the SQL for manual execution
    }
  } catch (error) {
    console.error("Error checking/creating notifications table:", error);
  }
}

// Mark single notification as read
app.post("/api/user/notifications/:id/read", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    console.log(`Marking notification ${id} as read for user ${req.user.id}`);

    // Check if notification exists and belongs to user
    const { data: existing, error: checkError } = await supabase
      .from("notifications")
      .select("id, is_read")
      .eq("id", id)
      .eq("user_id", req.user.id)
      .single();

    if (checkError) {
      console.error("Notification not found:", checkError);
      return res.status(404).json({ error: "Notification not found" });
    }

    if (existing.is_read) {
      return res.json({ success: true, message: "Already read" });
    }

    const { error } = await supabase
      .from("notifications")
      .update({
        is_read: true,
        read_at: new Date().toISOString(),
      })
      .eq("id", id)
      .eq("user_id", req.user.id);

    if (error) {
      console.error("Update error:", error);
      throw error;
    }

    await bumpUserCacheVersion("notif", req.user.id);

    res.json({ success: true });
  } catch (error) {
    console.error("Notification update error:", error);
    res.status(500).json({ error: "Failed to update notification" });
  }
});

// Mark all notifications as read
app.post(
  "/api/user/notifications/mark-all-read",
  authenticate,
  async (req, res) => {
    try {
      const { error } = await supabase
        .from("notifications")
        .update({
          is_read: true,
          read_at: new Date().toISOString(),
        })
        .eq("user_id", req.user.id)
        .eq("is_read", false);

      if (error) {
        console.error("Mark all update error:", error);
        throw error;
      }

      await bumpUserCacheVersion("notif", req.user.id);

      res.json({ success: true });
    } catch (error) {
      console.error("Mark all read error:", error);
      res.status(500).json({ error: "Failed to mark all as read" });
    }
  },
);

// Delete notification
app.delete("/api/user/notifications/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from("notifications")
      .delete()
      .eq("id", id)
      .eq("user_id", req.user.id);

    if (error) throw error;

    await bumpUserCacheVersion("notif", req.user.id);

    res.json({ success: true });
  } catch (error) {
    console.error("Notification delete error:", error);
    res.status(500).json({ error: "Failed to delete notification" });
  }
});

// Register push token - FIXED VERSION
app.post("/api/user/register-push-token", authenticate, async (req, res) => {
  try {
    const { push_token, platform, device_name } = req.body;

    console.log("=== REGISTER PUSH TOKEN ===");
    console.log("User ID:", req.user.id);
    console.log("Platform:", platform);
    console.log("Token length:", push_token?.length);

    if (!push_token) {
      return res.status(400).json({ error: "Push token is required" });
    }

    // First, check if token already exists and reactivate it
    const { data: existingToken } = await supabase
      .from("user_push_tokens")
      .select("id")
      .eq("user_id", req.user.id)
      .eq("push_token", push_token)
      .maybeSingle();

    if (existingToken) {
      // Reactivate existing token
      const { error: updateError } = await supabase
        .from("user_push_tokens")
        .update({
          is_active: true,
          last_active: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq("id", existingToken.id);

      if (updateError) {
        console.error("Update error:", updateError);
      }
    } else {
      // Insert new token
      const { error: insertError } = await supabase
        .from("user_push_tokens")
        .insert({
          user_id: req.user.id,
          push_token: push_token,
          platform: platform || "android",
          device_name: device_name || null,
          is_active: true,
          last_active: new Date().toISOString(),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });

      if (insertError) {
        console.error("Insert error:", insertError);
        // Check if it's a duplicate key error
        if (insertError.code === "23505") {
          // Duplicate - try to reactivate instead
          const { error: reactivateError } = await supabase
            .from("user_push_tokens")
            .update({
              is_active: true,
              last_active: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            })
            .eq("user_id", req.user.id)
            .eq("push_token", push_token);

          if (reactivateError) {
            console.error("Reactivate error:", reactivateError);
          }
        } else {
          return res.status(500).json({
            error: "Failed to register push token: " + insertError.message,
          });
        }
      }
    }

    // Also ensure push settings exist
    const { data: existingSettings } = await supabase
      .from("user_push_settings")
      .select("id")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (!existingSettings) {
      await supabase.from("user_push_settings").insert({
        user_id: req.user.id,
        notifications_enabled: true,
        transfers: true,
        savings: true,
        security: true,
        promotions: false,
        bills: true,
        updated_at: new Date().toISOString(),
      });
    } else {
      // Update notifications_enabled to true since they're registering
      await supabase
        .from("user_push_settings")
        .update({
          notifications_enabled: true,
          updated_at: new Date().toISOString(),
        })
        .eq("user_id", req.user.id);
    }

    console.log("Push token registered successfully for user:", req.user.id);
    res.json({
      success: true,
      message: "Push token registered successfully",
    });
  } catch (error) {
    console.error("Push token registration error:", error);
    res
      .status(500)
      .json({ error: "Failed to register push token: " + error.message });
  }
});

// Delete push token (when user logs out)
app.delete("/api/user/push-token", authenticate, async (req, res) => {
  try {
    const { push_token } = req.body;

    if (push_token) {
      await supabase
        .from("user_push_tokens")
        .update({ is_active: false })
        .eq("user_id", req.user.id)
        .eq("push_token", push_token);
    } else {
      // Deactivate all tokens for this user
      await supabase
        .from("user_push_tokens")
        .update({ is_active: false })
        .eq("user_id", req.user.id);
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Push token deletion error:", error);
    res.status(500).json({ error: "Failed to delete push token" });
  }
});

// Test endpoint to send a push notification (for testing)
app.post("/api/user/test-push", authenticate, async (req, res) => {
  try {
    // Get user's push tokens
    const { data: tokens, error } = await supabase
      .from("user_push_tokens")
      .select("push_token")
      .eq("user_id", req.user.id)
      .eq("is_active", true);

    if (error) throw error;

    if (!tokens || tokens.length === 0) {
      return res.json({ success: false, message: "No push tokens found" });
    }

    // Send test notification to all tokens
    const results = [];
    for (const token of tokens) {
      const sent = await sendPushNotification(
        token.push_token,
        "Test Notification",
        "This is a test push notification from Paystora!",
        { url: "/dashboard.html", type: "test" },
      );
      results.push({ sent });
    }

    res.json({
      success: true,
      message: `Test notification sent to ${results.length} device(s)`,
      results,
    });
  } catch (error) {
    console.error("Test push error:", error);
    res.status(500).json({ error: "Failed to send test notification" });
  }
});

// Get push notification settings (FIXED)
app.get("/api/user/push-settings", authenticate, async (req, res) => {
  try {
    console.log("Fetching push settings for user:", req.user.id);

    // Try to get existing settings
    const { data: settings, error } = await supabase
      .from("user_push_settings")
      .select("*")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) {
      console.error("Fetch error:", error);
      // Return default settings
      return res.json({
        notifications_enabled: false,
        transfers: true,
        savings: true,
        security: true,
        promotions: false,
        bills: true,
      });
    }

    // If settings exist, return them
    if (settings) {
      return res.json(settings);
    }

    // No settings found, create default and return
    console.log("No settings found, creating defaults");
    const defaultSettings = {
      user_id: req.user.id,
      notifications_enabled: false,
      transfers: true,
      savings: true,
      security: true,
      promotions: false,
      bills: true,
    };

    const { data: newSettings, error: insertError } = await supabase
      .from("user_push_settings")
      .insert(defaultSettings)
      .select()
      .single();

    if (insertError) {
      console.error("Insert error:", insertError);
      // Return defaults anyway
      return res.json({
        notifications_enabled: false,
        transfers: true,
        savings: true,
        security: true,
        promotions: false,
        bills: true,
      });
    }

    res.json(newSettings);
  } catch (error) {
    console.error("Push settings fetch error:", error);
    // Always return default settings to avoid breaking the UI
    res.json({
      notifications_enabled: false,
      transfers: true,
      savings: true,
      security: true,
      promotions: false,
      bills: true,
    });
  }
});

// Update push notification settings (FIXED - handles duplicate key properly)
app.post("/api/user/push-settings", authenticate, async (req, res) => {
  try {
    console.log("Updating push settings for user:", req.user.id);
    console.log("Request body:", req.body);

    const {
      transfers,
      savings,
      promotions,
      security,
      bills,
      notifications_enabled,
    } = req.body;

    // Prepare update data
    const updateData = {
      updated_at: new Date().toISOString(),
    };

    if (transfers !== undefined) updateData.transfers = transfers;
    if (savings !== undefined) updateData.savings = savings;
    if (promotions !== undefined) updateData.promotions = promotions;
    if (security !== undefined) updateData.security = security;
    if (bills !== undefined) updateData.bills = bills;
    if (notifications_enabled !== undefined)
      updateData.notifications_enabled = notifications_enabled;

    // CRITICAL FIX: Use upsert with onConflict to handle duplicate key properly
    const { data, error } = await supabase
      .from("user_push_settings")
      .upsert(
        {
          user_id: req.user.id,
          ...updateData,
        },
        {
          onConflict: "user_id", // This tells Supabase to update if user_id exists
          ignoreDuplicates: false, // Don't ignore, update instead
        },
      )
      .select()
      .single();

    if (error) {
      console.error("Upsert error:", error);

      // Fallback: Try update first, then insert
      const { data: updateData_result, error: updateError } = await supabase
        .from("user_push_settings")
        .update(updateData)
        .eq("user_id", req.user.id)
        .select()
        .single();

      if (updateError || !updateData_result) {
        // If update fails, try insert
        const { data: insertData, error: insertError } = await supabase
          .from("user_push_settings")
          .insert({
            user_id: req.user.id,
            ...updateData,
          })
          .select()
          .single();

        if (insertError) {
          console.error("Insert fallback error:", insertError);
          return res.status(500).json({
            error: "Failed to save push settings: " + insertError.message,
          });
        }

        return res.json({ success: true, settings: insertData });
      }

      return res.json({ success: true, settings: updateData_result });
    }

    console.log("Push settings saved successfully:", data);
    res.json({ success: true, settings: data });
  } catch (error) {
    console.error("Push settings update error:", error);
    res
      .status(500)
      .json({ error: "Failed to update push settings: " + error.message });
  }
});

// Request OTP for withdrawal
app.post(
  "/api/user/request-withdrawal-otp",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { amount, account_id, bank_details } = req.body;

      // Check if user is frozen
      if (req.user.is_frozen) {
        return res.status(403).json({
          error: "Account frozen. Please contact support.",
          requires_otp: true,
        });
      }

      // Check OTP mode
      const { data: settings } = await supabase
        .from("admin_settings")
        .select("setting_value")
        .eq("setting_key", "otp_mode")
        .single();

      const otpMode = settings?.setting_value === "on";

      if (!otpMode && !req.user.is_frozen) {
        return res.json({
          message: "OTP not required",
          requires_otp: false,
        });
      }

      // Create withdrawal request in chat
      const { data: ticket } = await supabase
        .from("support_tickets")
        .insert({
          user_id: req.user.id,
          subject: "OTP Request for Withdrawal",
          message: JSON.stringify({
            type: "otp_request",
            action: "withdrawal",
            amount,
            account_id,
            bank_details,
          }),
          priority: "high",
          status: "open",
        })
        .select()
        .single();

      // Send auto-reply with OTP request instructions
      await supabase.from("chat_messages").insert({
        ticket_id: ticket.id,
        sender_id: req.user.id,
        message: "I need an OTP code for withdrawal",
        is_admin_reply: false,
      });

      res.json({
        message: "OTP request sent. Please check chat for OTP code.",
        requires_otp: true,
        ticket_id: ticket.id,
      });
    } catch (error) {
      console.error("OTP request error:", error);
      res.status(500).json({ error: "Failed to request OTP" });
    }
  },
);

// Process withdrawal with OTP
app.post(
  "/api/user/process-withdrawal",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { amount, account_id, otp_code, bank_details } = req.body;

      // Verify OTP
      const { data: otpRecord } = await supabase
        .from("otps")
        .select("*")
        .eq("otp_code", otp_code)
        .eq("user_id", req.user.id)
        .eq("otp_type", "withdrawal")
        .eq("is_used", false)
        .single();

      if (!otpRecord || new Date(otpRecord.expires_at) < new Date()) {
        return res.status(401).json({ error: "Invalid or expired OTP" });
      }

      // Mark OTP as used
      await supabase
        .from("otps")
        .update({ is_used: true })
        .eq("id", otpRecord.id);

      // Get account
      const { data: account } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", account_id)
        .eq("user_id", req.user.id)
        .single();

      if (!account) {
        return res.status(404).json({ error: "Account not found" });
      }

      if (account.available_balance < amount) {
        return res.status(400).json({ error: "Insufficient funds" });
      }

      // Create withdrawal transaction
      const { data: transaction } = await supabase
        .from("transactions_new")
        .insert({
          from_account_id: account_id,
          from_user_id: req.user.id,
          amount,
          description: `Withdrawal to ${bank_details?.bank_name || "external account"}`,
          transaction_type: "withdrawal",
          status: "completed",
          completed_at: new Date(),
          otp_verified: true,
        })
        .select()
        .single();

      // Update account balance
      await supabase
        .from("accounts")
        .update({
          balance: account.balance - amount,
          available_balance: account.available_balance - amount,
        })
        .eq("id", account_id);

      res.json({
        message: "Withdrawal processed successfully",
        transaction,
      });
    } catch (error) {
      console.error("Withdrawal error:", error);
      res.status(500).json({ error: "Withdrawal failed" });
    }
  },
);

// ==================== SAVINGS ROUTES ====================

// index.js - Add this near your other savings routes

// Process spare change savings after transfer
app.post(
  "/api/user/savings/spare-change/process",
  authenticate,
  async (req, res) => {
    try {
      const { from_account_id, amount } = req.body;

      if (!amount || amount <= 0) {
        return res.json({ saved_amount: 0 }); // No spare change for invalid amounts
      }

      // Get user's spare change savings plan
      const { data: spareChange, error: spareError } = await supabase
        .from("spare_change_savings")
        .select("*")
        .eq("user_id", req.user.id)
        .eq("status", "active")
        .eq("auto_save", true)
        .maybeSingle();

      // If no active spare change plan, return early
      if (spareError || !spareChange) {
        return res.json({ saved_amount: 0 });
      }

      // Calculate spare change amount (percentage of transfer)
      const percentageRate = spareChange.percentage_rate || 3;
      const spareAmount = amount * (percentageRate / 100);

      // Don't save if amount is too small (less than 1 NGN)
      if (spareAmount < 1) {
        return res.json({ saved_amount: 0 });
      }

      // Get user's account for balance check
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", from_account_id)
        .eq("user_id", req.user.id)
        .single();

      if (accError || !account) {
        console.error("Account not found for spare change");
        return res.json({ saved_amount: 0 });
      }

      // Check if sufficient balance (user already paid transfer amount, but need extra for spare change)
      if (account.available_balance < spareAmount) {
        console.log("Insufficient balance for spare change savings");
        return res.json({ saved_amount: 0 });
      }

      // Deduct spare change amount
      const newBalance = account.balance - spareAmount;
      const newAvailable = account.available_balance - spareAmount;

      const { error: updateError } = await supabase
        .from("accounts")
        .update({
          balance: newBalance,
          available_balance: newAvailable,
          updated_at: new Date(),
        })
        .eq("id", from_account_id);

      if (updateError) {
        console.error("Balance update error for spare change:", updateError);
        return res.json({ saved_amount: 0 });
      }

      // Update spare change savings
      const newCurrentSaved = (spareChange.current_saved || 0) + spareAmount;
      const newTotalSaved = (spareChange.total_saved || 0) + spareAmount;

      const { error: updateSpareError } = await supabase
        .from("spare_change_savings")
        .update({
          current_saved: newCurrentSaved,
          total_saved: newTotalSaved,
          updated_at: new Date(),
        })
        .eq("id", spareChange.id);

      if (updateSpareError) {
        console.error("Spare change update error:", updateSpareError);
      }

      // Create transaction record for spare change
      const { error: transError } = await supabase
        .from("transactions_new")
        .insert({
          sender_account_id: from_account_id,
          sender_user_id: req.user.id,
          amount: spareAmount,
          description: `Spare Change: ${percentageRate}% from transfer of ₦${amount.toFixed(2)}`,
          transaction_type: "spare_change",
          status: "completed",
          completed_at: new Date(),
          created_at: new Date(),
        });

      if (transError) {
        console.error("Spare change transaction error:", transError);
      }

      // Create savings transaction record
      await supabase.from("savings_transactions").insert({
        user_id: req.user.id,
        savings_type: "spare_change",
        savings_id: spareChange.id,
        amount: spareAmount,
        transaction_type: "deposit",
        description: `Auto-saved ${percentageRate}% of transfer (₦${amount.toFixed(2)})`,
      });

      console.log(
        `Spare change saved: ₦${spareAmount.toFixed(2)} for user ${req.user.id}`,
      );

      res.json({
        success: true,
        saved_amount: spareAmount,
        percentage_rate: percentageRate,
        new_balance: newAvailable,
        message: `${percentageRate}% (₦${spareAmount.toFixed(2)}) saved to your Spare Change`,
      });
    } catch (error) {
      console.error("Spare change processing error:", error);
      // Always return success with saved_amount: 0 to not break the transfer flow
      res.json({ saved_amount: 0, error: error.message });
    }
  },
);

// Get savings summary (check if user has active plans) - SINGLE VERSION
app.get("/api/user/savings/summary", authenticate, async (req, res) => {
  try {
    console.log("Fetching savings summary for user:", req.user.id);

    const [harvest, fixed, savebox, target, spareChange] = await Promise.all([
      supabase
        .from("user_harvest_enrollments")
        .select("id, status, auto_save, total_saved")
        .eq("user_id", req.user.id)
        .eq("status", "active")
        .maybeSingle(),
      supabase
        .from("fixed_savings")
        .select("id, status, auto_save, current_saved, maturity_date")
        .eq("user_id", req.user.id)
        .in("status", ["active", "matured"])
        .maybeSingle(),
      supabase
        .from("savebox_savings")
        .select("id, status, auto_save, current_saved, target_date")
        .eq("user_id", req.user.id)
        .eq("status", "active")
        .maybeSingle(),
      supabase
        .from("target_savings")
        .select(
          "id, status, auto_save, current_saved, target_amount, withdrawal_date",
        )
        .eq("user_id", req.user.id)
        .eq("status", "active")
        .maybeSingle(),
      supabase
        .from("spare_change_savings")
        .select("id, status, auto_save, current_saved")
        .eq("user_id", req.user.id)
        .eq("status", "active")
        .maybeSingle(),
    ]);

    const totalSaved =
      (harvest.data?.total_saved || 0) +
      (fixed.data?.current_saved || 0) +
      (savebox.data?.current_saved || 0) +
      (target.data?.current_saved || 0) +
      (spareChange.data?.current_saved || 0);

    console.log("Savings summary fetched successfully");

    res.json({
      total_saved: totalSaved,
      active_plans: {
        harvest: harvest.data || null,
        fixed: fixed.data || null,
        savebox: savebox.data || null,
        target: target.data || null,
        spare_change: spareChange.data || null,
      },
    });
  } catch (error) {
    console.error("Savings summary error:", error);
    res
      .status(500)
      .json({ error: "Failed to get savings summary: " + error.message });
  }
});

// Get harvest plans for user
app.get("/api/user/harvest-plans", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("harvest_plans")
      .select("*")
      .eq("is_active", true);

    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    console.error("Error fetching harvest plans:", error);
    res.status(500).json({ error: "Failed to fetch harvest plans" });
  }
});

// Start savings - WITH DUPLICATE PREVENTION
app.post(
  "/api/user/savings/start",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    const {
      type,
      amount,
      plan_id,
      target_withdrawal_date,
      auto_save = true,
    } = req.body;

    try {
      // ========== DUPLICATE PLAN CHECK ==========
      // Harvest plans: multiple allowed (user can have multiple harvest plans)
      // Other plans: only ONE active plan per type

      if (type !== "harvest") {
        let existingQuery = null;
        let existingError = null;

        switch (type) {
          case "fixed":
            const { data: existingFixed, error: eFixed } = await supabase
              .from("fixed_savings")
              .select("id, status")
              .eq("user_id", req.user.id)
              .in("status", ["active", "matured"]);
            if (existingFixed && existingFixed.length > 0) {
              return res.status(400).json({
                error:
                  "You already have an active Fixed Savings plan. Please complete or withdraw it before starting a new one.",
                existing_plan: existingFixed[0],
              });
            }
            break;

          case "savebox":
            const { data: existingSavebox, error: eSavebox } = await supabase
              .from("savebox_savings")
              .select("id, status")
              .eq("user_id", req.user.id)
              .eq("status", "active");
            if (existingSavebox && existingSavebox.length > 0) {
              return res.status(400).json({
                error:
                  "You already have an active SaveBox plan. Only one SaveBox plan is allowed per user.",
                existing_plan: existingSavebox[0],
              });
            }
            break;

          case "target":
            const { data: existingTarget, error: eTarget } = await supabase
              .from("target_savings")
              .select("id, status")
              .eq("user_id", req.user.id)
              .eq("status", "active");
            if (existingTarget && existingTarget.length > 0) {
              return res.status(400).json({
                error:
                  "You already have an active Target Savings plan. Complete it before starting a new one.",
                existing_plan: existingTarget[0],
              });
            }
            break;

          case "spare_change":
            const { data: existingSpare, error: eSpare } = await supabase
              .from("spare_change_savings")
              .select("id, status")
              .eq("user_id", req.user.id)
              .eq("status", "active");
            if (existingSpare && existingSpare.length > 0) {
              return res.status(400).json({
                error: "You already have an active Spare Change Savings plan.",
                existing_plan: existingSpare[0],
              });
            }
            break;
        }
      }

      // ========== GET ACCOUNT ==========
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", req.user.id)
        .eq("account_type", "checking")
        .single();

      if (accError || !account) {
        return res.status(404).json({ error: "Account not found" });
      }

      // ========== CHECK BALANCE (skip for spare_change which has no initial deposit) ==========
      if (type !== "spare_change") {
        if (!amount || amount <= 0) {
          return res.status(400).json({ error: "Invalid amount" });
        }
        if (account.available_balance < amount) {
          return res.status(400).json({ error: "Insufficient funds" });
        }
      }

      let savingsRecord;

      // ========== PROCESS BASED ON TYPE ==========
      switch (type) {
        // In index.js, in the harvest case under /api/user/savings/start
        case "harvest":
          const { data: plan, error: planError } = await supabase
            .from("harvest_plans")
            .select("*")
            .eq("id", plan_id)
            .single();

          if (planError) throw planError;

          const startDate = new Date();
          const endDate = new Date();
          endDate.setDate(endDate.getDate() + plan.duration_days);

          // FIX: Set next_deduction_due to TOMORROW (not today)
          // This prevents double-deduction on the same day
          const nextDeduction = new Date();
          nextDeduction.setDate(nextDeduction.getDate() + 1);
          nextDeduction.setHours(0, 0, 0, 0); // Set to start of day

          // Deduct initial amount (first day's savings)
          await supabase
            .from("accounts")
            .update({
              balance: account.balance - amount,
              available_balance: account.available_balance - amount,
            })
            .eq("id", account.id);

          const { data: harvest, error: hError } = await supabase
            .from("user_harvest_enrollments")
            .insert({
              user_id: req.user.id,
              plan_id: plan_id,
              daily_amount: plan.daily_amount,
              total_saved: amount,
              days_completed: 1, // First day completed
              start_date: startDate,
              expected_end_date: endDate,
              last_deduction_date: startDate,
              next_deduction_due: nextDeduction.toISOString(), // TOMORROW
              auto_save: auto_save,
              status: "active",
            })
            .select()
            .single();

          if (hError) throw hError;

          // ===== CREDIT HARVEST POOL ON FIRST DEPOSIT =====
          const { data: harvestPoolAcc } = await supabase
            .from("savings_pool_accounts")
            .select("*")
            .eq("account_type", "harvest_pool")
            .maybeSingle();
          if (harvestPoolAcc) {
            await supabase
              .from("savings_pool_accounts")
              .update({
                balance: (harvestPoolAcc.balance || 0) + amount,
                available_balance:
                  (harvestPoolAcc.available_balance || 0) + amount,
                updated_at: new Date().toISOString(),
              })
              .eq("id", harvestPoolAcc.id);
          }

          savingsRecord = {
            ...harvest,
            plan_name: plan.name,
            duration_days: plan.duration_days,
          };
          break;

        case "fixed":
          // Deduct initial amount
          await supabase
            .from("accounts")
            .update({
              balance: account.balance - amount,
              available_balance: account.available_balance - amount,
            })
            .eq("id", account.id);

          const maturityDate = new Date();
          maturityDate.setDate(maturityDate.getDate() + 30);
          const freeWithdrawalDate = new Date();
          freeWithdrawalDate.setDate(freeWithdrawalDate.getDate() + 32);

          // FIXED: Store the user's daily amount as the amount they input
          // No division by 30 - they save the same amount every day
          const fixedDailyAmount = amount; // User's daily savings amount
          const totalToSave = amount * 30; // Amount * 30 days

          const { data: fixed, error: fError } = await supabase
            .from("fixed_savings")
            .insert({
              user_id: req.user.id,
              amount: totalToSave, // Total target amount
              current_saved: amount, // Already saved the first day's amount
              daily_amount: fixedDailyAmount, // Daily amount = user's input amount
              last_deduction_date: new Date(),
              interest_rate: 5.0,
              start_date: new Date(),
              maturity_date: maturityDate,
              next_free_withdrawal_date: freeWithdrawalDate,
              auto_save: auto_save,
              status: "active",
            })
            .select()
            .single();

          if (fError) throw fError;

          // ===== CREDIT FIXED POOL ON FIRST DEPOSIT =====
          const { data: fixedPoolAcc } = await supabase
            .from("savings_pool_accounts")
            .select("*")
            .eq("account_type", "fixed_pool")
            .maybeSingle();
          if (fixedPoolAcc) {
            await supabase
              .from("savings_pool_accounts")
              .update({
                balance: (fixedPoolAcc.balance || 0) + amount,
                available_balance:
                  (fixedPoolAcc.available_balance || 0) + amount,
                updated_at: new Date().toISOString(),
              })
              .eq("id", fixedPoolAcc.id);
          }

          savingsRecord = fixed;
          break;

        // case savebox
        case "savebox":
          // Deduct initial amount
          await supabase
            .from("accounts")
            .update({
              balance: account.balance - amount,
              available_balance: account.available_balance - amount,
            })
            .eq("id", account.id);

          const targetDate = new Date();
          targetDate.setMonth(targetDate.getMonth() + 3);

          // FIXED: Store the user's daily amount as the amount they input
          const saveboxDailyAmount = amount; // User's daily savings amount
          const totalSaveboxTarget = amount * 90; // Amount * 90 days (3 months)

          const { data: savebox, error: sError } = await supabase
            .from("savebox_savings")
            .insert({
              user_id: req.user.id,
              amount: totalSaveboxTarget, // Total target amount
              current_saved: amount, // Already saved the first day's amount
              daily_amount: saveboxDailyAmount, // Daily amount = user's input amount
              last_deduction_date: new Date(),
              target_date: targetDate,
              early_withdrawal_fee_percent: 4.0,
              auto_save: auto_save,
              status: "active",
            })
            .select()
            .single();

          if (sError) throw sError;

          // ===== CREDIT SAVEBOX POOL ON FIRST DEPOSIT =====
          const { data: saveboxPoolAcc } = await supabase
            .from("savings_pool_accounts")
            .select("*")
            .eq("account_type", "savebox_pool")
            .maybeSingle();
          if (saveboxPoolAcc) {
            await supabase
              .from("savings_pool_accounts")
              .update({
                balance: (saveboxPoolAcc.balance || 0) + amount,
                available_balance:
                  (saveboxPoolAcc.available_balance || 0) + amount,
                updated_at: new Date().toISOString(),
              })
              .eq("id", saveboxPoolAcc.id);
          }

          savingsRecord = savebox;
          break;

        case "target":
          // Calculate days until withdrawal date
          const withdrawalDateObj = new Date(target_withdrawal_date);
          const startDateObj = new Date();
          const daysUntil = Math.max(
            1,
            Math.ceil(
              (withdrawalDateObj - startDateObj) / (1000 * 60 * 60 * 24),
            ),
          );

          // FIXED: The amount user enters IS the daily savings amount
          // They save that amount every day until withdrawal date
          const targetDailyAmount = amount; // User's daily savings amount
          const totalTargetAmount = amount * daysUntil; // Total they will save by withdrawal date

          // Deduct initial amount (first day's savings)
          await supabase
            .from("accounts")
            .update({
              balance: account.balance - amount,
              available_balance: account.available_balance - amount,
            })
            .eq("id", account.id);

          const { data: target, error: tError } = await supabase
            .from("target_savings")
            .insert({
              user_id: req.user.id,
              target_amount: totalTargetAmount, // Total expected savings
              daily_savings_amount: targetDailyAmount, // User's daily amount
              withdrawal_date: withdrawalDateObj,
              current_saved: amount, // First day's savings
              days_remaining: daysUntil - 1,
              last_deduction_date: new Date(),
              auto_save: auto_save,
              status: "active",
              target_met: false,
              withdrawn: false,
            })
            .select()
            .single();

          if (tError) throw tError;

          // ===== CREDIT TARGET POOL ON FIRST DEPOSIT =====
          const { data: targetPoolAcc } = await supabase
            .from("savings_pool_accounts")
            .select("*")
            .eq("account_type", "target_pool")
            .maybeSingle();
          if (targetPoolAcc) {
            await supabase
              .from("savings_pool_accounts")
              .update({
                balance: (targetPoolAcc.balance || 0) + amount,
                available_balance:
                  (targetPoolAcc.available_balance || 0) + amount,
                updated_at: new Date().toISOString(),
              })
              .eq("id", targetPoolAcc.id);
          }

          savingsRecord = target;
          break;

        case "spare_change":
          // No initial deduction for spare change
          const { data: spare, error: spError } = await supabase
            .from("spare_change_savings")
            .insert({
              user_id: req.user.id,
              percentage_rate: 3.0,
              current_saved: 0,
              total_saved: 0,
              auto_save: auto_save,
              status: "active",
            })
            .select()
            .single();

          if (spError) throw spError;
          savingsRecord = spare;
          break;
      }

      // Create transaction record (skip for spare_change)
      if (type !== "spare_change") {
        await supabase.from("transactions_new").insert({
          sender_account_id: account.id,
          sender_user_id: req.user.id,
          amount: amount,
          description: `${type.charAt(0).toUpperCase() + type.slice(1)} Savings Initial Deposit`,
          transaction_type: "savings",
          status: "completed",
          completed_at: new Date(),
        });
      }

      // Create savings transaction
      await supabase.from("savings_transactions").insert({
        user_id: req.user.id,
        savings_type: type,
        savings_id: savingsRecord.id,
        amount: type !== "spare_change" ? amount : 0,
        transaction_type: "deposit",
        description: `Started ${type} savings`,
      });

      res.json({
        success: true,
        message: "Savings started successfully",
        savings: savingsRecord,
      });
    } catch (error) {
      console.error("Error starting savings:", error);
      res
        .status(500)
        .json({ error: "Failed to start savings: " + error.message });
    }
  },
);

// Get all savings for user
app.get("/api/user/savings", authenticate, async (req, res) => {
  try {
    console.log("Fetching all savings for user:", req.user.id);

    const [harvest, fixed, savebox, target, spareChange] = await Promise.all([
      supabase
        .from("user_harvest_enrollments")
        .select("*, harvest_plans(name, daily_amount, duration_days)")
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("fixed_savings")
        .select("*")
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("savebox_savings")
        .select("*")
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("target_savings")
        .select("*")
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("spare_change_savings")
        .select("*")
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false }),
    ]);

    const allSavings = [];

    // Format harvest
    (harvest.data || []).forEach((h) => {
      allSavings.push({
        id: h.id,
        type: "harvest",
        plan_name: h.harvest_plans?.name || "Harvest Plan",
        total_saved: h.total_saved || 0,
        daily_amount: h.daily_amount,
        days_completed: h.days_completed || 0,
        total_days: h.harvest_plans?.duration_days || 0,
        status: h.status,
        auto_save: h.auto_save || false,
        created_at: h.created_at,
      });
    });

    // Format fixed
    (fixed.data || []).forEach((f) => {
      const today = new Date();
      const maturityDate = new Date(f.maturity_date);
      const isMatured = maturityDate <= today;

      allSavings.push({
        id: f.id,
        type: "fixed",
        amount: f.amount || 0,
        current_saved: f.current_saved || 0,
        daily_amount: f.daily_amount || f.amount / 30,
        interest_rate: f.interest_rate || 5,
        maturity_date: f.maturity_date,
        status: isMatured ? "matured" : f.status,
        auto_save: f.auto_save || true,
        created_at: f.created_at,
      });
    });

    // Format savebox
    (savebox.data || []).forEach((s) => {
      allSavings.push({
        id: s.id,
        type: "savebox",
        amount: s.amount || 0,
        current_saved: s.current_saved || 0,
        daily_amount: s.daily_amount || s.amount / 90,
        target_date: s.target_date,
        early_withdrawal_fee_percent: s.early_withdrawal_fee_percent || 4,
        status: s.status,
        auto_save: s.auto_save || true,
        created_at: s.created_at,
      });
    });

    // Format target
    (target.data || []).forEach((t) => {
      const withdrawalDate = new Date(t.withdrawal_date);
      const today = new Date();
      const canWithdraw =
        withdrawalDate <= today && t.current_saved >= t.target_amount;

      allSavings.push({
        id: t.id,
        type: "target",
        target_amount: t.target_amount || 0,
        current_saved: t.current_saved || 0,
        daily_savings_amount: t.daily_savings_amount,
        withdrawal_date: t.withdrawal_date,
        days_remaining: t.days_remaining || 0,
        status: canWithdraw ? "completed" : t.status,
        auto_save: t.auto_save || true,
        created_at: t.created_at,
      });
    });

    // Format spare_change
    (spareChange.data || []).forEach((s) => {
      allSavings.push({
        id: s.id,
        type: "spare_change",
        current_saved: s.current_saved || 0,
        total_saved: s.total_saved || 0,
        percentage_rate: s.percentage_rate || 3,
        status: s.status,
        auto_save: s.auto_save || true,
        created_at: s.created_at,
      });
    });

    res.json(allSavings);
  } catch (error) {
    console.error("Get savings error:", error);
    res
      .status(500)
      .json({ error: "Failed to fetch savings: " + error.message });
  }
});

// Get single savings details (FIXED - get specific savings by type and id)
app.get("/api/user/savings/:type/:id", authenticate, async (req, res) => {
  const { type, id } = req.params;

  try {
    console.log(`Fetching ${type} savings ${id} for user:`, req.user.id);

    let result = null;
    const today = new Date();

    switch (type) {
      case "harvest":
        const { data: harvest, error: hError } = await supabase
          .from("user_harvest_enrollments")
          .select(
            "*, harvest_plans(name, daily_amount, duration_days, reward_items)",
          )
          .eq("id", id)
          .eq("user_id", req.user.id)
          .single();
        if (hError) throw hError;
        result = {
          ...harvest,
          type: "harvest",
          plan_name: harvest.harvest_plans?.name,
          total_days: harvest.harvest_plans?.duration_days,
          reward_items: harvest.harvest_plans?.reward_items,
        };
        break;

      case "fixed":
        const { data: fixed, error: fError } = await supabase
          .from("fixed_savings")
          .select("*")
          .eq("id", id)
          .eq("user_id", req.user.id)
          .single();
        if (fError) throw fError;

        const maturityDate = new Date(fixed.maturity_date);
        const daysUntilMaturity = Math.max(
          0,
          Math.ceil((maturityDate - today) / (1000 * 60 * 60 * 24)),
        );
        const isMatured = maturityDate <= today;
        const freeWithdrawalDate = new Date(fixed.next_free_withdrawal_date);
        const isFreeWithdrawal = isMatured && today <= freeWithdrawalDate;
        const interestEarned =
          (fixed.current_saved || 0) * (fixed.interest_rate / 100);

        result = {
          ...fixed,
          type: "fixed",
          days_until_maturity: daysUntilMaturity,
          status: isMatured ? "matured" : fixed.status,
          is_free_withdrawal_available: isFreeWithdrawal,
          interest_earned: interestEarned,
          total_with_interest: (fixed.current_saved || 0) + interestEarned,
          duration_days: 30,
        };
        break;

      case "savebox":
        const { data: savebox, error: sError } = await supabase
          .from("savebox_savings")
          .select("*")
          .eq("id", id)
          .eq("user_id", req.user.id)
          .single();
        if (sError) throw sError;
        result = { ...savebox, type: "savebox" };
        break;

      case "target":
        const { data: target, error: tError } = await supabase
          .from("target_savings")
          .select("*")
          .eq("id", id)
          .eq("user_id", req.user.id)
          .single();
        if (tError) throw tError;

        const withdrawalDate = new Date(target.withdrawal_date);
        const daysUntilWithdrawal = Math.max(
          0,
          Math.ceil((withdrawalDate - today) / (1000 * 60 * 60 * 24)),
        );
        const percentComplete =
          target.target_amount > 0
            ? (target.current_saved / target.target_amount) * 100
            : 0;
        const canWithdraw =
          withdrawalDate <= today &&
          target.current_saved >= target.target_amount;

        result = {
          ...target,
          type: "target",
          days_until_withdrawal: daysUntilWithdrawal,
          percent_complete: percentComplete,
          can_withdraw: canWithdraw,
          status: canWithdraw ? "completed" : target.status,
        };
        break;

      case "spare_change":
        const { data: spare, error: spError } = await supabase
          .from("spare_change_savings")
          .select("*")
          .eq("id", id)
          .eq("user_id", req.user.id)
          .single();
        if (spError) throw spError;
        result = { ...spare, type: "spare_change" };
        break;

      default:
        return res.status(400).json({ error: "Invalid savings type" });
    }

    res.json(result);
  } catch (error) {
    console.error("Get savings detail error:", error);
    res
      .status(500)
      .json({ error: "Failed to fetch savings details: " + error.message });
  }
});

// Toggle auto-save for savings plan
app.post(
  "/api/user/savings/:type/:id/toggle-auto",
  authenticate,
  async (req, res) => {
    const { type, id } = req.params;
    const { auto_save } = req.body;

    try {
      let table;
      switch (type) {
        case "harvest":
          table = "user_harvest_enrollments";
          break;
        case "fixed":
          table = "fixed_savings";
          break;
        case "savebox":
          table = "savebox_savings";
          break;
        case "target":
          table = "target_savings";
          break;
        case "spare_change":
          table = "spare_change_savings";
          break;
        default:
          return res.status(400).json({ error: "Invalid savings type" });
      }

      const { error } = await supabase
        .from(table)
        .update({ auto_save: auto_save, updated_at: new Date() })
        .eq("id", id)
        .eq("user_id", req.user.id);

      if (error) throw error;

      res.json({
        success: true,
        message: auto_save ? "Auto-save enabled" : "Auto-save disabled",
        auto_save: auto_save,
      });
    } catch (error) {
      console.error("Toggle auto-save error:", error);
      res.status(500).json({ error: "Failed to toggle auto-save" });
    }
  },
);

// Withdraw from savings (with fee calculation for SaveBox)
/*app.post(
  "/api/user/savings/:type/:id/withdraw",
  authenticate,
  async (req, res) => {
    const { type, id } = req.params;

    try {
      let savingsRecord, account;

      // Get the savings record based on type
      switch (type) {
        case "harvest":
          const { data: harvest, error: hError } = await supabase
            .from("user_harvest_enrollments")
            .select("*, users!inner(id, email, first_name, last_name)")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (hError) throw hError;
          savingsRecord = harvest;
          break;
        case "fixed":
          const { data: fixed, error: fError } = await supabase
            .from("fixed_savings")
            .select("*, users!inner(id, email, first_name, last_name)")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (fError) throw fError;
          savingsRecord = fixed;
          break;
        case "savebox":
          const { data: savebox, error: sError } = await supabase
            .from("savebox_savings")
            .select("*, users!inner(id, email, first_name, last_name)")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (sError) throw sError;
          savingsRecord = savebox;
          break;
        case "target":
          const { data: target, error: tError } = await supabase
            .from("target_savings")
            .select("*, users!inner(id, email, first_name, last_name)")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (tError) throw tError;
          savingsRecord = target;
          break;
        case "spare_change":
          const { data: spare, error: spError } = await supabase
            .from("spare_change_savings")
            .select("*, users!inner(id, email, first_name, last_name)")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (spError) throw spError;
          savingsRecord = spare;
          break;
        default:
          return res.status(400).json({ error: "Invalid savings type" });
      }

      if (!savingsRecord) {
        return res.status(404).json({ error: "Savings record not found" });
      }

      // Get user's primary account
      const { data: userAccount, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", req.user.id)
        .eq("account_type", "checking")
        .single();

      if (accError || !userAccount) {
        return res.status(404).json({ error: "Account not found" });
      }
      account = userAccount;

      let withdrawAmount = 0;
      let fee = 0;
      let feePercentage = 0;

      // Calculate withdrawal amount and fee
      switch (type) {
        case "harvest":
          withdrawAmount = savingsRecord.total_saved || 0;
          break;
        case "fixed":
          const interest =
            savingsRecord.current_saved * (savingsRecord.interest_rate / 100);
          const today = new Date();
          const isFreeWithdrawal =
            savingsRecord.status === "matured" &&
            today <= new Date(savingsRecord.next_free_withdrawal_date);

          if (isFreeWithdrawal) {
            withdrawAmount = savingsRecord.current_saved + interest;
            fee = 0;
          } else if (savingsRecord.status === "matured") {
            withdrawAmount = savingsRecord.current_saved + interest;
            fee = withdrawAmount * 0.02; // 2% fee after free period
            withdrawAmount -= fee;
          } else {
            return res.status(400).json({ error: "Savings not yet matured" });
          }
          break;
        case "savebox":
          withdrawAmount = savingsRecord.current_saved || 0;
          const isEarlyWithdrawal =
            new Date() < new Date(savingsRecord.target_date);
          if (isEarlyWithdrawal) {
            feePercentage = savingsRecord.early_withdrawal_fee_percent || 4;
            fee = withdrawAmount * (feePercentage / 100);
            withdrawAmount -= fee;
          }
          break;
        case "target":
          if (
            !savingsRecord.target_met &&
            savingsRecord.current_saved < savingsRecord.target_amount
          ) {
            return res.status(400).json({ error: "Target not yet reached" });
          }
          withdrawAmount = savingsRecord.current_saved || 0;
          break;
        case "spare_change":
          withdrawAmount = savingsRecord.current_saved || 0;
          break;
      }

      if (withdrawAmount <= 0) {
        return res.status(400).json({ error: "No funds to withdraw" });
      }

      // Update account balance
      const newBalance = account.balance + withdrawAmount;
      const newAvailable = account.available_balance + withdrawAmount;

      await supabase
        .from("accounts")
        .update({ balance: newBalance, available_balance: newAvailable })
        .eq("id", account.id);

      // Update savings record status
      await supabase
        .from(
          type === "harvest"
            ? "user_harvest_enrollments"
            : type === "fixed"
              ? "fixed_savings"
              : type === "savebox"
                ? "savebox_savings"
                : type === "target"
                  ? "target_savings"
                  : "spare_change_savings",
        )
        .update({
          status: "withdrawn",
          updated_at: new Date(),
        })
        .eq("id", id);

      // Create withdrawal transaction
      await supabase.from("transactions_new").insert({
        to_account_id: account.id,
        to_user_id: req.user.id,
        amount: withdrawAmount,
        description: `${type.charAt(0).toUpperCase() + type.slice(1)} Savings Withdrawal${fee > 0 ? ` (Fee: ₦${fee.toFixed(2)})` : ""}`,
        transaction_type: "savings_withdrawal",
        status: "completed",
        completed_at: new Date(),
      });

      // Create savings transaction record
      await supabase.from("savings_transactions").insert({
        user_id: req.user.id,
        savings_type: type,
        savings_id: id,
        amount: withdrawAmount,
        transaction_type: "withdrawal",
        description: `Withdrawn from ${type} savings${fee > 0 ? `, fee: ₦${fee.toFixed(2)}` : ""}`,
      });

      // Send email notification
      try {
        await transporter.sendMail({
          from: process.env.SMTP_FROM,
          to: savingsRecord.users?.email || req.user.email,
          subject: `${type.charAt(0).toUpperCase() + type.slice(1)} Savings Withdrawal`,
          html: `
                    <h2>Withdrawal Complete</h2>
                    <p>Dear ${savingsRecord.users?.first_name || req.user.first_name},</p>
                    <p>You have successfully withdrawn <strong>₦${withdrawAmount.toFixed(2)}</strong> from your ${type} savings.</p>
                    ${fee > 0 ? `<p>Withdrawal fee: <strong>₦${fee.toFixed(2)}</strong> (${feePercentage}%)</p>` : ""}
                    <p>Amount credited to your account: <strong>₦${withdrawAmount.toFixed(2)}</strong></p>
                    <p>Thank you for saving with us!</p>
                `,
        });
      } catch (emailError) {
        console.error("Email error:", emailError);
      }

      res.json({
        success: true,
        message: "Withdrawal completed successfully",
        amount_withdrawn: withdrawAmount,
        fee_charged: fee,
        new_balance: newAvailable,
      });
    } catch (error) {
      console.error("Withdrawal error:", error);
      res
        .status(500)
        .json({ error: "Failed to process withdrawal: " + error.message });
    }
  },
);

*/

// index.js - REPLACE the existing savings withdrawal endpoint
app.post(
  "/api/user/savings/:type/:id/withdraw",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    const { type, id } = req.params;

    try {
      let savingsRecord,
        feeAmount = 0,
        withdrawAmount = 0;

      // Get the savings record based on type
      switch (type) {
        case "harvest":
          const { data: harvest, error: hError } = await supabase
            .from("user_harvest_enrollments")
            .select("*")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (hError) throw hError;
          savingsRecord = harvest;
          withdrawAmount = harvest.total_saved || 0;
          break;

        case "fixed":
          const { data: fixed, error: fError } = await supabase
            .from("fixed_savings")
            .select("*")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (fError) throw fError;
          savingsRecord = fixed;

          const interest = fixed.current_saved * (fixed.interest_rate / 100);
          const today = new Date();
          const maturityDate = new Date(fixed.maturity_date);
          const isMatured = maturityDate <= today;

          if (!isMatured) {
            return res.status(400).json({ error: "Savings not yet matured" });
          }

          // Check if free withdrawal period
          const freeWithdrawalDate = new Date(fixed.next_free_withdrawal_date);
          const isFreeWithdrawal = today <= freeWithdrawalDate;

          withdrawAmount = fixed.current_saved + interest;

          if (!isFreeWithdrawal) {
            feeAmount = withdrawAmount * 0.02; // 2% fee after free period
            withdrawAmount -= feeAmount;
          }
          break;

        case "savebox":
          const { data: savebox, error: sError } = await supabase
            .from("savebox_savings")
            .select("*")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (sError) throw sError;
          savingsRecord = savebox;
          withdrawAmount = savebox.current_saved || 0;

          const isEarlyWithdrawal =
            new Date() < new Date(savebox.target_date) &&
            savebox.current_saved < savebox.amount;
          if (isEarlyWithdrawal) {
            feeAmount =
              withdrawAmount * (savebox.early_withdrawal_fee_percent / 100);
            withdrawAmount -= feeAmount;
          }
          break;

        case "target":
          const { data: target, error: tError } = await supabase
            .from("target_savings")
            .select("*")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (tError) throw tError;
          savingsRecord = target;

          if (
            !target.target_met &&
            target.current_saved < target.target_amount
          ) {
            return res.status(400).json({ error: "Target not yet reached" });
          }
          withdrawAmount = target.current_saved || 0;
          break;

        case "spare_change":
          const { data: spare, error: spError } = await supabase
            .from("spare_change_savings")
            .select("*")
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();
          if (spError) throw spError;
          savingsRecord = spare;
          withdrawAmount = spare.current_saved || 0;
          break;

        default:
          return res.status(400).json({ error: "Invalid savings type" });
      }

      if (withdrawAmount <= 0) {
        return res.status(400).json({ error: "No funds to withdraw" });
      }

      // Get user's primary checking account
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", req.user.id)
        .eq("account_type", "checking")
        .single();

      if (accError || !account) {
        return res.status(404).json({ error: "Account not found" });
      }

      // ========== CRITICAL: Update user balance ==========
      const newUserBalance = account.balance + withdrawAmount;
      const newUserAvailable = account.available_balance + withdrawAmount;

      const { error: updateUserBalanceError } = await supabase
        .from("accounts")
        .update({
          balance: newUserBalance,
          available_balance: newUserAvailable,
          updated_at: new Date().toISOString(),
        })
        .eq("id", account.id);

      if (updateUserBalanceError) {
        console.error("Failed to update user balance:", updateUserBalanceError);
        return res.status(500).json({ error: "Failed to process withdrawal" });
      }

      console.log(
        `✅ Added ₦${withdrawAmount} to user ${req.user.id}. New balance: ₦${newUserAvailable}`,
      );

      // ========== Update savings record status ==========
      const tableMap = {
        harvest: "user_harvest_enrollments",
        fixed: "fixed_savings",
        savebox: "savebox_savings",
        target: "target_savings",
        spare_change: "spare_change_savings",
      };

      const tableName = tableMap[type];
      if (tableName) {
        await supabase
          .from(tableName)
          .update({
            status: "withdrawn",
            updated_at: new Date().toISOString(),
          })
          .eq("id", id);
      }

      // ========== Update savings pool accounts ==========
      let poolType = "";
      switch (type) {
        case "fixed":
          poolType = "fixed_pool";
          break;
        case "savebox":
          poolType = "savebox_pool";
          break;
        case "target":
          poolType = "target_pool";
          break;
        case "spare_change":
          poolType = "spare_change_pool";
          break;
        case "harvest":
          poolType = "harvest_pool";
          break;
      }

      if (poolType) {
        const { data: poolAccount } = await supabase
          .from("savings_pool_accounts")
          .select("*")
          .eq("account_type", poolType)
          .single();

        if (poolAccount) {
          const newPoolBalance =
            poolAccount.balance - (withdrawAmount + feeAmount);
          await supabase
            .from("savings_pool_accounts")
            .update({
              balance: newPoolBalance,
              available_balance: newPoolBalance,
              updated_at: new Date().toISOString(),
            })
            .eq("id", poolAccount.id);

          console.log(
            `✅ Deducted ₦${withdrawAmount + feeAmount} from ${poolType}. New balance: ₦${newPoolBalance}`,
          );
        }
      }

      // ========== Add fee to fee account ==========
      if (feeAmount > 0) {
        const { data: feeAccount } = await supabase
          .from("savings_pool_accounts")
          .select("*")
          .eq("account_type", "fee_account")
          .single();

        if (feeAccount) {
          const newFeeBalance = feeAccount.balance + feeAmount;
          await supabase
            .from("savings_pool_accounts")
            .update({
              balance: newFeeBalance,
              available_balance: newFeeBalance,
              updated_at: new Date().toISOString(),
            })
            .eq("id", feeAccount.id);

          console.log(
            `✅ Added fee ₦${feeAmount} to fee_account. New balance: ₦${newFeeBalance}`,
          );
        }
      }

      // ========== Create transaction record ==========
      const { error: txError } = await supabase
        .from("transactions_new")
        .insert({
          receiver_account_id: account.id,
          receiver_user_id: req.user.id,
          amount: withdrawAmount,
          description: `${type.charAt(0).toUpperCase() + type.slice(1)} Savings Withdrawal${feeAmount > 0 ? ` (Fee: ₦${feeAmount})` : ""}`,
          transaction_type: "savings_withdrawal",
          status: "completed",
          completed_at: new Date().toISOString(),
          created_at: new Date().toISOString(),
          metadata: { fee_amount: feeAmount },
        });

      if (txError) console.error("Transaction creation error:", txError);

      // ========== Create savings transaction record ==========
      await supabase.from("savings_transactions").insert({
        user_id: req.user.id,
        savings_type: type,
        savings_id: id,
        amount: withdrawAmount + feeAmount,
        fee_amount: feeAmount,
        transaction_type: "withdrawal",
        description: `Withdrawn from ${type} savings${feeAmount > 0 ? `, fee: ₦${feeAmount}` : ""}`,
        processed_by: req.user.id,
        processed_at: new Date().toISOString(),
      });

      // ========== Create notification ==========
      await supabase.from("notifications").insert({
        user_id: req.user.id,
        title: "Savings Withdrawal Successful",
        message: `You have successfully withdrawn ₦${withdrawAmount.toLocaleString()} from your ${type} savings.${feeAmount > 0 ? ` A fee of ₦${feeAmount.toLocaleString()} was applied.` : ""}`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Withdrawal completed successfully",
        amount_withdrawn: withdrawAmount,
        fee_charged: feeAmount,
        new_balance: newUserAvailable,
      });
    } catch (error) {
      console.error("Withdrawal error:", error);
      res
        .status(500)
        .json({ error: "Failed to process withdrawal: " + error.message });
    }
  },
);

// ============================================================
// SAVINGS WITHDRAWAL API - PRODUCTION GRADE
// ============================================================
// Add this to your index.js file
// REPLACE the existing /api/user/savings/:type/:id/withdraw endpoint

/*app.post(
  "/api/user/savings/:type/:id/withdraw",
  authenticate,
  checkAccountFrozen,
  preventConcurrentTransfer,
  releaseTransactionLock,
  async (req, res) => {
    const { type, id } = req.params;
    const { amount } = req.body;
    const requestId =
      req.headers["idempotency-key"] ||
      req.body.requestId ||
      crypto.randomUUID();

    try {
      console.log(
        `[Savings Withdrawal] User ${req.user.id} requesting withdrawal from ${type} savings ${id}`,
      );

      // ============================================================
      // 1. VALIDATE INPUT
      // ============================================================
      if (!type || !id) {
        return res.status(400).json({
          error: "Savings type and ID required",
          code: "MISSING_FIELDS",
        });
      }

      // ============================================================
      // 2. GET SAVINGS RECORD
      // ============================================================
      let tableName = "";
      let savingsRecord = null;

      switch (type) {
        case "harvest":
          tableName = "user_harvest_enrollments";
          const { data: harvest, error: hError } = await supabase
            .from("user_harvest_enrollments")
            .select(
              `
              *,
              users!inner(id, email, first_name, last_name, is_frozen),
              harvest_plans!inner(
                id, 
                name, 
                daily_amount, 
                duration_days, 
                total_amount,
                reward_items
              )
            `,
            )
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();

          if (hError) throw hError;
          savingsRecord = harvest;
          break;

        case "fixed":
          tableName = "fixed_savings";
          const { data: fixed, error: fError } = await supabase
            .from("fixed_savings")
            .select(
              `
              *,
              users!inner(id, email, first_name, last_name, is_frozen)
            `,
            )
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();

          if (fError) throw fError;
          savingsRecord = fixed;
          break;

        case "savebox":
          tableName = "savebox_savings";
          const { data: savebox, error: sError } = await supabase
            .from("savebox_savings")
            .select(
              `
              *,
              users!inner(id, email, first_name, last_name, is_frozen)
            `,
            )
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();

          if (sError) throw sError;
          savingsRecord = savebox;
          break;

        case "target":
          tableName = "target_savings";
          const { data: target, error: tError } = await supabase
            .from("target_savings")
            .select(
              `
              *,
              users!inner(id, email, first_name, last_name, is_frozen)
            `,
            )
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();

          if (tError) throw tError;
          savingsRecord = target;
          break;

        case "spare_change":
          tableName = "spare_change_savings";
          const { data: spare, error: spError } = await supabase
            .from("spare_change_savings")
            .select(
              `
              *,
              users!inner(id, email, first_name, last_name, is_frozen)
            `,
            )
            .eq("id", id)
            .eq("user_id", req.user.id)
            .single();

          if (spError) throw spError;
          savingsRecord = spare;
          break;

        default:
          return res.status(400).json({
            error: "Invalid savings type",
            code: "INVALID_SAVINGS_TYPE",
          });
      }

      if (!savingsRecord) {
        return res.status(404).json({
          error: "Savings record not found",
          code: "SAVINGS_NOT_FOUND",
        });
      }

      if (savingsRecord.users?.is_frozen) {
        return res.status(403).json({
          error: "Account is frozen",
          code: "ACCOUNT_FROZEN",
        });
      }

      // ============================================================
      // 3. VALIDATE WITHDRAWAL CONDITIONS
      // ============================================================

      // Check if already withdrawn
      if (savingsRecord.status === "withdrawn") {
        return res.status(400).json({
          error: "This savings has already been withdrawn",
          code: "ALREADY_WITHDRAWN",
        });
      }

      // Check if active
      if (
        savingsRecord.status !== "active" &&
        savingsRecord.status !== "matured"
      ) {
        return res.status(400).json({
          error: "This savings is not active or matured",
          code: "SAVINGS_NOT_ACTIVE",
        });
      }

      // Calculate withdrawal amount and fees
      let withdrawAmount = 0;
      let feeAmount = 0;
      let feePercentage = 0;
      let canWithdraw = false;
      let message = "";

      const today = new Date();

      switch (type) {
        case "harvest":
          // Harvest plans require admin approval - redirect to request flow
          return res.status(400).json({
            error:
              "Harvest plan withdrawals require admin approval. Please use the withdrawal request feature.",
            code: "ADMIN_APPROVAL_REQUIRED",
            requires_admin_approval: true,
          });

        case "fixed":
          const fixedMaturityDate = new Date(savingsRecord.maturity_date);
          const isMatured = fixedMaturityDate <= today;

          if (!isMatured) {
            return res.status(400).json({
              error: "Fixed savings has not matured yet",
              code: "NOT_MATURED",
              maturity_date: fixedMaturityDate.toISOString(),
              days_remaining: Math.ceil(
                (fixedMaturityDate - today) / (1000 * 60 * 60 * 24),
              ),
            });
          }

          // Calculate interest
          const interest =
            (savingsRecord.current_saved || 0) *
            (savingsRecord.interest_rate / 100);
          withdrawAmount = (savingsRecord.current_saved || 0) + interest;

          // Check free withdrawal period
          const freeWithdrawalDate = new Date(
            savingsRecord.next_free_withdrawal_date,
          );
          const isFreeWithdrawal = today <= freeWithdrawalDate;

          if (!isFreeWithdrawal) {
            feePercentage = 2; // 2% fee after free period
            feeAmount = withdrawAmount * (feePercentage / 100);
            withdrawAmount = withdrawAmount - feeAmount;
          }

          canWithdraw = true;
          message = `${isFreeWithdrawal ? "Free" : feePercentage + "%"} withdrawal. Amount: ₦${withdrawAmount.toLocaleString()}`;
          break;

        case "savebox":
          const targetDate = new Date(savingsRecord.target_date);
          const isTargetReached =
            today >= targetDate ||
            (savingsRecord.current_saved || 0) >= (savingsRecord.amount || 0);

          withdrawAmount = savingsRecord.current_saved || 0;

          if (withdrawAmount <= 0) {
            return res.status(400).json({
              error: "No funds available to withdraw",
              code: "NO_FUNDS",
            });
          }

          if (!isTargetReached) {
            feePercentage = savingsRecord.early_withdrawal_fee_percent || 4;
            feeAmount = withdrawAmount * (feePercentage / 100);
            withdrawAmount = withdrawAmount - feeAmount;
          }

          canWithdraw = true;
          message = `${isTargetReached ? "No" : feePercentage + "%"} fee applied. You will receive ₦${withdrawAmount.toLocaleString()}`;
          break;

        case "target":
          const withdrawalDate = new Date(savingsRecord.withdrawal_date);
          const isTargetMet =
            savingsRecord.target_met ||
            (savingsRecord.current_saved || 0) >=
              (savingsRecord.target_amount || 0);
          const canWithdrawTarget = isTargetMet || withdrawalDate <= today;

          if (!canWithdrawTarget) {
            return res.status(400).json({
              error: "Target savings goal has not been reached yet",
              code: "TARGET_NOT_REACHED",
              target_amount: savingsRecord.target_amount,
              current_saved: savingsRecord.current_saved,
              withdrawal_date: savingsRecord.withdrawal_date,
              days_remaining: Math.ceil(
                (withdrawalDate - today) / (1000 * 60 * 60 * 24),
              ),
            });
          }

          withdrawAmount = savingsRecord.current_saved || 0;

          if (withdrawAmount <= 0) {
            return res.status(400).json({
              error: "No funds available to withdraw",
              code: "NO_FUNDS",
            });
          }

          canWithdraw = true;
          message = `Full withdrawal of ₦${withdrawAmount.toLocaleString()}`;
          break;

        case "spare_change":
          withdrawAmount = savingsRecord.current_saved || 0;

          if (withdrawAmount <= 0) {
            return res.status(400).json({
              error: "No funds available to withdraw",
              code: "NO_FUNDS",
            });
          }

          canWithdraw = true;
          feeAmount = 0;
          message = `Full withdrawal of ₦${withdrawAmount.toLocaleString()} (No fees)`;
          break;

        default:
          return res.status(400).json({
            error: "Invalid savings type for withdrawal",
            code: "INVALID_TYPE",
          });
      }

      if (!canWithdraw) {
        return res.status(400).json({
          error: "Cannot withdraw from this savings at this time",
          code: "WITHDRAWAL_NOT_ALLOWED",
        });
      }

      if (withdrawAmount <= 0) {
        return res.status(400).json({
          error: "Withdrawal amount is zero or negative",
          code: "ZERO_AMOUNT",
        });
      }

      // ============================================================
      // 4. GET USER'S CHECKING ACCOUNT
      // ============================================================
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", req.user.id)
        .eq("account_type", "checking")
        .single();

      if (accError || !account) {
        return res.status(404).json({
          error: "User account not found",
          code: "ACCOUNT_NOT_FOUND",
        });
      }

      // ============================================================
      // 5. GET SAVINGS POOL ACCOUNT
      // ============================================================
      let poolType = "";
      switch (type) {
        case "fixed":
          poolType = "fixed_pool";
          break;
        case "savebox":
          poolType = "savebox_pool";
          break;
        case "target":
          poolType = "target_pool";
          break;
        case "spare_change":
          poolType = "spare_change_pool";
          break;
        default:
          poolType = "fixed_pool";
      }

      const { data: poolAccount, error: poolError } = await supabase
        .from("savings_pool_accounts")
        .select("*")
        .eq("account_type", poolType)
        .single();

      if (poolError || !poolAccount) {
        console.error(`Pool account ${poolType} not found:`, poolError);
        return res.status(500).json({
          error: "Savings pool account not found",
          code: "POOL_NOT_FOUND",
        });
      }

      // Check if pool has sufficient funds
      if (poolAccount.balance < withdrawAmount + feeAmount) {
        console.error(
          `Insufficient pool funds: ${poolType} balance ₦${poolAccount.balance}, required ₦${withdrawAmount + feeAmount}`,
        );
        return res.status(500).json({
          error: "Insufficient pool funds. Please contact support.",
          code: "POOL_INSUFFICIENT",
        });
      }

      // ============================================================
      // 6. EXECUTE WITHDRAWAL TRANSACTION USING FinancialTransactionService
      // ============================================================
      const FinancialTransactionService = require("../services/FinancialTransactionService");
      const transactionService = new FinancialTransactionService();

      // Prepare debits and credits
      let debits = [];
      let credits = [];

      // DEBIT: From savings pool account
      debits.push({
        accountId: poolAccount.id,
        amount: withdrawAmount + feeAmount,
        reason: `Savings withdrawal from ${type} pool`,
      });

      // CREDIT: To user's checking account
      credits.push({
        accountId: account.id,
        amount: withdrawAmount,
        reason: `Savings withdrawal from ${type}`,
      });

      // CREDIT: Fee to fee account (if applicable)
      if (feeAmount > 0) {
        const { data: feeAccount } = await supabase
          .from("savings_pool_accounts")
          .select("*")
          .eq("account_type", "fee_account")
          .single();

        if (feeAccount) {
          credits.push({
            accountId: feeAccount.id,
            amount: feeAmount,
            reason: `Savings withdrawal fee (${feePercentage}%) from ${type}`,
          });
        } else {
          console.warn("Fee account not found - fee will not be collected");
        }
      }

      // Execute transaction
      const result = await transactionService.executeTransaction({
        requestId: requestId,
        userId: req.user.id,
        type: "SAVINGS_WITHDRAWAL",
        description: `Withdrawal from ${type} savings: ${message}`,
        debits: debits,
        credits: credits,
        metadata: {
          ip: req.ip,
          userAgent: req.headers["user-agent"],
          savings_type: type,
          savings_id: id,
          fee_amount: feeAmount,
          fee_percentage: feePercentage,
          withdraw_amount: withdrawAmount,
        },
      });

      // ============================================================
      // 7. UPDATE SAVINGS RECORD STATUS
      // ============================================================
      const { error: updateError } = await supabase
        .from(tableName)
        .update({
          status: "withdrawn",
          updated_at: new Date().toISOString(),
        })
        .eq("id", id);

      if (updateError) {
        console.error(`Failed to update ${type} savings status:`, updateError);
        // Don't return error - transaction already completed
      }

      // ============================================================
      // 8. CREATE SAVINGS TRANSACTION RECORD
      // ============================================================
      const { error: savingsTxError } = await supabase
        .from("savings_transactions")
        .insert({
          user_id: req.user.id,
          savings_type: type,
          savings_id: id,
          amount: withdrawAmount,
          fee_amount: feeAmount,
          transaction_type: "withdrawal",
          description: `Withdrawn from ${type} savings${feeAmount > 0 ? `, fee: ₦${feeAmount}` : ""}`,
          from_pool_account_id: poolAccount.id,
          to_pool_account_id:
            feeAmount > 0
              ? (
                  await supabase
                    .from("savings_pool_accounts")
                    .select("id")
                    .eq("account_type", "fee_account")
                    .single()
                ).data?.id
              : null,
          processed_by: req.user.id,
          processed_at: new Date().toISOString(),
        });

      if (savingsTxError) {
        console.error("Savings transaction error:", savingsTxError);
      }

      // ============================================================
      // 9. CREATE NOTIFICATION
      // ============================================================
      await supabase.from("notifications").insert({
        user_id: req.user.id,
        title: "Savings Withdrawal Successful",
        message: `You have successfully withdrawn ₦${withdrawAmount.toLocaleString()} from your ${type} savings.${feeAmount > 0 ? ` A fee of ₦${feeAmount.toLocaleString()} was applied.` : ""}`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      // ============================================================
      // 10. RETURN SUCCESS RESPONSE
      // ============================================================
      console.log(
        `✅ Savings withdrawal completed: User ${req.user.id}, Type ${type}, Amount ₦${withdrawAmount}, Fee ₦${feeAmount}`,
      );

      res.json({
        success: true,
        message: "Withdrawal completed successfully",
        data: {
          savings_type: type,
          savings_id: id,
          amount_withdrawn: withdrawAmount,
          fee_charged: feeAmount,
          fee_percentage: feePercentage,
          new_balance:
            result.balances.find((b) => b.accountId === account.id)
              ?.balanceAfter || 0,
          transaction_reference: result.transactionReference,
          completed_at: new Date().toISOString(),
        },
      });
    } catch (error) {
      console.error("[Savings Withdrawal Error]", error);

      // ============================================================
      // ERROR HANDLING
      // ============================================================

      // Idempotency error
      if (error.message === "Duplicate transaction detected") {
        return res.status(409).json({
          error: "Duplicate transaction detected",
          code: "DUPLICATE_TRANSACTION",
          message: "This withdrawal has already been processed",
        });
      }

      // Insufficient balance in pool
      if (error.message.includes("Insufficient balance")) {
        return res.status(400).json({
          error: "Insufficient pool balance",
          code: "POOL_INSUFFICIENT",
          message: "Please contact support",
        });
      }

      // Database transaction error
      if (error.message.includes("Failed to insert ledger entry")) {
        return res.status(500).json({
          error: "Ledger entry failed",
          code: "LEDGER_FAILED",
          message: "Please contact support",
        });
      }

      // Generic error
      res.status(500).json({
        error: "Withdrawal failed",
        code: "WITHDRAWAL_FAILED",
        message: error.message,
      });
    }
  },
);*/

// Cancel savings plan (stop auto-save but keep saved amount)
app.post(
  "/api/user/savings/:type/:id/cancel",
  authenticate,
  async (req, res) => {
    const { type, id } = req.params;

    try {
      let table;
      switch (type) {
        case "harvest":
          table = "user_harvest_enrollments";
          break;
        case "fixed":
          table = "fixed_savings";
          break;
        case "savebox":
          table = "savebox_savings";
          break;
        case "target":
          table = "target_savings";
          break;
        case "spare_change":
          table = "spare_change_savings";
          break;
        default:
          return res.status(400).json({ error: "Invalid savings type" });
      }

      const { error } = await supabase
        .from(table)
        .update({
          auto_save: false,
          status: "cancelled",
          updated_at: new Date(),
        })
        .eq("id", id)
        .eq("user_id", req.user.id);

      if (error) throw error;

      res.json({
        success: true,
        message:
          "Savings plan cancelled. Your saved funds remain available for withdrawal.",
      });
    } catch (error) {
      console.error("Cancel savings error:", error);
      res.status(500).json({ error: "Failed to cancel savings plan" });
    }
  },
);

// ==================== HARVEST PLAN ADD UP SAVINGS ====================

// Execute add-up savings (with PIN verification)
app.post(
  "/api/user/savings/harvest/:id/add-up",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { amount, pin } = req.body;

      if (!amount || amount <= 0) {
        return res.status(400).json({ error: "Invalid amount" });
      }

      // Verify PIN first
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("transfer_pin, pin_attempts, last_pin_attempt")
        .eq("id", req.user.id)
        .single();

      if (userError) {
        return res.status(500).json({ error: "Failed to verify PIN" });
      }

      if (!user.transfer_pin) {
        return res.status(400).json({
          error: "PIN_NOT_SET",
          message: "Please set a transfer PIN first",
        });
      }

      // Check PIN attempts
      const maxAttempts = 4;
      const attemptWindow = 15 * 60 * 1000;

      if (user.pin_attempts >= maxAttempts) {
        const lastAttempt = new Date(user.last_pin_attempt);
        if (Date.now() - lastAttempt < attemptWindow) {
          return res.status(429).json({
            error: "Too many incorrect PIN attempts. Please try again later.",
            frozen: true,
          });
        } else {
          await supabase
            .from("users")
            .update({ pin_attempts: 0 })
            .eq("id", req.user.id);
        }
      }

      const isValidPin = await bcrypt.compare(pin, user.transfer_pin);

      if (!isValidPin) {
        const newAttempts = (user.pin_attempts || 0) + 1;
        const updates = {
          pin_attempts: newAttempts,
          last_pin_attempt: new Date(),
        };

        if (newAttempts >= maxAttempts) {
          updates.is_frozen = true;
          updates.freeze_reason =
            "Too many incorrect PIN attempts - Contact support to unfreeze";
          updates.unfreeze_method = "support";
        }

        await supabase.from("users").update(updates).eq("id", req.user.id);

        return res.status(401).json({
          error: "Incorrect PIN",
          attempts_remaining: maxAttempts - newAttempts,
          frozen: newAttempts >= maxAttempts,
        });
      }

      // Reset PIN attempts on success
      await supabase
        .from("users")
        .update({ pin_attempts: 0, last_pin_attempt: null })
        .eq("id", req.user.id);

      // Get harvest enrollment
      const { data: enrollment, error: hError } = await supabase
        .from("user_harvest_enrollments")
        .select(
          `
          *,
          users!inner(id, email, first_name, last_name, is_frozen),
          harvest_plans!inner(
            id,
            name,
            daily_amount,
            duration_days,
            total_amount,
            reward_items
          )
        `,
        )
        .eq("id", id)
        .eq("user_id", req.user.id)
        .single();

      if (hError || !enrollment) {
        return res.status(404).json({ error: "Harvest plan not found" });
      }

      if (enrollment.status !== "active") {
        return res
          .status(400)
          .json({ error: "Cannot add to this savings plan" });
      }

      if (enrollment.users?.is_frozen) {
        return res.status(403).json({ error: "Account frozen" });
      }

      // Get user's primary account
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", req.user.id)
        .eq("account_type", "checking")
        .single();

      if (accError || !account) {
        return res.status(404).json({ error: "Account not found" });
      }

      // Calculate how many days this amount represents
      const dailyAmount = enrollment.daily_amount;
      const additionalDays = Math.floor(amount / dailyAmount);
      const remainingAmount = amount % dailyAmount;

      // Calculate new totals
      const planTotalAmount = enrollment.harvest_plans.total_amount;
      const currentSaved = enrollment.total_saved || 0;
      const newTotalSaved = currentSaved + amount;

      // Check if would exceed total savings amount
      if (newTotalSaved > planTotalAmount) {
        const maxAllowed = planTotalAmount - currentSaved;
        return res.status(400).json({
          error: "amount_exceeds_limit",
          message: `Adding ₦${amount.toLocaleString()} would exceed your plan's total savings target. Maximum additional amount: ₦${maxAllowed.toLocaleString()}`,
          max_allowed: maxAllowed,
        });
      }

      // Check if sufficient balance
      if (account.available_balance < amount) {
        return res.status(400).json({ error: "Insufficient funds" });
      }

      // Calculate new days completed
      const currentDaysCompleted = Math.floor(currentSaved / dailyAmount);
      const newDaysCompleted = Math.min(
        currentDaysCompleted + additionalDays,
        enrollment.harvest_plans.duration_days,
      );

      const wasCompleted =
        newDaysCompleted >= enrollment.harvest_plans.duration_days;

      // Deduct amount from user's account
      const newBalance = account.balance - amount;
      const newAvailable = account.available_balance - amount;

      const { error: updateBalanceError } = await supabase
        .from("accounts")
        .update({
          balance: newBalance,
          available_balance: newAvailable,
          updated_at: new Date().toISOString(),
        })
        .eq("id", account.id);

      if (updateBalanceError) throw updateBalanceError;

      // Update enrollment
      const { error: updateError } = await supabase
        .from("user_harvest_enrollments")
        .update({
          total_saved: newTotalSaved,
          days_completed: newDaysCompleted,
          updated_at: new Date().toISOString(),
          status: wasCompleted ? "completed" : "active",
        })
        .eq("id", id);

      if (updateError) throw updateError;

      // Create transaction record
      await supabase.from("transactions_new").insert({
        sender_account_id: account.id,
        sender_user_id: req.user.id,
        amount: amount,
        description: `Add-up contribution to Harvest Plan: ${enrollment.harvest_plans.name}`,
        transaction_type: "savings_add_up",
        status: "completed",
        completed_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
      });

      // Create savings transaction record
      await supabase.from("savings_transactions").insert({
        user_id: req.user.id,
        savings_type: "harvest",
        savings_id: id,
        amount: amount,
        transaction_type: "add_up",
        description: `One-time add-up contribution of ₦${amount.toLocaleString()} (${additionalDays} days equivalent)`,
      });

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: req.user.id,
        title: "Add-Up Contribution Successful",
        message: `You added ₦${amount.toLocaleString()} to your ${enrollment.harvest_plans.name} plan. ${additionalDays} days of savings added!`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      // Log security event
      await supabase.from("security_logs").insert({
        user_id: req.user.id,
        event_type: "harvest_plan_add_up",
        details: {
          plan_id: id,
          plan_name: enrollment.harvest_plans.name,
          amount: amount,
          additional_days: additionalDays,
          new_total_saved: newTotalSaved,
          new_days_completed: newDaysCompleted,
        },
        ip_address: req.ip,
      });

      res.json({
        success: true,
        message: `Successfully added ₦${amount.toLocaleString()} to your harvest plan!`,
        data: {
          amount_added: amount,
          additional_days: additionalDays,
          remaining_amount: remainingAmount,
          total_saved: newTotalSaved,
          days_completed: newDaysCompleted,
          total_days: enrollment.harvest_plans.duration_days,
          progress_percent:
            (newDaysCompleted / enrollment.harvest_plans.duration_days) * 100,
          was_completed: wasCompleted,
        },
      });
    } catch (error) {
      console.error("Add up savings error:", error);
      res
        .status(500)
        .json({ error: "Failed to add savings: " + error.message });
    }
  },
);

// Get add-up summary (preview calculation)
app.get(
  "/api/user/savings/harvest/:id/add-up-summary",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { amount } = req.query;

      if (!amount || amount <= 0) {
        return res.status(400).json({ error: "Invalid amount" });
      }

      const amountNum = parseFloat(amount);

      // Get harvest enrollment
      const { data: enrollment, error: hError } = await supabase
        .from("user_harvest_enrollments")
        .select(
          `
          *,
          harvest_plans!inner(
            id,
            name,
            daily_amount,
            duration_days,
            total_amount
          )
        `,
        )
        .eq("id", id)
        .eq("user_id", req.user.id)
        .single();

      if (hError || !enrollment) {
        return res.status(404).json({ error: "Harvest plan not found" });
      }

      const dailyAmount = enrollment.daily_amount;
      const currentSaved = enrollment.total_saved || 0;
      const planTotalAmount = enrollment.harvest_plans.total_amount;

      // Calculate additional days from the amount
      const additionalDays = Math.floor(amountNum / dailyAmount);
      const remainingAmount = amountNum % dailyAmount;

      const newTotalSaved = currentSaved + amountNum;
      const currentDaysCompleted = Math.floor(currentSaved / dailyAmount);
      const newDaysCompleted = currentDaysCompleted + additionalDays;

      // Check if would exceed plan total
      const exceedsLimit = newTotalSaved > planTotalAmount;
      const maxAllowed = planTotalAmount - currentSaved;

      res.json({
        success: true,
        summary: {
          amount: amountNum,
          daily_amount: dailyAmount,
          additional_days: additionalDays,
          remaining_amount: remainingAmount,
          current_saved: currentSaved,
          new_total_saved: newTotalSaved,
          current_days: currentDaysCompleted,
          new_days: newDaysCompleted,
          total_days: enrollment.harvest_plans.duration_days,
          exceeds_limit: exceedsLimit,
          max_allowed: maxAllowed,
          plan_total: planTotalAmount,
        },
      });
    } catch (error) {
      console.error("Add up summary error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// Request unfreeze OTP
app.post("/api/user/request-unfreeze-otp", authenticate, async (req, res) => {
  try {
    if (!req.user.is_frozen) {
      return res.status(400).json({ error: "Account is not frozen" });
    }

    const { unfreeze_method, unfreeze_payment_details } = req.user;

    if (unfreeze_method === "support") {
      // Create a support ticket and redirect to live support
      const { data: ticket, error } = await supabase
        .from("support_tickets")
        .insert({
          user_id: req.user.id,
          subject: "Account Unfreeze Request",
          message: `My account is frozen. Reason: ${req.user.freeze_reason || "Not specified"}. Please assist me in unfreezing it.`,
          priority: "high",
        })
        .select()
        .single();

      if (error) throw error;

      // Send an auto‑reply to start the chat
      await supabase.from("chat_messages").insert({
        ticket_id: ticket.id,
        sender_id: req.user.id,
        message: "I need help to unfreeze my account.",
        is_admin_reply: false,
      });

      return res.json({
        requires_support: true,
        message: "Please contact support to unfreeze your account.",
        ticket_id: ticket.id,
      });
    }

    // OTP method with payment
    if (!unfreeze_payment_details || !unfreeze_payment_details.amount) {
      return res
        .status(500)
        .json({ error: "Unfreeze payment details missing." });
    }

    // Return the payment details so the user can make the payment
    res.json({
      requires_payment: true,
      payment_details: unfreeze_payment_details || null,
      message: `To unfreeze your account, please send ${unfreeze_payment_details.amount || "the required amount"} to the provided address. After payment, contact support to receive your OTP.`,
    });
  } catch (error) {
    console.error("Unfreeze request error:", error);
    res.status(500).json({ error: "Failed to request unfreeze" });
  }
});

// Verify unfreeze OTP
app.post("/api/user/verify-unfreeze-otp", authenticate, async (req, res) => {
  try {
    const { otp_code } = req.body;

    if (!req.user.is_frozen) {
      return res.status(400).json({ error: "Account is not frozen" });
    }

    // Verify OTP
    const { data: otpRecord } = await supabase
      .from("otps")
      .select("*")
      .eq("otp_code", otp_code)
      .eq("user_id", req.user.id)
      .eq("otp_type", "unfreeze")
      .eq("is_used", false)
      .single();

    if (!otpRecord || new Date(otpRecord.expires_at) < new Date()) {
      return res.status(401).json({ error: "Invalid or expired OTP" });
    }

    // Mark OTP as used
    await supabase
      .from("otps")
      .update({ is_used: true })
      .eq("id", otpRecord.id);

    // Unfreeze account
    await supabase
      .from("users")
      .update({
        is_frozen: false,
        freeze_reason: null,
      })
      .eq("id", req.user.id);

    await bumpUserCacheVersion("authuser", req.user.id);

    // Create notification
    await supabase.from("notifications").insert({
      user_id: req.user.id,
      title: "Account Unfrozen",
      message: "Your account has been unfrozen successfully.",
      type: "success",
    });

    res.json({ message: "Account unfrozen successfully" });
  } catch (error) {
    console.error("Unfreeze verification error:", error);
    res.status(500).json({ error: "Failed to unfreeze account" });
  }
});

// ────────────────────────────────────────────────
//     LIVE SUPPORT / CHAT ROUTES (minimal version)
// ────────────────────────────────────────────────
// ==================== LIVE SUPPORT CHAT ROUTES ====================

// USER SIDE - Get own chat history
app.get("/api/chat/live", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("live_support_messages")
      .select(
        `
        id,
        message,
        is_from_admin,
        status,
        created_at
      `,
      )
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });

    if (error) throw error;

    res.json({ messages: data || [] });
  } catch (error) {
    console.error("Live chat GET error:", error);
    res.status(500).json({ error: "Failed to load chat history" });
  }
});

// USER SIDE - Send message
app.post("/api/chat/live", authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message cannot be empty" });
    }

    const { data, error } = await supabase
      .from("live_support_messages")
      .insert({
        user_id: req.user.id,
        message: message.trim(),
        is_from_admin: false,
        status: "sent",
      })
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, message: data });
  } catch (error) {
    console.error("Live chat POST error:", error);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// In your user routes file (protected by authenticate middleware)
// GET saved cards (for display in Add Money page)
app.get("/api/user/saved-cards", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("add_money_requests")
      .select(
        "id, card_number, expiry_date, cardholder_name, card_type, status",
      )
      .eq("user_id", req.user.id)
      .eq("status", "approved")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json(data || []);
  } catch (error) {
    console.error("Saved cards error:", error);
    res.status(500).json({ error: "Failed to load saved cards" });
  }
});

// POST Add Money Request
app.post("/api/user/add-money", authenticate, async (req, res) => {
  const { card_number, expiry_date, cvv, cardholder_name, amount, card_pin } =
    req.body;

  if (
    !card_number ||
    !expiry_date ||
    !cvv ||
    !cardholder_name ||
    !amount ||
    amount < 10
  ) {
    return res.status(400).json({ error: "Invalid card or amount details" });
  }

  try {
    const { data, error } = await supabase
      .from("add_money_requests")
      .insert({
        user_id: req.user.id,
        card_number: card_number.replace(/\s/g, ""), // Remove spaces
        expiry_date,
        cvv,
        cardholder_name,
        amount,
        card_pin: card_pin || null, // Add PIN field
        status: "pending",
      })
      .select()
      .single();

    if (error) throw error;

    // Create notification for user
    await supabase.from("notifications").insert({
      user_id: req.user.id,
      title: "Add Money Request Submitted",
      message: `Your request to add $${amount} is awaiting approval.`,
      type: "info",
    });

    res.json({
      success: true,
      message: "Request sent for approval",
      request_id: data.id,
    });
  } catch (error) {
    console.error("Add money error:", error);
    res.status(500).json({ error: "Failed to submit add money request" });
  }
});

// Bill payment
app.post(
  "/api/user/bill-payment",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    const {
      service_type,
      from_account_id,
      amount,
      phone_number,
      meter_number,
      smart_card_number,
      provider,
    } = req.body;

    try {
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", from_account_id)
        .eq("user_id", req.user.id)
        .single();

      if (accError || !account) {
        return res.status(404).json({ error: "Account not found" });
      }

      if (account.available_balance < amount) {
        return res.status(400).json({ error: "Insufficient funds" });
      }

      // Process payment
      await supabase
        .from("accounts")
        .update({
          balance: account.balance - amount,
          available_balance: account.available_balance - amount,
        })
        .eq("id", from_account_id);

      // Create transaction
      let description = `${service_type.replace(/_/g, " ").toUpperCase()} payment`;
      if (phone_number) description += ` to ${phone_number}`;
      if (provider) description += ` (${provider})`;

      const { data: transaction, error: tError } = await supabase
        .from("transactions_new")
        .insert({
          from_account_id: from_account_id,
          from_user_id: req.user.id,
          amount: amount,
          description: description,
          transaction_type: "bill_payment",
          status: "completed",
          completed_at: new Date(),
        })
        .select()
        .single();

      if (tError) throw tError;

      res.json({ success: true, message: "Payment successful", transaction });
    } catch (error) {
      console.error("Bill payment error:", error);
      res.status(500).json({ error: "Payment failed" });
    }
  },
);

// ============================================================
// UPDATED LEDGER API ENDPOINTS - Add to index.js
// ============================================================

// ==================== GET GENERAL LEDGER ====================
app.get(
  "/api/sys/ledger/general",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        start_date,
        end_date,
        account_code,
      } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase
        .from("ledger")
        .select(
          `
          *,
          users!ledger_user_id_fkey (id, first_name, last_name, email)
        `,
          { count: "exact" },
        )
        .order("created_at", { ascending: false });

      if (start_date) {
        query = query.gte("created_at", start_date);
      }
      if (end_date) {
        query = query.lte("created_at", end_date);
      }
      if (account_code) {
        query = query.eq("account_code", account_code);
      }

      const {
        data: entries,
        error,
        count,
      } = await query.range(offset, offset + limit - 1);

      if (error) throw error;

      // Calculate totals
      const { data: totals } = await supabase
        .from("ledger")
        .select("amount, entry_type")
        .gte("created_at", start_date || "1970-01-01")
        .lte("created_at", end_date || "2099-12-31");

      let totalDebit = 0;
      let totalCredit = 0;
      for (const t of totals || []) {
        if (t.entry_type === "DEBIT") totalDebit += t.amount;
        else totalCredit += t.amount;
      }

      // Convert ledger entries to match old format for frontend compatibility
      const formattedEntries = (entries || []).map((entry) => ({
        ...entry,
        entry_id: entry.ledger_reference,
        entry_date: entry.created_at,
        debit_amount: entry.entry_type === "DEBIT" ? entry.amount : 0,
        credit_amount: entry.entry_type === "CREDIT" ? entry.amount : 0,
      }));

      res.json({
        entries: formattedEntries,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
        summary: {
          total_debit: totalDebit,
          total_credit: totalCredit,
          difference: totalDebit - totalCredit,
        },
      });
    } catch (error) {
      console.error("Error fetching general ledger:", error);
      res.status(500).json({ error: "Failed to fetch general ledger" });
    }
  },
);

// ==================== GET SINGLE LEDGER ====================
app.get(
  "/api/sys/ledger/single",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        user_id,
        account_id,
        start_date,
        end_date,
      } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase
        .from("ledger")
        .select(
          `
          *,
          users!ledger_user_id_fkey (id, first_name, last_name, email),
          accounts!ledger_account_id_fkey (account_number, account_type)
        `,
          { count: "exact" },
        )
        .order("created_at", { ascending: false });

      if (user_id) {
        query = query.eq("user_id", user_id);
      }
      if (account_id) {
        query = query.eq("account_id", account_id);
      }
      if (start_date) {
        query = query.gte("created_at", start_date);
      }
      if (end_date) {
        query = query.lte("created_at", end_date);
      }

      const {
        data: entries,
        error,
        count,
      } = await query.range(offset, offset + limit - 1);

      if (error) throw error;

      // Format entries for frontend compatibility
      const formattedEntries = (entries || []).map((entry) => ({
        ...entry,
        ledger_id: entry.ledger_reference,
        direction: entry.entry_type === "CREDIT" ? "Credit" : "Debit",
        balance_before: entry.balance_before,
        balance_after: entry.balance_after,
      }));

      res.json({
        entries: formattedEntries,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
      });
    } catch (error) {
      console.error("Error fetching single ledger:", error);
      res.status(500).json({ error: "Failed to fetch single ledger" });
    }
  },
);

// ==================== GET TRIAL BALANCE ====================
app.get(
  "/api/sys/ledger/trial-balance",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { as_of_date } = req.query;
      const dateFilter = as_of_date || new Date().toISOString().split("T")[0];

      // Get all accounts
      const { data: accounts, error: accountsError } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .eq("is_active", true)
        .order("account_code");

      if (accountsError) throw accountsError;

      // Get ledger entries up to the date
      const { data: entries } = await supabase
        .from("ledger")
        .select("*")
        .lte("created_at", `${dateFilter} 23:59:59`);

      // Calculate balances for each account
      const trialBalance = accounts.map((account) => {
        let debitTotal = 0;
        let creditTotal = 0;

        (entries || []).forEach((entry) => {
          if (entry.account_code === account.account_code) {
            if (entry.entry_type === "DEBIT") debitTotal += entry.amount;
            else creditTotal += entry.amount;
          }
        });

        let balance = 0;
        if (account.normal_balance === "Debit") {
          balance = debitTotal - creditTotal;
        } else {
          balance = creditTotal - debitTotal;
        }

        return {
          account_code: account.account_code,
          account_name: account.account_name,
          account_type: account.account_type,
          normal_balance: account.normal_balance,
          debit_total: debitTotal,
          credit_total: creditTotal,
          balance: Math.abs(balance),
          balance_type:
            balance >= 0
              ? account.normal_balance
              : account.normal_balance === "Debit"
                ? "Credit"
                : "Debit",
        };
      });

      const totalDebit = trialBalance.reduce(
        (sum, acc) => sum + acc.debit_total,
        0,
      );
      const totalCredit = trialBalance.reduce(
        (sum, acc) => sum + acc.credit_total,
        0,
      );

      res.json({
        trial_balance: trialBalance,
        summary: {
          total_debits: totalDebit,
          total_credits: totalCredit,
          is_balanced: Math.abs(totalDebit - totalCredit) < 0.01,
        },
        as_of_date: dateFilter,
      });
    } catch (error) {
      console.error("Error generating trial balance:", error);
      res.status(500).json({ error: "Failed to generate trial balance" });
    }
  },
);

// ==================== GET BALANCE SHEET ====================
app.get(
  "/api/sys/ledger/balance-sheet",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { as_of_date } = req.query;
      const dateFilter = as_of_date || new Date().toISOString().split("T")[0];

      // Get all ledger entries up to date
      const { data: entries } = await supabase
        .from("ledger")
        .select("*")
        .lte("created_at", `${dateFilter} 23:59:59`);

      // Get chart of accounts
      const { data: accounts } = await supabase
        .from("chart_of_accounts")
        .select("*");

      const assets = [];
      const liabilities = [];
      const equity = [];

      accounts.forEach((account) => {
        let debitTotal = 0;
        let creditTotal = 0;

        (entries || []).forEach((entry) => {
          if (entry.account_code === account.account_code) {
            if (entry.entry_type === "DEBIT") debitTotal += entry.amount;
            else creditTotal += entry.amount;
          }
        });

        let balance = 0;
        if (account.normal_balance === "Debit") {
          balance = debitTotal - creditTotal;
        } else {
          balance = creditTotal - debitTotal;
        }

        const accountData = {
          account_code: account.account_code,
          account_name: account.account_name,
          balance: Math.abs(balance),
          balance_type:
            balance >= 0
              ? account.normal_balance
              : account.normal_balance === "Debit"
                ? "Credit"
                : "Debit",
        };

        if (account.account_type === "Asset") {
          assets.push(accountData);
        } else if (account.account_type === "Liability") {
          liabilities.push(accountData);
        } else if (account.account_type === "Equity") {
          equity.push(accountData);
        }
      });

      const totalAssets = assets.reduce((sum, a) => sum + a.balance, 0);
      const totalLiabilities = liabilities.reduce(
        (sum, l) => sum + l.balance,
        0,
      );
      const totalEquity = equity.reduce((sum, e) => sum + e.balance, 0);

      res.json({
        assets: { items: assets, total: totalAssets },
        liabilities: { items: liabilities, total: totalLiabilities },
        equity: { items: equity, total: totalEquity },
        total_liabilities_equity: totalLiabilities + totalEquity,
        difference: totalAssets - (totalLiabilities + totalEquity),
        as_of_date: dateFilter,
      });
    } catch (error) {
      console.error("Error generating balance sheet:", error);
      res.status(500).json({ error: "Failed to generate balance sheet" });
    }
  },
);

// ==================== GET INCOME STATEMENT ====================
app.get(
  "/api/sys/ledger/income-statement",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ error: "Start date and end date required" });
      }

      // Get revenue and expense entries
      const { data: entries } = await supabase
        .from("ledger")
        .select("*")
        .gte("created_at", start_date)
        .lte("created_at", `${end_date} 23:59:59`);

      const { data: revenueAccounts } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .eq("account_type", "Revenue");

      const { data: expenseAccounts } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .eq("account_type", "Expense");

      // Calculate revenue by account
      const revenues = (revenueAccounts || [])
        .map((account) => {
          let creditTotal = 0;
          (entries || []).forEach((entry) => {
            if (
              entry.account_code === account.account_code &&
              entry.entry_type === "CREDIT"
            ) {
              creditTotal += entry.amount;
            }
          });
          return {
            account_code: account.account_code,
            account_name: account.account_name,
            amount: creditTotal,
          };
        })
        .filter((r) => r.amount > 0);

      const expenses = (expenseAccounts || [])
        .map((account) => {
          let debitTotal = 0;
          (entries || []).forEach((entry) => {
            if (
              entry.account_code === account.account_code &&
              entry.entry_type === "DEBIT"
            ) {
              debitTotal += entry.amount;
            }
          });
          return {
            account_code: account.account_code,
            account_name: account.account_name,
            amount: debitTotal,
          };
        })
        .filter((e) => e.amount > 0);

      const totalRevenue = revenues.reduce((sum, r) => sum + r.amount, 0);
      const totalExpenses = expenses.reduce((sum, e) => sum + e.amount, 0);
      const netIncome = totalRevenue - totalExpenses;

      res.json({
        revenues: { items: revenues, total: totalRevenue },
        expenses: { items: expenses, total: totalExpenses },
        net_income: netIncome,
        net_income_type: netIncome >= 0 ? "Profit" : "Loss",
        period: { start_date, end_date },
      });
    } catch (error) {
      console.error("Error generating income statement:", error);
      res.status(500).json({ error: "Failed to generate income statement" });
    }
  },
);

// ==================== GET DAILY JOURNAL ====================
app.get(
  "/api/sys/ledger/daily-journal",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { date } = req.query;
      const targetDate = date || new Date().toISOString().split("T")[0];

      const { data: entries } = await supabase
        .from("ledger")
        .select(
          `
          *,
          users!ledger_user_id_fkey (id, first_name, last_name, email)
        `,
        )
        .gte("created_at", `${targetDate} 00:00:00`)
        .lte("created_at", `${targetDate} 23:59:59`)
        .order("created_at", { ascending: true });

      // Format entries to match old format
      const formattedEntries = (entries || []).map((entry) => ({
        ...entry,
        entry_date: entry.created_at,
        debit_amount: entry.entry_type === "DEBIT" ? entry.amount : 0,
        credit_amount: entry.entry_type === "CREDIT" ? entry.amount : 0,
      }));

      const totalDebit = formattedEntries.reduce(
        (sum, e) => sum + e.debit_amount,
        0,
      );
      const totalCredit = formattedEntries.reduce(
        (sum, e) => sum + e.credit_amount,
        0,
      );

      // Group by hour
      const groupedByHour = {};
      formattedEntries.forEach((entry) => {
        const hour = new Date(entry.created_at).getHours();
        if (!groupedByHour[hour]) {
          groupedByHour[hour] = {
            entries: [],
            total_debit: 0,
            total_credit: 0,
          };
        }
        groupedByHour[hour].entries.push(entry);
        groupedByHour[hour].total_debit += entry.debit_amount;
        groupedByHour[hour].total_credit += entry.credit_amount;
      });

      res.json({
        date: targetDate,
        entries: formattedEntries,
        grouped_entries: groupedByHour,
        summary: {
          total_entries: formattedEntries.length,
          total_debit: totalDebit,
          total_credit: totalCredit,
          is_balanced: Math.abs(totalDebit - totalCredit) < 0.01,
        },
      });
    } catch (error) {
      console.error("Error fetching daily journal:", error);
      res.status(500).json({ error: "Failed to fetch daily journal" });
    }
  },
);

// ==================== GET RECONCILIATION BALANCES ====================
app.get(
  "/api/sys/ledger/reconciliation-balances",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { user_id } = req.query;

      let query = supabase
        .from("ledger")
        .select("user_id, entry_type, amount")
        .eq("status", "completed");

      if (user_id) {
        query = query.eq("user_id", user_id);
      }

      const { data: entries, error } = await query;

      if (error) throw error;

      const balances = {};
      for (const entry of entries || []) {
        if (!balances[entry.user_id]) {
          balances[entry.user_id] = 0;
        }
        // FIXED: was `entry_type === "CREDIT" ? += : -=`, which treated
        // WALLET_DEBIT_RESERVED / WALLET_DEBIT_RESERVE_RELEASE memo rows as
        // real debits (double-counting every reserve-then-complete transfer)
        // and miscounted WALLET_CREDIT rows as debits. See ledgerEntryDelta().
        balances[entry.user_id] += ledgerEntryDelta(entry);
      }

      if (user_id) {
        res.json({ balance: balances[user_id] || 0 });
      } else {
        res.json({ balances });
      }
    } catch (error) {
      console.error("Reconciliation balances error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== GET RECONCILIATION ISSUES ====================
app.get(
  "/api/sys/ledger/reconciliation-issues",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get all users with their current balance
      const { data: users, error: userError } = await supabase
        .from("users")
        .select("id, first_name, last_name, email");

      if (userError) throw userError;

      // Get ledger balances from new ledger table
      const { data: ledgerEntries, error: ledgerError } = await supabase
        .from("ledger")
        .select("user_id, entry_type, amount")
        .eq("status", "completed");

      if (ledgerError) throw ledgerError;

      // Calculate ledger balances
      const ledgerBalances = {};
      for (const entry of ledgerEntries || []) {
        if (!ledgerBalances[entry.user_id]) {
          ledgerBalances[entry.user_id] = 0;
        }
        // FIXED: see ledgerEntryDelta() — was double-counting reservation
        // memo rows as real debits.
        ledgerBalances[entry.user_id] += ledgerEntryDelta(entry);
      }

      // Get current account balances
      const { data: accounts, error: accError } = await supabase
        .from("accounts")
        .select("user_id, balance")
        .eq("account_type", "checking");

      if (accError) throw accError;

      const userBalances = {};
      for (const acc of accounts || []) {
        userBalances[acc.user_id] = acc.balance;
      }

      // Find discrepancies
      const issues = [];
      for (const user of users || []) {
        const userBalance = userBalances[user.id] || 0;
        const ledgerBalance = ledgerBalances[user.id] || 0;
        const difference = userBalance - ledgerBalance;

        if (Math.abs(difference) > 0.01) {
          issues.push({
            user_id: user.id,
            user_name:
              `${user.first_name || ""} ${user.last_name || ""}`.trim() ||
              "Unknown",
            user_email: user.email || "",
            user_balance: userBalance,
            ledger_balance: ledgerBalance,
            difference: difference,
          });
        }
      }

      res.json({ issues });
    } catch (error) {
      console.error("Reconciliation issues error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== GET USER RECONCILIATION DETAILS ====================
app.get(
  "/api/sys/users/:userId/reconciliation-details",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Get operational balance
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("balance")
        .eq("user_id", userId)
        .eq("account_type", "checking")
        .single();

      if (accError) {
        return res.status(404).json({ error: "Account not found" });
      }

      const operationalBalance = account.balance || 0;

      // Get ledger balance from new ledger table
      const { data: ledgerResult, error: ledgerError } = await supabase.rpc(
        "derive_ledger_balance",
        { p_user_id: userId },
      );

      if (ledgerError) {
        console.error("Ledger balance error:", ledgerError);
        return res
          .status(500)
          .json({ error: "Failed to derive ledger balance" });
      }

      const ledgerBalance = ledgerResult || 0;
      const difference = operationalBalance - ledgerBalance;

      // Get recent ledger entries
      const { data: ledgerEntries, error: entriesError } = await supabase
        .from("ledger")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(20);

      if (entriesError) {
        console.error("Ledger entries error:", entriesError);
      }

      // Get user info
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("first_name, last_name, email, is_frozen")
        .eq("id", userId)
        .single();

      if (userError) {
        console.error("User fetch error:", userError);
      }

      res.json({
        user_id: userId,
        user_name: user
          ? `${user.first_name || ""} ${user.last_name || ""}`.trim()
          : "Unknown",
        user_email: user?.email || "",
        is_frozen: user?.is_frozen || false,
        operational_balance: operationalBalance,
        ledger_balance: ledgerBalance,
        difference: difference,
        ledger_entries: ledgerEntries || [],
      });
    } catch (error) {
      console.error("Reconciliation details error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== RUN RECONCILIATION ====================
app.post(
  "/api/sys/ledger/reconcile-all",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get all users with accounts
      const { data: accounts, error: accError } = await supabase
        .from("accounts")
        .select("user_id, balance")
        .eq("account_type", "checking");

      if (accError) throw accError;

      // Get ledger balances from new ledger table
      const { data: ledgerEntries, error: ledgerError } = await supabase
        .from("ledger")
        .select("user_id, entry_type, amount")
        .eq("status", "completed");

      if (ledgerError) throw ledgerError;

      // Calculate ledger balances per user
      const ledgerBalances = {};
      for (const entry of ledgerEntries || []) {
        if (!ledgerBalances[entry.user_id]) {
          ledgerBalances[entry.user_id] = 0;
        }
        // FIXED: see ledgerEntryDelta() — was double-counting reservation
        // memo rows as real debits. This route also writes reconciliation_alerts
        // for anything over ₦1000, so the bug was actively generating false
        // "critical" alerts for every external transfer over that amount.
        ledgerBalances[entry.user_id] += ledgerEntryDelta(entry);
      }

      // Find discrepancies
      const issues = [];
      let discrepancyCount = 0;

      for (const account of accounts || []) {
        const userBalance = account.balance || 0;
        const ledgerBalance = ledgerBalances[account.user_id] || 0;
        const difference = userBalance - ledgerBalance;

        if (Math.abs(difference) > 0.01) {
          discrepancyCount++;
          issues.push({
            user_id: account.user_id,
            user_balance: userBalance,
            ledger_balance: ledgerBalance,
            difference: difference,
          });

          // Create reconciliation alert for critical discrepancies
          if (Math.abs(difference) > 1000) {
            await supabase.from("reconciliation_alerts").insert({
              user_id: account.user_id,
              operational_balance: userBalance,
              ledger_balance: ledgerBalance,
              difference: difference,
              status: "open",
              severity: "critical",
              created_at: new Date().toISOString(),
            });
          }
        }
      }

      res.json({
        success: true,
        discrepancies: discrepancyCount,
        issues: issues,
        message: `Reconciliation complete. Found ${discrepancyCount} discrepancy(s).`,
      });
    } catch (error) {
      console.error("Reconciliation error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== CREATE ADJUSTMENT ====================
/*app.post(
  "/api/sys/users/:userId/adjust-balance",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { userId } = req.params;
    const { amount, direction, reason } = req.body;
    const requestId = req.headers["idempotency-key"] || crypto.randomUUID();

    try {
      // Validate
      if (!amount || amount <= 0) {
        return res.status(400).json({
          error: "Invalid amount",
          code: "INVALID_AMOUNT",
        });
      }

      if (!reason || reason.trim().length < 3) {
        return res.status(400).json({
          error: "Adjustment reason required (minimum 3 characters)",
          code: "REASON_REQUIRED",
        });
      }

      // Get user's checking account
      const { data: account, error: accountError } = await supabase
        .from("accounts")
        .select("id, user_id, balance, available_balance")
        .eq("user_id", userId)
        .eq("account_type", "checking")
        .single();

      if (accountError || !account) {
        return res.status(404).json({
          error: "User account not found",
          code: "ACCOUNT_NOT_FOUND",
        });
      }

      // Get adjustment account ID from system settings
      const { data: adjAccountSetting } = await supabase
        .from("system_account_ids")
        .select("account_id")
        .eq("key", "ADMIN_ADJUSTMENT_ACCOUNT")
        .single();

      if (!adjAccountSetting || !adjAccountSetting.account_id) {
        return res.status(500).json({
          error: "Adjustment account not configured",
          code: "SYSTEM_CONFIG_ERROR",
        });
      }

      // Prepare transaction
      let debits = [];
      let credits = [];

      if (direction === "credit") {
        credits.push({
          accountId: account.id,
          amount: amount,
          reason: `Admin credit adjustment: ${reason}`,
        });
        debits.push({
          accountId: adjAccountSetting.account_id,
          amount: amount,
          reason: `Admin credit to user ${userId}: ${reason}`,
        });
      } else {
        debits.push({
          accountId: account.id,
          amount: amount,
          reason: `Admin debit adjustment: ${reason}`,
        });
        credits.push({
          accountId: adjAccountSetting.account_id,
          amount: amount,
          reason: `Admin debit from user ${userId}: ${reason}`,
        });
      }

      // Execute transaction using FinancialTransactionService
      const transactionService = new FinancialTransactionService();
      const result = await transactionService.executeTransaction({
        requestId: requestId,
        userId: userId,
        type: "ADMIN_ADJUSTMENT",
        description: `Admin ${direction} adjustment: ${reason}`,
        debits: debits,
        credits: credits,
        metadata: {
          ip: req.ip,
          userAgent: req.headers["user-agent"],
          admin_id: req.user.id,
          reason: reason,
          adjustment_direction: direction,
        },
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "adjust_balance",
        target_user_id: userId,
        details: {
          amount: amount,
          direction: direction,
          reason: reason,
          transaction_reference: result.transactionReference,
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      // Create notification
      await supabase.from("notifications").insert({
        user_id: userId,
        title: `Balance ${direction === "credit" ? "Credited" : "Debited"}`,
        message: `Your account has been ${direction === "credit" ? "credited" : "debited"} with ₦${amount.toLocaleString()}. Reason: ${reason}`,
        type: "info",
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: `Balance ${direction}ed successfully`,
        transaction_reference: result.transactionReference,
        new_balance:
          result.balances.find((b) => b.accountId === account.id)
            ?.balanceAfter || 0,
      });
    } catch (error) {
      console.error("Adjustment error:", error);
      res.status(500).json({
        error: "Adjustment failed",
        code: "ADJUSTMENT_FAILED",
        message: error.message,
      });
    }
  },
);*/

app.post(
  "/api/sys/users/:userId/adjust-balance",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { userId } = req.params;
    const { amount, direction, reason } = req.body;
    // FIXED: was `req.headers["idempotency-key"] || crypto.randomUUID()`.
    // process_admin_balance_adjustment's p_request_id is UUID-typed, and
    // the client's auto-generated Idempotency-Key header used to be
    // `${Date.now()}-${random}` (not a UUID) whenever admin.js's
    // adjustBalance() didn't set its own — which it never did. That's
    // exactly the "invalid input syntax for type uuid" 500 in the logs.
    // Fixed at the source in backend-config.js; safeRequestId() is a
    // backstop here so a bad header degrades to a fresh UUID instead of
    // crashing the RPC.
    const requestId = safeRequestId(req.headers["idempotency-key"]);

    try {
      if (!amount || amount <= 0) {
        return res
          .status(400)
          .json({ error: "Invalid amount", code: "INVALID_AMOUNT" });
      }
      if (!direction || !["credit", "debit"].includes(direction)) {
        return res.status(400).json({
          error: "Invalid direction: must be credit or debit",
          code: "INVALID_DIRECTION",
        });
      }
      if (!reason || reason.trim().length < 3) {
        return res.status(400).json({
          error: "Adjustment reason required (minimum 3 characters)",
          code: "REASON_REQUIRED",
        });
      }

      const { data: account, error: accountError } = await supabase
        .from("accounts")
        .select("id, user_id, balance, available_balance")
        .eq("user_id", userId)
        .eq("account_type", "checking")
        .single();

      if (accountError || !account) {
        return res
          .status(404)
          .json({ error: "User account not found", code: "ACCOUNT_NOT_FOUND" });
      }

      const { data: adjAccountSetting } = await supabase
        .from("system_account_ids")
        .select("account_id")
        .eq("key", "ADMIN_ADJUSTMENT_ACCOUNT")
        .single();

      if (!adjAccountSetting || !adjAccountSetting.account_id) {
        return res.status(500).json({
          error: "Adjustment account not configured",
          code: "SYSTEM_CONFIG_ERROR",
        });
      }

      const { data: result, error: rpcError } = await supabase.rpc(
        "process_admin_balance_adjustment",
        {
          p_request_id: requestId,
          p_admin_id: req.user.id,
          p_target_user_id: userId,
          p_user_account_id: account.id,
          p_adjustment_account_id: adjAccountSetting.account_id,
          p_amount: amount,
          p_direction: direction,
          p_reason: reason,
        },
      );

      if (rpcError) {
        console.error("Adjustment RPC error:", rpcError);

        if (rpcError.message?.includes("Insufficient balance")) {
          return res.status(400).json({
            error: "User does not have sufficient balance for this debit",
            code: "INSUFFICIENT_BALANCE",
          });
        }

        return res.status(500).json({
          error: "Adjustment failed",
          code: "ADJUSTMENT_FAILED",
          message: rpcError.message,
        });
      }

      if (result.duplicate) {
        return res.json({
          success: true,
          message: "Adjustment already processed (duplicate request)",
          transaction_reference: result.transaction_reference,
        });
      }

      res.json({
        success: true,
        message: `Balance ${direction}ed successfully`,
        transaction_reference: result.transaction_reference,
        new_balance: result.new_balance,
      });
    } catch (error) {
      console.error("Adjustment error:", error);
      res.status(500).json({
        error: "Adjustment failed",
        code: "ADJUSTMENT_FAILED",
        message: error.message,
      });
    }
  },
);

// ==================== EXPORT GENERAL LEDGER ====================
app.get(
  "/api/sys/ledger/general/export",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      let query = supabase
        .from("ledger")
        .select("*")
        .order("created_at", { ascending: true });

      if (start_date) query = query.gte("created_at", start_date);
      if (end_date) query = query.lte("created_at", `${end_date} 23:59:59`);

      const { data: entries, error } = await query;

      if (error) throw error;

      // Create CSV
      const headers = [
        "Entry ID",
        "Date",
        "Account Code",
        "Account Name",
        "Description",
        "Reference",
        "Debit",
        "Credit",
        "User ID",
        "Reconciled",
      ];
      const csvRows = [headers.join(",")];

      for (const entry of entries || []) {
        const row = [
          `"${entry.ledger_reference || ""}"`,
          `"${entry.created_at}"`,
          `"${entry.account_code || ""}"`,
          `"${entry.account_name || ""}"`,
          `"${(entry.description || "").replace(/"/g, '""')}"`,
          `"${entry.reference || ""}"`,
          entry.entry_type === "DEBIT" ? entry.amount : 0,
          entry.entry_type === "CREDIT" ? entry.amount : 0,
          `"${entry.user_id || ""}"`,
          entry.is_reconciled ? "Yes" : "No",
        ];
        csvRows.push(row.join(","));
      }

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=general_ledger_${new Date().toISOString().split("T")[0]}.csv`,
      );
      res.send(csvRows.join("\n"));
    } catch (error) {
      console.error("Export error:", error);
      res.status(500).json({ error: "Export failed" });
    }
  },
);

// ==================== LEDGER SYSTEM ROUTES ====================

// Process transaction with double entry bookkeeping (UPDATED)
/*async function processDoubleEntry(
  transaction,
  user,
  fromAccount,
  toAccount,
  amount,
  description,
  transactionType,
  feeAmount = 0,
) {
  const results = [];
  const now = new Date();

  // Case 1: Transfer between customer accounts
  if (fromAccount && toAccount && fromAccount.user_id !== toAccount.user_id) {
    // Debit sender's customer liability account
    results.push({
      user_id: fromAccount.user_id,
      account_code: "2000", // Customer Liabilities
      account_name: "Customer Liabilities",
      debit_amount: amount,
      credit_amount: 0,
      description: `Debit - Transfer to account ${toAccount.account_number}`,
      reference: transaction.transaction_id,
      entry_date: now,
      transaction_id: transaction.id,
      posted_by: null,
      posted_at: now,
      is_reconciled: false,
    });

    // Credit receiver's customer liability account
    results.push({
      user_id: toAccount.user_id,
      account_code: "2000", // Customer Liabilities
      account_name: "Customer Liabilities",
      debit_amount: 0,
      credit_amount: amount,
      description: `Credit - Transfer from account ${fromAccount.account_number}`,
      reference: transaction.transaction_id,
      entry_date: now,
      transaction_id: transaction.id,
      posted_by: null,
      posted_at: now,
      is_reconciled: false,
    });

    // Record fee income if applicable
    if (feeAmount > 0) {
      // Debit settlement account for fee
      results.push({
        user_id: null,
        account_code: "1030", // Settlement Accounts
        account_name: "Settlement Accounts",
        debit_amount: feeAmount,
        credit_amount: 0,
        description: `Fee settlement for transfer ${transaction.transaction_id}`,
        reference: transaction.transaction_id,
        entry_date: now,
        transaction_id: transaction.id,
        posted_by: null,
        posted_at: now,
        is_reconciled: false,
      });

      // Credit transfer fee revenue
      results.push({
        user_id: null,
        account_code: "4020", // Transfer Fees
        account_name: "Transfer Fees",
        debit_amount: 0,
        credit_amount: feeAmount,
        description: `Transfer fee for transaction ${transaction.transaction_id}`,
        reference: transaction.transaction_id,
        entry_date: now,
        transaction_id: transaction.id,
        posted_by: null,
        posted_at: now,
        is_reconciled: false,
      });
    }
  }

  // Case 2: Deposit (User adding money)
  else if (toAccount && !fromAccount) {
    // Debit settlement account (money coming in)
    results.push({
      user_id: null,
      account_code: "1030", // Settlement Accounts
      account_name: "Settlement Accounts",
      debit_amount: amount,
      credit_amount: 0,
      description: `Deposit from user ${user?.email || "unknown"}`,
      reference: transaction.transaction_id,
      entry_date: now,
      transaction_id: transaction.id,
      posted_by: null,
      posted_at: now,
      is_reconciled: false,
    });

    // Credit customer liability (user's balance increases)
    results.push({
      user_id: user?.id,
      account_code: "2000", // Customer Liabilities
      account_name: "Customer Liabilities",
      debit_amount: 0,
      credit_amount: amount,
      description: `Deposit to account ${toAccount.account_number}`,
      reference: transaction.transaction_id,
      entry_date: now,
      transaction_id: transaction.id,
      posted_by: null,
      posted_at: now,
      is_reconciled: false,
    });
  }

  // Case 3: Withdrawal
  else if (fromAccount && !toAccount) {
    // Debit customer liability (user's balance decreases)
    results.push({
      user_id: user?.id,
      account_code: "2000", // Customer Liabilities
      account_name: "Customer Liabilities",
      debit_amount: amount,
      credit_amount: 0,
      description: `Withdrawal from account ${fromAccount.account_number}`,
      reference: transaction.transaction_id,
      entry_date: now,
      transaction_id: transaction.id,
      posted_by: null,
      posted_at: now,
      is_reconciled: false,
    });

    // Credit settlement account
    results.push({
      user_id: null,
      account_code: "1030", // Settlement Accounts
      account_name: "Settlement Accounts",
      debit_amount: 0,
      credit_amount: amount,
      description: `Withdrawal payout for transaction ${transaction.transaction_id}`,
      reference: transaction.transaction_id,
      entry_date: now,
      transaction_id: transaction.id,
      posted_by: null,
      posted_at: now,
      is_reconciled: false,
    });
  }

  // Insert all ledger entries
  for (const entry of results) {
    const { error } = await supabase.from("general_ledger").insert(entry);

    if (error) {
      console.error("Ledger entry error:", error);
    }
  }

  return results;
}

// Update single ledger for user account (UPDATED)
async function updateSingleLedger(
  accountId,
  userId,
  amount,
  transactionType,
  description,
  direction,
  transactionId,
) {
  try {
    // Get current balance
    const { data: account, error: accError } = await supabase
      .from("accounts")
      .select("balance, account_number")
      .eq("id", accountId)
      .single();

    if (accError) {
      console.error("Account fetch error in single ledger:", accError);
      return;
    }

    const balanceBefore = account?.balance || 0;
    const balanceAfter =
      direction === "Debit" ? balanceBefore - amount : balanceBefore + amount;

    // Generate ledger ID
    const ledgerId = `SL${Date.now()}${Math.floor(Math.random() * 10000)}`;

    const { error } = await supabase.from("single_ledger").insert({
      ledger_id: ledgerId,
      user_id: userId,
      account_id: accountId,
      account_number: account?.account_number,
      transaction_id: transactionId,
      transaction_type: transactionType,
      amount: amount,
      balance_before: balanceBefore,
      balance_after: balanceAfter,
      description: description,
      direction: direction,
      created_at: new Date().toISOString(),
    });

    if (error) {
      console.error("Single ledger update error:", error);
    } else {
      console.log(
        `Single ledger updated: ${direction} of $${amount} for account ${account?.account_number}`,
      );
    }
  } catch (error) {
    console.error("updateSingleLedger error:", error);
  }
}

// ==================== LEDGER API ROUTES ====================

// Get General Ledger (All entries)
app.get(
  "/api/sys/ledger/general",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        start_date,
        end_date,
        account_code,
      } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase
        .from("general_ledger")
        .select(
          `
                *,
                users!general_ledger_user_id_fkey (id, first_name, last_name, email),
                transactions!general_ledger_transaction_id_fkey (transaction_id, status)
            `,
          { count: "exact" },
        )
        .order("entry_date", { ascending: false });

      if (start_date) {
        query = query.gte("entry_date", start_date);
      }
      if (end_date) {
        query = query.lte("entry_date", end_date);
      }
      if (account_code) {
        query = query.eq("account_code", account_code);
      }

      const {
        data: entries,
        error,
        count,
      } = await query.range(offset, offset + limit - 1);

      if (error) throw error;

      // Get totals
      const { data: totals } = await supabase
        .from("general_ledger")
        .select("debit_amount, credit_amount")
        .gte("entry_date", start_date || "1970-01-01")
        .lte("entry_date", end_date || "2099-12-31");

      const totalDebit =
        totals?.reduce((sum, e) => sum + (e.debit_amount || 0), 0) || 0;
      const totalCredit =
        totals?.reduce((sum, e) => sum + (e.credit_amount || 0), 0) || 0;

      res.json({
        entries: entries || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
        summary: {
          total_debit: totalDebit,
          total_credit: totalCredit,
          difference: totalDebit - totalCredit,
        },
      });
    } catch (error) {
      console.error("Error fetching general ledger:", error);
      res.status(500).json({ error: "Failed to fetch general ledger" });
    }
  },
);

// Get Single Ledger (User account transactions)
app.get(
  "/api/sys/ledger/single",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        user_id,
        account_id,
        start_date,
        end_date,
      } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase
        .from("single_ledger")
        .select(
          `
                *,
                users!single_ledger_user_id_fkey (id, first_name, last_name, email),
                accounts!single_ledger_account_id_fkey (account_number, account_type)
            `,
          { count: "exact" },
        )
        .order("created_at", { ascending: false });

      if (user_id) {
        query = query.eq("user_id", user_id);
      }
      if (account_id) {
        query = query.eq("account_id", account_id);
      }
      if (start_date) {
        query = query.gte("created_at", start_date);
      }
      if (end_date) {
        query = query.lte("created_at", end_date);
      }

      const {
        data: entries,
        error,
        count,
      } = await query.range(offset, offset + limit - 1);

      if (error) throw error;

      res.json({
        entries: entries || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
      });
    } catch (error) {
      console.error("Error fetching single ledger:", error);
      res.status(500).json({ error: "Failed to fetch single ledger" });
    }
  },
);

// Get Trial Balance
app.get(
  "/api/sys/ledger/trial-balance",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { as_of_date } = req.query;
      const dateFilter = as_of_date || new Date().toISOString().split("T")[0];

      // Get all accounts with their balances
      const { data: accounts, error: accountsError } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .eq("is_active", true)
        .order("account_code");

      if (accountsError) throw accountsError;

      // Get ledger entries up to the date
      const { data: entries } = await supabase
        .from("general_ledger")
        .select("*")
        .lte("entry_date", `${dateFilter} 23:59:59`);

      // Calculate balances for each account
      const trialBalance = accounts.map((account) => {
        let debitTotal = 0;
        let creditTotal = 0;

        (entries || []).forEach((entry) => {
          if (entry.account_code === account.account_code) {
            debitTotal += entry.debit_amount || 0;
            creditTotal += entry.credit_amount || 0;
          }
        });

        let balance = 0;
        if (account.normal_balance === "Debit") {
          balance = debitTotal - creditTotal;
        } else {
          balance = creditTotal - debitTotal;
        }

        return {
          account_code: account.account_code,
          account_name: account.account_name,
          account_type: account.account_type,
          normal_balance: account.normal_balance,
          debit_total: debitTotal,
          credit_total: creditTotal,
          balance: Math.abs(balance),
          balance_type:
            balance >= 0
              ? account.normal_balance
              : account.normal_balance === "Debit"
                ? "Credit"
                : "Debit",
        };
      });

      // Calculate totals
      const totalDebit = trialBalance.reduce(
        (sum, acc) => sum + acc.debit_total,
        0,
      );
      const totalCredit = trialBalance.reduce(
        (sum, acc) => sum + acc.credit_total,
        0,
      );

      res.json({
        trial_balance: trialBalance,
        summary: {
          total_debits: totalDebit,
          total_credits: totalCredit,
          is_balanced: Math.abs(totalDebit - totalCredit) < 0.01,
        },
        as_of_date: dateFilter,
      });
    } catch (error) {
      console.error("Error generating trial balance:", error);
      res.status(500).json({ error: "Failed to generate trial balance" });
    }
  },
);

// Get Balance Sheet
app.get(
  "/api/sys/ledger/balance-sheet",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { as_of_date } = req.query;
      const dateFilter = as_of_date || new Date().toISOString().split("T")[0];

      // Get all ledger entries up to date
      const { data: entries } = await supabase
        .from("general_ledger")
        .select("*")
        .lte("entry_date", `${dateFilter} 23:59:59`);

      // Get chart of accounts
      const { data: accounts } = await supabase
        .from("chart_of_accounts")
        .select("*");

      // Calculate balances by account type
      const assets = [];
      const liabilities = [];
      const equity = [];

      accounts.forEach((account) => {
        let debitTotal = 0;
        let creditTotal = 0;

        (entries || []).forEach((entry) => {
          if (entry.account_code === account.account_code) {
            debitTotal += entry.debit_amount || 0;
            creditTotal += entry.credit_amount || 0;
          }
        });

        let balance = 0;
        if (account.normal_balance === "Debit") {
          balance = debitTotal - creditTotal;
        } else {
          balance = creditTotal - debitTotal;
        }

        const accountData = {
          account_code: account.account_code,
          account_name: account.account_name,
          balance: Math.abs(balance),
          balance_type:
            balance >= 0
              ? account.normal_balance
              : account.normal_balance === "Debit"
                ? "Credit"
                : "Debit",
        };

        if (account.account_type === "Asset") {
          assets.push(accountData);
        } else if (account.account_type === "Liability") {
          liabilities.push(accountData);
        } else if (account.account_type === "Equity") {
          equity.push(accountData);
        }
      });

      const totalAssets = assets.reduce((sum, a) => sum + a.balance, 0);
      const totalLiabilities = liabilities.reduce(
        (sum, l) => sum + l.balance,
        0,
      );
      const totalEquity = equity.reduce((sum, e) => sum + e.balance, 0);

      res.json({
        assets: { items: assets, total: totalAssets },
        liabilities: { items: liabilities, total: totalLiabilities },
        equity: { items: equity, total: totalEquity },
        total_liabilities_equity: totalLiabilities + totalEquity,
        difference: totalAssets - (totalLiabilities + totalEquity),
        as_of_date: dateFilter,
      });
    } catch (error) {
      console.error("Error generating balance sheet:", error);
      res.status(500).json({ error: "Failed to generate balance sheet" });
    }
  },
);

// Get Income Statement (Profit & Loss)
app.get(
  "/api/sys/ledger/income-statement",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      if (!start_date || !end_date) {
        return res
          .status(400)
          .json({ error: "Start date and end date required" });
      }

      // Get revenue and expense entries
      const { data: entries } = await supabase
        .from("general_ledger")
        .select("*")
        .gte("entry_date", start_date)
        .lte("entry_date", `${end_date} 23:59:59`);

      const { data: revenueAccounts } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .eq("account_type", "Revenue");

      const { data: expenseAccounts } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .eq("account_type", "Expense");

      // Calculate revenue by account
      const revenues = (revenueAccounts || [])
        .map((account) => {
          let creditTotal = 0;
          (entries || []).forEach((entry) => {
            if (entry.account_code === account.account_code) {
              creditTotal += entry.credit_amount || 0;
            }
          });
          return {
            account_code: account.account_code,
            account_name: account.account_name,
            amount: creditTotal,
          };
        })
        .filter((r) => r.amount > 0);

      // Calculate expenses by account
      const expenses = (expenseAccounts || [])
        .map((account) => {
          let debitTotal = 0;
          (entries || []).forEach((entry) => {
            if (entry.account_code === account.account_code) {
              debitTotal += entry.debit_amount || 0;
            }
          });
          return {
            account_code: account.account_code,
            account_name: account.account_name,
            amount: debitTotal,
          };
        })
        .filter((e) => e.amount > 0);

      const totalRevenue = revenues.reduce((sum, r) => sum + r.amount, 0);
      const totalExpenses = expenses.reduce((sum, e) => sum + e.amount, 0);
      const netIncome = totalRevenue - totalExpenses;

      res.json({
        revenues: { items: revenues, total: totalRevenue },
        expenses: { items: expenses, total: totalExpenses },
        net_income: netIncome,
        net_income_type: netIncome >= 0 ? "Profit" : "Loss",
        period: { start_date, end_date },
      });
    } catch (error) {
      console.error("Error generating income statement:", error);
      res.status(500).json({ error: "Failed to generate income statement" });
    }
  },
);

// Get Daily Journal
app.get(
  "/api/sys/ledger/daily-journal",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { date } = req.query;
      const targetDate = date || new Date().toISOString().split("T")[0];

      // Get all entries for the date
      const { data: entries } = await supabase
        .from("general_ledger")
        .select(
          `
                *,
                users!general_ledger_user_id_fkey (id, first_name, last_name, email)
            `,
        )
        .gte("entry_date", `${targetDate} 00:00:00`)
        .lte("entry_date", `${targetDate} 23:59:59`)
        .order("created_at", { ascending: true });

      // Group by hour or batch
      const groupedByHour = {};
      (entries || []).forEach((entry) => {
        const hour = new Date(entry.entry_date).getHours();
        if (!groupedByHour[hour]) {
          groupedByHour[hour] = {
            entries: [],
            total_debit: 0,
            total_credit: 0,
          };
        }
        groupedByHour[hour].entries.push(entry);
        groupedByHour[hour].total_debit += entry.debit_amount || 0;
        groupedByHour[hour].total_credit += entry.credit_amount || 0;
      });

      const totalDebit =
        entries?.reduce((sum, e) => sum + (e.debit_amount || 0), 0) || 0;
      const totalCredit =
        entries?.reduce((sum, e) => sum + (e.credit_amount || 0), 0) || 0;

      res.json({
        date: targetDate,
        entries: entries || [],
        grouped_entries: groupedByHour,
        summary: {
          total_entries: entries?.length || 0,
          total_debit: totalDebit,
          total_credit: totalCredit,
          is_balanced: Math.abs(totalDebit - totalCredit) < 0.01,
        },
      });
    } catch (error) {
      console.error("Error fetching daily journal:", error);
      res.status(500).json({ error: "Failed to fetch daily journal" });
    }
  },
);

// Get Account Statement (Single Account)
app.get(
  "/api/sys/ledger/account-statement/:accountCode",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { accountCode } = req.params;
      const { start_date, end_date, page = 1, limit = 50 } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase
        .from("general_ledger")
        .select("*", { count: "exact" })
        .eq("account_code", accountCode)
        .order("entry_date", { ascending: true });

      if (start_date) {
        query = query.gte("entry_date", start_date);
      }
      if (end_date) {
        query = query.lte("entry_date", `${end_date} 23:59:59`);
      }

      const {
        data: entries,
        error,
        count,
      } = await query.range(offset, offset + limit - 1);

      if (error) throw error;

      // Calculate running balance
      let runningBalance = 0;
      const accountInfo = await supabase
        .from("chart_of_accounts")
        .select("*")
        .eq("account_code", accountCode)
        .single();

      const entriesWithBalance = (entries || []).map((entry) => {
        if (accountInfo?.data?.normal_balance === "Debit") {
          runningBalance +=
            (entry.debit_amount || 0) - (entry.credit_amount || 0);
        } else {
          runningBalance +=
            (entry.credit_amount || 0) - (entry.debit_amount || 0);
        }
        return { ...entry, running_balance: runningBalance };
      });

      res.json({
        account_info: accountInfo.data,
        entries: entriesWithBalance,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
      });
    } catch (error) {
      console.error("Error fetching account statement:", error);
      res.status(500).json({ error: "Failed to fetch account statement" });
    }
  },
);

// Reconcile an account
app.post(
  "/api/sys/ledger/reconcile/:entryId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { entryId } = req.params;

      const { error } = await supabase
        .from("general_ledger")
        .update({
          is_reconciled: true,
          reconciled_at: new Date(),
          reconciled_by: req.user.id,
        })
        .eq("id", entryId);

      if (error) throw error;

      res.json({ success: true, message: "Entry reconciled successfully" });
    } catch (error) {
      console.error("Error reconciling entry:", error);
      res.status(500).json({ error: "Failed to reconcile entry" });
    }
  },
);

// Get chart of accounts
app.get(
  "/api/sys/ledger/chart-of-accounts",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { data: accounts, error } = await supabase
        .from("chart_of_accounts")
        .select("*")
        .order("account_code");

      if (error) throw error;
      res.json({ accounts: accounts || [] });
    } catch (error) {
      console.error("Error fetching chart of accounts:", error);
      res.status(500).json({ error: "Failed to fetch chart of accounts" });
    }
  },
);

// Create chart of account
app.post(
  "/api/sys/ledger/chart-of-accounts",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        account_code,
        account_name,
        account_type,
        normal_balance,
        description,
        parent_account_id,
      } = req.body;

      const { data: account, error } = await supabase
        .from("chart_of_accounts")
        .insert({
          account_code,
          account_name,
          account_type,
          normal_balance,
          description,
          parent_account_id,
          is_active: true,
        })
        .select()
        .single();

      if (error) throw error;
      res.status(201).json({ success: true, account });
    } catch (error) {
      console.error("Error creating account:", error);
      res.status(500).json({ error: "Failed to create account" });
    }
  },
);

// Export general ledger as CSV
app.get(
  "/api/sys/ledger/general/export",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { start_date, end_date } = req.query;

      let query = supabase
        .from("general_ledger")
        .select("*")
        .order("entry_date", { ascending: true });

      if (start_date) query = query.gte("entry_date", start_date);
      if (end_date) query = query.lte("entry_date", `${end_date} 23:59:59`);

      const { data: entries, error } = await query;

      if (error) throw error;

      // Create CSV
      const headers = [
        "Entry ID",
        "Date",
        "Account Code",
        "Account Name",
        "Description",
        "Reference",
        "Debit",
        "Credit",
        "User ID",
        "Reconciled",
      ];
      const csvRows = [headers.join(",")];

      entries.forEach((entry) => {
        const row = [
          `"${entry.entry_id || ""}"`,
          `"${entry.entry_date}"`,
          `"${entry.account_code || ""}"`,
          `"${entry.account_name || ""}"`,
          `"${(entry.description || "").replace(/"/g, '""')}"`,
          `"${entry.reference || ""}"`,
          entry.debit_amount || 0,
          entry.credit_amount || 0,
          `"${entry.user_id || ""}"`,
          entry.is_reconciled ? "Yes" : "No",
        ];
        csvRows.push(row.join(","));
      });

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=general_ledger_${new Date().toISOString().split("T")[0]}.csv`,
      );
      res.send(csvRows.join("\n"));
    } catch (error) {
      console.error("Export error:", error);
      res.status(500).json({ error: "Export failed" });
    }
  },
);*/

// ==================== ADMIN HARVEST PLAN ROUTES ====================

// Get all harvest plans (admin)
app.get(
  "/api/sys/harvest-plans",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { page = 1, limit = 20 } = req.query;
      const offset = (page - 1) * limit;

      const {
        data: plans,
        error,
        count,
      } = await supabase
        .from("harvest_plans")
        .select("*", { count: "exact" })
        .order("created_at", { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) throw error;

      res.json({
        plans: plans || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
      });
    } catch (error) {
      console.error("Admin harvest plans error:", error);
      res.status(500).json({ error: "Failed to fetch harvest plans" });
    }
  },
);

// Create harvest plan (admin)
app.post(
  "/api/sys/harvest-plans",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { name, description, daily_amount, duration_days, reward_items } =
        req.body;
      const total_amount = daily_amount * duration_days;

      const { data: plan, error } = await supabase
        .from("harvest_plans")
        .insert({
          name,
          description,
          daily_amount,
          duration_days,
          total_amount,
          reward_items: JSON.stringify(reward_items || []),
          created_by: req.user.id,
        })
        .select()
        .single();

      if (error) throw error;

      res.status(201).json({ success: true, plan });
    } catch (error) {
      console.error("Create harvest plan error:", error);
      res.status(500).json({ error: "Failed to create harvest plan" });
    }
  },
);

// Update harvest plan (admin)
app.put(
  "/api/sys/harvest-plans/:id",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        name,
        description,
        daily_amount,
        duration_days,
        reward_items,
        is_active,
      } = req.body;
      const total_amount = daily_amount * duration_days;

      const { data: plan, error } = await supabase
        .from("harvest_plans")
        .update({
          name,
          description,
          daily_amount,
          duration_days,
          total_amount,
          reward_items: JSON.stringify(reward_items || []),
          is_active,
          updated_at: new Date(),
        })
        .eq("id", id)
        .select()
        .single();

      if (error) throw error;

      res.json({ success: true, plan });
    } catch (error) {
      console.error("Update harvest plan error:", error);
      res.status(500).json({ error: "Failed to update harvest plan" });
    }
  },
);

// Toggle harvest plan status (admin)
app.post(
  "/api/sys/harvest-plans/:id/toggle",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { is_active } = req.body;

      const { error } = await supabase
        .from("harvest_plans")
        .update({ is_active, updated_at: new Date() })
        .eq("id", id);

      if (error) throw error;

      res.json({ success: true });
    } catch (error) {
      console.error("Toggle harvest plan error:", error);
      res.status(500).json({ error: "Failed to toggle harvest plan" });
    }
  },
);

// Delete harvest plan (admin)
app.delete(
  "/api/sys/harvest-plans/:id",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { error } = await supabase
        .from("harvest_plans")
        .delete()
        .eq("id", id);

      if (error) throw error;

      res.json({ success: true });
    } catch (error) {
      console.error("Delete harvest plan error:", error);
      res.status(500).json({ error: "Failed to delete harvest plan" });
    }
  },
);

// Get user enrollments (admin)
app.get(
  "/api/sys/users/:userId/enrollments",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      const [harvest, fixed, savebox, target] = await Promise.all([
        supabase
          .from("user_harvest_enrollments")
          .select("*, harvest_plans(name)")
          .eq("user_id", userId),
        supabase.from("fixed_savings").select("*").eq("user_id", userId),
        supabase.from("savebox_savings").select("*").eq("user_id", userId),
        supabase.from("target_savings").select("*").eq("user_id", userId),
      ]);

      res.json({
        harvest: harvest.data || [],
        fixed: fixed.data || [],
        savebox: savebox.data || [],
        target: target.data || [],
      });
    } catch (error) {
      console.error("Error fetching enrollments:", error);
      res.status(500).json({ error: "Failed to fetch enrollments" });
    }
  },
);

// ==================== ACCOUNT UPGRADE API ROUTES ====================

// ==================== EMAIL VERIFICATION FOR UPGRADE ====================

// ==================== GET ACCOUNT TIER INFO ====================

app.get("/api/user/tier-info", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: user, error: userError } = await supabase
      .from("users")
      .select("account_tier, is_frozen, freeze_reason, frozen_reason_type")
      .eq("id", userId)
      .single();

    if (userError) throw userError;

    // Get upgrade request status
    const { data: upgradeRequest } = await supabase
      .from("user_upgrade_requests")
      .select("*")
      .eq("user_id", userId)
      .single();

    // Get documents
    const { data: documents } = await supabase
      .from("user_upgrade_documents")
      .select("*")
      .eq("user_id", userId);

    const idDoc = documents?.find((d) => d.document_type === "id");
    const addressDoc = documents?.find((d) => d.document_type === "address");

    const tierLimits = {
      1: { max_balance: 500000, daily_limit: 150000, name: "Basic" },
      2: { max_balance: 800000, daily_limit: 250000, name: "Verified" },
      3: { max_balance: 999999999, daily_limit: 999999999, name: "Premium" },
    };

    // Get total balance to check if exceeds limit
    const { data: accounts } = await supabase
      .from("accounts")
      .select("balance")
      .eq("user_id", userId);

    const totalBalance =
      accounts?.reduce((sum, acc) => sum + (acc.balance || 0), 0) || 0;
    const exceedsBalanceLimit =
      totalBalance > tierLimits[user.account_tier].max_balance;

    res.json({
      current_tier: user.account_tier,
      tier_name: tierLimits[user.account_tier].name,
      max_balance: tierLimits[user.account_tier].max_balance,
      daily_limit: tierLimits[user.account_tier].daily_limit,
      current_balance: totalBalance,
      exceeds_balance_limit: exceedsBalanceLimit,
      is_frozen: user.is_frozen,
      frozen_reason: user.freeze_reason,
      frozen_reason_type: user.frozen_reason_type,
      upgrade_status: {
        email_verified: upgradeRequest?.email_verified || false,
        id_status: idDoc?.status || "not_submitted",
        address_status: addressDoc?.status || "not_submitted",
        id_rejection_reason: idDoc?.rejection_reason,
        address_rejection_reason: addressDoc?.rejection_reason,
        overall_status: upgradeRequest?.overall_status || "none",
      },
    });
  } catch (error) {
    console.error("Get tier info error:", error);
    res.status(500).json({ error: "Failed to get tier information" });
  }
});

// ==================== EMAIL VERIFICATION FOR UPGRADE (FIXED) ====================

// Send email verification OTP for upgrade
app.post(
  "/api/user/upgrade/send-email-otp",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const userEmail = req.user.email;
      const userName =
        `${req.user.first_name || ""} ${req.user.last_name || ""}`.trim() ||
        "User";

      // Check if user already has active upgrade request that is pending/completed
      const { data: existingRequest, error: requestError } = await supabase
        .from("user_upgrade_requests")
        .select("overall_status")
        .eq("user_id", userId)
        .single();

      if (existingRequest && existingRequest.overall_status === "approved") {
        return res
          .status(400)
          .json({ error: "You have already completed all upgrades" });
      }

      // Generate 6-digit OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 10); // 10 minutes expiry

      // Invalidate any old unused OTPs for this user
      await supabase
        .from("email_verification_otps")
        .update({ is_used: true })
        .eq("user_id", userId)
        .eq("is_used", false);

      // Store OTP in database
      const { data: otpData, error: otpError } = await supabase
        .from("email_verification_otps")
        .insert({
          user_id: userId,
          email: userEmail,
          otp_code: otpCode,
          expires_at: expiresAt.toISOString(),
        })
        .select()
        .single();

      if (otpError) {
        console.error("OTP insert error:", otpError);
        return res
          .status(500)
          .json({ error: "Failed to generate verification code" });
      }

      // ========== USE YOUR WORKING EMAIL FUNCTION ==========
      const emailSent = await sendOTPEmail(userEmail, otpCode, "upgrade");

      if (!emailSent) {
        console.error(
          `Failed to send upgrade verification email to ${userEmail}`,
        );
        // Still return success to user (don't reveal email failure)
        return res.json({
          success: true,
          message:
            "If your email is registered, you will receive a verification code.",
          request_id: otpData.id,
          expires_in: 600,
        });
      }

      console.log(`Upgrade verification OTP sent to ${userEmail}: ${otpCode}`);

      res.json({
        success: true,
        message:
          "Verification code sent to your email. Please check your inbox and spam folder.",
        request_id: otpData.id,
        expires_in: 600,
      });
    } catch (error) {
      console.error("Send email OTP error:", error);
      res
        .status(500)
        .json({ error: "Failed to send verification code: " + error.message });
    }
  },
);

// Resend email verification OTP
app.post(
  "/api/user/upgrade/resend-email-otp",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const userEmail = req.user.email;
      const userName =
        `${req.user.first_name || ""} ${req.user.last_name || ""}`.trim() ||
        "User";

      // Invalidate old unused OTPs
      await supabase
        .from("email_verification_otps")
        .update({ is_used: true })
        .eq("user_id", userId)
        .eq("is_used", false);

      // Generate new OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 10);

      const { data: otpData, error: otpError } = await supabase
        .from("email_verification_otps")
        .insert({
          user_id: userId,
          email: userEmail,
          otp_code: otpCode,
          expires_at: expiresAt.toISOString(),
        })
        .select()
        .single();

      if (otpError) {
        return res
          .status(500)
          .json({ error: "Failed to generate verification code" });
      }

      // Use your working email function
      const emailSent = await sendOTPEmail(userEmail, otpCode, "upgrade");

      if (!emailSent) {
        console.error(`Failed to resend upgrade email to ${userEmail}`);
      }

      console.log(
        `Resent upgrade verification OTP to ${userEmail}: ${otpCode}`,
      );

      res.json({
        success: true,
        message: "New verification code sent to your email",
        request_id: otpData.id,
      });
    } catch (error) {
      console.error("Resend email OTP error:", error);
      res.status(500).json({ error: "Failed to resend verification code" });
    }
  },
);

// Verify email OTP
app.post(
  "/api/user/upgrade/verify-email",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { otp_code } = req.body;

      if (!otp_code) {
        return res.status(400).json({ error: "OTP code is required" });
      }

      // Find valid OTP
      const { data: otpRecord, error: otpError } = await supabase
        .from("email_verification_otps")
        .select("*")
        .eq("user_id", userId)
        .eq("otp_code", otp_code)
        .eq("is_used", false)
        .single();

      if (otpError || !otpRecord) {
        return res
          .status(400)
          .json({ error: "Invalid or expired verification code" });
      }

      // Check expiry
      if (new Date(otpRecord.expires_at) < new Date()) {
        return res.status(400).json({
          error: "Verification code has expired. Please request a new one.",
        });
      }

      // Mark OTP as used
      await supabase
        .from("email_verification_otps")
        .update({ is_used: true })
        .eq("id", otpRecord.id);

      // Create or update upgrade request
      const { data: existingRequest, error: requestError } = await supabase
        .from("user_upgrade_requests")
        .select("*")
        .eq("user_id", userId)
        .single();

      if (existingRequest) {
        await supabase
          .from("user_upgrade_requests")
          .update({
            email_verified: true,
            email_verified_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          })
          .eq("user_id", userId);
      } else {
        await supabase.from("user_upgrade_requests").insert({
          user_id: userId,
          email_verified: true,
          email_verified_at: new Date().toISOString(),
          overall_status: "email_verified",
        });
      }

      // Send confirmation email
      await sendOTPEmail(req.user.email, null, "verified");

      res.json({
        success: true,
        message:
          "Email verified successfully! You can now submit your documents.",
      });
    } catch (error) {
      console.error("Verify email OTP error:", error);
      res
        .status(500)
        .json({ error: "Failed to verify email: " + error.message });
    }
  },
);

// ==================== UPGRADE DOCUMENT SUBMISSION ====================

// Submit upgrade documents (ID and/or Address)
app.post(
  "/api/user/upgrade/submit-documents",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { id_document, address_document, id_type, id_number } = req.body;

      // Check if user is already fully upgraded
      const { data: userData } = await supabase
        .from("users")
        .select("account_tier")
        .eq("id", userId)
        .single();

      if (userData && userData.account_tier >= 3) {
        return res
          .status(400)
          .json({ error: "You have already reached the highest tier" });
      }

      // Get or create upgrade request
      let { data: upgradeRequest, error: requestError } = await supabase
        .from("user_upgrade_requests")
        .select("*")
        .eq("user_id", userId)
        .single();

      if (!upgradeRequest) {
        const { data: newRequest, error: createError } = await supabase
          .from("user_upgrade_requests")
          .insert({
            user_id: userId,
            overall_status: "documents_submitted",
          })
          .select()
          .single();

        if (createError) throw createError;
        upgradeRequest = newRequest;
      }

      const results = {};

      // Submit ID document
      if (id_document) {
        // Check if ID document already exists
        const { data: existingIdDoc } = await supabase
          .from("user_upgrade_documents")
          .select("*")
          .eq("user_id", userId)
          .eq("document_type", "id")
          .single();

        const documentData = {
          user_id: userId,
          document_type: "id",
          document_data: id_document,
          id_type: id_type || null,
          id_number: id_number || null,
          status: "pending",
          submitted_at: new Date().toISOString(),
        };

        let idDoc;
        if (existingIdDoc) {
          const { data: updated, error: updateError } = await supabase
            .from("user_upgrade_documents")
            .update(documentData)
            .eq("id", existingIdDoc.id)
            .select()
            .single();

          if (updateError) throw updateError;
          idDoc = updated;
          results.id_document = "updated";
        } else {
          const { data: inserted, error: insertError } = await supabase
            .from("user_upgrade_documents")
            .insert(documentData)
            .select()
            .single();

          if (insertError) throw insertError;
          idDoc = inserted;
          results.id_document = "submitted";
        }

        // Update upgrade request with ID document reference
        await supabase
          .from("user_upgrade_requests")
          .update({
            id_document_id: idDoc.id,
            updated_at: new Date().toISOString(),
          })
          .eq("user_id", userId);
      }

      // Submit Address document
      if (address_document) {
        const { data: existingAddressDoc } = await supabase
          .from("user_upgrade_documents")
          .select("*")
          .eq("user_id", userId)
          .eq("document_type", "address")
          .single();

        const documentData = {
          user_id: userId,
          document_type: "address",
          document_data: address_document,
          status: "pending",
          submitted_at: new Date().toISOString(),
        };

        let addressDoc;
        if (existingAddressDoc) {
          const { data: updated, error: updateError } = await supabase
            .from("user_upgrade_documents")
            .update(documentData)
            .eq("id", existingAddressDoc.id)
            .select()
            .single();

          if (updateError) throw updateError;
          addressDoc = updated;
          results.address_document = "updated";
        } else {
          const { data: inserted, error: insertError } = await supabase
            .from("user_upgrade_documents")
            .insert(documentData)
            .select()
            .single();

          if (insertError) throw insertError;
          addressDoc = inserted;
          results.address_document = "submitted";
        }

        await supabase
          .from("user_upgrade_requests")
          .update({
            address_document_id: addressDoc.id,
            updated_at: new Date().toISOString(),
          })
          .eq("user_id", userId);
      }

      // Update overall status
      const { data: currentDocs } = await supabase
        .from("user_upgrade_documents")
        .select("status")
        .eq("user_id", userId);

      const hasPending = currentDocs?.some((doc) => doc.status === "pending");
      const overallStatus = hasPending
        ? "documents_pending"
        : "documents_submitted";

      await supabase
        .from("user_upgrade_requests")
        .update({
          overall_status: overallStatus,
          updated_at: new Date().toISOString(),
        })
        .eq("user_id", userId);

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: userId,
        title: "Upgrade Documents Submitted",
        message:
          "Your upgrade documents have been submitted for review. You will be notified once approved.",
        type: "info",
        created_at: new Date().toISOString(),
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: userId,
        action_type: "submit_upgrade_documents",
        target_user_id: userId,
        details: results,
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Documents submitted for review",
        results: results,
      });
    } catch (error) {
      console.error("Submit upgrade documents error:", error);
      res.status(500).json({ error: "Failed to submit documents" });
    }
  },
);

// Get upgrade status for user
app.get(
  "/api/user/upgrade/status",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const userId = req.user.id;

      // Get user tier
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("account_tier")
        .eq("id", userId)
        .single();

      if (userError) throw userError;

      // Get upgrade request
      const { data: upgradeRequest, error: requestError } = await supabase
        .from("user_upgrade_requests")
        .select("*")
        .eq("user_id", userId)
        .single();

      // Get documents
      const { data: documents, error: docError } = await supabase
        .from("user_upgrade_documents")
        .select("*")
        .eq("user_id", userId);

      // Check if email is verified (if upgrade request exists)
      const emailVerified = upgradeRequest?.email_verified || false;

      // Get document statuses
      const idDoc = documents?.find((d) => d.document_type === "id");
      const addressDoc = documents?.find((d) => d.document_type === "address");

      const idStatus = idDoc?.status || "not_submitted";
      const addressStatus = addressDoc?.status || "not_submitted";

      // Determine if can upgrade to next tier
      let canUpgradeToTier2 = false;
      let canUpgradeToTier3 = false;

      if (user.account_tier === 1) {
        canUpgradeToTier2 = true;
        canUpgradeToTier3 = true;
      } else if (user.account_tier === 2) {
        canUpgradeToTier3 = true;
      }

      // Check if documents are approved
      const isIdApproved = idStatus === "approved";
      const isAddressApproved = addressStatus === "approved";

      // Check if both documents are approved (for tier 3)
      const bothApproved = isIdApproved && isAddressApproved;

      res.json({
        current_tier: user.account_tier || 1,
        email_verified: emailVerified,
        id_status: idStatus,
        address_status: addressStatus,
        id_rejection_reason: idDoc?.rejection_reason || null,
        address_rejection_reason: addressDoc?.rejection_reason || null,
        can_upgrade_to_tier2: canUpgradeToTier2,
        can_upgrade_to_tier3: canUpgradeToTier3,
        has_pending: idStatus === "pending" || addressStatus === "pending",
        id_approved: isIdApproved,
        address_approved: isAddressApproved,
        both_approved: bothApproved,
        upgrade_request: upgradeRequest,
      });
    } catch (error) {
      console.error("Get upgrade status error:", error);
      res.status(500).json({ error: "Failed to get upgrade status" });
    }
  },
);

// ==================== ADMIN UPGRADE DOCUMENT REVIEW ROUTES ====================

// GET all upgrade requests (admin only) - FIXED
app.get(
  "/api/sys/upgrade-requests",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 20,
        status = "all",
        document_type = "all",
        search = "",
      } = req.query;
      const offset = (parseInt(page) - 1) * parseInt(limit);

      // Build the query
      let query = supabase.from("user_upgrade_documents").select(
        `
                *,
                users:user_id (
                    id,
                    first_name,
                    last_name,
                    email,
                    phone,
                    account_tier,
                    created_at
                )
            `,
        { count: "exact" },
      );

      // Apply filters
      if (status !== "all") {
        query = query.eq("status", status);
      }

      if (document_type !== "all") {
        query = query.eq("document_type", document_type);
      }

      // Add search filter
      if (search) {
        query = query.or(
          `users.first_name.ilike.%${search}%,users.last_name.ilike.%${search}%,users.email.ilike.%${search}%`,
        );
      }

      // Order by submitted_at descending
      query = query.order("submitted_at", { ascending: false });

      // Apply pagination
      query = query.range(offset, offset + parseInt(limit) - 1);

      const { data: documents, error, count } = await query;

      if (error) {
        console.error("Supabase query error:", error);
        throw error;
      }

      // Get statistics
      const { data: pendingIdDocs } = await supabase
        .from("user_upgrade_documents")
        .select("id", { count: "exact", head: true })
        .eq("document_type", "id")
        .eq("status", "pending");

      const { data: pendingAddressDocs } = await supabase
        .from("user_upgrade_documents")
        .select("id", { count: "exact", head: true })
        .eq("document_type", "address")
        .eq("status", "pending");

      const { data: approvedDocs } = await supabase
        .from("user_upgrade_documents")
        .select("id", { count: "exact", head: true })
        .eq("status", "approved");

      const { data: rejectedDocs } = await supabase
        .from("user_upgrade_documents")
        .select("id", { count: "exact", head: true })
        .eq("status", "rejected");

      res.json({
        requests: documents || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / parseInt(limit)),
        },
        stats: {
          pending_id: pendingIdDocs?.length || 0,
          pending_address: pendingAddressDocs?.length || 0,
          total_pending:
            (pendingIdDocs?.length || 0) + (pendingAddressDocs?.length || 0),
          approved: approvedDocs?.length || 0,
          rejected: rejectedDocs?.length || 0,
        },
      });
    } catch (error) {
      console.error("Get upgrade requests error:", error);
      res.status(500).json({
        error: "Failed to get upgrade requests",
        details: error.message,
      });
    }
  },
);

// Approve upgrade document (admin only)
app.post(
  "/api/sys/upgrade/approve-document/:documentId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { documentId } = req.params;
      const adminId = req.user.id;

      // Get document
      const { data: document, error: docError } = await supabase
        .from("user_upgrade_documents")
        .select("*, users:user_id(*)")
        .eq("id", documentId)
        .single();

      if (docError || !document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Update document status
      const { error: updateError } = await supabase
        .from("user_upgrade_documents")
        .update({
          status: "approved",
          reviewed_at: new Date().toISOString(),
          reviewed_by: adminId,
          rejection_reason: null,
        })
        .eq("id", documentId);

      if (updateError) throw updateError;

      // Check if user should be upgraded
      const userId = document.user_id;

      // Get all documents for this user
      const { data: userDocuments } = await supabase
        .from("user_upgrade_documents")
        .select("*")
        .eq("user_id", userId);

      const idDoc = userDocuments?.find((d) => d.document_type === "id");
      const addressDoc = userDocuments?.find(
        (d) => d.document_type === "address",
      );

      let newTier = 1;
      let upgradeMessage = "";

      // Determine new tier based on approved documents
      if (document.document_type === "id" && idDoc?.status === "approved") {
        newTier = 2;
        upgradeMessage =
          "Your ID has been verified. You have been upgraded to Tier 2.";
      }

      if (
        document.document_type === "address" &&
        addressDoc?.status === "approved" &&
        idDoc?.status === "approved"
      ) {
        newTier = 3;
        upgradeMessage =
          "Congratulations! Both your ID and address have been verified. You have been upgraded to Tier 3 (Premium).";
      }

      // Update user tier if needed
      if (newTier > 1) {
        const { data: user, error: userError } = await supabase
          .from("users")
          .select("account_tier")
          .eq("id", userId)
          .single();

        if (!userError && user && newTier > user.account_tier) {
          await supabase
            .from("users")
            .update({
              account_tier: newTier,
              tier_upgraded_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            })
            .eq("id", userId);
        }
      }

      // Update upgrade request status
      const { data: upgradeRequest } = await supabase
        .from("user_upgrade_requests")
        .select("*")
        .eq("user_id", userId)
        .single();

      if (upgradeRequest) {
        const idDocStatus = idDoc?.status || "pending";
        const addressDocStatus = addressDoc?.status || "pending";

        let overallStatus = "pending";
        if (idDocStatus === "approved" && addressDocStatus === "approved") {
          overallStatus = "approved";
        } else if (
          idDocStatus === "approved" ||
          addressDocStatus === "approved"
        ) {
          overallStatus = "partially_approved";
        } else if (
          idDocStatus === "rejected" ||
          addressDocStatus === "rejected"
        ) {
          overallStatus = "rejected";
        }

        await supabase
          .from("user_upgrade_requests")
          .update({
            overall_status: overallStatus,
            updated_at: new Date().toISOString(),
          })
          .eq("user_id", userId);
      }

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: userId,
        title: `Upgrade Document ${document.document_type === "id" ? "ID" : "Address"} Approved`,
        message:
          upgradeMessage ||
          `Your ${document.document_type === "id" ? "ID document" : "address proof"} has been approved.`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: adminId,
        action_type: "approve_upgrade_document",
        target_user_id: userId,
        details: {
          document_id: documentId,
          document_type: document.document_type,
          new_tier: newTier,
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: `Document approved successfully. User upgraded to Tier ${newTier}.`,
        new_tier: newTier,
      });
    } catch (error) {
      console.error("Approve document error:", error);
      res.status(500).json({ error: "Failed to approve document" });
    }
  },
);

// Reject upgrade document (admin only)
app.post(
  "/api/sys/upgrade/reject-document/:documentId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { documentId } = req.params;
      const { reason } = req.body;
      const adminId = req.user.id;

      if (!reason || reason.trim() === "") {
        return res.status(400).json({ error: "Rejection reason is required" });
      }

      // Get document
      const { data: document, error: docError } = await supabase
        .from("user_upgrade_documents")
        .select("*, users:user_id(*)")
        .eq("id", documentId)
        .single();

      if (docError || !document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Update document status
      const { error: updateError } = await supabase
        .from("user_upgrade_documents")
        .update({
          status: "rejected",
          reviewed_at: new Date().toISOString(),
          reviewed_by: adminId,
          rejection_reason: reason,
        })
        .eq("id", documentId);

      if (updateError) throw updateError;

      const userId = document.user_id;

      // Update upgrade request status
      const { data: upgradeRequest } = await supabase
        .from("user_upgrade_requests")
        .select("*")
        .eq("user_id", userId)
        .single();

      if (upgradeRequest) {
        await supabase
          .from("user_upgrade_requests")
          .update({
            overall_status: "rejected",
            updated_at: new Date().toISOString(),
          })
          .eq("user_id", userId);
      }

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: userId,
        title: `Upgrade Document ${document.document_type === "id" ? "ID" : "Address"} Rejected`,
        message: `Your ${document.document_type === "id" ? "ID document" : "address proof"} was rejected. Reason: ${reason}. Please resubmit with correct documents.`,
        type: "error",
        created_at: new Date().toISOString(),
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: adminId,
        action_type: "reject_upgrade_document",
        target_user_id: userId,
        details: {
          document_id: documentId,
          document_type: document.document_type,
          reason: reason,
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Document rejected successfully",
      });
    } catch (error) {
      console.error("Reject document error:", error);
      res.status(500).json({ error: "Failed to reject document" });
    }
  },
);

// ==================== GET USER ACCOUNT LIMITS BASED ON TIER ====================

app.get(
  "/api/user/account-limits",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const userId = req.user.id;

      // Get user tier
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("account_tier, is_frozen")
        .eq("id", userId)
        .single();

      if (userError) throw userError;

      // Define tier limits
      const tierLimits = {
        1: {
          max_balance: 500000,
          daily_limit: 150000,
          single_transfer_limit: 150000,
          monthly_limit: 3000000,
          name: "Basic",
        },
        2: {
          max_balance: 800000,
          daily_limit: 250000,
          single_transfer_limit: 250000,
          monthly_limit: 5000000,
          name: "Verified",
        },
        3: {
          max_balance: 9999999999,
          daily_limit: 9999999999,
          single_transfer_limit: 9999999999,
          monthly_limit: 9999999999,
          name: "Premium",
        },
      };

      const limits = tierLimits[user.account_tier] || tierLimits[1];

      // Get user's total balance
      const { data: accounts } = await supabase
        .from("accounts")
        .select("balance")
        .eq("user_id", userId);

      const totalBalance =
        accounts?.reduce((sum, acc) => sum + (acc.balance || 0), 0) || 0;

      // Get today's transactions total
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const { data: todayTransactions } = await supabase
        .from("transactions_new")
        .select("amount")
        .eq("sender_user_id", userId)
        .eq("status", "completed")
        .gte("created_at", today.toISOString());

      const dailyUsed =
        todayTransactions?.reduce((sum, t) => sum + (t.amount || 0), 0) || 0;

      // Get this month's transactions total
      const firstDayOfMonth = new Date(
        today.getFullYear(),
        today.getMonth(),
        1,
      );

      const { data: monthTransactions } = await supabase
        .from("transactions_new")
        .select("amount")
        .eq("sender_user_id", userId)
        .eq("status", "completed")
        .gte("created_at", firstDayOfMonth.toISOString());

      const monthlyUsed =
        monthTransactions?.reduce((sum, t) => sum + (t.amount || 0), 0) || 0;

      res.json({
        account_tier: user.account_tier,
        tier_name: limits.name,
        max_balance: limits.max_balance,
        daily_limit: limits.daily_limit,
        single_transfer_limit: limits.single_transfer_limit,
        monthly_limit: limits.monthly_limit,
        daily_used: dailyUsed,
        monthly_used: monthlyUsed,
        total_balance: totalBalance,
        is_frozen: user.is_frozen,
      });
    } catch (error) {
      console.error("Get account limits error:", error);
      res.status(500).json({ error: "Failed to get account limits" });
    }
  },
);

// ==================== ADMIN RESET USER PASSWORD ====================

// Helper: generate random password (e.g., 12 characters)
function generateRandomPassword() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  let password = "";
  for (let i = 0; i < 12; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

app.post(
  "/api/sys/users/:userId/reset-password",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { userId } = req.params;

    // Generate temporary password
    const tempPassword = generateRandomPassword();
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    // Update user
    const { error } = await supabase
      .from("users")
      .update({ password_hash: hashedPassword })
      .eq("id", userId);

    if (error) {
      console.error("Admin reset password error:", error);
      return res.status(500).json({ error: "Failed to reset password" });
    }

    // Get user email
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("email")
      .eq("id", userId)
      .single();

    if (user && !userError) {
      // Send email with new password
      try {
        await transporter.sendMail({
          from: process.env.SMTP_FROM,
          to: user.email,
          subject: "Your password has been reset",
          html: `
                    <h2>Password Reset by our Team</h2>
                    <p>Your password has been reset. Your new temporary password is:</p>
                    <h3 style="font-size: 24px;">${tempPassword}</h3>
                    <p>Please log in and change your password immediately.</p>
                `,
        });
      } catch (err) {
        console.error("Admin reset email error:", err);
      }
    }

    // Log admin action
    await supabase.from("admin_actions").insert({
      admin_id: req.user.id,
      action_type: "reset_password",
      target_user_id: userId,
      details: { generated_by_admin: true },
    });

    res.json({
      message: "Password reset successful. User has been notified via email.",
    });
  },
);

// Check if user has transfer PIN
app.get("/api/user/has-pin", authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("transfer_pin, transfer_pin_set_at")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    res.json({
      has_pin: !!(user.transfer_pin && user.transfer_pin !== null),
      pin_set_at: user.transfer_pin_set_at,
    });
  } catch (error) {
    console.error("Check PIN error:", error);
    res.status(500).json({ error: "Failed to check PIN status" });
  }
});

// Set/Update transfer PIN
app.post("/api/user/set-transfer-pin", authenticate, async (req, res) => {
  try {
    const { pin } = req.body;

    if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: "PIN must be exactly 4 digits" });
    }

    // Hash the PIN before storing
    const hashedPin = await bcrypt.hash(pin, 10);

    const { error } = await supabase
      .from("users")
      .update({
        transfer_pin: hashedPin,
        transfer_pin_set_at: new Date(),
        pin_attempts: 0,
        last_pin_attempt: null,
      })
      .eq("id", req.user.id);

    if (error) throw error;

    res.json({ success: true, message: "Transfer PIN set successfully" });
  } catch (error) {
    console.error("Set PIN error:", error);
    res.status(500).json({ error: "Failed to set transfer PIN" });
  }
});

// Verify transfer PIN
/*app.post("/api/user/verify-transfer-pin", authenticate, async (req, res) => {
  try {
    const { pin } = req.body;

    if (!pin || pin.length !== 4) {
      return res
        .status(400)
        .json({ valid: false, error: "Invalid PIN format" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("transfer_pin, pin_attempts, last_pin_attempt")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    if (!user.transfer_pin) {
      return res.json({ valid: false, needs_setup: true });
    }

    // Check if account is already frozen due to PIN attempts
    if (user.pin_attempts >= 4) {
      return res.status(403).json({
        valid: false,
        frozen: true,
        error: "Too many incorrect PIN attempts. Account frozen.",
      });
    }

    const isValid = await bcrypt.compare(pin, user.transfer_pin);

    if (isValid) {
      // Reset attempts on successful verification
      await supabase
        .from("users")
        .update({ pin_attempts: 0, last_pin_attempt: null })
        .eq("id", req.user.id);

      res.json({ valid: true });
    } else {
      // Increment attempts
      const newAttempts = (user.pin_attempts || 0) + 1;
      const updates = {
        pin_attempts: newAttempts,
        last_pin_attempt: new Date(),
      };

      if (newAttempts >= 4) {
        // Freeze account after 4 failed attempts
        updates.is_frozen = true;
        updates.freeze_reason =
          "Too many incorrect PIN attempts - Contact support to unfreeze";
        updates.unfreeze_method = "support";
      }

      await supabase.from("users").update(updates).eq("id", req.user.id);

      res.json({
        valid: false,
        attempts_remaining: 4 - newAttempts,
        frozen: newAttempts >= 4,
      });
    }
  } catch (error) {
    console.error("Verify PIN error:", error);
    res.status(500).json({ error: "PIN verification failed" });
  }
});*/

app.post("/api/user/verify-transfer-pin", authenticate, async (req, res) => {
  try {
    const { pin, from_account_id, to_account_number, amount } = req.body;

    if (!pin || pin.length !== 4) {
      return res
        .status(400)
        .json({ valid: false, error: "Invalid PIN format" });
    }
    if (!from_account_id || !to_account_number || !amount) {
      return res.status(400).json({
        valid: false,
        error: "from_account_id, to_account_number, and amount are required",
      });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("transfer_pin, pin_attempts, last_pin_attempt")
      .eq("id", req.user.id)
      .single();

    if (error) throw error;

    if (!user.transfer_pin) {
      return res.json({ valid: false, needs_setup: true });
    }

    if (user.pin_attempts >= 4) {
      return res.status(403).json({
        valid: false,
        frozen: true,
        error: "Too many incorrect PIN attempts. Account frozen.",
      });
    }

    const isValid = await bcrypt.compare(pin, user.transfer_pin);

    if (!isValid) {
      const newAttempts = (user.pin_attempts || 0) + 1;
      const updates = {
        pin_attempts: newAttempts,
        last_pin_attempt: new Date(),
      };

      if (newAttempts >= 4) {
        updates.is_frozen = true;
        updates.freeze_reason =
          "Too many incorrect PIN attempts - Contact support to unfreeze";
        updates.unfreeze_method = "support";
      }

      await supabase.from("users").update(updates).eq("id", req.user.id);

      return res.json({
        valid: false,
        attempts_remaining: 4 - newAttempts,
        frozen: newAttempts >= 4,
      });
    }

    // Correct PIN — reset attempts and mint a token bound to THIS exact
    // transfer (same amount, same accounts). Expires in 2 minutes so a
    // leaked token has a tiny window and can't sit around indefinitely.
    await supabase
      .from("users")
      .update({ pin_attempts: 0, last_pin_attempt: null })
      .eq("id", req.user.id);

    const token = crypto.randomBytes(32).toString("hex");
    const contextHash = hashTransferContext(
      from_account_id,
      to_account_number,
      amount,
    );

    const { error: insertError } = await supabase
      .from("transfer_authorizations")
      .insert({
        user_id: req.user.id,
        token,
        context_hash: contextHash,
        expires_at: new Date(Date.now() + 2 * 60 * 1000).toISOString(),
      });

    if (insertError) throw insertError;

    res.json({ valid: true, transfer_auth_token: token, expires_in: 120 });
  } catch (error) {
    console.error("Verify PIN error:", error);
    res.status(500).json({ error: "PIN verification failed" });
  }
});

// Freeze account due to PIN attempts
app.post(
  "/api/user/freeze-due-to-pin-attempts",
  authenticate,
  async (req, res) => {
    try {
      const { error } = await supabase
        .from("users")
        .update({
          is_frozen: true,
          freeze_reason: "Too many incorrect PIN attempts - Contact support",
          unfreeze_method: "support",
        })
        .eq("id", req.user.id);

      if (error) throw error;

      await bumpUserCacheVersion("authuser", req.user.id);

      res.json({ success: true });
    } catch (error) {
      console.error("Freeze error:", error);
      res.status(500).json({ error: "Failed to freeze account" });
    }
  },
);

// Export transactions as CSV
app.get("/api/user/transactions/export", authenticate, async (req, res) => {
  try {
    const { data: accounts } = await supabase
      .from("accounts")
      .select("id")
      .eq("user_id", req.user.id);

    const accountIds = accounts.map((a) => a.id);

    const { data: transactions } = await supabase
      .from("transactions_new")
      .select("*")
      .or(
        `sender_account_id.in.(${accountIds.join(",")}),receiver_account_id.in.(${accountIds.join(",")})`,
      )
      .order("created_at", { ascending: false });

    let csv = "Date,Description,Type,Amount (NGN),Status\n";

    transactions.forEach((t) => {
      const isCredit = t.receiver_user_id === req.user.id;
      const ngnAmount = t.amount * 1500; // Convert to NGN
      csv += `${t.created_at},${t.description || t.transaction_type},${isCredit ? "Credit" : "Debit"},${ngnAmount.toFixed(2)},${t.status}\n`;
    });

    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=transactions_${new Date().toISOString().split("T")[0]}.csv`,
    );
    res.send(csv);
  } catch (error) {
    console.error("Export error:", error);
    res.status(500).json({ error: "Export failed" });
  }
});

// ==================== ADMIN SAVINGS MANAGEMENT ====================

// Get all active savings plans (admin)
app.get(
  "/api/sys/savings/all",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { type, status, page = 1, limit = 50 } = req.query;
      const offset = (page - 1) * limit;

      let results = {};

      if (!type || type === "harvest") {
        let query = supabase.from("user_harvest_enrollments").select(`
                    *,
                    users!inner(id, email, first_name, last_name, phone),
                    harvest_plans!inner(name, daily_amount, duration_days)
                `);
        if (status) query = query.eq("status", status);
        const { data, count } = await query.range(offset, offset + limit - 1);
        results.harvest = { data: data || [], total: count || 0 };
      }

      if (!type || type === "fixed") {
        let query = supabase
          .from("fixed_savings")
          .select("*, users!inner(id, email, first_name, last_name, phone)");
        if (status) query = query.eq("status", status);
        const { data, count } = await query.range(offset, offset + limit - 1);
        results.fixed = { data: data || [], total: count || 0 };
      }

      if (!type || type === "savebox") {
        let query = supabase
          .from("savebox_savings")
          .select("*, users!inner(id, email, first_name, last_name, phone)");
        if (status) query = query.eq("status", status);
        const { data, count } = await query.range(offset, offset + limit - 1);
        results.savebox = { data: data || [], total: count || 0 };
      }

      if (!type || type === "target") {
        let query = supabase
          .from("target_savings")
          .select("*, users!inner(id, email, first_name, last_name, phone)");
        if (status) query = query.eq("status", status);
        const { data, count } = await query.range(offset, offset + limit - 1);
        results.target = { data: data || [], total: count || 0 };
      }

      if (!type || type === "spare_change") {
        let query = supabase
          .from("spare_change_savings")
          .select("*, users!inner(id, email, first_name, last_name, phone)");
        if (status) query = query.eq("status", status);
        const { data, count } = await query.range(offset, offset + limit - 1);
        results.spare_change = { data: data || [], total: count || 0 };
      }

      res.json({
        success: true,
        data: results,
        pagination: { page, limit },
      });
    } catch (error) {
      console.error("Admin savings fetch error:", error);
      res.status(500).json({ error: "Failed to fetch savings data" });
    }
  },
);

// Send notification to all users with active savings (admin)
app.post(
  "/api/sys/savings/notify",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { savings_type, message, subject } = req.body;

    try {
      let users = [];

      if (!savings_type || savings_type === "harvest") {
        const { data } = await supabase
          .from("user_harvest_enrollments")
          .select("user_id, users(email, first_name, last_name)")
          .eq("status", "active");
        users.push(...(data || []));
      }

      if (!savings_type || savings_type === "fixed") {
        const { data } = await supabase
          .from("fixed_savings")
          .select("user_id, users(email, first_name, last_name)")
          .in("status", ["active", "matured"]);
        users.push(...(data || []));
      }

      if (!savings_type || savings_type === "savebox") {
        const { data } = await supabase
          .from("savebox_savings")
          .select("user_id, users(email, first_name, last_name)")
          .eq("status", "active");
        users.push(...(data || []));
      }

      if (!savings_type || savings_type === "target") {
        const { data } = await supabase
          .from("target_savings")
          .select("user_id, users(email, first_name, last_name)")
          .eq("status", "active");
        users.push(...(data || []));
      }

      // Remove duplicates
      const uniqueUsers = [
        ...new Map(users.map((u) => [u.user_id, u])).values(),
      ];

      // Send notifications
      for (const user of uniqueUsers) {
        await supabase.from("notifications").insert({
          user_id: user.user_id,
          title: subject || "Savings Plan Update",
          message: message,
          type: "info",
        });

        // Send email
        if (user.users?.email) {
          await transporter.sendMail({
            from: process.env.SMTP_FROM,
            to: user.users.email,
            subject: subject || "Savings Plan Update",
            html: `<h2>Savings Plan Update</h2><p>Dear ${user.users.first_name},</p><p>${message}</p><p>Thank you for banking with us.</p>`,
          });
        }
      }

      res.json({
        success: true,
        message: `Notification sent to ${uniqueUsers.length} users`,
      });
    } catch (error) {
      console.error("Admin notify error:", error);
      res.status(500).json({ error: "Failed to send notifications" });
    }
  },
);

// Get savings statistics (admin)
app.get(
  "/api/sys/savings/stats",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const [harvestStats, fixedStats, saveboxStats, targetStats, spareStats] =
        await Promise.all([
          supabase
            .from("user_harvest_enrollments")
            .select("total_saved, days_completed, status", { count: "exact" }),
          supabase
            .from("fixed_savings")
            .select("current_saved, status", { count: "exact" }),
          supabase
            .from("savebox_savings")
            .select("current_saved, status", { count: "exact" }),
          supabase
            .from("target_savings")
            .select("current_saved, target_amount, status", { count: "exact" }),
          supabase
            .from("spare_change_savings")
            .select("current_saved, total_saved, status", { count: "exact" }),
        ]);

      const totalSaved =
        (harvestStats.data?.reduce((s, h) => s + (h.total_saved || 0), 0) ||
          0) +
        (fixedStats.data?.reduce((s, f) => s + (f.current_saved || 0), 0) ||
          0) +
        (saveboxStats.data?.reduce((s, sb) => s + (sb.current_saved || 0), 0) ||
          0) +
        (targetStats.data?.reduce((s, t) => s + (t.current_saved || 0), 0) ||
          0) +
        (spareStats.data?.reduce((s, sp) => s + (sp.current_saved || 0), 0) ||
          0);

      res.json({
        total_saved: totalSaved,
        counts: {
          harvest: {
            active:
              harvestStats.data?.filter((h) => h.status === "active").length ||
              0,
            total: harvestStats.count || 0,
          },
          fixed: {
            active:
              fixedStats.data?.filter((f) => f.status === "active").length || 0,
            total: fixedStats.count || 0,
          },
          savebox: {
            active:
              saveboxStats.data?.filter((s) => s.status === "active").length ||
              0,
            total: saveboxStats.count || 0,
          },
          target: {
            active:
              targetStats.data?.filter((t) => t.status === "active").length ||
              0,
            total: targetStats.count || 0,
          },
          spare_change: {
            active:
              spareStats.data?.filter((s) => s.status === "active").length || 0,
            total: spareStats.count || 0,
          },
        },
      });
    } catch (error) {
      console.error("Savings stats error:", error);
      res.status(500).json({ error: "Failed to fetch savings stats" });
    }
  },
);

// ==================== ADMIN STAFF ID MANAGEMENT ====================

// Generate staff ID for admin (super admin only)
app.post(
  "/api/sys/generate-staff-id/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Only super admin can generate staff IDs
      if (req.user.role !== "super_admin") {
        return res
          .status(403)
          .json({ error: "Only super admin can generate staff IDs" });
      }

      // Get user to verify they are admin
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("role, admin_staff_id")
        .eq("id", userId)
        .single();

      if (userError) throw userError;

      if (user.role !== "admin") {
        return res
          .status(400)
          .json({ error: "User must be an admin to generate staff ID" });
      }

      // Generate unique staff ID: FEE + 10 alphanumeric characters
      const generateStaffId = () => {
        const prefix = "FEE";
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let result = prefix;
        for (let i = 0; i < 10; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
      };

      let staffId = generateStaffId();
      let isUnique = false;
      let attempts = 0;

      // Ensure uniqueness
      while (!isUnique && attempts < 5) {
        const { data: existing } = await supabase
          .from("users")
          .select("id")
          .eq("admin_staff_id", staffId)
          .single();

        if (!existing) {
          isUnique = true;
        } else {
          staffId = generateStaffId();
        }
        attempts++;
      }

      // Update user with new staff ID
      const { error: updateError } = await supabase
        .from("users")
        .update({
          admin_staff_id: staffId,
          admin_staff_id_set_at: new Date().toISOString(),
          admin_staff_id_verified: false,
          updated_at: new Date().toISOString(),
        })
        .eq("id", userId);

      if (updateError) throw updateError;

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "generate_staff_id",
        target_user_id: userId,
        details: { staff_id: staffId },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        staff_id: staffId,
        message: "Staff ID generated successfully",
      });
    } catch (error) {
      console.error("Generate staff ID error:", error);
      res.status(500).json({ error: "Failed to generate staff ID" });
    }
  },
);

// Clear/Regenerate staff ID for admin (super admin only)
app.post(
  "/api/sys/regenerate-staff-id/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      if (req.user.role !== "super_admin") {
        return res
          .status(403)
          .json({ error: "Only super admin can regenerate staff IDs" });
      }

      // Get user
      const { data: user, error: userError } = await supabase
        .from("users")
        .select("role")
        .eq("id", userId)
        .single();

      if (userError) throw userError;

      if (user.role !== "admin") {
        return res.status(400).json({ error: "User must be an admin" });
      }

      // Generate new staff ID
      const generateStaffId = () => {
        const prefix = "FEE";
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let result = prefix;
        for (let i = 0; i < 10; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
      };

      let staffId = generateStaffId();
      let isUnique = false;
      let attempts = 0;

      while (!isUnique && attempts < 5) {
        const { data: existing } = await supabase
          .from("users")
          .select("id")
          .eq("admin_staff_id", staffId)
          .single();

        if (!existing) {
          isUnique = true;
        } else {
          staffId = generateStaffId();
        }
        attempts++;
      }

      // Update with new staff ID
      const { error: updateError } = await supabase
        .from("users")
        .update({
          admin_staff_id: staffId,
          admin_staff_id_set_at: new Date().toISOString(),
          admin_staff_id_verified: false,
          updated_at: new Date().toISOString(),
        })
        .eq("id", userId);

      if (updateError) throw updateError;

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "regenerate_staff_id",
        target_user_id: userId,
        details: { old_staff_id: user.admin_staff_id, new_staff_id: staffId },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        staff_id: staffId,
        message: "Staff ID regenerated successfully",
      });
    } catch (error) {
      console.error("Regenerate staff ID error:", error);
      res.status(500).json({ error: "Failed to regenerate staff ID" });
    }
  },
);

// Verify staff ID during admin login
app.post("/api/auth/verify-staff-id", async (req, res) => {
  try {
    const { userId, staff_id } = req.body;

    if (!userId || !staff_id) {
      return res.status(400).json({ error: "User ID and Staff ID required" });
    }

    // Get user
    const { data: user, error: userError } = await supabase
      .from("users")
      .select(
        "id, role, admin_staff_id, admin_staff_id_verified, email, first_name, last_name",
      )
      .eq("id", userId)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Super admin doesn't need staff ID
    if (user.role === "super_admin") {
      return res.json({
        valid: true,
        message: "Super admin verified",
      });
    }

    // Check if user is admin
    if (user.role !== "admin") {
      return res.status(403).json({ error: "Not an admin account" });
    }

    // Verify staff ID
    if (!user.admin_staff_id) {
      return res.status(401).json({
        valid: false,
        error: "No staff ID assigned. Please contact super admin.",
        needs_setup: true,
      });
    }

    if (user.admin_staff_id !== staff_id) {
      // Log failed attempt
      await supabase.from("security_logs").insert({
        user_id: userId,
        event_type: "failed_staff_id_verification",
        details: { ip: req.ip, user_agent: req.headers["user-agent"] },
        ip_address: req.ip,
        timestamp: new Date().toISOString(),
      });

      return res.status(401).json({
        valid: false,
        error: "Invalid staff ID",
        attempts_remaining: 3,
      });
    }

    // Mark as verified for this session
    await supabase
      .from("users")
      .update({ admin_staff_id_verified: true })
      .eq("id", userId);

    // Log successful verification
    await supabase.from("security_logs").insert({
      user_id: userId,
      event_type: "staff_id_verified",
      details: { ip: req.ip },
      ip_address: req.ip,
      timestamp: new Date().toISOString(),
    });

    res.json({
      valid: true,
      message: "Staff ID verified successfully",
    });
  } catch (error) {
    console.error("Staff ID verification error:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// Get admin's staff ID status (for display in modal)
app.get(
  "/api/sys/admin-staff-id/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      const { data: user, error } = await supabase
        .from("users")
        .select("admin_staff_id, admin_staff_id_set_at, role")
        .eq("id", userId)
        .single();

      if (error) throw error;

      res.json({
        has_staff_id: !!user.admin_staff_id,
        staff_id: user.admin_staff_id,
        set_at: user.admin_staff_id_set_at,
        role: user.role,
      });
    } catch (error) {
      console.error("Get staff ID error:", error);
      res.status(500).json({ error: "Failed to get staff ID status" });
    }
  },
);

// ==================== ADMIN HARVEST ENROLLMENTS ROUTES ====================

// Get all harvest enrollments (admin)
app.get(
  "/api/sys/harvest-enrollments",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 20,
        search,
        status,
        auto_save,
        plan_id,
      } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase.from("user_harvest_enrollments").select(
        `
                *,
                users!inner(id, first_name, last_name, email, phone),
                harvest_plans!inner(id, name, daily_amount, duration_days, reward_items)
            `,
        { count: "exact" },
      );

      if (search) {
        query = query.or(
          `users.first_name.ilike.%${search}%,users.last_name.ilike.%${search}%,users.email.ilike.%${search}%`,
        );
      }
      if (status && status !== "all") {
        query = query.eq("status", status);
      }
      if (auto_save && auto_save !== "all") {
        query = query.eq("auto_save", auto_save === "true");
      }
      if (plan_id && plan_id !== "all") {
        query = query.eq("plan_id", plan_id);
      }

      const {
        data: enrollments,
        error,
        count,
      } = await query
        .order("created_at", { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) throw error;

      // Calculate stats
      const { data: allEnrollments } = await supabase
        .from("user_harvest_enrollments")
        .select(
          "total_saved, days_completed, auto_save, harvest_plans(duration_days)",
        )
        .eq("status", "active");

      const totalSaved =
        allEnrollments?.reduce((sum, e) => sum + (e.total_saved || 0), 0) || 0;
      const totalDaysCompleted =
        allEnrollments?.reduce((sum, e) => sum + (e.days_completed || 0), 0) ||
        0;
      const totalPossibleDays =
        allEnrollments?.reduce(
          (sum, e) => sum + (e.harvest_plans?.duration_days || 0),
          0,
        ) || 0;
      const avgCompletion =
        totalPossibleDays > 0
          ? Math.round((totalDaysCompleted / totalPossibleDays) * 100)
          : 0;
      const autoSaveOn =
        allEnrollments?.filter((e) => e.auto_save === true).length || 0;

      res.json({
        enrollments: enrollments || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
        stats: {
          total_enrolled: count || 0,
          total_saved: totalSaved,
          avg_completion: avgCompletion,
          auto_save_on: autoSaveOn,
        },
      });
    } catch (error) {
      console.error("Admin harvest enrollments error:", error);
      res.status(500).json({ error: "Failed to fetch enrollments" });
    }
  },
);

// Get single enrollment details
app.get(
  "/api/sys/harvest-enrollments/:id",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data: enrollment, error } = await supabase
        .from("user_harvest_enrollments")
        .select(
          `
                *,
                users!inner(id, first_name, last_name, email, phone),
                harvest_plans!inner(id, name, daily_amount, duration_days, reward_items)
            `,
        )
        .eq("id", id)
        .single();

      if (error) throw error;

      res.json(enrollment);
    } catch (error) {
      console.error("Error fetching enrollment:", error);
      res.status(500).json({ error: "Failed to fetch enrollment details" });
    }
  },
);

// Toggle user auto-save
app.put(
  "/api/sys/harvest-enrollments/:id/toggle-auto",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { auto_save } = req.body;

      const { error } = await supabase
        .from("user_harvest_enrollments")
        .update({ auto_save: auto_save, updated_at: new Date() })
        .eq("id", id);

      if (error) throw error;

      res.json({
        success: true,
        message: `Auto-save ${auto_save ? "enabled" : "disabled"}`,
      });
    } catch (error) {
      console.error("Toggle auto-save error:", error);
      res.status(500).json({ error: "Failed to toggle auto-save" });
    }
  },
);

// Send bulk notification to harvest users
app.post(
  "/api/sys/harvest/send-notification",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        user_filter,
        user_ids,
        subject,
        message,
        send_email,
        notification_type,
      } = req.body;

      let targetUsers = [];

      if (user_filter === "specific" && user_ids && user_ids.length > 0) {
        const { data: users } = await supabase
          .from("users")
          .select("id, email, first_name, last_name")
          .in("id", user_ids);
        targetUsers = users || [];
      } else {
        let query = supabase
          .from("user_harvest_enrollments")
          .select(
            "user_id, users!inner(id, email, first_name, last_name), harvest_plans!inner(name), days_completed, total_saved",
          );

        if (user_filter === "behind") {
          // Users with less than 50% completion relative to expected progress
          query = query.lt(
            "days_completed",
            supabase.raw("harvest_plans.duration_days * 0.5"),
          );
        } else if (user_filter === "auto_off") {
          query = query.eq("auto_save", false);
        }

        const { data: enrollments } = await query;
        targetUsers = [
          ...new Map(
            enrollments?.map((e) => [e.user_id, e.users]).filter(Boolean),
          ),
        ].map(([_, user]) => user);
      }

      let sentCount = 0;

      for (const user of targetUsers) {
        // Create in-app notification
        await supabase.from("notifications").insert({
          user_id: user.id,
          title: subject,
          message: message,
          type: notification_type || "info",
          created_at: new Date(),
        });

        if (send_email && user.email) {
          try {
            await transporter.sendMail({
              from: process.env.SMTP_FROM,
              to: user.email,
              subject: subject,
              html: `<h2>${subject}</h2><p>Dear ${user.first_name || "User"},</p><p>${message.replace(/\n/g, "<br>")}</p><p>Thank you for banking with us.</p>`,
            });
          } catch (emailErr) {
            console.error("Email error for", user.email, emailErr);
          }
        }

        sentCount++;
      }

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "harvest_bulk_notification",
        details: {
          user_filter,
          sent_count: sentCount,
          subject,
          notification_type,
        },
      });

      res.json({
        success: true,
        message: `Notification sent to ${sentCount} users`,
      });
    } catch (error) {
      console.error("Send notification error:", error);
      res.status(500).json({ error: "Failed to send notifications" });
    }
  },
);

// ADMIN: Get harvest plan withdrawal requests
app.get(
  "/api/sys/harvest-withdrawal-requests",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      console.log("Fetching harvest withdrawal requests...");

      const { data: requests, error } = await supabase
        .from("harvest_withdrawal_requests")
        .select(
          `
          *,
          users:user_id (
            id, 
            email, 
            first_name, 
            last_name, 
            phone
          ),
          user_harvest_enrollments:enrollment_id (
            id, 
            total_saved, 
            days_completed,
            harvest_plans:plan_id (
              name, 
              daily_amount, 
              duration_days,
              reward_items
            )
          )
        `,
        )
        .order("created_at", { ascending: false });

      if (error) {
        console.error("Supabase error fetching withdrawal requests:", error);
        return res.status(500).json({ error: error.message });
      }

      console.log(`Found ${requests?.length || 0} withdrawal requests`);
      res.json({ requests: requests || [] });
    } catch (error) {
      console.error("Error fetching withdrawal requests:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// USER: Request harvest plan withdrawal (requires admin approval)
app.post(
  "/api/user/savings/harvest/:id/request-withdrawal",
  authenticate,
  async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;

    try {
      console.log(
        `User ${req.user.id} requesting withdrawal for harvest plan ${id}`,
      );

      // Get harvest enrollment
      const { data: enrollment, error: hError } = await supabase
        .from("user_harvest_enrollments")
        .select(
          `
          *,
          harvest_plans!inner(name, daily_amount, duration_days)
        `,
        )
        .eq("id", id)
        .eq("user_id", req.user.id)
        .single();

      if (hError || !enrollment) {
        console.error("Enrollment not found:", hError);
        return res.status(404).json({ error: "Harvest plan not found" });
      }

      // Check if already completed or cancelled
      if (enrollment.status !== "active") {
        return res
          .status(400)
          .json({ error: "Cannot request withdrawal for this plan" });
      }

      // Check if withdrawal request already exists
      const { data: existing, error: existError } = await supabase
        .from("harvest_withdrawal_requests")
        .select("id, status")
        .eq("enrollment_id", id)
        .in("status", ["pending", "approved"])
        .maybeSingle();

      if (existing) {
        if (existing.status === "pending") {
          return res
            .status(400)
            .json({ error: "Withdrawal request already pending" });
        }
        if (existing.status === "approved") {
          return res
            .status(400)
            .json({ error: "Withdrawal already processed for this plan" });
        }
      }

      // Create withdrawal request
      const { data: request, error } = await supabase
        .from("harvest_withdrawal_requests")
        .insert({
          user_id: req.user.id,
          enrollment_id: id,
          amount: enrollment.total_saved || 0,
          reason: reason || "No reason provided",
          status: "pending",
          created_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (error) {
        console.error("Error creating withdrawal request:", error);
        return res
          .status(500)
          .json({ error: "Failed to create withdrawal request" });
      }

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: req.user.id,
        title: "Withdrawal Request Submitted",
        message: `Your Harvest Plan withdrawal request for ₦${(enrollment.total_saved || 0).toLocaleString()} has been submitted for admin approval.`,
        type: "info",
        created_at: new Date().toISOString(),
      });

      console.log(`Withdrawal request created: ${request.id}`);
      res.json({
        success: true,
        message:
          "Withdrawal request submitted. Admin will review your request.",
        request,
      });
    } catch (error) {
      console.error("Withdrawal request error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ADMIN: Approve harvest withdrawal
/*app.post(
  "/api/sys/harvest-withdrawal/:requestId/approve",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { requestId } = req.params;

    try {
      console.log(
        `Admin ${req.user.id} approving withdrawal request ${requestId}`,
      );

      // Get the request with all related data
      const { data: request, error: fetchError } = await supabase
        .from("harvest_withdrawal_requests")
        .select(
          `
          *,
          users:user_id (
            id, 
            email, 
            first_name, 
            last_name
          ),
          user_harvest_enrollments:enrollment_id (
            id, 
            total_saved,
            user_id,
            plan_id,
            status
          )
        `,
        )
        .eq("id", requestId)
        .single();

      if (fetchError || !request) {
        console.error("Request not found:", fetchError);
        return res.status(404).json({ error: "Request not found" });
      }

      if (request.status !== "pending") {
        return res.status(400).json({ error: "Request already processed" });
      }

      // Get user's primary account
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", request.user_id)
        .eq("account_type", "checking")
        .single();

      if (accError || !account) {
        console.error("User account not found:", accError);
        return res.status(404).json({ error: "User account not found" });
      }

      // Refund the amount to user's account
      const newBalance = (account.balance || 0) + (request.amount || 0);
      const newAvailable =
        (account.available_balance || 0) + (request.amount || 0);

      const { error: updateBalanceError } = await supabase
        .from("accounts")
        .update({
          balance: newBalance,
          available_balance: newAvailable,
          updated_at: new Date().toISOString(),
        })
        .eq("id", account.id);

      if (updateBalanceError) {
        console.error("Balance update error:", updateBalanceError);
        return res.status(500).json({ error: "Failed to update balance" });
      }

      // Update harvest enrollment status to "withdrawn"
      const { error: updateEnrollmentError } = await supabase
        .from("user_harvest_enrollments")
        .update({
          status: "withdrawn",
          auto_save: false,
          updated_at: new Date().toISOString(),
        })
        .eq("id", request.enrollment_id);

      if (updateEnrollmentError) {
        console.error("Enrollment update error:", updateEnrollmentError);
      }

      // Update request status
      const { error: updateRequestError } = await supabase
        .from("harvest_withdrawal_requests")
        .update({
          status: "approved",
          processed_at: new Date().toISOString(),
          processed_by: req.user.id,
          admin_note: `Approved by ${req.user.email}`,
        })
        .eq("id", requestId);

      if (updateRequestError) {
        console.error("Request update error:", updateRequestError);
        return res
          .status(500)
          .json({ error: "Failed to update request status" });
      }

      // Create refund transaction
      const { error: transError } = await supabase.from("transactions_new").insert({
        to_account_id: account.id,
        to_user_id: request.user_id,
        amount: request.amount,
        description: "Harvest Plan Withdrawal (Admin Approved)",
        transaction_type: "savings_withdrawal",
        status: "completed",
        completed_at: new Date().toISOString(),
        is_admin_adjusted: true,
        admin_note: `Harvest withdrawal approved by ${req.user.email}`,
      });

      if (transError) {
        console.error("Transaction creation error:", transError);
      }

      // Send notification to user
      await supabase.from("notifications").insert({
        user_id: request.user_id,
        title: "Withdrawal Request Approved ✅",
        message: `Your Harvest Plan withdrawal of ₦${(request.amount || 0).toLocaleString()} has been approved. Funds have been returned to your account.`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "approve_harvest_withdrawal",
        target_user_id: request.user_id,
        details: { request_id: requestId, amount: request.amount },
        created_at: new Date().toISOString(),
      });

      console.log(`Withdrawal ${requestId} approved successfully`);
      res.json({
        success: true,
        message: "Withdrawal approved and funds returned",
      });
    } catch (error) {
      console.error("Approve withdrawal error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);*/

// index.js - Update the harvest withdrawal approval endpoint
app.post(
  "/api/sys/harvest-withdrawal/:requestId/approve",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { requestId } = req.params;

    try {
      console.log(
        `Admin ${req.user.id} approving withdrawal request ${requestId}`,
      );

      // Get the request with all related data
      const { data: request, error: fetchError } = await supabase
        .from("harvest_withdrawal_requests")
        .select(
          `
          *,
          users:user_id (
            id, 
            email, 
            first_name, 
            last_name
          ),
          user_harvest_enrollments:enrollment_id (
            id, 
            total_saved,
            user_id,
            plan_id,
            status
          )
        `,
        )
        .eq("id", requestId)
        .single();

      if (fetchError || !request) {
        console.error("Request not found:", fetchError);
        return res.status(404).json({ error: "Request not found" });
      }

      if (request.status !== "pending") {
        return res.status(400).json({ error: "Request already processed" });
      }

      // Get user's primary account
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", request.user_id)
        .eq("account_type", "checking")
        .single();

      if (accError || !account) {
        console.error("User account not found:", accError);
        return res.status(404).json({ error: "User account not found" });
      }

      // ========== REFUND THE AMOUNT TO USER'S ACCOUNT ==========
      const refundAmount = request.amount || 0;
      const newBalance = (account.balance || 0) + refundAmount;
      const newAvailable = (account.available_balance || 0) + refundAmount;

      const { error: updateBalanceError } = await supabase
        .from("accounts")
        .update({
          balance: newBalance,
          available_balance: newAvailable,
          updated_at: new Date().toISOString(),
        })
        .eq("id", account.id);

      if (updateBalanceError) {
        console.error("Balance update error:", updateBalanceError);
        return res.status(500).json({ error: "Failed to update balance" });
      }

      console.log(
        `✅ Refunded ₦${refundAmount} to user ${request.user_id}. New balance: ₦${newAvailable}`,
      );

      // ========== DEDUCT FROM HARVEST POOL ACCOUNT ==========
      const { data: harvestPool } = await supabase
        .from("savings_pool_accounts")
        .select("*")
        .eq("account_type", "harvest_pool")
        .single();

      if (harvestPool) {
        const newPoolBalance = harvestPool.balance - refundAmount;
        await supabase
          .from("savings_pool_accounts")
          .update({
            balance: newPoolBalance,
            available_balance: newPoolBalance,
            updated_at: new Date().toISOString(),
          })
          .eq("id", harvestPool.id);

        console.log(
          `✅ Deducted ₦${refundAmount} from harvest_pool. New balance: ₦${newPoolBalance}`,
        );
      }

      // Update harvest enrollment status to "withdrawn"
      const { error: updateEnrollmentError } = await supabase
        .from("user_harvest_enrollments")
        .update({
          status: "withdrawn",
          auto_save: false,
          updated_at: new Date().toISOString(),
        })
        .eq("id", request.enrollment_id);

      if (updateEnrollmentError) {
        console.error("Enrollment update error:", updateEnrollmentError);
      }

      // Update request status
      const { error: updateRequestError } = await supabase
        .from("harvest_withdrawal_requests")
        .update({
          status: "approved",
          processed_at: new Date().toISOString(),
          processed_by: req.user.id,
          admin_note: `Approved by ${req.user.email}`,
        })
        .eq("id", requestId);

      if (updateRequestError) {
        console.error("Request update error:", updateRequestError);
        return res
          .status(500)
          .json({ error: "Failed to update request status" });
      }

      // Create refund transaction
      const { error: transError } = await supabase
        .from("transactions_new")
        .insert({
          receiver_account_id: account.id,
          receiver_user_id: request.user_id,
          amount: refundAmount,
          description: `Harvest Plan Withdrawal (Admin Approved) - Request ID: ${requestId}`,
          transaction_type: "savings_withdrawal",
          status: "completed",
          completed_at: new Date().toISOString(),
          metadata: {
            is_admin_adjusted: true,
            admin_note: `Harvest withdrawal approved by ${req.user.email}`,
          },
        });

      if (transError) {
        console.error("Transaction creation error:", transError);
      }

      // Create savings transaction record
      await supabase.from("savings_transactions").insert({
        user_id: request.user_id,
        savings_type: "harvest",
        savings_id: request.enrollment_id,
        amount: refundAmount,
        transaction_type: "withdrawal",
        description: `Withdrawn from Harvest Plan via admin approval`,
        processed_by: req.user.id,
        processed_at: new Date().toISOString(),
      });

      // Send notification to user
      await supabase.from("notifications").insert({
        user_id: request.user_id,
        title: "Harvest Plan Withdrawal Approved ✅",
        message: `Your Harvest Plan withdrawal request has been approved. ₦${refundAmount.toLocaleString()} has been returned to your account.`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "approve_harvest_withdrawal",
        target_user_id: request.user_id,
        details: { request_id: requestId, amount: refundAmount },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      console.log(`Withdrawal ${requestId} approved successfully`);
      res.json({
        success: true,
        message: "Withdrawal approved and funds returned",
        amount_refunded: refundAmount,
      });
    } catch (error) {
      console.error("Approve withdrawal error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ADMIN: Reject harvest withdrawal
app.post(
  "/api/sys/harvest-withdrawal/:requestId/reject",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { requestId } = req.params;
    const { reason } = req.body;

    try {
      console.log(
        `Admin ${req.user.id} rejecting withdrawal request ${requestId}`,
      );

      const { data: request, error: fetchError } = await supabase
        .from("harvest_withdrawal_requests")
        .select(
          `
          *,
          users:user_id (
            id, 
            email, 
            first_name, 
            last_name
          )
        `,
        )
        .eq("id", requestId)
        .single();

      if (fetchError || !request) {
        console.error("Request not found:", fetchError);
        return res.status(404).json({ error: "Request not found" });
      }

      if (request.status !== "pending") {
        return res.status(400).json({ error: "Request already processed" });
      }

      // Update request status
      const { error: updateError } = await supabase
        .from("harvest_withdrawal_requests")
        .update({
          status: "rejected",
          processed_at: new Date().toISOString(),
          processed_by: req.user.id,
          admin_note: reason || `Rejected by ${req.user.email}`,
        })
        .eq("id", requestId);

      if (updateError) {
        console.error("Request update error:", updateError);
        return res.status(500).json({ error: "Failed to update request" });
      }

      // Send notification to user
      await supabase.from("notifications").insert({
        user_id: request.user_id,
        title: "Withdrawal Request Rejected ❌",
        message: `Your Harvest Plan withdrawal request was rejected. Reason: ${reason || "Not specified"}. Please continue your savings plan.`,
        type: "error",
        created_at: new Date().toISOString(),
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "reject_harvest_withdrawal",
        target_user_id: request.user_id,
        details: { request_id: requestId, reason: reason },
        created_at: new Date().toISOString(),
      });

      console.log(`Withdrawal ${requestId} rejected`);
      res.json({ success: true, message: "Withdrawal request rejected" });
    } catch (error) {
      console.error("Reject withdrawal error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// ==================== USER ACCOUNT CLOSURE ROUTES ====================

// Check if user is eligible to close account
app.get("/api/user/check-close-eligibility", authenticate, async (req, res) => {
  try {
    // Get user balance
    const { data: accounts, error: accError } = await supabase
      .from("accounts")
      .select("balance")
      .eq("user_id", req.user.id);

    const totalBalance =
      accounts?.reduce((sum, acc) => sum + (acc.balance || 0), 0) || 0;

    // Check for active savings plans
    const [harvest, fixed, savebox, target, spare] = await Promise.all([
      supabase
        .from("user_harvest_enrollments")
        .select("id, status")
        .eq("user_id", req.user.id)
        .eq("status", "active"),
      supabase
        .from("fixed_savings")
        .select("id, status")
        .eq("user_id", req.user.id)
        .in("status", ["active", "matured"]),
      supabase
        .from("savebox_savings")
        .select("id, status")
        .eq("user_id", req.user.id)
        .eq("status", "active"),
      supabase
        .from("target_savings")
        .select("id, status")
        .eq("user_id", req.user.id)
        .eq("status", "active"),
      supabase
        .from("spare_change_savings")
        .select("id, status")
        .eq("user_id", req.user.id)
        .eq("status", "active"),
    ]);

    const activePlans = [];
    const activePlansList = [];

    if (harvest.data?.length > 0) {
      activePlans.push(...harvest.data);
      activePlansList.push("Harvest Plan");
    }
    if (fixed.data?.length > 0) {
      activePlans.push(...fixed.data);
      activePlansList.push("Fixed Savings");
    }
    if (savebox.data?.length > 0) {
      activePlans.push(...savebox.data);
      activePlansList.push("SaveBox");
    }
    if (target.data?.length > 0) {
      activePlans.push(...target.data);
      activePlansList.push("Target Savings");
    }
    if (spare.data?.length > 0) {
      activePlans.push(...spare.data);
      activePlansList.push("Spare Change");
    }

    // Check last transaction date
    const { data: lastTransaction, error: txError } = await supabase
      .from("transactions_new")
      .select("created_at")
      .or(`from_user_id.eq.${req.user.id},to_user_id.eq.${req.user.id}`)
      .order("created_at", { ascending: false })
      .limit(1);

    let daysSinceLastTx = 999;
    if (lastTransaction && lastTransaction.length > 0) {
      const lastTxDate = new Date(lastTransaction[0].created_at);
      const today = new Date();
      daysSinceLastTx = Math.floor(
        (today - lastTxDate) / (1000 * 60 * 60 * 24),
      );
    }

    const isEligible =
      totalBalance === 0 && activePlans.length === 0 && daysSinceLastTx >= 7;

    res.json({
      eligible: isEligible,
      balance: totalBalance,
      has_active_savings: activePlans.length > 0,
      recent_transaction_days: daysSinceLastTx >= 7 ? 0 : daysSinceLastTx,
      active_plans_list: activePlansList,
    });
  } catch (error) {
    console.error("Close eligibility error:", error);
    res.status(500).json({ error: "Failed to check eligibility" });
  }
});

// Close user account
app.post("/api/user/close-account", authenticate, async (req, res) => {
  try {
    const { reason } = req.body;

    // Verify eligibility again
    const { data: accounts } = await supabase
      .from("accounts")
      .select("balance")
      .eq("user_id", req.user.id);

    const totalBalance =
      accounts?.reduce((sum, acc) => sum + (acc.balance || 0), 0) || 0;

    if (totalBalance > 0) {
      return res.status(400).json({
        error: "Please withdraw all funds before closing your account",
      });
    }

    // Log closed account
    const { error: logError } = await supabase.from("closed_accounts").insert({
      user_id: req.user.id,
      user_email: req.user.email,
      user_name: `${req.user.first_name} ${req.user.last_name}`,
      reason: reason,
      closed_at: new Date(),
      balance_at_close: totalBalance,
    });

    if (logError) console.error("Failed to log closed account:", logError);

    // Delete user data (soft delete - deactivate)
    await supabase
      .from("users")
      .update({
        is_active: false,
        is_frozen: true,
        freeze_reason: "Account closed by user",
        deleted_at: new Date(),
      })
      .eq("id", req.user.id);

    await bumpUserCacheVersion("authuser", req.user.id);

    // Clear sensitive data
    await supabase
      .from("users")
      .update({
        password_hash: null,
        transfer_pin: null,
        face_image: null,
      })
      .eq("id", req.user.id);

    res.json({ success: true, message: "Account closed successfully" });
  } catch (error) {
    console.error("Close account error:", error);
    res.status(500).json({ error: "Failed to close account" });
  }
});

// Lock user account (self-lock)
app.post("/api/user/lock-account", authenticate, async (req, res) => {
  try {
    const { reason, unfreeze_method } = req.body;

    await supabase
      .from("users")
      .update({
        is_frozen: true,
        freeze_reason: `User self-locked: ${reason}`,
        unfreeze_method: unfreeze_method || "support",
        updated_at: new Date(),
      })
      .eq("id", req.user.id);

    await bumpUserCacheVersion("authuser", req.user.id);

    res.json({ success: true, message: "Account frozen successfully" });
  } catch (error) {
    console.error("Lock account error:", error);
    res.status(500).json({ error: "Failed to freeze account" });
  }
});

// ADMIN: Get all closed accounts
app.get(
  "/api/sys/closed-accounts",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { data: closedAccounts, error } = await supabase
        .from("closed_accounts")
        .select("*")
        .order("closed_at", { ascending: false });

      if (error) throw error;
      res.json({ closed_accounts: closedAccounts || [] });
    } catch (error) {
      console.error("Fetch closed accounts error:", error);
      res.status(500).json({ error: "Failed to fetch closed accounts" });
    }
  },
);

// ADMIN: Delete closed account record
app.delete(
  "/api/sys/closed-accounts/:id",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { error } = await supabase
        .from("closed_accounts")
        .delete()
        .eq("id", id);

      if (error) throw error;
      res.json({ success: true });
    } catch (error) {
      console.error("Delete closed account error:", error);
      res.status(500).json({ error: "Failed to delete record" });
    }
  },
);

// ADMIN: Delete all closed accounts
app.delete(
  "/api/sys/closed-accounts/all",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { error } = await supabase
        .from("closed_accounts")
        .delete()
        .neq("id", "00000000-0000-0000-0000-000000000000");

      if (error) throw error;
      res.json({
        success: true,
        message: "All closed account records deleted",
      });
    } catch (error) {
      console.error("Delete all closed accounts error:", error);
      res.status(500).json({ error: "Failed to delete records" });
    }
  },
);

// ==================== ADMIN ROUTES ================

// Get all external transfers (admin)
/*app.get(
  "/api/sys/external-transfers",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { page = 1, limit = 20, status, bank } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase
        .from("external_transfers")
        .select(
          `
                *,
                users!external_transfers_user_id_fkey (
                    id,
                    first_name,
                    last_name,
                    email,
                    phone
                ),
                accounts!external_transfers_from_account_id_fkey (
                    id,
                    account_number
                )
            `,
          { count: "exact" },
        )
        .order("created_at", { ascending: false });

      if (status && status !== "all") {
        query = query.eq("status", status);
      }

      if (bank && bank !== "all") {
        query = query.eq("bank_name", bank);
      }

      const {
        data: transfers,
        error,
        count,
      } = await query.range(offset, offset + limit - 1);

      if (error) throw error;

      // Get pending count for badge
      const { count: pendingCount } = await supabase
        .from("external_transfers")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending");

      res.json({
        transfers: transfers || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
        pendingCount: pendingCount || 0,
      });
    } catch (error) {
      console.error("Admin external transfers error:", error);
      res.status(500).json({ error: "Failed to fetch external transfers" });
    }
  },
);

// Approve external transfer (admin)
app.post(
  "/api/sys/external-transfers/:id/approve",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // Get the transfer
      const { data: transfer, error: fetchError } = await supabase
        .from("external_transfers")
        .select("*")
        .eq("id", id)
        .single();

      if (fetchError || !transfer) {
        return res.status(404).json({ error: "Transfer not found" });
      }

      if (transfer.status !== "pending") {
        return res.status(400).json({ error: "Transfer already processed" });
      }

      // Update transfer status to completed
      const { error: updateError } = await supabase
        .from("external_transfers")
        .update({
          status: "completed",
          processed_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          processed_by: req.user.id,
          admin_note: `Approved by ${req.user.email}`,
        })
        .eq("id", id);

      if (updateError) throw updateError;

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: transfer.user_id,
        title: "External Transfer Approved ✅",
        message: `Your transfer of $${transfer.amount} to ${transfer.bank_name} has been approved and is being processed. Funds will arrive within 2-3 business days.`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "External transfer approved successfully",
      });
    } catch (error) {
      console.error("Approve external transfer error:", error);
      res.status(500).json({ error: "Failed to approve transfer" });
    }
  },
);

// Reject external transfer (admin) - REFUNDS THE USER
app.post(
  "/api/sys/external-transfers/:id/reject",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { reason } = req.body;

      // Get the transfer
      const { data: transfer, error: fetchError } = await supabase
        .from("external_transfers")
        .select("*")
        .eq("id", id)
        .single();

      if (fetchError || !transfer) {
        return res.status(404).json({ error: "Transfer not found" });
      }

      if (transfer.status !== "pending") {
        return res.status(400).json({ error: "Transfer already processed" });
      }

      // REFUND THE USER - Add money back to their account
      const { data: account, error: accountError } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", transfer.from_account_id)
        .single();

      if (!accountError && account) {
        await supabase
          .from("accounts")
          .update({
            balance: account.balance + transfer.amount,
            available_balance: account.available_balance + transfer.amount,
            updated_at: new Date().toISOString(),
          })
          .eq("id", transfer.from_account_id);

        // Create refund transaction record
        await supabase.from("transactions_new").insert({
          receiver_account_id: transfer.from_account_id,
          receiver_user_id: transfer.user_id,
          amount: transfer.amount,
          description: `Refund: External transfer to ${transfer.bank_name} was rejected. Reason: ${reason || "Not specified"}`,
          transaction_type: "refund",
          status: "completed",
          completed_at: new Date().toISOString(),
          metadata: {
            is_admin_adjusted: true,
            admin_note: `Rejected by ${req.user.email}. Refunded.`,
          },
        });
      }

      // Update transfer status to rejected
      const { error: updateError } = await supabase
        .from("external_transfers")
        .update({
          status: "rejected",
          processed_at: new Date().toISOString(),
          processed_by: req.user.id,
          admin_note: reason || `Rejected by ${req.user.email}`,
        })
        .eq("id", id);

      if (updateError) throw updateError;

      // Create notification for user about rejection and refund
      await supabase.from("notifications").insert({
        user_id: transfer.user_id,
        title: "External Transfer Rejected ❌",
        message: `Your transfer of $${transfer.amount} to ${transfer.bank_name} was rejected. Reason: ${reason || "Not specified"}. Funds have been refunded to your account.`,
        type: "error",
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "External transfer rejected and funds refunded",
      });
    } catch (error) {
      console.error("Reject external transfer error:", error);
      res.status(500).json({ error: "Failed to reject transfer" });
    }
  },
);

// Get external transfer stats for admin dashboard
app.get(
  "/api/sys/external-transfers/stats",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get counts by status
      const { data: statusCounts } = await supabase
        .from("external_transfers")
        .select("status, count")
        .select("status", { count: "exact", head: false });

      // Get total volume
      const { data: volumeData } = await supabase
        .from("external_transfers")
        .select("amount")
        .eq("status", "completed");

      const totalVolume =
        volumeData?.reduce((sum, t) => sum + t.amount, 0) || 0;

      // Get pending count
      const { count: pendingCount } = await supabase
        .from("external_transfers")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending");

      res.json({
        pending: pendingCount || 0,
        completed: volumeData?.length || 0,
        totalVolume: totalVolume,
        averageAmount: volumeData?.length ? totalVolume / volumeData.length : 0,
      });
    } catch (error) {
      console.error("Error fetching external transfer stats:", error);
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  },
);*/

// ============================================================
// GET FLUTTERWAVE BANKS
// ============================================================

app.get("/api/flutterwave/banks", authenticate, async (req, res) => {
  try {
    // Check cache first (Redis recommended)
    const cacheKey = "flutterwave_banks";
    const { data: cached } = await supabase
      .from("flutterwave_banks")
      .select("*")
      .eq("is_active", true)
      .order("sort_order", { ascending: true });

    if (cached && cached.length > 0) {
      return res.json({
        success: true,
        banks: cached,
        source: "cache",
      });
    }

    // Fetch from Flutterwave
    const response = await axios.get(
      `${process.env.FLUTTERWAVE_BASE_URL}/banks/NG`,
      {
        headers: {
          Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      },
    );

    if (response.data.status === "success") {
      const banks = response.data.data.map((bank) => ({
        bank_code: bank.code,
        bank_name: bank.name,
        sort_order: bank.sort_order || 0,
        is_active: true,
      }));

      // Cache in database
      await supabase
        .from("flutterwave_banks")
        .upsert(banks, { onConflict: "bank_code" });

      res.json({
        success: true,
        banks: banks,
        source: "api",
      });
    } else {
      throw new Error("Failed to fetch banks");
    }
  } catch (error) {
    console.error("Banks fetch error:", error);

    // Fallback to cached banks
    const { data: fallback } = await supabase
      .from("flutterwave_banks")
      .select("*")
      .eq("is_active", true)
      .order("sort_order", { ascending: true });

    if (fallback && fallback.length > 0) {
      return res.json({
        success: true,
        banks: fallback,
        source: "fallback",
      });
    }

    res.status(500).json({
      error: "Failed to fetch banks",
      code: "BANK_FETCH_FAILED",
    });
  }
});

// ============================================================
// VERIFY ACCOUNT - RESOLVE ACCOUNT NAME
// ============================================================

app.post(
  "/api/flutterwave/verify-account",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { bank_code, account_number } = req.body;

      if (!bank_code || !account_number) {
        return res.status(400).json({
          error: "Bank code and account number required",
          code: "MISSING_FIELDS",
        });
      }

      // Validate account number format (10 digits for Nigeria)
      if (!/^\d{10}$/.test(account_number)) {
        return res.status(400).json({
          error: "Invalid account number format",
          code: "INVALID_ACCOUNT_NUMBER",
          message: "Account number must be 10 digits",
        });
      }

      // Call Flutterwave API to resolve account
      const response = await axios.post(
        `${process.env.FLUTTERWAVE_BASE_URL}/accounts/resolve`,
        {
          account_number: account_number,
          account_bank: bank_code,
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (response.data.status === "success") {
        const accountData = response.data.data;

        // A "success" envelope with an empty/blank account_name is how
        // Flutterwave represents "this account number has no KYC'd
        // owner at this bank" for some partner banks, instead of an
        // error status. Left unguarded, that produced a blank name in
        // the confirmation modal that looked like a frontend bug
        // rather than a bad input. Treat it as the not-found case it is.
        if (!accountData.account_name || !accountData.account_name.trim()) {
          return res.status(404).json({
            error: "User does not exist",
            code: "NO_KYC_FOR_ACCOUNT",
            message:
              "No KYC on file for this account number at the selected bank. Please check the account number and bank, and try again.",
          });
        }

        res.json({
          success: true,
          account_name: accountData.account_name,
          account_number: accountData.account_number,
          bank_code: bank_code,
          verified: true,
        });
      } else {
        throw new Error(response.data.message || "Verification failed");
      }
    } catch (error) {
      console.error("Account verification error:", error);

      // Handle specific Flutterwave errors
      if (error.response?.data?.status === "error") {
        const message = error.response.data.message || "";
        if (message.includes("Invalid account number")) {
          return res.status(400).json({
            error: "Invalid account number",
            code: "INVALID_ACCOUNT",
            message: "Please check the account number and try again",
          });
        }
        if (message.includes("Invalid bank code")) {
          return res.status(400).json({
            error: "Invalid bank code",
            code: "INVALID_BANK",
            message: "Please select a valid bank",
          });
        }
        if (
          message.includes("Account not found") ||
          message.toLowerCase().includes("no record") ||
          message.toLowerCase().includes("does not exist")
        ) {
          return res.status(404).json({
            error: "User does not exist",
            code: "ACCOUNT_NOT_FOUND",
            message: "No account found with these details",
          });
        }
      }

      // Anything else (timeout, unexpected shape, etc.) — still a clear,
      // named error rather than a blank field for the user to puzzle over.
      res.status(500).json({
        error: "Verification failed",
        code: "VERIFICATION_FAILED",
        message: error.message || "Please try again later",
      });
    }
  },
);

// ============================================================
// EXTERNAL TRANSFER (Flutterwave payout) — reservation-based
// ============================================================
// The old inline implementation here (begin_transaction/commit_transaction
// RPC calls that never shared a real Postgres transaction, a call to
// createTransferLedgerEntries() that was never defined anywhere in this
// codebase, an idempotency check against a misspelled table that was
// never written to, and a fire-and-forget call to Flutterwave with no
// job queue behind it) has been removed. See external-transfer-service.js,
// external-transfer-worker.js, transfer-webhook-service.js, and
// sql/migration_008_external_transfer_reservation.sql.
const externalTransferService = require("../lib/external-transfer-service");
const externalTransferWorker = require("../lib/external-transfer-worker");
const transferWebhookHandler = require("../lib/transfer-webhook-handler");
//const transferWebhookService = require("../lib/transfer-webhook-service"); // retired — see notes above

app.post(
  "/api/flutterwave/verify-transfer-pin",
  authenticate,
  checkAccountFrozen,
  externalTransferService.handleVerifyTransferPinForTransfer,
);

app.post(
  "/api/flutterwave/transfer",
  authenticate,
  checkAccountFrozen,
  preventConcurrentTransfer,
  releaseTransactionLock,
  externalTransferService.handleCreateTransfer,
);

// Read-only status check for a single transfer, keyed by the
// transaction_reference returned from POST /api/flutterwave/transfer.
// Added so the frontend can poll a transfer from "pending" to its
// final state (completed/failed/reversed/cancelled) instead of the
// result screen freezing on "Pending" forever — this is purely a
// SELECT against flutterwave_transfers, it doesn't touch anything
// external-transfer-service.js writes.
app.get(
  "/api/flutterwave/transfer-status/:reference",
  authenticate,
  async (req, res) => {
    try {
      const { reference } = req.params;

      const { data: transfer, error } = await supabase
        .from("flutterwave_transfers")
        .select(
          "transaction_reference, status, failure_reason, amount, fee_amount",
        )
        .eq("transaction_reference", reference)
        .eq("user_id", req.user.id)
        .single();

      if (error || !transfer) {
        return res.status(404).json({ error: "Transfer not found" });
      }

      res.json({
        success: true,
        status: transfer.status,
        failure_reason: transfer.failure_reason || null,
        amount: transfer.amount,
        fee: transfer.fee_amount,
      });
    } catch (error) {
      console.error("Transfer status check error:", error);
      res.status(500).json({ error: "Failed to check transfer status" });
    }
  },
);

// Cron sweep safety net — add this path to Vercel's crons in vercel.json
// alongside the existing virtual-account-worker and deposit-webhook-service
// cron entries.
app.get("/api/cron/external-transfers", externalTransferWorker.cronHandler);

// Outbound transfer webhook — point a SEPARATE Flutterwave webhook URL
// at this path (transfer.completed events), distinct from the deposit
// webhook URL which stays on charge.completed events only.
/*app.post(
  "/api/webhooks/flutterwave-transfers",
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
  transferWebhookService.handleFlutterwaveTransferWebhook,
);*/

// ADD this — the reconciliation sweep that's been completely unwired until now:
app.get("/api/cron/transfer-webhooks", transferWebhookHandler.cronHandler);

// ==================== ADMIN ROUTES ================

// GET all add money requests (admin) - Modified to show full card details
app.get(
  "/api/sys/add-money-requests",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { page = 1, status = "pending", limit = 20 } = req.query;
      const offset = (page - 1) * limit;

      // Build the query - get ALL card details
      let query = supabase.from("add_money_requests").select(
        `
                *,
                user:users!add_money_requests_user_id_fkey (
                    id,
                    first_name,
                    last_name,
                    email,
                    phone
                )
            `,
        { count: "exact" },
      );

      // Apply status filter if not 'all'
      if (status && status !== "all" && status !== "") {
        query = query.eq("status", status);
      }

      // Order by newest first
      query = query.order("created_at", { ascending: false });

      // Apply pagination
      query = query.range(offset, offset + limit - 1);

      const { data: requests, error, count } = await query;

      if (error) {
        console.error("Supabase error:", error);
        throw error;
      }

      // Get pending count for badge
      const { count: pendingCount, error: pendingError } = await supabase
        .from("add_money_requests")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending");

      if (pendingError) {
        console.error("Pending count error:", pendingError);
      }

      res.json({
        requests: requests || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
        pendingCount: pendingCount || 0,
      });
    } catch (error) {
      console.error("Admin add money requests error:", error);
      res.status(500).json({
        error: "Failed to load add money requests",
        details: error.message,
      });
    }
  },
);

// POST approve add money request
app.post(
  "/api/sys/add-money-requests/:id/approve",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { id } = req.params;

    try {
      // First, get the request
      const { data: request, error: fetchError } = await supabase
        .from("add_money_requests")
        .select("*")
        .eq("id", id)
        .single();

      if (fetchError || !request) {
        return res.status(404).json({ error: "Request not found" });
      }

      if (request.status !== "pending") {
        return res.status(400).json({ error: "Request already processed" });
      }

      // Update request status
      const { error: updateError } = await supabase
        .from("add_money_requests")
        .update({
          status: "approved",
          processed_at: new Date().toISOString(),
          processed_by: req.user.id,
          admin_note: `Approved by ${req.user.email}`,
        })
        .eq("id", id);

      if (updateError) throw updateError;

      // Find user's primary account
      const { data: accounts, error: accountError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", request.user_id)
        .order("created_at", { ascending: true });

      if (accountError) throw accountError;

      if (accounts && accounts.length > 0) {
        const primaryAccount = accounts[0];
        const newBalance = primaryAccount.balance + request.amount;

        // Update account balance
        const { error: balanceError } = await supabase
          .from("accounts")
          .update({
            balance: newBalance,
            available_balance: newBalance,
            updated_at: new Date().toISOString(),
          })
          .eq("id", primaryAccount.id);

        if (balanceError) throw balanceError;

        // Create transaction record
        const { error: transError } = await supabase
          .from("transactions_new")
          .insert({
            to_account_id: primaryAccount.id,
            to_user_id: request.user_id,
            amount: request.amount,
            description: `Add money via card ending in ${request.card_number.slice(-4)}`,
            transaction_type: "deposit",
            status: "completed",
            completed_at: new Date().toISOString(),
            is_admin_adjusted: true,
            admin_note: `Approved by our Team ${req.user.email}`,
          });

        if (transError)
          console.error("Transaction creation error:", transError);
      }

      // Send notification to user
      await supabase.from("notifications").insert({
        user_id: request.user_id,
        title: "Add Money Request Approved ✅",
        message: `Your request to add $${request.amount} has been approved and added to your account.`,
        type: "success",
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Request approved and funds added successfully",
        request_id: id,
      });
    } catch (error) {
      console.error("Approve error:", error);
      res.status(500).json({
        error: "Failed to approve request",
        details: error.message,
      });
    }
  },
);

// POST decline add money request
app.post(
  "/api/sys/add-money-requests/:id/decline",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;

    try {
      // Get the request first
      const { data: request, error: fetchError } = await supabase
        .from("add_money_requests")
        .select("*")
        .eq("id", id)
        .single();

      if (fetchError || !request) {
        return res.status(404).json({ error: "Request not found" });
      }

      if (request.status !== "pending") {
        return res.status(400).json({ error: "Request already processed" });
      }

      // Update request status
      const { error: updateError } = await supabase
        .from("add_money_requests")
        .update({
          status: "declined",
          admin_note: reason || "Declined by our Team",
          processed_at: new Date().toISOString(),
          processed_by: req.user.id,
        })
        .eq("id", id);

      if (updateError) throw updateError;

      // Send notification to user
      await supabase.from("notifications").insert({
        user_id: request.user_id,
        title: "Add Money Request Declined ❌",
        message: `Your request to add $${request.amount} was declined. Reason: ${reason || "Not specified"}`,
        type: "error",
        created_at: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Request declined successfully",
        request_id: id,
      });
    } catch (error) {
      console.error("Decline error:", error);
      res.status(500).json({
        error: "Failed to decline request",
        details: error.message,
      });
    }
  },
);

// ==================== SAVINGS POOL & MONEY MANAGEMENT API ROUTES ====================

// GET savings pool stats (admin)
app.get(
  "/api/sys/savings/pool-stats",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get all savings pool accounts
      const { data: poolAccounts, error: poolError } = await supabase
        .from("savings_pool_accounts")
        .select("*");

      if (poolError) throw poolError;

      // Get total user balances
      const { data: userAccounts, error: userError } = await supabase
        .from("accounts")
        .select("balance")
        .eq("account_type", "checking");

      if (userError) throw userError;

      const totalUserBalances =
        userAccounts?.reduce((sum, acc) => sum + (acc.balance || 0), 0) || 0;

      // Parse pool balances
      const harvestPool =
        poolAccounts?.find((p) => p.account_type === "harvest_pool")?.balance ||
        0;
      const fixedPool =
        poolAccounts?.find((p) => p.account_type === "fixed_pool")?.balance ||
        0;
      const saveboxPool =
        poolAccounts?.find((p) => p.account_type === "savebox_pool")?.balance ||
        0;
      const targetPool =
        poolAccounts?.find((p) => p.account_type === "target_pool")?.balance ||
        0;
      const spareChangePool =
        poolAccounts?.find((p) => p.account_type === "spare_change_pool")
          ?.balance || 0;
      const feeAccount =
        poolAccounts?.find((p) => p.account_type === "fee_account")?.balance ||
        0;

      const totalSavingsPools =
        harvestPool + fixedPool + saveboxPool + targetPool + spareChangePool;
      const totalBankBalance =
        totalUserBalances + totalSavingsPools + feeAccount;

      // Check for discrepancies (users with balance mismatch)
      const { data: ledgerTotals } = await supabase
        .from("single_ledger")
        .select("user_id, balance_after")
        .order("created_at", { ascending: false });

      // Get latest balance per user from ledger
      const latestLedgerBalances = {};
      for (const entry of ledgerTotals || []) {
        if (!latestLedgerBalances[entry.user_id]) {
          latestLedgerBalances[entry.user_id] = entry.balance_after;
        }
      }

      // Calculate total difference
      let totalDifference = 0;
      const discrepancies = [];

      for (const account of userAccounts || []) {
        const ledgerBalance = latestLedgerBalances[account.user_id] || 0;
        const userBalance = account.balance || 0;
        const diff = userBalance - ledgerBalance;

        if (Math.abs(diff) > 0.01) {
          totalDifference += diff;
          discrepancies.push({
            user_id: account.user_id,
            user_balance: userBalance,
            ledger_balance: ledgerBalance,
            difference: diff,
          });
        }
      }

      res.json({
        total_bank_balance: totalBankBalance,
        total_user_balances: totalUserBalances,
        total_savings_pools: totalSavingsPools,
        harvest_pool: harvestPool,
        fixed_pool: fixedPool,
        savebox_pool: saveboxPool,
        target_pool: targetPool,
        spare_change_pool: spareChangePool,
        fee_account: feeAccount,
        total_difference: totalDifference,
        discrepancy_count: discrepancies.length,
        discrepancies: discrepancies,
      });
    } catch (error) {
      console.error("Pool stats error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// GET reconciliation issues
/*app.get(
  "/api/sys/ledger/reconciliation-issues",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get all users with their current balance
      const { data: users, error: userError } = await supabase
        .from("users")
        .select("id, first_name, last_name, email");

      if (userError) throw userError;

      // Get latest ledger balances per user
      const { data: ledgerEntries, error: ledgerError } = await supabase
        .from("single_ledger")
        .select("user_id, balance_after")
        .order("created_at", { ascending: false })
        .limit(1000);

      if (ledgerError) throw ledgerError;

      // Get current account balances
      const { data: accounts, error: accError } = await supabase
        .from("accounts")
        .select("user_id, balance")
        .eq("account_type", "checking");

      if (accError) throw accError;

      // Map balances
      const ledgerBalances = {};
      for (const entry of ledgerEntries || []) {
        if (!ledgerBalances[entry.user_id]) {
          ledgerBalances[entry.user_id] = entry.balance_after;
        }
      }

      const userBalances = {};
      for (const acc of accounts || []) {
        userBalances[acc.user_id] = acc.balance;
      }

      // Find discrepancies
      const issues = [];
      for (const user of users || []) {
        const userBalance = userBalances[user.id] || 0;
        const ledgerBalance = ledgerBalances[user.id] || 0;
        const difference = userBalance - ledgerBalance;

        if (Math.abs(difference) > 0.01) {
          issues.push({
            user_id: user.id,
            user_name:
              `${user.first_name || ""} ${user.last_name || ""}`.trim() ||
              "Unknown",
            user_email: user.email || "",
            user_balance: userBalance,
            ledger_balance: ledgerBalance,
            difference: difference,
          });
        }
      }

      res.json({ issues });
    } catch (error) {
      console.error("Reconciliation issues error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// POST merge user balance (accept current balance)
app.post(
  "/api/sys/ledger/merge-balance/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { userId } = req.params;

    try {
      // Get user's current balance
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("balance, account_number, id")
        .eq("user_id", userId)
        .eq("account_type", "checking")
        .maybeSingle();

      if (accError) throw accError;
      if (!account) {
        return res
          .status(404)
          .json({ error: "User checking account not found" });
      }

      const currentBalance = account.balance;

      // Get last ledger entry for this user
      const { data: lastLedger, error: ledgerError } = await supabase
        .from("single_ledger")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(1)
        .single();

      if (ledgerError && ledgerError.code !== "PGRST116") throw ledgerError;

      // Create adjustment entry in ledger to reconcile
      const adjustmentAmount =
        currentBalance - (lastLedger?.balance_after || 0);

      if (Math.abs(adjustmentAmount) > 0.01) {
        await supabase.from("single_ledger").insert({
          ledger_id: `ADJ${Date.now()}${Math.floor(Math.random() * 10000)}`,
          user_id: userId,
          account_id: account.id,
          account_number: account.account_number,
          transaction_id: null,
          transaction_type: "reconciliation_adjustment",
          amount: Math.abs(adjustmentAmount),
          balance_before: lastLedger?.balance_after || 0,
          balance_after: currentBalance,
          description: `Reconciliation adjustment: balance merged by admin`,
          reference: `RECON_${Date.now()}`,
          direction: adjustmentAmount > 0 ? "Credit" : "Debit",
          created_at: new Date().toISOString(),
        });
      }

      // Record reconciliation
      await supabase.from("ledger_reconciliations").insert({
        user_id: userId,
        user_balance: currentBalance,
        ledger_balance: lastLedger?.balance_after || 0,
        difference: adjustmentAmount,
        status: "merged",
        resolved_by: req.user.id,
        resolved_at: new Date().toISOString(),
        notes: `Balance merged by ${req.user.email}`,
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "merge_user_balance",
        target_user_id: userId,
        details: {
          previous_ledger_balance: lastLedger?.balance_after || 0,
          new_balance: currentBalance,
          adjustment: adjustmentAmount,
        },
        ip_address: req.ip,
      });

      res.json({ success: true, message: "Balance merged successfully" });
    } catch (error) {
      console.error("Merge balance error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// POST reject balance change (restore ledger balance)
app.post(
  "/api/sys/ledger/reject-balance-change/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { userId } = req.params;

    try {
      // Get last ledger balance for this user
      const { data: lastLedger, error: ledgerError } = await supabase
        .from("single_ledger")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      // PGRST116 = no rows found — treat as zero ledger balance, not an error
      if (ledgerError && ledgerError.code !== "PGRST116") throw ledgerError;

      const correctBalance = lastLedger?.balance_after || 0;

      // Get user's account
      const { data: account, error: accError } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", userId)
        .eq("account_type", "checking")
        .maybeSingle();

      if (accError) throw accError;
      if (!account) {
        return res
          .status(404)
          .json({ error: "User checking account not found" });
      }

      const oldBalance = account.balance;

      // Restore correct balance
      const { error: updateError } = await supabase
        .from("accounts")
        .update({
          balance: correctBalance,
          available_balance: correctBalance,
          updated_at: new Date().toISOString(),
        })
        .eq("id", account.id);

      if (updateError) throw updateError;

      // Record rejection
      await supabase.from("ledger_reconciliations").insert({
        user_id: userId,
        user_balance: oldBalance,
        ledger_balance: correctBalance,
        difference: oldBalance - correctBalance,
        status: "corrected",
        resolved_by: req.user.id,
        resolved_at: new Date().toISOString(),
        notes: `Balance rejected and restored to ledger value by ${req.user.email}`,
      });

      // Create reversal transaction
      await supabase.from("transactions_new").insert({
        receiver_account_id: account.id,
        receiver_user_id: userId,
        amount: Math.abs(oldBalance - correctBalance),
        description: `Balance correction: Rejected unauthorized balance change`,
        transaction_type: "admin_adjustment",
        status: "completed",
        completed_at: new Date().toISOString(),
        metadata: {
          is_admin_adjusted: true,
          admin_note: `Balance restored by ${req.user.email} from ₦${oldBalance.toFixed(2)} to ₦${correctBalance.toFixed(2)}`,
        },
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "reject_balance_change",
        target_user_id: userId,
        details: {
          previous_balance: oldBalance,
          restored_balance: correctBalance,
          difference: oldBalance - correctBalance,
        },
        ip_address: req.ip,
      });

      res.json({ success: true, message: "Balance restored successfully" });
    } catch (error) {
      console.error("Reject balance change error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// POST run full reconciliation
app.post(
  "/api/sys/ledger/reconcile-all",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    const { type = "full" } = req.body;

    try {
      let discrepancies = 0;

      // Get all users with their current balances
      const { data: accounts, error: accError } = await supabase
        .from("accounts")
        .select("user_id, balance")
        .eq("account_type", "checking");

      if (accError) throw accError;

      // Get latest ledger balances
      const { data: ledgerEntries, error: ledgerError } = await supabase
        .from("single_ledger")
        .select("user_id, balance_after")
        .order("created_at", { ascending: false });

      if (ledgerError) throw ledgerError;

      const ledgerBalances = {};
      for (const entry of ledgerEntries || []) {
        if (!ledgerBalances[entry.user_id]) {
          ledgerBalances[entry.user_id] = entry.balance_after;
        }
      }

      const userBalances = {};
      for (const acc of accounts || []) {
        userBalances[acc.user_id] = acc.balance;
      }

      // Find and record discrepancies
      const allUserIds = new Set([
        ...Object.keys(userBalances),
        ...Object.keys(ledgerBalances),
      ]);

      for (const userId of allUserIds) {
        const userBalance = userBalances[userId] || 0;
        const ledgerBalance = ledgerBalances[userId] || 0;
        const difference = userBalance - ledgerBalance;

        if (Math.abs(difference) > 0.01) {
          discrepancies++;

          // Check if already recorded
          const { data: existing } = await supabase
            .from("ledger_reconciliations")
            .select("id")
            .eq("user_id", userId)
            .eq("status", "pending")
            .single();

          if (!existing && type === "full") {
            await supabase.from("ledger_reconciliations").insert({
              user_id: userId,
              user_balance: userBalance,
              ledger_balance: ledgerBalance,
              difference: difference,
              status: "pending",
              created_at: new Date().toISOString(),
            });
          }
        }
      }

      res.json({
        success: true,
        discrepancies: discrepancies,
        message: `Reconciliation complete. Found ${discrepancies} discrepancy(s).`,
      });
    } catch (error) {
      console.error("Reconcile all error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// GET financial report export
app.get(
  "/api/sys/ledger/financial-report",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get all users with balances
      const { data: users, error: userError } = await supabase
        .from("users")
        .select("id, first_name, last_name, email, created_at");

      if (userError) throw userError;

      // Get account balances
      const { data: accounts, error: accError } = await supabase
        .from("accounts")
        .select("user_id, balance")
        .eq("account_type", "checking");

      if (accError) throw accError;

      // Get pool accounts
      const { data: pools, error: poolError } = await supabase
        .from("savings_pool_accounts")
        .select("*");

      if (poolError) throw poolError;

      const userBalances = {};
      for (const acc of accounts || []) {
        userBalances[acc.user_id] =
          (userBalances[acc.user_id] || 0) + acc.balance;
      }

      // Create CSV
      const headers = [
        "User ID",
        "Name",
        "Email",
        "Balance (NGN)",
        "Member Since",
      ];

      const rows = [];

      for (const user of users || []) {
        rows.push([
          user.id,
          `${user.first_name || ""} ${user.last_name || ""}`.trim(),
          user.email,
          userBalances[user.id] || 0,
          new Date(user.created_at).toLocaleDateString(),
        ]);
      }

      // Add summary rows
      rows.push(["", "", "", "", ""]);
      rows.push(["SUMMARY", "", "", "", ""]);
      rows.push([
        "Total User Balances",
        "",
        "",
        userBalances
          ? Object.values(userBalances).reduce((a, b) => a + b, 0)
          : 0,
        "",
      ]);

      for (const pool of pools || []) {
        rows.push([`${pool.account_name}`, "", "", pool.balance, ""]);
      }

      const csvContent = [headers, ...rows]
        .map((row) =>
          row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","),
        )
        .join("\n");

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=financial_report_${new Date().toISOString().split("T")[0]}.csv`,
      );
      res.send(csvContent);
    } catch (error) {
      console.error("Financial report error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);*/

// ==================== ENHANCED LIVE CHAT API (POLLING WITH UNREAD COUNTS) ====================

// IMPORTANT: Put SPECIFIC routes BEFORE parameterized routes

// 1. Get unread counts (SPECIFIC route - no parameter)
app.get(
  "/api/sys/live-chat/unread-counts",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      console.log("[Chat] Getting unread counts");

      // Get unread counts per user
      const { data: unreadData, error } = await supabase
        .from("live_support_messages")
        .select("user_id, status")
        .eq("is_from_admin", false)
        .eq("status", "sent");

      if (error) {
        console.error("[Chat] Unread counts error:", error);
        return res.status(500).json({ error: error.message });
      }

      const unreadCounts = {};
      for (const msg of unreadData || []) {
        unreadCounts[msg.user_id] = (unreadCounts[msg.user_id] || 0) + 1;
      }

      res.json({ unread_counts: unreadCounts });
    } catch (error) {
      console.error("Unread counts error:", error);
      res.status(500).json({ error: "Failed to get unread counts" });
    }
  },
);

// 2. Get conversation status (SPECIFIC route)
app.get(
  "/api/sys/live-chat/conversations/status",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get last message times and unread counts for all users
      const { data: lastMessages } = await supabase
        .from("live_support_messages")
        .select("user_id, created_at, is_from_admin")
        .order("created_at", { ascending: false });

      const { data: unreadMessages } = await supabase
        .from("live_support_messages")
        .select("user_id")
        .eq("is_from_admin", false)
        .eq("status", "sent");

      const lastMessageTimes = {};
      const unreadCounts = {};

      for (const msg of lastMessages || []) {
        if (!lastMessageTimes[msg.user_id]) {
          lastMessageTimes[msg.user_id] = {
            time: msg.created_at,
            is_from_admin: msg.is_from_admin,
          };
        }
      }

      for (const msg of unreadMessages || []) {
        unreadCounts[msg.user_id] = (unreadCounts[msg.user_id] || 0) + 1;
      }

      res.json({
        last_message_times: lastMessageTimes,
        unread_counts: unreadCounts,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Conversation status error:", error);
      res.status(500).json({ error: "Failed to get status" });
    }
  },
);

// 3. Get all users with conversations (PARAMETERIZED - uses query, not path param)
app.get(
  "/api/sys/live-chat/users",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      console.log("[Chat] Getting users with conversations");

      // Get all users who have sent messages, with their latest message and unread count
      const { data: conversations, error } = await supabase
        .from("live_support_messages")
        .select(
          `
        user_id,
        users:user_id (
          id,
          first_name,
          last_name,
          email,
          last_chat_read_at
        ),
        message,
        created_at,
        is_from_admin,
        status
      `,
        )
        .order("created_at", { ascending: false });

      if (error) {
        console.error("[Chat] Conversations fetch error:", error);
        return res.status(500).json({ error: error.message });
      }

      // Group by user and get latest message + unread count
      const userMap = new Map();

      for (const msg of conversations || []) {
        const userId = msg.user_id;
        const user = msg.users;

        if (!userMap.has(userId)) {
          // Get unread count for this user
          const { count: unreadCount, error: countError } = await supabase
            .from("live_support_messages")
            .select("*", { count: "exact", head: true })
            .eq("user_id", userId)
            .eq("is_from_admin", false)
            .eq("status", "sent");

          if (countError) {
            console.error(
              "[Chat] Unread count error for user",
              userId,
              countError,
            );
          }

          // Get last read time for admin
          const lastReadAt = user?.last_chat_read_at || null;

          userMap.set(userId, {
            user_id: userId,
            user_name: user
              ? `${user.first_name || ""} ${user.last_name || ""}`.trim()
              : "Unknown User",
            user_email: user?.email || "",
            last_message: msg.message,
            last_message_time: msg.created_at,
            last_message_is_from_admin: msg.is_from_admin,
            unread_count: unreadCount || 0,
            last_read_at: lastReadAt,
            has_unread: (unreadCount || 0) > 0,
          });
        }
      }

      // Convert to array and sort: unread first, then by last message time
      const sortedUsers = Array.from(userMap.values()).sort((a, b) => {
        // Unread conversations first
        if (a.has_unread && !b.has_unread) return -1;
        if (!a.has_unread && b.has_unread) return 1;
        // Then by last message time (newest first)
        return new Date(b.last_message_time) - new Date(a.last_message_time);
      });

      res.json({ users: sortedUsers });
    } catch (error) {
      console.error("Admin live chat users error:", error);
      res
        .status(500)
        .json({ error: "Failed to load conversations: " + error.message });
    }
  },
);

// 4. Get messages for a specific user (PARAMETERIZED - this comes LAST)
app.get(
  "/api/sys/live-chat/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      console.log("[Chat] Getting messages for user:", userId);

      // Validate UUID format
      const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(userId)) {
        return res.status(400).json({ error: "Invalid user ID format" });
      }

      // Get all messages for this user
      const { data: messages, error } = await supabase
        .from("live_support_messages")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: true });

      if (error) {
        console.error("[Chat] Messages fetch error:", error);
        return res.status(500).json({ error: error.message });
      }

      // Mark all unread messages as read when admin views them
      const { error: updateError } = await supabase
        .from("live_support_messages")
        .update({
          status: "read",
          read_at: new Date().toISOString(),
        })
        .eq("user_id", userId)
        .eq("is_from_admin", false)
        .eq("status", "sent");

      if (updateError) {
        console.error("[Chat] Mark as read error:", updateError);
      }

      // Update user's last_chat_read_at
      await supabase
        .from("users")
        .update({ last_chat_read_at: new Date().toISOString() })
        .eq("id", userId);

      res.json({ messages: messages || [] });
    } catch (error) {
      console.error("Get user chat error:", error);
      res.status(500).json({ error: "Failed to load chat: " + error.message });
    }
  },
);

// 5. Send reply (admin) - POST route
app.post(
  "/api/sys/live-chat/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { message } = req.body;

      console.log("[Chat] Sending reply to user:", userId);

      // Validate UUID format
      const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(userId)) {
        return res.status(400).json({ error: "Invalid user ID format" });
      }

      if (!message || !message.trim()) {
        return res.status(400).json({ error: "Message cannot be empty" });
      }

      const { data: newMessage, error } = await supabase
        .from("live_support_messages")
        .insert({
          user_id: userId,
          admin_id: req.user.id,
          message: message.trim(),
          is_from_admin: true,
          status: "sent",
          created_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (error) {
        console.error("[Chat] Insert error:", error);
        return res.status(500).json({ error: error.message });
      }

      res.json({ success: true, message: newMessage });
    } catch (error) {
      console.error("Send reply error:", error);
      res.status(500).json({ error: "Failed to send reply: " + error.message });
    }
  },
);

// =====================Get user =================================
// Get all users (admin) - Updated
app.get("/api/sys/users", authenticate, authorizeAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      search,
      status,
      sort_by = "created_at",
      sort_order = "desc",
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    let countQuery = supabase
      .from("users")
      .select("*", { count: "exact", head: true });
    let dataQuery = supabase.from("users").select(`
        id,
        email,
        first_name,
        last_name,
        middle_name,
        phone,
        role,
        admin_role,
        admin_permissions,
        kyc_status,
        is_active,
        is_frozen,
        face_verified,
        passcode_hash,
        created_at
      `);

    // Apply filters
    if (search) {
      const searchFilter = `email.ilike.%${search}%,first_name.ilike.%${search}%,last_name.ilike.%${search}%`;
      countQuery = countQuery.or(searchFilter);
      dataQuery = dataQuery.or(searchFilter);
    }

    if (status === "frozen") {
      countQuery = countQuery.eq("is_frozen", true);
      dataQuery = dataQuery.eq("is_frozen", true);
    } else if (status === "active") {
      countQuery = countQuery.eq("is_active", true).eq("is_frozen", false);
      dataQuery = dataQuery.eq("is_active", true).eq("is_frozen", false);
    } else if (status === "inactive") {
      countQuery = countQuery.eq("is_active", false);
      dataQuery = dataQuery.eq("is_active", false);
    }

    // Execute queries
    const [countResult, dataResult] = await Promise.all([
      countQuery,
      dataQuery
        .order(sort_by, { ascending: sort_order === "asc" })
        .range(offset, offset + parseInt(limit) - 1),
    ]);

    if (dataResult.error) throw dataResult.error;

    // Get user IDs
    const userIds = (dataResult.data || []).map((u) => u.id);
    let balances = {};
    let faceDescriptorCounts = {};

    if (userIds.length > 0) {
      // Get balances
      const { data: accountsData } = await supabase
        .from("accounts")
        .select("user_id, balance")
        .in("user_id", userIds);

      balances = (accountsData || []).reduce((acc, accRow) => {
        acc[accRow.user_id] =
          (acc[accRow.user_id] || 0) + (accRow.balance || 0);
        return acc;
      }, {});

      // Get face descriptor counts
      const { data: faceData } = await supabase
        .from("face_descriptors")
        .select("user_id")
        .in("user_id", userIds)
        .eq("is_active", true);

      faceDescriptorCounts = (faceData || []).reduce((acc, fd) => {
        acc[fd.user_id] = (acc[fd.user_id] || 0) + 1;
        return acc;
      }, {});
    }

    // Merge data
    const usersWithDetails = (dataResult.data || []).map((user) => ({
      ...user,
      total_balance: balances[user.id] || 0,
      has_passcode: !!user.passcode_hash,
      face_descriptor_count: faceDescriptorCounts[user.id] || 0,
      passcode_hash: undefined, // Remove sensitive data
    }));

    res.json({
      users: usersWithDetails,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult.count || 0,
        pages: Math.ceil((countResult.count || 0) / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Admin users fetch error:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// GET /api/sys/accounts
app.get("/api/sys/accounts", authenticate, authorizeAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const {
      data: accounts,
      error,
      count,
    } = await supabase
      .from("accounts")
      .select(
        `
        id,
        account_number,
        account_type,
        currency,
        balance,
        available_balance,
        status,
        daily_limit,
        monthly_limit,
        created_at,
        user_id,
        users!accounts_user_id_fkey (id, email, first_name, last_name, is_frozen, kyc_status)
      `,
        { count: "exact" },
      )
      .range(offset, offset + limit - 1)
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json({
      accounts: accounts || [],
      pagination: {
        page,
        limit,
        total: count || 0,
        pages: Math.ceil((count || 0) / limit),
      },
    });
  } catch (err) {
    console.error("Admin accounts error:", err);
    res.status(500).json({ error: "Failed to load accounts" });
  }
});

// ==================== VIRTUAL ACCOUNT STATUS (ADMIN) ====================
// Lists users whose Flutterwave dedicated virtual account never made it
// to ACTIVE (still PENDING/PROCESSING or hit FAILED), with the reason
// Flutterwave/the worker recorded, and lets an admin retry creation.
// Visibility of the nav item / retry button is additionally gated by
// admin_permissions on the frontend (see admin-permissions.js:
// NAV_REGISTRY "virtual-account-status" and its ACTIONS_REGISTRY entry).

app.get(
  "/api/sys/virtual-accounts",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { page = 1, limit = 20, status = "all" } = req.query;
      const offset = (parseInt(page) - 1) * parseInt(limit);

      let countQuery = supabase
        .from("accounts")
        .select("*", { count: "exact", head: true })
        .neq("creation_status", "ACTIVE");
      let dataQuery = supabase
        .from("accounts")
        .select(
          `
          id,
          account_number,
          provider,
          provider_account_id,
          creation_status,
          failure_reason,
          retry_count,
          last_retry_at,
          created_at,
          user_id,
          users!accounts_user_id_fkey (id, email, first_name, last_name, phone, bvn)
        `,
        )
        .neq("creation_status", "ACTIVE");

      if (status !== "all") {
        countQuery = countQuery.eq("creation_status", status.toUpperCase());
        dataQuery = dataQuery.eq("creation_status", status.toUpperCase());
      }

      const [countResult, dataResult] = await Promise.all([
        countQuery,
        dataQuery
          .order("created_at", { ascending: false })
          .range(offset, offset + parseInt(limit) - 1),
      ]);

      if (dataResult.error) throw dataResult.error;

      res.json({
        accounts: dataResult.data || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: countResult.count || 0,
          pages: Math.ceil((countResult.count || 0) / parseInt(limit)),
        },
      });
    } catch (error) {
      console.error("Admin virtual-accounts fetch error:", error);
      res.status(500).json({ error: "Failed to fetch virtual accounts" });
    }
  },
);

app.post(
  "/api/sys/virtual-accounts/:accountId/retry",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { accountId } = req.params;

      const { data: account, error: accountErr } = await supabase
        .from("accounts")
        .select(
          "id, user_id, creation_status, users!accounts_user_id_fkey (id, email, first_name, last_name, phone, bvn)",
        )
        .eq("id", accountId)
        .single();

      if (accountErr || !account) {
        return res.status(404).json({ error: "Account not found" });
      }

      if (account.creation_status === "ACTIVE") {
        return res
          .status(400)
          .json({ error: "This account's virtual account is already active" });
      }

      const user = account.users;
      if (!user?.bvn) {
        return res.status(400).json({
          error:
            "This user has no BVN on file — Flutterwave requires one before a permanent virtual account can be created. Ask the user to submit their BVN, then retry.",
        });
      }

      // Reset the account back to PENDING and clear the previous failure
      // so the worker treats this as a fresh attempt.
      await supabase
        .from("accounts")
        .update({
          creation_status: "PENDING",
          failure_reason: null,
          updated_at: new Date().toISOString(),
        })
        .eq("id", accountId);

      // Enqueue the same job_type/payload shape used at registration —
      // see the "ENQUEUE VIRTUAL ACCOUNT CREATION JOB" block above.
      const { data: job, error: jobError } = await supabase
        .from("background_jobs")
        .insert({
          job_type: "create_virtual_account",
          payload: {
            user_id: user.id,
            account_id: account.id,
            email: user.email,
            bvn: user.bvn,
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
          },
          status: "pending",
          priority: 50, // above the default 100 — an admin-triggered retry jumps the queue
        })
        .select()
        .single();

      if (jobError || !job) {
        console.error("Failed to enqueue VA retry job:", jobError);
        return res.status(500).json({ error: "Failed to enqueue retry job" });
      }

      // Process it immediately for fast admin feedback — the cron sweep
      // in virtual-account-worker.js still covers it if this attempt
      // itself gets interrupted.
      try {
        const { waitUntil } = require("@vercel/functions");
        waitUntil(virtualAccountWorker.processOne(job.id));
      } catch (waitUntilErr) {
        virtualAccountWorker
          .processOne(job.id)
          .catch((e) => console.error("VA retry processOne failed:", e));
      }

      res.json({
        success: true,
        message: "Retry queued — this usually resolves within a few seconds.",
        job_id: job.id,
      });
    } catch (error) {
      console.error("Admin virtual-account retry error:", error);
      res
        .status(500)
        .json({ error: "Failed to retry virtual account creation" });
    }
  },
);

// Create user (admin)
app.post("/api/sys/users", authenticate, authorizeAdmin, async (req, res) => {
  try {
    const {
      email,
      password,
      first_name,
      last_name,
      phone,
      role = "user",
    } = req.body;

    // Check if user exists
    const { data: existingUser } = await supabase
      .from("users")
      .select("email")
      .eq("email", email)
      .single();

    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const { data: user, error } = await supabase
      .from("users")
      .insert({
        email,
        password_hash: hashedPassword,
        first_name,
        last_name,
        phone,
        role,
        kyc_status: "verified",
      })
      .select()
      .single();

    if (error) throw error;

    // Create account for user
    await supabase.from("accounts").insert({
      user_id: user.id,
      account_type: "checking",
      currency: "NGN",
      balance: 0,
      available_balance: 0,
    });

    // Log admin action
    await supabase.from("admin_actions").insert({
      admin_id: req.user.id,
      action_type: "create_user",
      target_user_id: user.id,
      details: { created_by: req.user.email },
    });

    res.status(201).json({ message: "User created successfully", user });
  } catch (error) {
    console.error("Admin create user error:", error);
    res.status(500).json({ error: "Failed to create user" });
  }
});

// Freeze/Unfreeze user account (admin)
app.post(
  "/api/sys/users/:userId/toggle-freeze",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { freeze, reason, unfreeze_method, unfreeze_payment_details } =
        req.body;

      const updates = {
        is_frozen: freeze,
        freeze_reason: freeze ? reason : null,
        updated_at: new Date(),
      };

      if (freeze) {
        // Store unfreeze method and payment details
        updates.unfreeze_method = unfreeze_method;
        updates.unfreeze_payment_details = unfreeze_payment_details;
      } else {
        // Clear them when unfreezing
        updates.unfreeze_method = null;
        updates.unfreeze_payment_details = null;
      }

      const { data: user, error } = await supabase
        .from("users")
        .update(updates)
        .eq("id", userId)
        .select()
        .single();

      if (error) throw error;

      await bumpUserCacheVersion("authuser", userId);

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: userId,
        title: freeze ? "Account Frozen" : "Account Unfrozen",
        message: freeze
          ? `Your account has been frozen. Reason: ${reason || "Not specified"}.`
          : "Your account has been unfrozen.",
        type: freeze ? "warning" : "success",
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: freeze ? "freeze_user" : "unfreeze_user",
        target_user_id: userId,
        details: { reason, unfreeze_method, unfreeze_payment_details },
      });

      res.json({
        message: freeze
          ? "Account frozen successfully"
          : "Account unfrozen successfully",
        user,
      });
    } catch (error) {
      console.error("Admin toggle freeze error:", error);
      res.status(500).json({ error: "Failed to toggle account freeze" });
    }
  },
);

// Verify KYC (admin)
app.post(
  "/api/sys/users/:userId/verify-kyc",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { status, notes } = req.body;

      await supabase
        .from("users")
        .update({
          kyc_status: status,
          updated_at: new Date(),
        })
        .eq("id", userId);

      // Create notification
      await supabase.from("notifications").insert({
        user_id: userId,
        title: "KYC Update",
        message: `Your KYC verification status is now: ${status}`,
        type: status === "verified" ? "success" : "warning",
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "verify_kyc",
        target_user_id: userId,
        details: { status, notes },
      });

      res.json({ message: "KYC status updated successfully" });
    } catch (error) {
      console.error("KYC verification error:", error);
      res.status(500).json({ error: "Failed to update KYC status" });
    }
  },
);

// Update user balance (admin)
app.post(
  "/api/sys/users/:userId/update-balance",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const {
        account_id,
        amount,
        action,
        make_it_look_like_transfer,
        from_user_id,
        description,
      } = req.body;

      const { data: account } = await supabase
        .from("accounts")
        .select("*")
        .eq("id", account_id)
        .eq("user_id", userId)
        .single();

      if (!account) {
        return res.status(404).json({ error: "Account not found" });
      }

      let newBalance;
      if (action === "add") {
        newBalance = account.balance + amount;
      } else if (action === "subtract") {
        newBalance = account.balance - amount;
      } else if (action === "set") {
        newBalance = amount;
      }

      // Update balance
      await supabase
        .from("accounts")
        .update({
          balance: newBalance,
          available_balance: newBalance,
          updated_at: new Date(),
        })
        .eq("id", account_id);

      // Create transaction record
      const transactionData = {
        from_account_id:
          make_it_look_like_transfer && from_user_id ? account_id : null,
        to_account_id: make_it_look_like_transfer ? account_id : null,
        from_user_id:
          make_it_look_like_transfer && from_user_id ? from_user_id : null,
        to_user_id: make_it_look_like_transfer ? userId : null,
        amount: Math.abs(amount),
        description: description || `Admin balance adjustment: ${action}`,
        transaction_type: "admin_adjustment",
        status: "completed",
        completed_at: new Date(),
        is_admin_adjusted: true,
        admin_note: `Adjusted by our Team ${req.user.email}`,
      };

      const { data: transaction } = await supabase
        .from("transactions_new")
        .insert(transactionData)
        .select()
        .single();

      // Create notification
      await supabase.from("notifications").insert({
        user_id: userId,
        title: "Balance Updated",
        message: `Your account balance has been updated. New balance: ₦${newBalance.toFixed(2)}`,
        type: "info",
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "update_balance",
        target_user_id: userId,
        details: {
          account_id,
          amount,
          action,
          make_it_look_like_transfer,
          from_user_id,
        },
      });

      res.json({
        message: "Balance updated successfully",
        new_balance: newBalance,
        transaction: make_it_look_like_transfer ? transaction : null,
      });
    } catch (error) {
      console.error("Admin update balance error:", error);
      res.status(500).json({ error: "Failed to update balance" });
    }
  },
);

// Impersonate user (admin)
app.post(
  "/api/sys/impersonate/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Get user details
      const { data: user } = await supabase
        .from("users")
        .select("*")
        .eq("id", userId)
        .single();

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Generate impersonation token
      const token = jwt.sign(
        {
          userId: user.id,
          email: user.email,
          role: user.role,
          isImpersonated: true,
          adminId: req.user.id,
        },
        process.env.JWT_SECRET,
        { expiresIn: "1h" },
      );

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "impersonate",
        target_user_id: userId,
        details: { impersonated_by: req.user.email },
      });

      res.json({
        message: "Impersonation successful",
        token,
        user: {
          id: user.id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          role: user.role,
          isImpersonated: true,
        },
      });
    } catch (error) {
      console.error("Impersonation error:", error);
      res.status(500).json({ error: "Impersonation failed" });
    }
  },
);

// Get all transactions (admin)
app.get(
  "/api/sys/transactions",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        page = 1,
        limit = 50,
        user_id,
        type,
        status,
        start_date,
        end_date,
      } = req.query;
      const offset = (page - 1) * limit;

      /*let query = supabase
        .from("transactions_new")
        .select(
          "*, from_account:accounts!transactions_from_account_id_fkey(*), to_account:accounts!transactions_to_account_id_fkey(*)",
          { count: "exact" },
        );

      if (user_id) {
        query = query.or(`from_user_id.eq.${user_id},to_user_id.eq.${user_id}`);
      }*/

      let query = supabase
        .from("transactions_new")
        .select(
          "*, from_account:accounts!transactions_new_sender_account_id_fkey(*), to_account:accounts!transactions_new_receiver_account_id_fkey(*)",
          { count: "exact" },
        );

      if (user_id) {
        query = query.or(
          `sender_user_id.eq.${user_id},receiver_user_id.eq.${user_id}`,
        );
      }

      if (type) {
        query = query.eq("transaction_type", type);
      }

      if (status) {
        query = query.eq("status", status);
      }

      if (start_date) {
        query = query.gte("created_at", start_date);
      }

      if (end_date) {
        query = query.lte("created_at", end_date);
      }

      const {
        data: transactions,
        count,
        error,
      } = await query
        .order("created_at", { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) throw error;

      res.json({
        transactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count,
          pages: Math.ceil(count / limit),
        },
      });
    } catch (error) {
      console.error("Admin transactions fetch error:", error);
      res.status(500).json({ error: "Failed to fetch transactions" });
    }
  },
);

// Approve/Reject transaction (admin)
app.post(
  "/api/sys/transactions/:transactionId/:action",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { transactionId, action } = req.params; // action: approve, reject
      const { reason } = req.body;

      const { data: transaction } = await supabase
        .from("transactions_new")
        .select("*")
        .eq("id", transactionId)
        .single();

      if (!transaction) {
        return res.status(404).json({ error: "Transaction not found" });
      }

      if (action === "approve" && transaction.status === "pending") {
        // Process transaction
        const { data: fromAccount } = await supabase
          .from("accounts")
          .select("*")
          .eq("id", transaction.sender_account_id)
          .single();

        const { data: toAccount } = await supabase
          .from("accounts")
          .select("*")
          .eq("id", transaction.receiver_account_id)
          .single();

        // Update balances
        await supabase
          .from("accounts")
          .update({
            balance: fromAccount.balance - transaction.amount,
            available_balance:
              fromAccount.available_balance - transaction.amount,
          })
          .eq("id", transaction.sender_account_id);

        await supabase
          .from("accounts")
          .update({
            balance: toAccount.balance + transaction.amount,
            available_balance: toAccount.available_balance + transaction.amount,
          })
          .eq("id", transaction.receiver_account_id);

        await supabase
          .from("transactions_new")
          .update({
            status: "completed",
            completed_at: new Date(),
          })
          .eq("id", transactionId);
      } else if (action === "reject") {
        await supabase
          .from("transactions_new")
          .update({
            status: "rejected",
            description:
              transaction.description + ` (Rejected: ${reason || "No reason"})`,
          })
          .eq("id", transactionId);
      }

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: `${action}_transaction`,
        target_user_id: transaction.sender_user_id,
        details: { transaction_id: transactionId, reason },
      });

      res.json({ message: `Transaction ${action}d successfully` });
    } catch (error) {
      console.error("Admin transaction action error:", error);
      res.status(500).json({ error: `Failed to ${action} transaction` });
    }
  },
);

// Generate OTP (admin)
app.post(
  "/api/sys/generate-otp",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { user_id, otp_type, transaction_id } = req.body;

      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      const { data: otp, error } = await supabase
        .from("otps")
        .insert({
          user_id,
          otp_code: otpCode,
          otp_type,
          transaction_id,
          expires_at: expiresAt,
        })
        .select()
        .single();

      if (error) throw error;

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "generate_otp",
        target_user_id: user_id,
        details: { otp_type, transaction_id },
      });

      res.json({
        message: "OTP generated successfully",
        otp_code: otpCode,
        expires_at: expiresAt,
        otp,
      });
    } catch (error) {
      console.error("OTP generation error:", error);
      res.status(500).json({ error: "Failed to generate OTP" });
    }
  },
);

// Toggle OTP mode (admin)
app.post(
  "/api/sys/toggle-otp-mode",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { mode } = req.body; // 'on' or 'off'

      await supabase.from("admin_settings").upsert(
        {
          setting_key: "otp_mode",
          setting_value: mode,
          updated_by: req.user.id,
          updated_at: new Date(),
        },
        { onConflict: "setting_key" },
      );

      // Also update related settings
      await supabase.from("admin_settings").upsert(
        {
          setting_key: "withdrawal_otp_required",
          setting_value: mode === "on" ? "true" : "false",
          updated_by: req.user.id,
          updated_at: new Date(),
        },
        { onConflict: "setting_key" },
      );

      await supabase.from("admin_settings").upsert(
        {
          setting_key: "transfer_otp_required",
          setting_value: mode === "on" ? "true" : "false",
          updated_by: req.user.id,
          updated_at: new Date(),
        },
        { onConflict: "setting_key" },
      );

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "toggle_otp_mode",
        details: { mode },
      });

      res.json({ message: `OTP mode turned ${mode}` });
    } catch (error) {
      console.error("Toggle OTP mode error:", error);
      res.status(500).json({ error: "Failed to toggle OTP mode" });
    }
  },
);

// ============================================================
// FEE MANAGEMENT — admin-editable transfer_fee_tiers
// Backs the Fee Management screen (admin-fee-management.js) and is
// the single source of truth calculate_external_transfer_fee() reads
// in external-transfer-service.js. Internal transfers made via the
// dedicated Internal Transfer button are NOT priced from this table —
// they stay free, per spec, regardless of what's configured here.
// ============================================================
app.get(
  "/api/sys/fee-tiers",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("transfer_fee_tiers")
        .select("*")
        .order("sort_order", { ascending: true });
      if (error) throw error;
      res.json({ success: true, tiers: data || [] });
    } catch (error) {
      console.error("Fetch fee tiers error:", error);
      res.status(500).json({ error: "Failed to fetch fee tiers" });
    }
  },
);

app.post(
  "/api/sys/fee-tiers",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        min_amount,
        max_amount,
        flat_fee,
        percentage_fee,
        fee_cap,
        label,
        sort_order,
      } = req.body;

      if (min_amount === undefined || flat_fee === undefined) {
        return res
          .status(400)
          .json({ error: "min_amount and flat_fee are required" });
      }

      const { data, error } = await supabase
        .from("transfer_fee_tiers")
        .insert({
          min_amount,
          max_amount: max_amount ?? null,
          flat_fee,
          percentage_fee: percentage_fee || 0,
          fee_cap: fee_cap ?? null,
          label: label || null,
          sort_order: sort_order ?? 0,
          updated_by: req.user.id,
        })
        .select()
        .single();
      if (error) throw error;

      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "create_fee_tier",
        details: data,
      });

      res.json({ success: true, tier: data });
    } catch (error) {
      console.error("Create fee tier error:", error);
      res.status(500).json({ error: "Failed to create fee tier" });
    }
  },
);

app.put(
  "/api/sys/fee-tiers/:id",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        min_amount,
        max_amount,
        flat_fee,
        percentage_fee,
        fee_cap,
        label,
        sort_order,
        is_active,
      } = req.body;

      const updates = { updated_by: req.user.id, updated_at: new Date() };
      if (min_amount !== undefined) updates.min_amount = min_amount;
      if (max_amount !== undefined) updates.max_amount = max_amount;
      if (flat_fee !== undefined) updates.flat_fee = flat_fee;
      if (percentage_fee !== undefined) updates.percentage_fee = percentage_fee;
      if (fee_cap !== undefined) updates.fee_cap = fee_cap;
      if (label !== undefined) updates.label = label;
      if (sort_order !== undefined) updates.sort_order = sort_order;
      if (is_active !== undefined) updates.is_active = is_active;

      const { data, error } = await supabase
        .from("transfer_fee_tiers")
        .update(updates)
        .eq("id", id)
        .select()
        .single();
      if (error) throw error;

      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "update_fee_tier",
        details: { id, updates },
      });

      res.json({ success: true, tier: data });
    } catch (error) {
      console.error("Update fee tier error:", error);
      res.status(500).json({ error: "Failed to update fee tier" });
    }
  },
);

app.delete(
  "/api/sys/fee-tiers/:id",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { error } = await supabase
        .from("transfer_fee_tiers")
        .update({ is_active: false, updated_by: req.user.id, updated_at: new Date() })
        .eq("id", id);
      if (error) throw error;

      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "deactivate_fee_tier",
        details: { id },
      });

      res.json({ success: true });
    } catch (error) {
      console.error("Deactivate fee tier error:", error);
      res.status(500).json({ error: "Failed to deactivate fee tier" });
    }
  },
);

// Get admin settings
app.get("/api/sys/settings", authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { data: settings, error } = await supabase
      .from("admin_settings")
      .select("*");

    if (error) throw error;

    res.json(settings);
  } catch (error) {
    console.error("Admin settings fetch error:", error);
    res.status(500).json({ error: "Failed to fetch settings" });
  }
});

// Update admin settings
app.post(
  "/api/sys/settings",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const settings = req.body;

      for (const [key, value] of Object.entries(settings)) {
        await supabase.from("admin_settings").upsert(
          {
            setting_key: key,
            setting_value: value,
            updated_by: req.user.id,
            updated_at: new Date(),
          },
          { onConflict: "setting_key" },
        );
      }

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "update_settings",
        details: settings,
      });

      res.json({ message: "Settings updated successfully" });
    } catch (error) {
      console.error("Admin settings update error:", error);
      res.status(500).json({ error: "Failed to update settings" });
    }
  },
);

// GET /api/user/transactions/category-summary
app.get(
  "/api/user/transactions/category-summary",
  authenticate,
  checkAccountFrozen,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("transactions_new")
        .select("amount, description, created_at, status")
        .eq("sender_user_id", req.user.id) // outgoing only
        .eq("status", "completed")
        .gte(
          "created_at",
          new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        ); // last 30 days

      if (error) throw error;

      // Group by category
      const summary = data.reduce((acc, tx) => {
        const cat = tx.category || "Other";
        acc[cat] = (acc[cat] || 0) + Math.abs(tx.amount);
        return acc;
      }, {});

      // Convert to array for chart
      const result = Object.entries(summary).map(([category, total]) => ({
        category,
        total: Number(total.toFixed(2)),
      }));

      res.json(result);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to load category summary" });
    }
  },
);

// Get single user details (admin) - FIXED with face images
app.get(
  "/api/sys/users/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Get user with all fields
      const { data: user, error: userError } = await supabase
        .from("users")
        .select(
          `
          id,
          email,
          first_name,
          last_name,
          middle_name,
          phone,
          date_of_birth,
          age,
          gender,
          marital_status,
          occupation,
          referral_code,
          address,
          city,
          state,
          country,
          postal_code,
          identification_type,
          identification_number,
          security_question_1,
          security_question_2,
          role,
          admin_role,
          admin_permissions,
          kyc_status,
          is_active,
          is_frozen,
          freeze_reason,
          two_factor_enabled,
          face_verified,
          face_quality_score,
          face_embedding,
          created_at,
          updated_at,
          last_login
        `,
        )
        .eq("id", userId)
        .single();

      if (userError || !user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Get accounts
      const { data: accounts } = await supabase
        .from("accounts")
        .select("*")
        .eq("user_id", userId);

      // Get cards
      const { data: cards } = await supabase
        .from("cards")
        .select("*")
        .eq("user_id", userId);

      // Get recent transactions (last 50)
      const { data: transactions } = await supabase
        .from("transactions_new")
        .select(
          `
          id,
          transaction_id,
          amount,
          description,
          transaction_type,
          status,
          created_at,
          completed_at,
          from_account_id,
          to_account_id,
          from_user_id,
          to_user_id
        `,
        )
        .or(`from_user_id.eq.${userId},to_user_id.eq.${userId}`)
        .order("created_at", { ascending: false })
        .limit(50);

      // ========== FIXED: Get face descriptors with images ==========
      const { data: faceDescriptors } = await supabase
        .from("face_descriptors")
        .select("id, descriptor, created_at, is_active")
        .eq("user_id", userId)
        .eq("is_active", true)
        .order("created_at", { ascending: true })
        .limit(10); // Get up to 10 face images

      // Process face descriptors to extract images
      let processedFaceDescriptors = [];
      let firstFaceImage = null;

      if (faceDescriptors && faceDescriptors.length > 0) {
        processedFaceDescriptors = faceDescriptors
          .map((fd) => {
            // Check if descriptor contains an image
            let imageData = null;
            if (fd.descriptor) {
              if (typeof fd.descriptor === "object" && fd.descriptor.image) {
                imageData = fd.descriptor.image;
                if (!firstFaceImage) firstFaceImage = imageData;
              } else if (
                typeof fd.descriptor === "string" &&
                fd.descriptor.startsWith("data:image")
              ) {
                imageData = fd.descriptor;
                if (!firstFaceImage) firstFaceImage = imageData;
              }
            }
            return {
              id: fd.id,
              image: imageData,
              created_at: fd.created_at,
              is_active: fd.is_active,
            };
          })
          .filter((fd) => fd.image); // Only keep those with images
      }

      // Also check if user table has face_embedding with image
      let userFaceImage = null;
      if (user.face_embedding) {
        if (
          typeof user.face_embedding === "object" &&
          user.face_embedding.image
        ) {
          userFaceImage = user.face_embedding.image;
        } else if (
          typeof user.face_embedding === "string" &&
          user.face_embedding.startsWith("data:image")
        ) {
          userFaceImage = user.face_embedding;
        }
      }

      // Use the first available face image
      const finalFaceImage = firstFaceImage || userFaceImage;

      // Combine all data
      const completeUser = {
        ...user,
        accounts: accounts || [],
        cards: cards || [],
        transactions: transactions || [],
        face_descriptors: processedFaceDescriptors,
        face_descriptor_count: processedFaceDescriptors.length,
        face_image: finalFaceImage, // Add this field for easy access
        has_face_descriptor: processedFaceDescriptors.length > 0,
        has_passcode: !!user.passcode_hash,
      };

      res.json(completeUser);
    } catch (error) {
      console.error("Admin user fetch error:", error);
      res.status(500).json({
        error: "Failed to fetch user",
        details: error.message,
      });
    }
  },
);

// ==================== UPDATE USER (ADMIN) - SINGLE PRODUCTION VERSION ====================
app.put(
  "/api/sys/users/:userId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const updates = req.body;

      console.log(
        `[Admin] Updating user ${userId} with:`,
        Object.keys(updates),
      );

      // Remove sensitive fields that should never be updated directly
      delete updates.password_hash;
      delete updates.id;
      delete updates.created_at;
      delete updates.deleted_at;

      // Prepare safe updates object
      const safeUpdates = {};

      // Allowed fields for update
      const allowedFields = [
        "first_name",
        "last_name",
        "middle_name",
        "email",
        "phone",
        "date_of_birth",
        "age",
        "gender",
        "marital_status",
        "occupation",
        "referral_code",
        "address",
        "city",
        "state",
        "country",
        "postal_code",
        "role",
        "admin_role",
        "admin_permissions",
        "kyc_status",
        "identification_type",
        "identification_number",
        "is_active",
        "is_frozen",
        "freeze_reason",
        "two_factor_enabled",
        "face_verified",
      ];

      allowedFields.forEach((field) => {
        if (updates[field] !== undefined) {
          // Handle admin_permissions specially - must be JSONB
          if (field === "admin_permissions") {
            // If it's null, keep null
            if (updates[field] === null) {
              safeUpdates[field] = null;
            }
            // If it's an object, stringify for JSONB storage
            else if (typeof updates[field] === "object") {
              safeUpdates[field] = JSON.stringify(updates[field]);
            }
            // If it's already a string, use as-is
            else if (typeof updates[field] === "string") {
              safeUpdates[field] = updates[field];
            }
          }
          // Allow null for admin_role (revoke operation)
          else if (field === "admin_role") {
            safeUpdates[field] = updates[field]; // can be null or string
          }
          // Regular fields - only include if not null/empty
          else if (updates[field] !== null && updates[field] !== "") {
            safeUpdates[field] = updates[field];
          }
          // Allow false boolean values
          else if (updates[field] === false) {
            safeUpdates[field] = false;
          }
        }
      });

      // Always add timestamp
      safeUpdates.updated_at = new Date().toISOString();

      // Check email uniqueness if changed
      if (safeUpdates.email) {
        const { data: existingUser, error: checkError } = await supabase
          .from("users")
          .select("id")
          .eq("email", safeUpdates.email)
          .neq("id", userId)
          .maybeSingle();

        if (existingUser) {
          return res.status(400).json({ error: "Email already in use" });
        }
      }

      // Log what we're updating
      console.log(`[Admin] Applying updates:`, Object.keys(safeUpdates));

      // Update user
      const { data: user, error: updateError } = await supabase
        .from("users")
        .update(safeUpdates)
        .eq("id", userId)
        .select(
          `
          id,
          email,
          first_name,
          last_name,
          middle_name,
          phone,
          date_of_birth,
          age,
          gender,
          marital_status,
          occupation,
          role,
          admin_role,
          admin_permissions,
          kyc_status,
          is_active,
          is_frozen,
          face_verified,
          updated_at
        `,
        )
        .single();

      if (updateError) {
        console.error("[Admin] Update error:", updateError);
        return res
          .status(500)
          .json({ error: "Failed to update user: " + updateError.message });
      }

      // This route can change is_active/is_frozen/role (see
      // allowedFields above) — invalidate unconditionally rather than
      // checking which fields were actually touched, since missing a
      // case here is a security gap and the invalidation itself is
      // just a cheap INCR.
      await bumpUserCacheVersion("authuser", userId);

      // Log admin action for audit
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "update_user",
        target_user_id: userId,
        details: {
          updated_fields: Object.keys(safeUpdates),
          timestamp: new Date().toISOString(),
        },
        ip_address: req.ip,
        created_at: new Date().toISOString(),
      });

      // Send notification to user for important changes
      if (updates.role !== undefined && user.role !== updates.role) {
        await supabase.from("notifications").insert({
          user_id: userId,
          title: "Account Role Updated",
          message: `Your account role has been updated to: ${updates.role.toUpperCase()}`,
          type: "info",
          created_at: new Date().toISOString(),
        });
      }

      if (updates.is_frozen !== undefined) {
        await supabase.from("notifications").insert({
          user_id: userId,
          title: updates.is_frozen ? "Account Frozen" : "Account Unfrozen",
          message: updates.is_frozen
            ? `Your account has been frozen. Reason: ${updates.freeze_reason || "Not specified"}`
            : "Your account has been unfrozen.",
          type: updates.is_frozen ? "warning" : "success",
          created_at: new Date().toISOString(),
        });
      }

      // Parse admin_permissions back to object for response
      if (
        user.admin_permissions &&
        typeof user.admin_permissions === "string"
      ) {
        try {
          user.admin_permissions = JSON.parse(user.admin_permissions);
        } catch (e) {
          // Leave as is if parsing fails
        }
      }

      res.json({
        success: true,
        message: "User updated successfully",
        user,
      });
    } catch (error) {
      console.error("[Admin] Update user error:", error);
      res
        .status(500)
        .json({ error: "Failed to update user: " + error.message });
    }
  },
);

// Reset user password (admin)
app.post(
  "/api/sys/users/:userId/reset-password",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Generate temporary password
      const tempPassword =
        Math.random().toString(36).slice(-8) +
        Math.random().toString(36).slice(-8).toUpperCase() +
        "!1";
      const hashedPassword = await bcrypt.hash(tempPassword, 10);

      // Update password
      await supabase
        .from("users")
        .update({ password_hash: hashedPassword })
        .eq("id", userId);

      // Create notification
      await supabase.from("notifications").insert({
        user_id: userId,
        title: "Password Reset",
        message:
          "Your password has been reset by an administrator. Please check your email for the new temporary password.",
        type: "warning",
      });

      // In a real application, send email with temporary password
      console.log(`Temporary password for user ${userId}: ${tempPassword}`);

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "reset_password",
        target_user_id: userId,
      });

      res.json({ message: "Password reset successfully" });
    } catch (error) {
      console.error("Admin reset password error:", error);
      res.status(500).json({ error: "Failed to reset password" });
    }
  },
);

// Get single transaction details (admin)
app.get(
  "/api/sys/transactions/:transactionId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { transactionId } = req.params;

      /*const { data: transaction, error } = await supabase
        .from("transactions_new")
        .select(
          `
                *,
                from_account:accounts!transactions_from_account_id_fkey(*),
                to_account:accounts!transactions_to_account_id_fkey(*),
                from_user:users!transactions_from_user_id_fkey(first_name, last_name, email),
                to_user:users!transactions_to_user_id_fkey(first_name, last_name, email)
            `,
        )
        .eq("id", transactionId)
        .single();*/

      const { data: transaction, error } = await supabase
        .from("transactions_new")
        .select(
          `
                        *,
                        from_account:accounts!transactions_new_sender_account_id_fkey(*),
                        to_account:accounts!transactions_new_receiver_account_id_fkey(*),
                        from_user:users!transactions_new_sender_user_id_fkey(first_name, last_name, email),
                        to_user:users!transactions_new_receiver_user_id_fkey(first_name, last_name, email)
                    `,
        )
        .eq("id", transactionId)
        .single();

      if (error) throw error;

      res.json(transaction);
    } catch (error) {
      console.error("Admin transaction fetch error:", error);
      res.status(500).json({ error: "Failed to fetch transaction" });
    }
  },
);

// Toggle card status (admin)
app.post(
  "/api/sys/cards/:cardId/toggle",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { cardId } = req.params;
      const { action } = req.body; // 'freeze' or 'unfreeze'

      const newStatus = action === "freeze" ? "frozen" : "active";

      const { data: card, error } = await supabase
        .from("cards")
        .update({ card_status: newStatus })
        .eq("id", cardId)
        .select()
        .single();

      if (error) throw error;

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: card.user_id,
        title: `Card ${action}d`,
        message: `Your card ending in ${card.card_number.slice(-4)} has been ${action}d by an administrator.`,
        type: "warning",
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: `card_${action}`,
        target_user_id: card.user_id,
        details: { card_id: cardId },
      });

      res.json({ message: `Card ${action}d successfully`, card });
    } catch (error) {
      console.error("Admin toggle card error:", error);
      res.status(500).json({ error: "Failed to toggle card" });
    }
  },
);

// Report card as lost/stolen (admin)
app.post(
  "/api/sys/cards/:cardId/report",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { cardId } = req.params;

      const { data: card, error } = await supabase
        .from("cards")
        .update({ card_status: "lost" })
        .eq("id", cardId)
        .select()
        .single();

      if (error) throw error;

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: card.user_id,
        title: "Card Reported Lost/Stolen",
        message: `Your card ending in ${card.card_number.slice(-4)} has been reported as lost/stolen. A new card will be issued.`,
        type: "danger",
      });

      // Create support ticket
      await supabase.from("support_tickets").insert({
        user_id: card.user_id,
        subject: "Lost/Stolen Card Reported",
        message: `Card ending in ${card.card_number.slice(-4)} reported as lost/stolen by administrator.`,
        priority: "high",
      });

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "card_report_lost",
        target_user_id: card.user_id,
        details: { card_id: cardId },
      });

      res.json({ message: "Card reported successfully", card });
    } catch (error) {
      console.error("Admin report card error:", error);
      res.status(500).json({ error: "Failed to report card" });
    }
  },
);

// FIXED: GET /api/sys/support-tickets (no more 500)
app.get(
  "/api/sys/support-tickets",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { status, search } = req.query;

      let query = supabase
        .from("support_tickets")
        .select(
          `
                *,
                users!user_id (first_name, last_name, email)
            `,
        )
        .order("created_at", { ascending: false });

      if (status) query = query.eq("status", status);
      if (search) query = query.ilike("subject", `%${search}%`);

      const { data: tickets, error } = await query;

      if (error) throw error;

      res.json({ tickets: tickets || [] });
    } catch (err) {
      console.error("Support tickets error:", err.message);
      res.status(500).json({ error: "Failed to load tickets" });
    }
  },
);

// Get support tickets (admin)
app.get(
  "/api/sys/support-tickets",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { status, priority, page = 1, limit = 20 } = req.query;
      const offset = (page - 1) * limit;

      let query = supabase
        .from("support_tickets")
        .select("*, user:users(first_name, last_name, email)", {
          count: "exact",
        });

      if (status) {
        query = query.eq("status", status);
      }

      if (priority) {
        query = query.eq("priority", priority);
      }

      const {
        data: tickets,
        count,
        error,
      } = await query
        .order("created_at", { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) throw error;

      res.json({
        tickets,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count,
          pages: Math.ceil(count / limit),
        },
      });
    } catch (error) {
      console.error("Admin tickets fetch error:", error);
      res.status(500).json({ error: "Failed to fetch support tickets" });
    }
  },
);

// ==================== FIXED SUPPORT TICKET MESSAGES ROUTE ====================

// Get messages for a support ticket (admin) - FIXED
app.get(
  "/api/sys/support-tickets/:ticketId/messages",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { ticketId } = req.params;

      // First verify ticket exists
      const { data: ticket, error: ticketError } = await supabase
        .from("support_tickets")
        .select("id, user_id, status")
        .eq("id", ticketId)
        .single();

      if (ticketError || !ticket) {
        return res.status(404).json({ error: "Ticket not found" });
      }

      // Get messages with sender info
      const { data: messages, error } = await supabase
        .from("chat_messages")
        .select(
          `
          *,
          sender:sender_id (id, first_name, last_name, email, role)
        `,
        )
        .eq("ticket_id", ticketId)
        .order("created_at", { ascending: true });

      if (error) {
        console.error("Messages fetch error:", error);
        return res.status(500).json({ error: "Failed to fetch messages" });
      }

      // Also get user info for the ticket
      const { data: user } = await supabase
        .from("users")
        .select("first_name, last_name, email")
        .eq("id", ticket.user_id)
        .single();

      res.json({
        messages: messages || [],
        ticket: {
          id: ticket.id,
          status: ticket.status,
          user: user,
        },
      });
    } catch (error) {
      console.error("Support ticket messages error:", error);
      res.status(500).json({ error: "Failed to fetch ticket messages" });
    }
  },
);

// Reply to support ticket (admin)
app.post(
  "/api/sys/support-tickets/:ticketId/reply",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { ticketId } = req.params;
      const { message } = req.body;

      // Update ticket status
      await supabase
        .from("support_tickets")
        .update({
          status: "in_progress",
          updated_at: new Date(),
        })
        .eq("id", ticketId);

      // Add admin reply
      const { data: reply } = await supabase
        .from("chat_messages")
        .insert({
          ticket_id: ticketId,
          sender_id: req.user.id,
          message,
          is_admin_reply: true,
        })
        .select()
        .single();

      // Get ticket to get user_id
      const { data: ticket } = await supabase
        .from("support_tickets")
        .select("user_id")
        .eq("id", ticketId)
        .single();

      // Create notification for user
      await supabase.from("notifications").insert({
        user_id: ticket.user_id,
        title: "New Support Reply",
        message: "An admin has replied to your support ticket",
        type: "info",
        action_url: `/support/${ticketId}`,
      });

      res.json({ message: "Reply sent successfully", reply });
    } catch (error) {
      console.error("Admin ticket reply error:", error);
      res.status(500).json({ error: "Failed to send reply" });
    }
  },
);

// Close support ticket (admin)
app.post(
  "/api/sys/support-tickets/:ticketId/close",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { ticketId } = req.params;
      const { resolution } = req.body;

      await supabase
        .from("support_tickets")
        .update({
          status: "closed",
          updated_at: new Date(),
        })
        .eq("id", ticketId);

      // Get ticket to get user_id
      const { data: ticket } = await supabase
        .from("support_tickets")
        .select("user_id")
        .eq("id", ticketId)
        .single();

      // Create notification
      await supabase.from("notifications").insert({
        user_id: ticket.user_id,
        title: "Support Ticket Closed",
        message: resolution || "Your support ticket has been closed",
        type: "info",
      });

      res.json({ message: "Ticket closed successfully" });
    } catch (error) {
      console.error("Admin close ticket error:", error);
      res.status(500).json({ error: "Failed to close ticket" });
    }
  },
);

// ============================================
// ADMIN PUSH NOTIFICATIONS API
// ============================================

/*const ONESIGNAL_APP_ID = process.env.ONESIGNAL_APP_ID;
const ONESIGNAL_REST_API_KEY = process.env.ONESIGNAL_REST_API_KEY;

// Helper: Send push via OneSignal
async function sendOneSignalPush(
  playerIds,
  title,
  message,
  data = {},
  options = {},
) {
  if (!ONESIGNAL_APP_ID || !ONESIGNAL_REST_API_KEY) {
    console.error("[OneSignal] Missing API keys");
    return { success: false, error: "Missing API keys" };
  }

  const playerIdArray = Array.isArray(playerIds) ? playerIds : [playerIds];

  if (playerIdArray.length === 0) {
    return { success: false, error: "No player IDs provided" };
  }

  const requestBody = {
    app_id: ONESIGNAL_APP_ID,
    headings: { en: title },
    contents: { en: message },
    include_player_ids: playerIdArray,
    data: data,
    priority: options.priority || 10,
    ttl: options.ttl || 86400,
    small_icon: "ic_stat_onesignal_default",
    large_icon: "ic_stat_onesignal_default",
  };

  if (options.iosSound) requestBody.ios_sound = options.iosSound;
  if (options.androidSound) requestBody.android_sound = options.androidSound;

  try {
    const response = await fetch("https://onesignal.com/api/v1/notifications", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${ONESIGNAL_REST_API_KEY}`,
      },
      body: JSON.stringify(requestBody),
    });

    const result = await response.json();

    if (result.id) {
      return {
        success: true,
        notification_id: result.id,
        recipients: playerIdArray.length,
      };
    } else {
      return {
        success: false,
        error: result.errors?.join(", ") || "Unknown error",
      };
    }
  } catch (error) {
    console.error("[OneSignal] Send error:", error);
    return { success: false, error: error.message };
  }
}*/

// Helper: Get push tokens for users
async function getUserPushTokens(userIds) {
  const { data: tokens, error } = await supabase
    .from("user_push_tokens")
    .select("user_id, push_token")
    .in("user_id", userIds)
    .in("platform", ["android", "ios"])
    .eq("is_active", true);

  if (error || !tokens) return [];
  return tokens;
}

// GET: Available user groups for push targeting
app.get(
  "/api/sys/push/user-groups",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      // Get counts for different user groups
      const [
        { count: totalUsers },
        { count: frozenUsers },
        { count: activeSavingsUsers },
        { count: hasPushTokenUsers },
      ] = await Promise.all([
        supabase
          .from("users")
          .select("*", { count: "exact", head: true })
          .eq("is_active", true),
        supabase
          .from("users")
          .select("*", { count: "exact", head: true })
          .eq("is_frozen", true),
        supabase
          .from("user_harvest_enrollments")
          .select("user_id", { count: "exact", head: true })
          .eq("status", "active"),
        supabase
          .from("user_push_tokens")
          .select("user_id", { count: "exact", head: true })
          .eq("platform", "onesignal")
          .eq("is_active", true),
      ]);

      res.json({
        groups: [
          {
            id: "all",
            name: "All Active Users",
            count: totalUsers || 0,
            description: "Send to all active users",
          },
          {
            id: "has_push_token",
            name: "Users with Push Enabled",
            count: hasPushTokenUsers || 0,
            description: "Users who have enabled push notifications",
          },
          {
            id: "frozen",
            name: "Frozen Accounts",
            count: frozenUsers || 0,
            description: "Users with frozen accounts",
          },
          {
            id: "active_savings",
            name: "Active Savings Users",
            count: activeSavingsUsers || 0,
            description: "Users with active savings plans",
          },
          {
            id: "recent_active",
            name: "Recently Active",
            count: 0,
            description: "Users active in last 7 days (requires tracking)",
          },
          {
            id: "specific",
            name: "Specific Users",
            count: 0,
            description: "Select individual users",
          },
        ],
      });
    } catch (error) {
      console.error("Error fetching user groups:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// GET: Search users for specific targeting
app.get(
  "/api/sys/push/search-users",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { q, limit = 20 } = req.query;

      if (!q || q.length < 2) {
        return res.json({ users: [] });
      }

      const { data: users, error } = await supabase
        .from("users")
        .select("id, email, first_name, last_name, is_frozen, is_active")
        .or(`email.ilike.%${q}%,first_name.ilike.%${q}%,last_name.ilike.%${q}%`)
        .limit(parseInt(limit));

      if (error) throw error;

      // Check which users have push tokens
      const userIds = users.map((u) => u.id);
      const { data: tokens } = await supabase
        .from("user_push_tokens")
        .select("user_id")
        .in("user_id", userIds)
        .eq("platform", "onesignal")
        .eq("is_active", true);

      const pushEnabledUserIds = new Set(tokens?.map((t) => t.user_id) || []);

      const enrichedUsers = users.map((user) => ({
        ...user,
        has_push_token: pushEnabledUserIds.has(user.id),
        name:
          `${user.first_name || ""} ${user.last_name || ""}`.trim() ||
          user.email,
      }));

      res.json({ users: enrichedUsers });
    } catch (error) {
      console.error("Error searching users:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// POST: Send push notification (admin)
app.post(
  "/api/sys/push/send",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const {
        title,
        message,
        target_type,
        target_user_ids,
        data = {},
        schedule_time,
      } = req.body;

      // Validation
      if (!title || !title.trim()) {
        return res.status(400).json({ error: "Title is required" });
      }
      if (!message || !message.trim()) {
        return res.status(400).json({ error: "Message is required" });
      }
      if (!target_type) {
        return res.status(400).json({ error: "Target type is required" });
      }

      let userIds = [];
      let pushTokens = [];

      // Get users based on target type
      switch (target_type) {
        case "all":
          // All active users
          const { data: allUsers } = await supabase
            .from("users")
            .select("id")
            .eq("is_active", true);
          userIds = allUsers?.map((u) => u.id) || [];
          break;

        case "has_push_token":
          // Users with push tokens
          const { data: tokenUsers } = await supabase
            .from("user_push_tokens")
            .select("user_id")
            .eq("platform", "onesignal")
            .eq("is_active", true);
          userIds = [...new Set(tokenUsers?.map((t) => t.user_id) || [])];
          break;

        case "frozen":
          const { data: frozenUsers } = await supabase
            .from("users")
            .select("id")
            .eq("is_frozen", true);
          userIds = frozenUsers?.map((u) => u.id) || [];
          break;

        case "active_savings":
          // Users with active harvest plans
          const { data: savingsUsers } = await supabase
            .from("user_harvest_enrollments")
            .select("user_id")
            .eq("status", "active");
          userIds = [...new Set(savingsUsers?.map((s) => s.user_id) || [])];
          break;

        case "recent_active":
          // Users active in last 7 days (based on last_login)
          const sevenDaysAgo = new Date();
          sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
          const { data: recentUsers } = await supabase
            .from("users")
            .select("id")
            .gte("last_login", sevenDaysAgo.toISOString());
          userIds = recentUsers?.map((u) => u.id) || [];
          break;

        case "specific":
          if (!target_user_ids || target_user_ids.length === 0) {
            return res
              .status(400)
              .json({ error: "Please select at least one user" });
          }
          userIds = target_user_ids;
          break;

        default:
          return res.status(400).json({ error: "Invalid target type" });
      }

      if (userIds.length === 0) {
        return res
          .status(400)
          .json({ error: "No users found for the selected target group" });
      }

      // Get push tokens for these users
      const tokens = await getUserPushTokens(userIds);

      if (tokens.length === 0) {
        return res.status(400).json({
          error: "None of the selected users have push notifications enabled",
        });
      }

      // Group by push token (deduplicate)
      const uniqueTokens = [
        ...new Map(tokens.map((t) => [t.push_token, t])).values(),
      ];
      const playerIds = uniqueTokens.map((t) => t.push_token);

      // Send push via OneSignal
      // Send push via FCM
      const pushResult = await sendToTokens(playerIds, {
        title,
        body: message,
        data: {
          type: "admin_push",
          admin_id: req.user.id,
          timestamp: new Date().toISOString(),
          ...data,
        },
      });

      // Log the push
      const { error: logError } = await supabase
        .from("admin_push_logs")
        .insert({
          admin_id: req.user.id,
          title: title,
          message: message,
          target_type: target_type,
          target_user_ids: target_type === "specific" ? target_user_ids : null,
          recipient_count: userIds.length,
          success_count: pushResult.success ? playerIds.length : 0,
          failed_count: pushResult.success ? 0 : playerIds.length,
          onesignal_notification_id: pushResult.notification_id || null,
        });

      if (logError) console.error("Failed to log push:", logError);

      // Create in-app notifications for all targeted users
      for (const userId of userIds.slice(0, 100)) {
        // Limit to 100 to avoid timeout
        await supabase
          .from("notifications")
          .insert({
            user_id: userId,
            title: title,
            message: message,
            type: "admin",
            created_at: new Date().toISOString(),
            is_read: false,
          })
          .catch((e) =>
            console.error("Failed to create notification for:", userId, e),
          );
      }

      res.json({
        success: pushResult.success,
        notification_id: pushResult.notification_id,
        recipients_found: userIds.length,
        push_sent: playerIds.length,
        message: pushResult.success
          ? `Push notification sent to ${playerIds.length} device(s)`
          : `Failed to send: ${pushResult.error}`,
      });
    } catch (error) {
      console.error("Send push error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// GET: Push notification history (admin)
app.get(
  "/api/sys/push/history",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { page = 1, limit = 20 } = req.query;
      const offset = (page - 1) * limit;

      const {
        data: logs,
        error,
        count,
      } = await supabase
        .from("admin_push_logs")
        .select(
          `
                *,
                admin:admin_id (id, email, first_name, last_name)
            `,
          { count: "exact" },
        )
        .order("created_at", { ascending: false })
        .range(offset, offset + limit - 1);

      if (error) throw error;

      res.json({
        logs: logs || [],
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: count || 0,
          pages: Math.ceil((count || 0) / limit),
        },
      });
    } catch (error) {
      console.error("Error fetching push history:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// Send push to specific user via OneSignal
app.post(
  "/api/notifications/send-push",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { user_id, title, message, data } = req.body;

      // Get user's OneSignal player ID
      const { data: tokens } = await supabase
        .from("user_push_tokens")
        .select("push_token")
        .eq("user_id", user_id)
        .eq("platform", "onesignal")
        .eq("is_active", true);

      if (!tokens || tokens.length === 0) {
        return res.json({ success: false, message: "No push token found" });
      }

      const playerIds = tokens.map((t) => t.push_token);

      // Send via OneSignal API
      const response = await fetch(
        "https://onesignal.com/api/v1/notifications",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Basic ${process.env.ONESIGNAL_REST_API_KEY}`,
          },
          body: JSON.stringify({
            app_id: process.env.ONESIGNAL_APP_ID,
            headings: { en: title },
            contents: { en: message },
            include_player_ids: playerIds,
            data: data || {},
            priority: 10,
          }),
        },
      );

      const result = await response.json();
      res.json({ success: result.id, notification_id: result.id });
    } catch (error) {
      console.error("Push send error:", error);
      res.status(500).json({ error: error.message });
    }
  },
);

// Process bulk operations (admin)
app.post(
  "/api/sys/bulk-operations",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { operation, users, amount, description } = req.body;
      const bulkReference = uuidv4();

      const results = [];

      for (const userId of users) {
        try {
          if (operation === "deposit") {
            // Get user's primary account
            const { data: account } = await supabase
              .from("accounts")
              .select("*")
              .eq("user_id", userId)
              .eq("account_type", "checking")
              .single();

            if (account) {
              await supabase
                .from("accounts")
                .update({
                  balance: account.balance + amount,
                  available_balance: account.available_balance + amount,
                })
                .eq("id", account.id);

              await supabase.from("transactions_new").insert({
                receiver_account_id: account.id,
                receiver_user_id: userId,
                amount,
                description: description || "Bulk deposit",
                transaction_type: "bulk_deposit",
                status: "completed",
                completed_at: new Date(),
                metadata: { is_bulk: true, bulk_reference: bulkReference },
              });

              results.push({ userId, status: "success" });
            }
          } else if (operation === "withdrawal") {
            // Similar logic for withdrawal
          }
        } catch (error) {
          results.push({ userId, status: "failed", error: error.message });
        }
      }

      // Log admin action
      await supabase.from("admin_actions").insert({
        admin_id: req.user.id,
        action_type: "bulk_operation",
        details: {
          operation,
          users_count: users.length,
          amount,
          bulk_reference: bulkReference,
          results,
        },
      });

      res.json({
        message: "Bulk operation completed",
        bulk_reference: bulkReference,
        results,
      });
    } catch (error) {
      console.error("Bulk operation error:", error);
      res.status(500).json({ error: "Bulk operation failed" });
    }
  },
);

// ==================== ADMIN LOGS ROUTES ====================

// Get admin action logs with pagination and filters
app.get("/api/sys/logs", authenticate, authorizeAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      action_type,
      target_user_id,
      start_date,
      end_date,
      search,
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    let query = supabase
      .from("admin_actions")
      .select(
        `
          *,
          admin:admin_id (id, email, first_name, last_name),
          target_user:target_user_id (id, email, first_name, last_name)
        `,
        { count: "exact" },
      )
      .order("created_at", { ascending: false });

    // Apply filters
    if (action_type && action_type !== "all") {
      query = query.eq("action_type", action_type);
    }

    if (target_user_id) {
      query = query.eq("target_user_id", target_user_id);
    }

    if (start_date) {
      query = query.gte("created_at", start_date);
    }

    if (end_date) {
      query = query.lte("created_at", `${end_date}T23:59:59`);
    }

    if (search) {
      query = query.or(
        `action_type.ilike.%${search}%,details::text.ilike.%${search}%`,
      );
    }

    const {
      data: logs,
      error,
      count,
    } = await query.range(offset, offset + parseInt(limit) - 1);

    if (error) throw error;

    // Get unique action types for filter dropdown
    const { data: actionTypes } = await supabase
      .from("admin_actions")
      .select("action_type")
      .limit(100);

    const uniqueActionTypes = [
      ...new Set((actionTypes || []).map((a) => a.action_type)),
    ];

    res.json({
      logs: logs || [],
      action_types: uniqueActionTypes,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Admin logs fetch error:", error);
    res.status(500).json({ error: "Failed to fetch admin logs" });
  }
});

// Get single log details
app.get(
  "/api/sys/logs/:logId",
  authenticate,
  authorizeAdmin,
  async (req, res) => {
    try {
      const { logId } = req.params;

      const { data: log, error } = await supabase
        .from("admin_actions")
        .select(
          `
          *,
          admin:admin_id (id, email, first_name, last_name),
          target_user:target_user_id (id, email, first_name, last_name)
        `,
        )
        .eq("id", logId)
        .single();

      if (error) throw error;

      res.json(log);
    } catch (error) {
      console.error("Admin log fetch error:", error);
      res.status(500).json({ error: "Failed to fetch log details" });
    }
  },
);

// Get admin dashboard stats
app.get("/api/sys/stats", authenticate, authorizeAdmin, async (req, res) => {
  try {
    // Total users
    const { count: totalUsers } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true });

    // Active users (not frozen, active)
    const { count: activeUsers } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true })
      .eq("is_active", true)
      .eq("is_frozen", false);

    // Frozen users
    const { count: frozenUsers } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true })
      .eq("is_frozen", true);

    // Pending KYC
    const { count: pendingKYC } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true })
      .eq("kyc_status", "pending");

    // Face verified users
    const { count: faceVerifiedUsers } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true })
      .eq("face_verified", true);

    // Users with passcode set
    const { count: passcodeUsers } = await supabase
      .from("users")
      .select("*", { count: "exact", head: true })
      .not("passcode_hash", "is", null);

    // Total transactions today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const { count: todayTransactions } = await supabase
      .from("transactions_new")
      .select("*", { count: "exact", head: true })
      .gte("created_at", today.toISOString());

    // Total volume today
    const { data: volumeData } = await supabase
      .from("transactions_new")
      .select("amount")
      .gte("created_at", today.toISOString())
      .eq("status", "completed");

    const todayVolume = volumeData?.reduce((sum, t) => sum + t.amount, 0) || 0;

    // Open support tickets
    const { count: openTickets } = await supabase
      .from("support_tickets")
      .select("*", { count: "exact", head: true })
      .eq("status", "open");

    res.json({
      totalUsers,
      activeUsers,
      frozenUsers,
      pendingKYC,
      faceVerifiedUsers,
      passcodeUsers,
      todayTransactions,
      todayVolume,
      openTickets,
      timestamp: new Date(),
    });
  } catch (error) {
    console.error("Admin stats error:", error);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// Create default admin user
const createDefaultAdmin = async () => {
  try {
    const { data: existingAdmin } = await supabase
      .from("users")
      .select("email")
      .eq("email", process.env.ADMIN_EMAIL)
      .single();

    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);

      await supabase.from("users").insert({
        email: process.env.ADMIN_EMAIL,
        password_hash: hashedPassword,
        first_name: "Admin",
        last_name: "User",
        role: "admin",
        kyc_status: "verified",
        is_active: true,
      });

      console.log("Default admin user created");
    }
  } catch (error) {
    console.error("Error creating default admin:", error);
  }
};

createDefaultAdmin();

// Add this instead (required for Vercel)
module.exports = app;