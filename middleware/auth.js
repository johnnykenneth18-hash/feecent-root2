const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const crypto = require("crypto");

const { getCachedUser, bumpUserCacheVersion } = require("../lib/cache-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");
    console.log("Auth header:", authHeader ? "Present" : "Missing");

    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      console.log("No token provided");
      return res.status(401).json({ error: "Please authenticate" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Token decoded for user:", decoded.userId);

    // Cache-aside on the per-request user lookup. This one query runs
    // on every one of ~70+ authenticated routes, so it's the single
    // hottest read in the app. TTL is short (5s) and is the PRIMARY
    // safety net here, not a backstop the way notif-cache's TTL is:
    // is_active/is_frozen/role are security-relevant, so every known
    // place that flips them (toggle-freeze, the generic admin user-edit
    // route, auto-freeze-on-balance-limit, freeze-due-to-pin-attempts,
    // unfreeze-via-otp, self-lock-account, close-account) also calls
    // bumpUserCacheVersion("authuser", userId) explicitly for
    // near-instant invalidation on those paths. The 5s TTL exists so
    // that even an update site nobody has wired invalidation into yet
    // (or one added later and missed) is bounded to a few seconds of
    // staleness, not "until someone notices a frozen account still
    // transacting."
    const user = await getCachedUser(decoded.userId, 5, async () => {
      const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("id", decoded.userId)
        .single();
      if (error || !data) return null;
      return data;
    });

    if (!user) {
      console.log("User not found:", decoded.userId);
      return res.status(401).json({ error: "User not found" });
    }

    if (!user.is_active) {
      console.log("User inactive:", user.id);
      return res.status(401).json({ error: "Account is deactivated" });
    }

    req.user = user;
    req.token = token;
    req.userRole = user.role; // Add this for easier access

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    res.status(401).json({ error: "Please authenticate" });
  }
};

// Admin authorization middleware — allows both 'admin' and 'super_admin'
/*const authorizeAdmin = async (req, res, next) => {
  if (req.user.role !== "admin" && req.user.role !== "super_admin") {
    return res.status(403).json({ error: "Access denied. Admin only." });
  }
  next();
};*/

const authorizeAdmin = async (req, res, next) => {
  // Super admin has full access to everything
  if (req.user.role === "super_admin") {
    return next();
  }

  // Regular admin
  if (req.user.role === "admin") {
    return next();
  }

  return res.status(403).json({ error: "Access denied. Admin only." });
};

// Strictly requires role === 'super_admin'. Deliberately separate from
// authorizeAdmin (which allows both admin and super_admin) — use this
// on operations even a fully-permissioned Admin should never be able to
// do, e.g. granting/changing/revoking admin access itself. Never derive
// this from req.body or any client-supplied value — always req.user.role,
// which authenticate() just re-read from the DB this request.
const requireSuperAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== "super_admin") {
    return res.status(403).json({
      error: "This action requires super admin access.",
      code: "SUPER_ADMIN_REQUIRED",
    });
  }
  next();
};

// ==================== SERVER-SIDE RBAC ENFORCEMENT ====================
// Mirrors the permission keys defined in admin-permissions.js's
// ACTIONS_REGISTRY on the frontend ("section:actionId", e.g.
// "users:freeze-user"). The two lists are kept in sync by convention —
// whenever a new action id is added client-side to gate a button, the
// matching route(s) it calls must get requirePermission(...) with the
// same key server-side. The client list controls what admins SEE; this
// is what actually controls what they can DO.
//
// This deliberately does not do its own DB read: authenticate() already
// fetched the full user row (role, admin_role, admin_permissions) fresh
// off Postgres this request (5s cache, explicitly invalidated the instant
// any of those fields changes via bumpUserCacheVersion), so req.user is
// already trustworthy and current. No client-supplied header, key, or
// body field is ever consulted for the authorization decision.
function requirePermission(permissionKey) {
  return (req, res, next) => {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ error: "Please authenticate" });
    }

    // Super admin: full access, always.
    if (user.role === "super_admin") {
      return next();
    }

    // Anything below "admin" never reaches action-level checks.
    if (user.role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admin only." });
    }

    // Admin with no role/permission set assigned yet -> deny by default,
    // not "deny only what's explicitly listed as missing."
    let permissions = user.admin_permissions;
    if (typeof permissions === "string") {
      try {
        permissions = JSON.parse(permissions);
      } catch (e) {
        permissions = null;
      }
    }

    const [section, actionId] = permissionKey.split(":");
    const allowed =
      !!permissions &&
      Array.isArray(permissions.actions?.[section]) &&
      permissions.actions[section].includes(actionId);

    if (!allowed) {
      console.warn(
        `[RBAC] Denied: admin ${user.id} (${user.admin_role || "no role"}) lacks "${permissionKey}" on ${req.method} ${req.originalUrl}`,
      );
      return res.status(403).json({
        error: `You don't have permission to perform this action.`,
        code: "PERMISSION_DENIED",
        required: permissionKey,
      });
    }

    next();
  };
}

// Check if account is frozen
const checkAccountFrozen = async (req, res, next) => {
  if (req.user.is_frozen) {
    return res.status(403).json({
      error: "Account frozen",
      freeze_reason: req.user.freeze_reason,
      canContact: true,
    });
  }
  next();
};

// Log admin actions
const logAdminAction = async (req, res, next) => {
  const originalJson = res.json;
  res.json = function (data) {
    if (req.user && req.user.role === "admin") {
      const { data: actionData, error } = supabase
        .from("admin_actions")
        .insert({
          admin_id: req.user.id,
          action_type: req.route ? req.route.path : "unknown",
          target_user_id: req.params.userId || req.body.userId,
          details: {
            method: req.method,
            body: req.body,
            params: req.params,
            query: req.query,
          },
          ip_address: req.ip,
        });
    }
    originalJson.call(this, data);
  };
  next();
};

// Rate limiting for OTP requests
const otpRateLimiter = require("express-rate-limit")({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: { error: "Too many OTP requests, please try again later" },
});

// ==================== TRANSACTION LOCKING MIDDLEWARE ====================

// Helper function to release lock
async function releaseLock(userId, requestId) {
  try {
    await supabase.rpc("release_transfer_lock", {
      p_user_id: userId,
      p_request_id: requestId,
    });
    console.log(`Lock released for user ${userId}`);
  } catch (error) {
    console.error("Error releasing lock:", error);
  }
}

// Middleware to prevent concurrent transfers
const preventConcurrentTransfer = async (req, res, next) => {
  try {
    const userId = req.user.id;

    // Generate unique request ID for this transaction attempt
    const requestId = crypto.randomUUID();

    // Check if user is already locked
    const { data: lockStatus, error: lockError } = await supabase.rpc(
      "is_user_locked",
      { p_user_id: userId },
    );

    if (lockError) {
      console.error("Lock check error:", lockError);
      // Continue anyway but log error
      return next();
    }

    if (lockStatus) {
      return res.status(409).json({
        error:
          "Another transaction is already in progress. Please wait a moment and try again.",
        code: "TRANSACTION_LOCKED",
        retry_after: 5,
      });
    }

    // Try to acquire lock
    const { data: lockAcquired, error: acquireError } = await supabase.rpc(
      "acquire_transfer_lock",
      {
        p_user_id: userId,
        p_request_id: requestId,
        p_lock_timeout_seconds: 30,
      },
    );

    if (acquireError) {
      console.error("Lock acquire error:", acquireError);
      // Continue anyway but log error
      return next();
    }

    if (!lockAcquired) {
      return res.status(409).json({
        error: "Unable to process transaction at this time. Please try again.",
        code: "TRANSACTION_BUSY",
      });
    }

    // Store request ID in request object for later release
    req.transactionLockId = requestId;
    req.userIdForLock = userId;

    next();
  } catch (error) {
    console.error("Lock middleware error:", error);
    // Continue without locking on error (better than blocking)
    next();
  }
};

// Middleware to release lock after request completes
const releaseTransactionLock = async (req, res, next) => {
  // Store original end function
  const originalEnd = res.end;
  const originalJson = res.json;
  const originalSend = res.send;

  // Override json method
  res.json = function (data) {
    // Call original with proper context
    originalJson.call(this, data);

    // Release lock after response
    if (req.transactionLockId && req.userIdForLock) {
      releaseLock(req.userIdForLock, req.transactionLockId);
    }
  };

  // Override send method
  res.send = function (data) {
    originalSend.call(this, data);

    if (req.transactionLockId && req.userIdForLock) {
      releaseLock(req.userIdForLock, req.transactionLockId);
    }
  };

  // Override end method
  res.end = function () {
    originalEnd.apply(this, arguments);

    if (req.transactionLockId && req.userIdForLock) {
      releaseLock(req.userIdForLock, req.transactionLockId);
    }
  };

  next();
};

// Cleanup expired locks periodically (run every minute)
// Note: This should ideally be in your main index.js, but can be here
let cleanupInterval = null;

const startLockCleanup = () => {
  if (cleanupInterval) return;
  cleanupInterval = setInterval(async () => {
    try {
      await supabase.rpc("cleanup_expired_locks");
      console.log("Expired locks cleaned up");
    } catch (error) {
      console.error("Lock cleanup error:", error);
    }
  }, 60000); // Run every minute
};

// Add these functions to auth.js

// Generate unique session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

// Generate unique session ID
/*function generateSessionId(userId) {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(16).toString("hex");
  const version = Date.now();
  return `${userId.substring(0, 8)}_${timestamp}_${random}_${version}`;
}*/

function hashTransferContext(fromAccountId, toAccountNumber, amount) {
  return crypto
    .createHash("sha256")
    .update(`${fromAccountId}:${toAccountNumber}:${amount}`)
    .digest("hex");
}

// Get device info for tracking
function getDeviceInfo(req) {
  const userAgent = req.headers["user-agent"] || "Unknown";
  const ip =
    req.ip ||
    req.connection?.remoteAddress ||
    req.headers["x-forwarded-for"] ||
    "Unknown";

  let deviceType = "Unknown";
  let browser = "Unknown";
  let os = "Unknown";

  if (userAgent.includes("Mobile")) deviceType = "Mobile";
  else if (userAgent.includes("Tablet")) deviceType = "Tablet";
  else deviceType = "Desktop";

  if (userAgent.includes("Chrome")) browser = "Chrome";
  else if (userAgent.includes("Firefox")) browser = "Firefox";
  else if (userAgent.includes("Safari")) browser = "Safari";
  else if (userAgent.includes("Edge")) browser = "Edge";

  if (userAgent.includes("Windows")) os = "Windows";
  else if (userAgent.includes("Mac")) os = "macOS";
  else if (userAgent.includes("Linux")) os = "Linux";
  else if (userAgent.includes("Android")) os = "Android";
  else if (userAgent.includes("iOS")) os = "iOS";

  return {
    device_name: `${deviceType} - ${browser} on ${os}`,
    ip_address: ip,
    user_agent: userAgent,
    device_type: deviceType,
    browser: browser,
    os: os,
  };
}

// ==================== FIXED: INVALIDATE ALL USER SESSIONS ====================

async function invalidateAllUserSessions(
  userId,
  reason = "New login from another device",
) {
  try {
    console.log(
      `[Session Invalidate] Invalidating all sessions for user: ${userId}`,
    );

    // Get all active sessions for logging
    const { data: oldSessions, error: fetchError } = await supabase
      .from("user_sessions")
      .select("id, session_id, device_name")
      .eq("user_id", userId)
      .eq("is_active", true);

    if (fetchError) {
      console.error("[Session Invalidate] Fetch error:", fetchError);
    }

    if (oldSessions && oldSessions.length > 0) {
      console.log(
        `[Session Invalidate] Found ${oldSessions.length} active session(s) to invalidate`,
      );

      // Invalidate ALL sessions
      const { error: updateError } = await supabase
        .from("user_sessions")
        .update({
          is_active: false,
          is_current: false,
          invalidated_reason: reason,
          expires_at: new Date().toISOString(),
        })
        .eq("user_id", userId)
        .eq("is_active", true);

      if (updateError) {
        console.error("[Session Invalidate] Update error:", updateError);
      }

      // Create notifications for each old session's device
      for (const session of oldSessions) {
        await supabase
          .from("notifications")
          .insert({
            user_id: userId,
            title: "Session Terminated",
            message: `Your session on ${session.device_name || "another device"} was terminated due to a new login.`,
            type: "security",
            created_at: new Date().toISOString(),
          })
          .catch((e) => console.error("Notification error:", e));
      }
    }

    // Clear active_session_id from users table
    const { error: clearError } = await supabase
      .from("users")
      .update({
        active_session_id: null,
        active_session_started_at: null,
      })
      .eq("id", userId);

    if (clearError) {
      console.error("[Session Invalidate] Clear user error:", clearError);
    }

    console.log(
      `[Session Invalidate] Successfully invalidated ${oldSessions?.length || 0} session(s)`,
    );
    return oldSessions?.length || 0;
  } catch (error) {
    console.error("[Session Invalidate] Error:", error);
    return 0;
  }
}

// ==================== FIXED: CREATE USER SESSION ====================

async function createUserSession(userId, token, deviceInfo) {
  try {
    console.log(`[Create Session] Creating new session for user: ${userId}`);

    const sessionId = generateSessionId();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days expiry

    // FIRST: Invalidate ALL existing sessions for this user
    await invalidateAllUserSessions(userId, "New login from another device");

    // SECOND: Insert new session
    const { data: session, error: sessionError } = await supabase
      .from("user_sessions")
      .insert({
        user_id: userId,
        session_token: token,
        session_id: sessionId,
        device_fingerprint: deviceInfo.device_name,
        device_name: deviceInfo.device_name,
        ip_address: deviceInfo.ip_address,
        user_agent: deviceInfo.user_agent,
        expires_at: expiresAt.toISOString(),
        is_active: true,
        is_current: true,
        created_at: new Date().toISOString(),
        last_activity: new Date().toISOString(),
      })
      .select()
      .single();

    if (sessionError) {
      console.error("[Create Session] Insert error:", sessionError);
      throw sessionError;
    }

    // THIRD: Update user's active session
    const { error: updateError } = await supabase
      .from("users")
      .update({
        active_session_id: sessionId,
        last_active_device: deviceInfo.device_name,
        active_session_started_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      })
      .eq("id", userId);

    if (updateError) {
      console.error("[Create Session] Update user error:", updateError);
    }

    console.log(`[Create Session] Session created successfully: ${sessionId}`);
    return { sessionId, session };
  } catch (error) {
    console.error("[Create Session] Error:", error);
    throw error;
  }
}

const checkSingleDeviceSession = async (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ error: "Please authenticate" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (jwtError) {
      return res.status(401).json({ error: "Invalid token" });
    }

    // Get user with active session info
    const { data: user, error: userError } = await supabase
      .from("users")
      .select(
        "id, active_session_id, is_active, is_frozen, last_active_device, session_version",
      )
      .eq("id", decoded.userId)
      .single();

    if (userError || !user) {
      return res.status(401).json({ error: "User not found" });
    }

    if (!user.is_active) {
      return res.status(401).json({ error: "Account deactivated" });
    }

    // Get the session record from database
    const { data: dbSession, error: sessionError } = await supabase
      .from("user_sessions")
      .select("id, session_id, is_active, session_version")
      .eq("session_token", token)
      .single();

    // STRICT CHECK: Compare database session_id with token's sessionId
    if (!dbSession || !dbSession.is_active) {
      // Session doesn't exist or is inactive in database
      console.log(
        `[Session] Session not found or inactive for user ${user.id}`,
      );
      return res.status(401).json({
        error: "session_expired",
        message: "Your session has expired. Please log in again.",
        code: "SESSION_EXPIRED",
      });
    }

    // CRITICAL: Compare session_id from token with database
    if (dbSession.session_id !== decoded.sessionId) {
      console.log(
        `[Session] MISMATCH: DB=${dbSession.session_id}, Token=${decoded.sessionId}`,
      );

      // Invalidate this token's session
      await supabase
        .from("user_sessions")
        .update({
          is_active: false,
          invalidated_reason:
            "Session token mismatch - another device logged in",
          expires_at: new Date().toISOString(),
        })
        .eq("session_token", token);

      return res.status(401).json({
        error: "session_expired",
        message:
          "You have been logged out because a new login was detected on another device.",
        code: "SESSION_REPLACED",
        device_name: user.last_active_device || "Another device",
      });
    }

    // Check if user's active_session_id points to this session
    if (
      user.active_session_id &&
      user.active_session_id !== dbSession.session_id
    ) {
      console.log(
        `[Session] User.active_session_id mismatch: ${user.active_session_id} vs ${dbSession.session_id}`,
      );

      return res.status(401).json({
        error: "session_expired",
        message: "Another device has taken over this session.",
        code: "SESSION_REPLACED",
        device_name: user.last_active_device || "Another device",
      });
    }

    // Update last activity
    await supabase
      .from("user_sessions")
      .update({ last_activity: new Date().toISOString() })
      .eq("session_token", token);

    req.user = user;
    req.token = token;
    req.sessionId = decoded.sessionId;
    next();
  } catch (error) {
    console.error("[Session Middleware] Error:", error.message);
    res.status(401).json({ error: "Please authenticate" });
  }
};

async function checkSessionValidity(userId, sessionId, token) {
  try {
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("active_session_id, last_active_device")
      .eq("id", userId)
      .single();

    if (userError || !user) {
      // DB error — fail open, never false-logout
      console.error("checkSessionValidity DB error:", userError);
      return { valid: true };
    }

    // No active_session_id in DB = session is being set up (race window)
    // or user has no session at all. Either way, don't logout.
    if (!user.active_session_id) {
      return { valid: true };
    }

    // No sessionId in token = old token format. Allow it — don't force logout.
    // It will expire naturally by JWT expiry date.
    if (!sessionId) {
      return { valid: true };
    }

    // Both sides have a value and they don't match = another device logged in.
    // This is the ONLY case that should trigger session-expired.html.
    if (user.active_session_id !== sessionId) {
      await supabase
        .from("user_sessions")
        .update({
          is_active: false,
          invalidated_reason: "New login from another device",
          expires_at: new Date().toISOString(),
        })
        .eq("user_id", userId)
        .eq("session_id", sessionId)
        .eq("is_active", true);

      return {
        valid: false,
        reason:
          "Your account was accessed from another device. This session has been terminated.",
        code: "SESSION_REPLACED",
        device_name: user.last_active_device || "Another device",
      };
    }

    return { valid: true };
  } catch (error) {
    console.error("checkSessionValidity error:", error);
    return { valid: true }; // Always fail open
  }
}

// ==================== FIXED: GET USER ACTIVE SESSIONS ====================

async function getUserActiveSessions(userId) {
  try {
    const { data: sessions, error } = await supabase
      .from("user_sessions")
      .select(
        "id, session_id, device_fingerprint, ip_address, user_agent, created_at, last_activity, is_current, device_name",
      )
      .eq("user_id", userId)
      .eq("is_active", true)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("[Get Sessions] Error:", error);
      return [];
    }

    return sessions || [];
  } catch (error) {
    console.error("[Get Sessions] Error:", error);
    return [];
  }
}

// ==================== FIXED: REVOKE SPECIFIC SESSION ====================

async function revokeSession(sessionId, userId, reason = "User initiated") {
  try {
    const { error } = await supabase
      .from("user_sessions")
      .update({
        is_active: false,
        is_current: false,
        invalidated_reason: reason,
        expires_at: new Date().toISOString(),
      })
      .eq("id", sessionId)
      .eq("user_id", userId);

    if (error) throw error;

    // If this was the active session, clear it from user record
    const { data: user } = await supabase
      .from("users")
      .select("active_session_id")
      .eq("id", userId)
      .single();

    if (user?.active_session_id === sessionId) {
      await supabase
        .from("users")
        .update({ active_session_id: null })
        .eq("id", userId);
    }

    return true;
  } catch (error) {
    console.error("[Revoke Session] Error:", error);
    return false;
  }
}

// ==================== FIXED: REVOKE CURRENT SESSION (LOGOUT) ====================

async function revokeCurrentSession(userId, sessionId, token) {
  try {
    console.log(
      `[Revoke Current] Revoking session for user: ${userId}, sessionId: ${sessionId}`,
    );

    // Update session to inactive
    const { error: sessionError } = await supabase
      .from("user_sessions")
      .update({
        is_active: false,
        is_current: false,
        invalidated_reason: "User logged out",
        expires_at: new Date().toISOString(),
      })
      .eq("user_id", userId)
      .eq("session_id", sessionId);

    if (sessionError) {
      console.error("[Revoke Current] Session update error:", sessionError);
    }

    // Clear user's active session if it matches
    await supabase
      .from("users")
      .update({
        active_session_id: null,
        active_session_started_at: null,
      })
      .eq("id", userId)
      .eq("active_session_id", sessionId);

    console.log(`[Revoke Current] Session revoked successfully`);
    return true;
  } catch (error) {
    console.error("[Revoke Current] Error:", error);
    return false;
  }
}

// Export new functions
module.exports = {
  authenticate,
  authorizeAdmin,
  requireSuperAdmin,
  requirePermission,
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
  generateSessionId,
  hashTransferContext,
};