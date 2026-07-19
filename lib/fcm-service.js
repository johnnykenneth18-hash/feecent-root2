// fcm-service.js
// Real server-side push sending via Firebase Cloud Messaging, using
// the Admin SDK. Replaces two things that existed before:
//   1. The Android branch in sendPushNotificationForInAppNotification()
//      in index.js, which never actually sent anything — it just
//      logged a message and set sent=true. That's why push never
//      worked even before OneSignal was tried.
//   2. sendOneSignalPush() and its ONESIGNAL_APP_ID/ONESIGNAL_REST_API_KEY
//      env vars, used only by the admin broadcast endpoint.
//
// Requires FIREBASE_SERVICE_ACCOUNT_JSON (or _PATH) env var — see
// FIREBASE_SERVICE_ACCOUNT_STEPS.md for how to generate and set it.

const admin = require("firebase-admin");

let initialized = false;

function ensureInitialized() {
  if (initialized) return;

  let credential;
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    const serviceAccount = JSON.parse(
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON,
    );
    credential = admin.credential.cert(serviceAccount);
  } else if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH) {
    credential = admin.credential.cert(
      require(process.env.FIREBASE_SERVICE_ACCOUNT_PATH),
    );
  } else {
    throw new Error(
      "Neither FIREBASE_SERVICE_ACCOUNT_JSON nor FIREBASE_SERVICE_ACCOUNT_PATH is set — see FIREBASE_SERVICE_ACCOUNT_STEPS.md",
    );
  }

  admin.initializeApp({ credential });
  initialized = true;
}

/**
 * Sends a push notification to a single FCM device token.
 * Returns { success, error?, invalidToken? } — invalidToken is set
 * true when FCM reports the token is dead/unregistered, so the
 * caller can deactivate it in user_push_tokens rather than retry it
 * forever.
 */
async function sendToToken(token, { title, body, data = {} }) {
  try {
    ensureInitialized();
  } catch (err) {
    console.error("[FCM] Not configured:", err.message);
    return { success: false, error: err.message };
  }

  // FCM's `data` payload values must all be strings.
  const stringData = Object.fromEntries(
    Object.entries(data).map(([k, v]) => [
      k,
      typeof v === "string" ? v : JSON.stringify(v),
    ]),
  );

  try {
    await admin.messaging().send({
      token,
      notification: { title, body },
      data: stringData,
      android: {
        priority: "high",
        notification: {
          channelId: "feecent_notifications", // matches AndroidManifest.xml's default_notification_channel_id
          sound: "default",
        },
      },
    });
    return { success: true };
  } catch (err) {
    const code = err.errorInfo?.code || err.code || "";
    const invalidToken =
      code.includes("registration-token-not-registered") ||
      code.includes("invalid-registration-token") ||
      code.includes("invalid-argument");
    console.error(`[FCM] Send failed (${code}):`, err.message);
    return { success: false, error: err.message, invalidToken };
  }
}

/**
 * Sends to multiple tokens at once (e.g. admin broadcast). Returns
 * per-token results so the caller can deactivate any dead tokens.
 */
async function sendToTokens(tokens, { title, body, data = {} }) {
  const results = await Promise.all(
    tokens.map(async (token) => ({
      token,
      ...(await sendToToken(token, { title, body, data })),
    })),
  );
  return {
    successCount: results.filter((r) => r.success).length,
    failureCount: results.filter((r) => !r.success).length,
    invalidTokens: results.filter((r) => r.invalidToken).map((r) => r.token),
    results,
  };
}

module.exports = { sendToToken, sendToTokens };
