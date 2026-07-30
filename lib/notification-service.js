// lib/notification-service.js
// Single source of truth for creating in-app notifications AND
// triggering the matching push. Used by index.js and by every
// payment-provider file (flutterwave, vtpass, paystack, etc.) so a
// notification created from anywhere always pushes too.

const { createClient } = require("@supabase/supabase-js");
const { sendToToken } = require("./fcm-service");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
);

// Moved here from index.js — unchanged logic, just relocated so it's
// callable from any file without requiring index.js itself.
async function sendPushNotificationForInAppNotification(
  userId,
  title,
  message,
  notificationId,
  type = "info",
) {
  try {
    const { data: tokens, error } = await supabase
      .from("user_push_tokens")
      .select("push_token, platform")
      .eq("user_id", userId)
      .eq("is_active", true);

    if (error || !tokens || tokens.length === 0) return false;

    const { data: settings } = await supabase
      .from("user_push_settings")
      .select("notifications_enabled, transfers, savings, security, promotions, bills")
      .eq("user_id", userId)
      .single();

    if (!settings || !settings.notifications_enabled) return false;

    let typeEnabled = true;
    if (type === "transfer") typeEnabled = settings.transfers !== false;
    else if (type === "savings") typeEnabled = settings.savings !== false;
    else if (type === "security") typeEnabled = settings.security !== false;
    else if (type === "promotion") typeEnabled = settings.promotions === true;
    else if (type === "bill") typeEnabled = settings.bills !== false;

    if (!typeEnabled) return false;

    let sent = false;
    for (const token of tokens) {
      if (token.platform === "android" || token.platform === "ios") {
        const result = await sendToToken(token.push_token, {
          title,
          body: message,
          data: { notificationId, type, timestamp: new Date().toISOString(), url: "/dashboard.html" },
        });
        if (result.success) {
          sent = true;
        } else if (result.invalidToken) {
          await supabase
            .from("user_push_tokens")
            .update({ is_active: false })
            .eq("push_token", token.push_token);
        }
      } else if (token.platform === "web") {
        try {
          const webpush = require("web-push");
          await webpush.sendNotification(
            JSON.parse(token.push_token),
            JSON.stringify({ title, body: message, data: { notificationId, type } }),
          );
          sent = true;
        } catch (err) {
          console.error("Web push error:", err);
        }
      }
    }
    return sent;
  } catch (error) {
    console.error("Send push notification error:", error);
    return false;
  }
}

// Raw-insert-plus-push wrapper — pass through whatever fields you'd
// normally give .insert({...}), get the row + a push for free.
async function notifyAndPush(insertPayload) {
  const { user_id, title, message, type = "info" } = insertPayload;

  const { data: notification, error } = await supabase
    .from("notifications")
    .insert(insertPayload)
    .select()
    .single();

  if (error) {
    console.error("Notification insert error:", error);
    return null;
  }

  await sendPushNotificationForInAppNotification(
    user_id,
    title,
    message,
    notification.id,
    type,
  );

  return notification;
}

module.exports = {
  notifyAndPush,
  sendPushNotificationForInAppNotification,
};