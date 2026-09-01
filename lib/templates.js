// lib/sms/templates.js
//
// Centralized message templates (section 22). Adapters only ever see
// the final rendered string — no provider adapter should ever contain
// a hardcoded FEECENT message, so every provider stays swappable.

const TEMPLATES = {
  LOGIN_OTP: (otp) => `Your FEECENT login code is ${otp}. It expires in 5 minutes. Never share this code with anyone.`,
  REGISTRATION_OTP: (otp) => `Your FEECENT verification code is ${otp}. It expires in 5 minutes.`,
  TRANSFER_OTP: (otp) => `Your FEECENT transfer authorization code is ${otp}. It expires in 5 minutes. Never share this code — FEECENT staff will never ask for it.`,
  WITHDRAWAL_OTP: (otp) => `Your FEECENT withdrawal code is ${otp}. It expires in 5 minutes. Never share this code with anyone.`,
  PASSWORD_RESET_OTP: (otp) => `Your FEECENT password reset code is ${otp}. It expires in 5 minutes. Didn't request this? Ignore this message.`,
  CHANGE_PHONE_OTP: (otp) => `Your FEECENT code to confirm this phone number change is ${otp}. It expires in 5 minutes.`,
  CHANGE_EMAIL_OTP: (otp) => `Your FEECENT code to confirm this email change is ${otp}. It expires in 5 minutes.`,
  DEVICE_VERIFICATION_OTP: (otp) => `Your FEECENT device verification code is ${otp}. It expires in 5 minutes.`,
  PIN_CHANGE_OTP: (otp) => `Your FEECENT PIN change code is ${otp}. It expires in 5 minutes. Never share this code with anyone.`,
  SECURITY_ACTION_OTP: (otp) => `Your FEECENT security verification code is ${otp}. It expires in 5 minutes.`,

  // Non-OTP transactional templates (section 22/23) — masked values only.
  TRANSACTION_SUCCESS: ({ amount, maskedAccount }) =>
    `FEECENT: Your transaction of NGN${amount} to ${maskedAccount} was successful.`,
  TRANSACTION_FAILED: ({ amount }) =>
    `FEECENT: Your transaction of NGN${amount} could not be completed. Please try again or contact support.`,
  SECURITY_ALERT: ({ detail }) => `FEECENT security alert: ${detail}. If this wasn't you, contact support immediately.`,
};

const PURPOSE_TO_TEMPLATE = {
  LOGIN: "LOGIN_OTP",
  REGISTRATION: "REGISTRATION_OTP",
  TRANSFER: "TRANSFER_OTP",
  WITHDRAWAL: "WITHDRAWAL_OTP",
  PASSWORD_RESET: "PASSWORD_RESET_OTP",
  CHANGE_PHONE: "CHANGE_PHONE_OTP",
  CHANGE_EMAIL: "CHANGE_EMAIL_OTP",
  DEVICE_VERIFICATION: "DEVICE_VERIFICATION_OTP",
  PIN_CHANGE: "PIN_CHANGE_OTP",
  SECURITY_ACTION: "SECURITY_ACTION_OTP",
};

function renderOtpMessage(purpose, otp) {
  const templateId = PURPOSE_TO_TEMPLATE[purpose];
  if (!templateId || !TEMPLATES[templateId]) {
    throw new Error(`No SMS template registered for OTP purpose "${purpose}"`);
  }
  return { templateId, message: TEMPLATES[templateId](otp) };
}

function render(templateId, params) {
  if (!TEMPLATES[templateId]) throw new Error(`Unknown SMS template "${templateId}"`);
  return TEMPLATES[templateId](params);
}

module.exports = { TEMPLATES, PURPOSE_TO_TEMPLATE, renderOtpMessage, render };
