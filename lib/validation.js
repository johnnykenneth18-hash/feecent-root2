// validation.js
//
// SECURITY FIX (Critical): "Missing Server-Side Input Validation".
// Centralized Zod schemas + a reusable Express middleware for the
// highest-risk endpoints (auth, PINs, transfers). Client-side checks in
// login.html/register.html/etc are trivially bypassed with curl/Postman —
// everything here re-validates on the server, which is the only copy that
// actually matters for security.
//
// Usage in index.js:
//   const { validate, schemas } = require("./validation");
//   app.post("/api/auth/register", registerLimiter, validate(schemas.register), async (req, res) => { ... });
//
// Install with: npm install zod --save

const { z } = require("zod");

// Generic middleware factory: validates req.body against `schema`.
// On failure, returns 400 with a compact list of field errors and never
// reaches the route handler — so a bad payload never touches Supabase.
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
    // Replace req.body with the parsed/coerced data so downstream code
    // works with trusted, typed values (e.g. trimmed strings).
    req.body = result.data;
    next();
  };
}

const email = z.string().trim().toLowerCase().email("Invalid email address").max(254);
const password = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128)
  .regex(/[A-Z]/, "Password must contain an uppercase letter")
  .regex(/[a-z]/, "Password must contain a lowercase letter")
  .regex(/[0-9]/, "Password must contain a number");
const fourDigitPin = z.string().regex(/^\d{4}$/, "PIN must be exactly 4 digits");
const sixDigitPasscode = z
  .string()
  .regex(/^\d{6}$/, "Passcode must be exactly 6 digits")
  .optional();
const bvn = z.string().regex(/^\d{11}$/, "BVN must be exactly 11 digits");
const uuid = z.string().uuid("Invalid ID format");
const name = z
  .string()
  .trim()
  .min(1, "Required")
  .max(100)
  .regex(/^[a-zA-Z\s'-]+$/, "Only letters, spaces, hyphens and apostrophes allowed");
const phone = z
  .string()
  .trim()
  .regex(/^\+?[0-9\s-]{7,20}$/, "Invalid phone number");

const schemas = {
  register: z.object({
    email,
    password,
    first_name: name,
    last_name: name,
    middle_name: name.optional().or(z.literal("")),
    phone,
    country: z.string().trim().min(1).max(100),
    state: z.string().trim().min(1).max(100),
    city: z.string().trim().min(1).max(100),
    address: z.string().trim().min(1).max(255),
    postal_code: z.string().trim().max(20).optional(),
    date_of_birth: z.string().optional(),
    gender: z.enum(["male", "female", "other"]).optional(),
    marital_status: z.string().trim().max(30).optional(),
    occupation: z.string().trim().max(100).optional(),
    referral_code: z.string().trim().max(30).optional().or(z.literal("")),
    age: z.number().int().min(18).max(120).optional(),
    security_question_1: z.string().trim().min(1).max(255),
    security_answer_1: z.string().trim().min(1).max(255),
    security_question_2: z.string().trim().min(1).max(255),
    security_answer_2: z.string().trim().min(1).max(255),
    passcode: sixDigitPasscode,
    face_images: z.array(z.string()).optional(),
    bvn,
  }),

  login: z.object({
    email,
    password: z.string().min(1, "Password is required").max(128),
    fingerprint: z.string().max(500).optional(),
  }),

  setTransferPin: z.object({
    pin: fourDigitPin,
  }),

  verifyTransferPin: z.object({
    pin: fourDigitPin,
    from_account_id: uuid,
    to_account_number: z.string().trim().regex(/^\d{6,20}$/, "Invalid account number"),
    amount: z.number().positive().max(100_000_000),
  }),

  verifySavingsPin: z.object({
    pin: fourDigitPin,
    type: z.enum(["target", "spare_change", "fixed", "flex"]),
    id: uuid,
  }),

  verifyStaffId: z.object({
    userId: uuid,
    staff_id: z
      .string()
      .trim()
      .toUpperCase()
      .regex(/^FEE[A-Z0-9]{10}$/, "Invalid staff ID format"),
  }),
};

module.exports = { validate, schemas };