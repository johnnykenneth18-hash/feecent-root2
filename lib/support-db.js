// support-db.js
//
// A completely separate Supabase client, pointed at a completely separate
// Supabase PROJECT (different URL, different service key) from your main
// banking database. This is the isolation boundary: nothing in the
// support/chat code path ever touches `supabase` (the bank client) from
// index.js, and nothing here can reach accounts/transactions/PINs even if
// this whole module were compromised — the credentials it holds simply
// don't have access to that other project.
//
// Env vars are intentionally named DIFFERENTLY from SUPABASE_URL /
// SUPABASE_SERVICE_KEY (the bank DB's vars) so the two can never be
// confused or accidentally left pointing at the same project:
//
//   SUPPORT_SUPABASE_URL=https://xxxxxxxx.supabase.co
//   SUPPORT_SUPABASE_SERVICE_KEY=eyJ...   (service_role key of the NEW project)
//
// Only the service_role key is used, and only from the server. The anon/
// public key for this project is never generated into any frontend bundle.

const { createClient } = require("@supabase/supabase-js");

if (!process.env.SUPPORT_SUPABASE_URL || !process.env.SUPPORT_SUPABASE_SERVICE_KEY) {
  console.error(
    "[support-db] SUPPORT_SUPABASE_URL / SUPPORT_SUPABASE_SERVICE_KEY are not set. " +
      "The support/chat system will not function until these are added to .env. " +
      "These are DELIBERATELY separate from SUPABASE_URL/SUPABASE_SERVICE_KEY — " +
      "point them at a brand-new, separate Supabase project.",
  );
}

const supportDb = createClient(
  process.env.SUPPORT_SUPABASE_URL,
  process.env.SUPPORT_SUPABASE_SERVICE_KEY,
  {
    auth: { persistSession: false, autoRefreshToken: false },
  },
);

// Same hard-timeout pattern used for the bank Supabase client in index.js —
// a stalled query on the support project should never hang a request.
function withDbTimeout(queryBuilder, ms = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  const builder =
    typeof queryBuilder.abortSignal === "function"
      ? queryBuilder.abortSignal(controller.signal)
      : queryBuilder;
  return Promise.resolve(builder).finally(() => clearTimeout(timer));
}

module.exports = { supportDb, withDbTimeout };