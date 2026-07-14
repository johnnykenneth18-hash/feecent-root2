// cache-service.js
//
// Redis cache layer, built on Upstash's REST-based client rather than a
// traditional TCP client (ioredis etc.) -- because this app runs on
// Vercel serverless functions. A persistent-connection Redis client
// opens a new TCP connection per cold start with nothing to reliably
// tear it down; in a serverless environment that reproduces exactly
// the kind of connection-exhaustion problem this cache exists to fix,
// just against Redis instead of Postgres. Upstash's client talks to
// Redis over plain HTTPS -- one request per call, nothing held open --
// which matches how serverless functions actually execute.
//
// ------------------------------------------------------------------
// SETUP (one-time):
//   1. Vercel dashboard -> Storage -> Create Database -> Upstash for
//      Redis (or provision directly at upstash.com). Either path gives
//      you two env vars -- add them to this project's environment:
//        UPSTASH_REDIS_REST_URL
//        UPSTASH_REDIS_REST_TOKEN
//   2. npm install @upstash/redis
// ------------------------------------------------------------------
//
// DESIGN PRINCIPLES -- read this before adding a new cached route:
//
// 1. FAIL OPEN, ALWAYS. A cache outage must never become an app
//    outage. Every read/write here is wrapped so a Redis error is
//    logged and treated as a cache miss / no-op -- the request falls
//    through to Postgres exactly as if caching didn't exist. A bug in
//    this file should degrade performance, never correctness or
//    availability.
//
// 2. CACHE-ASIDE, NOT WRITE-THROUGH (per your call on this). On a
//    write, we DELETE/invalidate the affected cache key(s) and let the
//    next GET repopulate them -- we do not try to compute and store
//    the new value directly at write time. Write-through means every
//    place that ever mutates a row (webhooks, admin actions, cron
//    jobs, this route, that route) has to independently reproduce the
//    exact same read/join/formatting logic its GET counterpart uses,
//    forever, in sync. One missed spot and the cache silently serves a
//    wrong balance. Invalidate-and-repopulate has one failure mode (a
//    stale read for a short window) instead of two (stale AND wrong).
//
// 3. NEVER CACHE AUTHORIZATION DECISIONS WITHOUT AN EXPLICIT, AUDITED
//    INVALIDATION PATH. Session validity / account-frozen / permission
//    checks are the one category where a stale cache is a security bug,
//    not a UX nit -- freeze an account, revoke a session, and a cached
//    "still valid" answer would keep letting requests through. If you
//    want that path cached, it needs a hard TTL ceiling in the low
//    single-digit seconds AND an explicit invalidation call at every
//    place that changes the underlying state (freeze/unfreeze, logout,
//    password change, session revoke) -- not just a TTL and a shrug.
//    Nothing here caches anything auth-related yet; see the note at
//    the bottom of this file.
//
// 4. VERSIONED KEYS for anything invalidated from more than one call
//    site. Notifications, for example, can be created from webhooks,
//    admin actions, and cron jobs scattered across several files --
//    tracking down and deleting every exact key variant (every
//    page/limit/filter combination a user has ever requested) isn't
//    tractable. Instead each cache key embeds a per-user version
//    counter; bumping that counter "forgets" every previously cached
//    variant in one O(1) call, with no KEYS/SCAN sweep (which Upstash
//    bills per key touched, and which doesn't belong in a request path
//    on a serverless plan regardless of billing).

let redis = null;
let warnedMissingConfig = false;

function getClient() {
  if (redis) return redis;

  if (
    !process.env.UPSTASH_REDIS_REST_URL ||
    !process.env.UPSTASH_REDIS_REST_TOKEN
  ) {
    if (!warnedMissingConfig) {
      console.warn(
        "[CACHE] UPSTASH_REDIS_REST_URL/TOKEN not set — caching is disabled, " +
          "every request will fall through to the database. Add those two " +
          "env vars (see cache-service.js header) to enable it.",
      );
      warnedMissingConfig = true;
    }
    return null;
  }

  // Lazy require so a deploy without the package installed yet doesn't
  // crash on boot — it'll just stay disabled until `npm install
  // @upstash/redis` is run, same as the missing-env-var case above.
  try {
    const { Redis } = require("@upstash/redis");
    redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });
  } catch (err) {
    if (!warnedMissingConfig) {
      console.warn(
        "[CACHE] @upstash/redis is not installed — run `npm install @upstash/redis`. " +
          "Caching is disabled until then.",
      );
      warnedMissingConfig = true;
    }
    return null;
  }
  return redis;
}

// ------------------------------------------------------------
// Low-level primitives. All fail open.
// ------------------------------------------------------------
async function cacheGet(key) {
  const client = getClient();
  if (!client) return null;
  try {
    return await client.get(key); // @upstash/redis auto-deserializes JSON
  } catch (err) {
    console.error(`[CACHE] GET failed for key "${key}":`, err.message);
    return null;
  }
}

async function cacheSet(key, value, ttlSeconds) {
  const client = getClient();
  if (!client) return;
  try {
    await client.set(key, value, ttlSeconds ? { ex: ttlSeconds } : undefined);
  } catch (err) {
    console.error(`[CACHE] SET failed for key "${key}":`, err.message);
  }
}

async function cacheDel(...keys) {
  const flat = keys.flat().filter(Boolean);
  if (flat.length === 0) return;
  const client = getClient();
  if (!client) return;
  try {
    await client.del(...flat);
  } catch (err) {
    console.error(
      `[CACHE] DEL failed for keys [${flat.join(", ")}]:`,
      err.message,
    );
  }
}

// ------------------------------------------------------------
// Per-namespace, per-user version counters (see design note 4 above).
// getUserCacheVersion() defaults to 1 the first time it's read for a
// given user so cache keys are stable and cacheable from a user's very
// first request, with no explicit "initialize version to 1" step
// needed anywhere.
// ------------------------------------------------------------
function versionKey(namespace, userId) {
  return `cachever:${namespace}:${userId}`;
}

async function getUserCacheVersion(namespace, userId) {
  const client = getClient();
  if (!client) return 1;
  try {
    const v = await client.get(versionKey(namespace, userId));
    return v || 1;
  } catch (err) {
    console.error(
      `[CACHE] version read failed for ${namespace}:${userId}:`,
      err.message,
    );
    return 1;
  }
}

// Call this from every write endpoint (or webhook/cron) that changes
// data a cached GET in this namespace depends on. Cheap (one INCR),
// safe to call more often than strictly necessary.
async function bumpUserCacheVersion(namespace, userId) {
  const client = getClient();
  if (!client) return;
  try {
    await client.incr(versionKey(namespace, userId));
  } catch (err) {
    console.error(
      `[CACHE] version bump failed for ${namespace}:${userId} — ` +
        `cached reads for this user may serve stale data until the TTL ` +
        `expires:`,
      err.message,
    );
  }
}

// ------------------------------------------------------------
// Express middleware factory — cache-aside for a GET route.
//
// buildKey(req) -> Promise<string|null> | string|null
//   Return the cache key for this request, or null/undefined to skip
//   caching entirely for this request (e.g. a query param combination
//   you've deliberately chosen not to cache).
//
// ttlSeconds
//   Hard ceiling on staleness even if you forget an invalidation call
//   somewhere. Pick this like a safety net, not a substitute for
//   calling bumpUserCacheVersion()/cacheDel() at the right write sites.
//
// Usage:
//   app.get("/api/user/notifications", authenticate,
//     cacheware(buildNotificationsCacheKey, 20),
//     async (req, res) => { ...unchanged handler... });
// ------------------------------------------------------------
function cacheware(buildKey, ttlSeconds) {
  return async (req, res, next) => {
    let key;
    try {
      key = await buildKey(req);
    } catch (err) {
      console.error("[CACHE] key builder threw, bypassing cache:", err);
      return next();
    }

    if (!key) return next();

    const cached = await cacheGet(key);
    if (cached !== null && cached !== undefined) {
      res.setHeader("X-Cache", "HIT");
      return res.json(cached);
    }

    res.setHeader("X-Cache", "MISS");

    // Capture whatever the route handler sends via res.json() and
    // populate the cache with it, without changing a single line of
    // the handler itself. Only cache real success responses — skip
    // 4xx/5xx so an error page never gets served back as if it were
    // good data.
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        cacheSet(key, body, ttlSeconds).catch(() => {});
      }
      return originalJson(body);
    };

    next();
  };
}

// ------------------------------------------------------------
// Cache-aside for a single hot internal lookup (not tied to an HTTP
// response the way cacheware() is) — built specifically for
// authenticate() in middleware/auth.js, which runs this exact lookup
// on every one of ~70+ authenticated routes. See that file for how
// invalidation is wired at every known is_active/is_frozen/role
// mutation site; ttlSeconds here is deliberately short because it's
// the PRIMARY safety net for a security-relevant value, not just a
// backstop the way the notifications TTL is.
// ------------------------------------------------------------
async function getCachedUser(userId, ttlSeconds, fetchUserFn) {
  const version = await getUserCacheVersion("authuser", userId);
  const key = `authuser:v${version}:u:${userId}`;

  const cached = await cacheGet(key);
  if (cached !== null && cached !== undefined) return cached;

  const user = await fetchUserFn();
  if (user) {
    await cacheSet(key, user, ttlSeconds);
  }
  return user;
}

module.exports = {
  cacheGet,
  cacheSet,
  cacheDel,
  cacheware,
  getCachedUser,
  getUserCacheVersion,
  bumpUserCacheVersion,
};
