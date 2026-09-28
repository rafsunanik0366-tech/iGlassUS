
const SESSION_COOKIE = "iglass_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const PBKDF2_ITERATIONS = 210000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // ----- API -----
      if (url.pathname === "/api/test-db" && request.method === "GET") {
        const result = await env.DB
          .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
          .all();

        return json({
          ok: true,
          database: "iglass-production",
          tables: result.results ?? []
        });
      }

      if (url.pathname === "/admin-setup" && request.method === "GET") {
        const existing = await env.DB
          .prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
          .first();

        if (existing) {
          return new Response(
            "<!doctype html><meta charset='utf-8'><title>Admin already created</title><body style='font-family:system-ui;padding:40px'><h2>Admin account already exists.</h2><p>This setup page is disabled.</p></body>",
            {
              headers: {
                "content-type": "text/html; charset=utf-8",
                "cache-control": "no-store"
              }
            }
          );
        }

        return new Response(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>iGlassUS Admin Setup</title>
<style>
body{font-family:system-ui;background:#f5f7fb;margin:0;padding:32px;color:#0b1736}
.card{max-width:520px;margin:40px auto;background:#fff;border:1px solid #dfe5ee;border-radius:18px;padding:24px;box-shadow:0 10px 35px rgba(0,0,0,.06)}
h1{margin-top:0}.muted{color:#6b7280;font-size:14px}
label{display:block;font-weight:700;margin:14px 0 6px}
input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ccd5e1;border-radius:10px}
button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:10px;background:#071331;color:#fff;font-weight:800;cursor:pointer}
#msg{margin-top:14px;padding:10px;border-radius:10px;display:none}
.ok{display:block!important;background:#eaf8ef;color:#167d50}.bad{display:block!important;background:#fff1f2;color:#b42346}
</style>
</head>
<body>
<div class="card">
  <h1>Create iGlassUS Admin</h1>
  <p class="muted">This page works only until the first Admin account is created.</p>

  <label>Admin username</label>
  <input id="username" autocomplete="username">

  <label>Email</label>
  <input id="email" type="email" autocomplete="email">

  <label>Password</label>
  <input id="password" type="password" autocomplete="new-password">

  <label>ADMIN_SETUP_KEY</label>
  <input id="setupKey" type="password" autocomplete="off">

  <button id="createBtn">Create Admin Account</button>
  <div id="msg"></div>
</div>

<script>
document.getElementById("createBtn").onclick = async () => {
  const msg = document.getElementById("msg");
  msg.className = "";
  msg.style.display = "none";

  const r = await fetch("/api/auth/bootstrap-admin", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-setup-key": document.getElementById("setupKey").value
    },
    body: JSON.stringify({
      username: document.getElementById("username").value,
      email: document.getElementById("email").value,
      password: document.getElementById("password").value
    })
  });

  const data = await r.json().catch(() => ({
    ok: false,
    error: "Invalid server response"
  }));

  msg.textContent = data.ok
    ? "Admin account created successfully."
    : (data.error || "Setup failed.");

  msg.className = data.ok ? "ok" : "bad";

  if (data.ok) {
    document.getElementById("setupKey").value = "";
    document.getElementById("password").value = "";
  }
};
</script>
</body>
</html>`, {
          headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store"
          }
        });
      }

      if (url.pathname === "/api/auth/bootstrap-admin" && request.method === "POST") {
        return bootstrapAdmin(request, env);
      }

      if (url.pathname === "/api/auth/login" && request.method === "POST") {
        return login(request, env);
      }

      if (url.pathname === "/api/auth/logout" && request.method === "POST") {
        return logout(request, env);
      }

      if (url.pathname === "/api/auth/me" && request.method === "GET") {
        return me(request, env);
      }

      if (url.pathname === "/api/admin/vendors" && request.method === "POST") {
        return createVendor(request, env);
      }

      if (url.pathname === "/api/admin/vendors" && request.method === "GET") {
        return listVendors(request, env);
      }

      if (url.pathname.startsWith("/api/")) {
        return json({ ok: false, error: "API route not found" }, 404);
      }

      // ----- STATIC WEBSITE -----
      return env.ASSETS.fetch(request);
    } catch (error) {
      return json(
        {
          ok: false,
          error: "Server error",
          details: String(error?.message || error)
        },
        500
      );
    }
  }
};

async function bootstrapAdmin(request, env) {
  if (!env.ADMIN_SETUP_KEY || typeof env.ADMIN_SETUP_KEY.get !== "function") {
    return json(
      { ok: false, error: "ADMIN_SETUP_KEY Secrets Store binding is not configured in Cloudflare." },
      500
    );
  }

  const setupKey = await env.ADMIN_SETUP_KEY.get();
  if (!setupKey) {
    return json(
      { ok: false, error: "ADMIN_SETUP_KEY could not be read from Cloudflare Secrets Store." },
      500
    );
  }

  const suppliedKey = request.headers.get("x-setup-key") || "";
  if (!safeEqualText(suppliedKey, setupKey)) {
    return json({ ok: false, error: "Invalid setup key." }, 403);
  }

  const existing = await env.DB
    .prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    .first();

  if (existing) {
    return json(
      { ok: false, error: "An admin already exists. Bootstrap is disabled." },
      409
    );
  }

  const body = await readJson(request);
  const username = normalizeUsername(body.username);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  const validationError = validateCredentials(username, email, password);
  if (validationError) return json({ ok: false, error: validationError }, 400);

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  await env.DB.prepare(
    `INSERT INTO users (id, email, username, password_hash, role, status)
     VALUES (?, ?, ?, ?, 'admin', 'active')`
  )
    .bind(id, email, username, passwordHash)
    .run();

  return json({
    ok: true,
    message: "Admin account created.",
    user: { id, email, username, role: "admin" }
  }, 201);
}

async function login(request, env) {
  const body = await readJson(request);
  const loginValue = String(body.login || body.username || body.email || "").trim();
  const password = String(body.password || "");

  if (!loginValue || !password) {
    return json({ ok: false, error: "Username/email and password are required." }, 400);
  }

  const user = await env.DB.prepare(
    `SELECT id, email, username, password_hash, role, status
     FROM users
     WHERE lower(username) = lower(?) OR lower(email) = lower(?)
     LIMIT 1`
  )
    .bind(loginValue, loginValue)
    .first();

  // Do not reveal whether username/email exists.
  if (!user || user.status !== "active") {
    await fakePasswordWork(password);
    return json({ ok: false, error: "Invalid login." }, 401);
  }

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return json({ ok: false, error: "Invalid login." }, 401);
  }

  // Remove expired sessions opportunistically.
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?")
    .bind(new Date().toISOString())
    .run();

  const rawToken = randomToken(32);
  const tokenHash = await sha256Hex(rawToken);
  const sessionId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, expires_at)
     VALUES (?, ?, ?, ?)`
  )
    .bind(sessionId, user.id, tokenHash, expiresAt)
    .run();

  return json(
    {
      ok: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role
      }
    },
    200,
    {
      "Set-Cookie": makeSessionCookie(rawToken, SESSION_TTL_SECONDS)
    }
  );
}

async function logout(request, env) {
  const rawToken = getCookie(request, SESSION_COOKIE);

  if (rawToken) {
    const tokenHash = await sha256Hex(rawToken);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    }
  );
}

async function me(request, env) {
  const user = await requireUser(request, env);
  if (!user) return json({ ok: false, error: "Not authenticated." }, 401);

  let vendor = null;
  if (user.role === "vendor") {
    vendor = await env.DB.prepare(
      `SELECT id, company_name, country, phone, currency, status
       FROM vendors WHERE user_id = ? LIMIT 1`
    )
      .bind(user.id)
      .first();
  }

  return json({
    ok: true,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      status: user.status
    },
    vendor
  });
}

async function createVendor(request, env) {
  const admin = await requireRole(request, env, "admin");
  if (!admin) return json({ ok: false, error: "Admin access required." }, 403);

  const body = await readJson(request);

  const username = normalizeUsername(body.username);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const companyName = String(body.company_name || body.companyName || "").trim();
  const country = String(body.country || "").trim();
  const phone = String(body.phone || "").trim();
  const currency = String(body.currency || "USD").trim().toUpperCase();
  const status = String(body.status || "active").trim().toLowerCase();

  const validationError = validateCredentials(username, email, password);
  if (validationError) return json({ ok: false, error: validationError }, 400);
  if (!companyName) return json({ ok: false, error: "Company name is required." }, 400);
  if (!["active", "disabled", "paused"].includes(status)) {
    return json({ ok: false, error: "Invalid vendor status." }, 400);
  }

  const userId = crypto.randomUUID();
  const vendorId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO users (id, email, username, password_hash, role, status)
         VALUES (?, ?, ?, ?, 'vendor', ?)`
      ).bind(userId, email, username, passwordHash, status === "active" ? "active" : status),

      env.DB.prepare(
        `INSERT INTO vendors
          (id, user_id, company_name, country, phone, currency, status)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(vendorId, userId, companyName, country, phone, currency, status)
    ]);
  } catch (error) {
    const message = String(error?.message || error);
    if (message.includes("UNIQUE")) {
      return json({ ok: false, error: "That username or email is already in use." }, 409);
    }
    throw error;
  }

  return json(
    {
      ok: true,
      message: "Vendor account created.",
      vendor: {
        id: vendorId,
        user_id: userId,
        company_name: companyName,
        username,
        email,
        country,
        phone,
        currency,
        status
      }
    },
    201
  );
}

async function listVendors(request, env) {
  const admin = await requireRole(request, env, "admin");
  if (!admin) return json({ ok: false, error: "Admin access required." }, 403);

  const rows = await env.DB.prepare(
    `SELECT
       v.id,
       v.company_name,
       v.country,
       v.phone,
       v.currency,
       v.status,
       v.created_at,
       u.id AS user_id,
       u.username,
       u.email
     FROM vendors v
     JOIN users u ON u.id = v.user_id
     ORDER BY v.created_at DESC`
  ).all();

  return json({ ok: true, vendors: rows.results ?? [] });
}

async function requireRole(request, env, role) {
  const user = await requireUser(request, env);
  if (!user || user.role !== role || user.status !== "active") return null;
  return user;
}

async function requireUser(request, env) {
  const rawToken = getCookie(request, SESSION_COOKIE);
  if (!rawToken) return null;

  const tokenHash = await sha256Hex(rawToken);

  const user = await env.DB.prepare(
    `SELECT u.id, u.email, u.username, u.role, u.status, s.expires_at
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?
     LIMIT 1`
  )
    .bind(tokenHash)
    .first();

  if (!user) return null;

  if (new Date(user.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
    return null;
  }

  return user;
}

function validateCredentials(username, email, password) {
  if (!/^[a-z0-9._-]{3,40}$/.test(username)) {
    return "Username must be 3-40 characters and use letters, numbers, dot, underscore, or hyphen.";
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return "Enter a valid email address.";
  }
  if (password.length < 12) {
    return "Password must be at least 12 characters.";
  }
  return null;
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

async function readJson(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    throw new Error("Expected application/json");
  }
  return request.json();
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derived = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(derived)}`;
}

async function verifyPassword(password, encoded) {
  try {
    const [scheme, iterationsText, saltB64, hashB64] = String(encoded || "").split("$");
    if (scheme !== "pbkdf2_sha256") return false;

    const iterations = Number(iterationsText);
    if (!Number.isInteger(iterations) || iterations < 100000) return false;

    const salt = base64ToBytes(saltB64);
    const expected = base64ToBytes(hashB64);
    const actual = await pbkdf2(password, salt, iterations);

    return safeEqualBytes(actual, expected);
  } catch {
    return false;
  }
}

async function fakePasswordWork(password) {
  const salt = new Uint8Array(16);
  await pbkdf2(password || "invalid", salt, PBKDF2_ITERATIONS);
}

async function pbkdf2(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

function randomToken(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return bytesToBase64Url(bytes);
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqualBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function safeEqualText(a, b) {
  const aa = new TextEncoder().encode(String(a));
  const bb = new TextEncoder().encode(String(b));
  return safeEqualBytes(aa, bb);
}

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

function makeSessionCookie(token, maxAge) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...extraHeaders
    }
  });
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}