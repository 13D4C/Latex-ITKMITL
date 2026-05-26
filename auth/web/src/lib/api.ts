// Tiny fetch wrapper that handles the CSRF double-submit dance.
// The /api/csrf endpoint sets a non-HttpOnly cookie; we echo its value in the
// X-CSRF-Token header. Reading document.cookie keeps us decoupled from the
// JSON response shape.

const CSRF_COOKIE = "itkmitl_csrf";

function readCookie(name: string): string {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const p = part.trim();
    if (p.startsWith(prefix)) return decodeURIComponent(p.slice(prefix.length));
  }
  return "";
}

async function ensureCsrf(): Promise<string> {
  let token = readCookie(CSRF_COOKIE);
  if (token) return token;
  const res = await fetch("/api/csrf", { credentials: "same-origin" });
  if (!res.ok) throw new Error("Could not initialize session");
  token = readCookie(CSRF_COOKIE);
  if (!token) throw new Error("CSRF cookie not issued");
  return token;
}

export interface LoginResult {
  ok: true;
  redirect: string;
}

export async function login(username: string, password: string): Promise<LoginResult> {
  const csrf = await ensureCsrf();
  const res = await fetch("/api/login", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
      Accept: "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  if (res.status === 429) {
    throw new Error("Too many attempts — wait a minute and try again.");
  }
  if (!res.ok) {
    // Server returns a generic message regardless of cause to prevent
    // user enumeration; we mirror that on the UI.
    throw new Error("Invalid username or password.");
  }
  return (await res.json()) as LoginResult;
}
