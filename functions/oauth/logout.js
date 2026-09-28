//POST /oauth/logout

import { sha256Base64Url } from "../_shared/crypto.js";
import { parseCookies, buildExpiredCookie } from "../_shared/cookies.js";
 
export async function onRequest(context) {
  const { request, env } = context;
 
  
  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "POST", "Cache-Control": "no-store" },
    });
  }
 
  
  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem não permitida", {
      status: 403,
      headers: { "Cache-Control": "no-store" },
    });
  }
 

  const cookies = parseCookies(request);
  const sessionValue = cookies["__Host-session"];
 
  if (sessionValue) {
    const sessionHash = await sha256Base64Url(sessionValue);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`)
      .bind(sessionHash)
      .run();
  }
 
  
  const headers = new Headers();
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.append("Set-Cookie", buildExpiredCookie("__Host-session", "Strict"));
  headers.set("Cache-Control", "no-store");
 
  return new Response(null, { status: 303, headers });
}
