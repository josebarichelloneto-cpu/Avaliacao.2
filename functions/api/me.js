//GET  /api/me
import { sha256Base64Url } from "../_shared/crypto.js";
import { parseCookies } from "../_shared/cookies.js";
 
export async function onRequestGet(context) {
  const { request, env } = context;
 
  const cookies = parseCookies(request);
  const sessionValue = cookies["__Host-session"];
 
  if (!sessionValue) {
    return unauthorized();
  }
 
  const sessionHash = await sha256Base64Url(sessionValue);
  const nowInSeconds = Math.floor(Date.now() / 1000);
 
  const session = await env.DB.prepare(
    `SELECT email, display_name
     FROM sessions
     WHERE id_hash = ? AND expires_at > ?`
  )
    .bind(sessionHash, nowInSeconds)
    .first();
 
  if (!session) {
    return unauthorized();
  }
  
  return Response.json(
    {
      email: session.email,
      displayName: session.display_name,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
 
function unauthorized() {
  return Response.json(
    { error: "unauthorized" },
    { status: 401, headers: { "Cache-Control": "no-store" } }
  );
}
