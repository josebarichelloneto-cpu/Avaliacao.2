//GET  /oauth/callback/google
//GET  /oauth/callback/github

import { sha256Base64Url, generateRandomToken } from "../../_shared/crypto.js";
import { PROVIDERS, isSupportedProvider } from "../../_shared/providers.js";
import { parseCookies, buildExpiredCookie } from "../../_shared/cookies.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";
 
const SESSION_TTL_SECONDS = 8 * 60 * 60; 
 
export async function onRequestGet(context) {
  const { request, env, params } = context;
  const provider = params.provider;
 
  if (!isSupportedProvider(provider)) {
    return notFound();
  }
 
  const url = new URL(request.url);
  const errorParam = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
 
 
  if (errorParam || !code || !state) {
    return badRequest("Resposta de autorização inválida");
  }
 
  const cookies = parseCookies(request);
  const transactionCookieValue = cookies["__Host-oauth-tx"];
  if (!transactionCookieValue) {
    return badRequest("Cookie de transação ausente");
  }
 
  const transactionHash = await sha256Base64Url(transactionCookieValue);
  const nowInSeconds = Math.floor(Date.now() / 1000);
 
  const transactionRow = await env.DB.prepare(
    `SELECT provider, state_hash, nonce, code_verifier, expires_at
     FROM oauth_transactions
     WHERE id_hash = ?`
  )
    .bind(transactionHash)
    .first();
 
  if (
    !transactionRow ||
    transactionRow.provider !== provider ||
    transactionRow.expires_at <= nowInSeconds
  ) {
    return badRequest("Transação inválida ou expirada");
  }
 
  
  const stateHash = await sha256Base64Url(state);
  if (stateHash !== transactionRow.state_hash) {
    return badRequest("Parâmetro state inválido");
  }
 
 
  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`)
    .bind(transactionHash)
    .run();
 
  const providerConfig = PROVIDERS[provider];
  const clientId =
    provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
  const clientSecret =
    provider === "google" ? env.GOOGLE_CLIENT_SECRET : env.GITHUB_CLIENT_SECRET;
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
 

  let identity;
  try {
    if (provider === "google") {
      identity = await confirmGoogleIdentity({
        code,
        codeVerifier: transactionRow.code_verifier,
        nonce: transactionRow.nonce,
        clientId,
        clientSecret,
        redirectUri,
        providerConfig,
      });
    } else {
      identity = await confirmGithubIdentity({
        code,
        codeVerifier: transactionRow.code_verifier,
        clientId,
        clientSecret,
        redirectUri,
        providerConfig,
      });
    }
  } catch (err) {
    
    return badRequest("Não foi possível confirmar a identidade");
  }
 
  
  const sessionValue = generateRandomToken();
  const sessionHash = await sha256Base64Url(sessionValue);
  const sessionExpiresAt = nowInSeconds + SESSION_TTL_SECONDS;
 
  await env.DB.prepare(
    `INSERT INTO sessions
      (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      sessionHash,
      identity.issuer,
      identity.subject,
      identity.email,
      identity.displayName,
      sessionExpiresAt,
      nowInSeconds
    )
    .run();
 
 
  const headers = new Headers();
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.append("Set-Cookie", buildExpiredCookie("__Host-oauth-tx", "Lax"));
  headers.append(
    "Set-Cookie",
    `__Host-session=${sessionValue}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`
  );
  headers.set("Cache-Control", "no-store");
 
  return new Response(null, { status: 302, headers });
}

async function confirmGoogleIdentity({
  code,
  codeVerifier,
  nonce,
  clientId,
  clientSecret,
  redirectUri,
  providerConfig,
}) {
  const tokenResponse = await fetch(providerConfig.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: codeVerifier,
    }),
  });
 
  if (!tokenResponse.ok) {
    throw new Error("Falha na troca do código com o Google");
  }
 
  const tokenBody = await tokenResponse.json();
  const idToken = tokenBody.id_token;
  if (!idToken) {
    throw new Error("Resposta do Google sem id_token");
  }
 
  const payload = await validateGoogleIdToken(idToken, {
    expectedAudience: clientId,
    expectedNonce: nonce,
  });
 
  return {
    issuer: "https://accounts.google.com",
    subject: payload.sub,
    email: payload.email ?? null,
    displayName: payload.name ?? null,
  };
}
 
async function confirmGithubIdentity({
  code,
  codeVerifier,
  clientId,
  clientSecret,
  redirectUri,
  providerConfig,
}) {
  const tokenResponse = await fetch(providerConfig.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      
      Accept: "application/json",
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });
 
  if (!tokenResponse.ok) {
    throw new Error("Falha na troca do código com o GitHub");
  }
 
  const tokenBody = await tokenResponse.json();
  const accessToken = tokenBody.access_token;
  const tokenType = tokenBody.token_type;
 
  if (!accessToken || !tokenType || tokenType.toLowerCase() !== "bearer") {
    throw new Error("Resposta do GitHub sem access_token Bearer válido");
  }
 
  const userResponse = await fetch(providerConfig.userInfoEndpoint, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
    },
  });
 
  if (userResponse.status !== 200) {
    throw new Error("Falha ao consultar /user no GitHub");
  }
 
  const userBody = await userResponse.json();
  if (typeof userBody.id !== "number") {
    throw new Error("Resposta do GitHub sem id numérico");
  }
 
  
  const basicAuthValue = btoa(`${clientId}:${clientSecret}`);
  const revokeResponse = await fetch(
    `https://api.github.com/applications/${clientId}/grant`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${basicAuthValue}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ access_token: accessToken }),
    }
  );
 
  if (revokeResponse.status !== 204) {
    throw new Error("Falha ao revogar a autorização no GitHub");
  }
 
  return {
    issuer: "https://github.com",
    subject: String(userBody.id),
    email: userBody.email ?? null,
    displayName: userBody.name ?? userBody.login ?? null,
  };
}
 
function notFound() {
  return new Response("Not found", {
    status: 404,
    headers: { "Cache-Control": "no-store" },
  });
}
 
function badRequest(message) {
  return new Response(message, {
    status: 400,
    headers: { "Cache-Control": "no-store" },
  });
}
