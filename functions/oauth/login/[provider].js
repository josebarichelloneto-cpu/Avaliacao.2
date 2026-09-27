GET  /oauth/login/google
GET  /oauth/login/github

import { generateRandomToken, sha256Base64Url } from "../../_shared/crypto.js";
import { PROVIDERS, isSupportedProvider } from "../../_shared/providers.js";
 
const TRANSACTION_TTL_SECONDS = 600; 
 
export async function onRequestGet(context) {
  const { env, params } = context;
  const provider = params.provider;
 
  
  if (!isSupportedProvider(provider)) {
    return new Response("Not found", {
      status: 404,
      headers: { "Cache-Control": "no-store" },
    });
  }
 
  const providerConfig = PROVIDERS[provider];
  const clientId =
    provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
 
 
  const transactionValue = generateRandomToken(); 
  const state = generateRandomToken();
  const codeVerifier = generateRandomToken();
  const nonce = provider === "google" ? generateRandomToken() : null;
 
  
  const transactionHash = await sha256Base64Url(transactionValue);
  const stateHash = await sha256Base64Url(state);
  const codeChallenge = await sha256Base64Url(codeVerifier); 
 
  const expiresAt = Math.floor(Date.now() / 1000) + TRANSACTION_TTL_SECONDS;
 
  await env.DB.prepare(
    `INSERT INTO oauth_transactions
      (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(transactionHash, provider, stateHash, nonce, codeVerifier, expiresAt)
    .run();
 
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  const authorizationUrl = new URL(providerConfig.authorizationEndpoint);
 
  authorizationUrl.searchParams.set("client_id", clientId);
  authorizationUrl.searchParams.set("redirect_uri", redirectUri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
 
  if (provider === "google") {
    authorizationUrl.searchParams.set("scope", "openid email profile");
    authorizationUrl.searchParams.set("nonce", nonce);
  }
 
  const headers = new Headers();
  headers.set("Location", authorizationUrl.toString());
  headers.append(
    "Set-Cookie",
    `__Host-oauth-tx=${transactionValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${TRANSACTION_TTL_SECONDS}`
  );
  headers.set("Cache-Control", "no-store");
 
  return new Response(null, { status: 302, headers });
}

