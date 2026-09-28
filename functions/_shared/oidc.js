const GOOGLE_DISCOVERY_URL =
  "https://accounts.google.com/.well-known/openid-configuration";
 
function base64UrlToUint8Array(base64Url) {
  let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
 
function base64UrlToJson(base64Url) {
  const bytes = base64UrlToUint8Array(base64Url);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}
 
export async function validateGoogleIdToken(
  idToken,
  { expectedAudience, expectedNonce }
) {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Formato de id_token inválido");
  }
  const [headerPart, payloadPart, signaturePart] = parts;
 
  const header = base64UrlToJson(headerPart);
  if (header.alg !== "RS256") {
    throw new Error("Algoritmo inesperado no id_token");
  }
 
  const payload = base64UrlToJson(payloadPart);
 
  const discoveryResponse = await fetch(GOOGLE_DISCOVERY_URL);
  if (!discoveryResponse.ok) {
    throw new Error("Falha ao obter o documento de descoberta do Google");
  }
  const discovery = await discoveryResponse.json();
 
  const jwksResponse = await fetch(discovery.jwks_uri);
  if (!jwksResponse.ok) {
    throw new Error("Falha ao obter o JWKS do Google");
  }
  const jwks = await jwksResponse.json();
 
  
  const matchingKey = jwks.keys.find((key) => key.kid === header.kid);
  if (!matchingKey) {
    throw new Error("Chave pública não encontrada para o kid do id_token");
  }
 
  
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    matchingKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
 
 
  const signingInput = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  const signatureBytes = base64UrlToUint8Array(signaturePart);
 
  const isSignatureValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signatureBytes,
    signingInput
  );
  if (!isSignatureValid) {
    throw new Error("Assinatura do id_token inválida");
  }
 
 
  const nowInSeconds = Math.floor(Date.now() / 1000);
 
  if (payload.iss !== discovery.issuer) {
    throw new Error("Emissor (iss) inválido no id_token");
  }
  if (payload.aud !== expectedAudience) {
    throw new Error("Audiência (aud) inválida no id_token");
  }
  if (typeof payload.exp !== "number" || payload.exp <= nowInSeconds) {
    throw new Error("id_token expirado");
  }
  if (typeof payload.iat !== "number" || payload.iat > nowInSeconds + 60) {
    throw new Error("Data de emissão (iat) inválida no id_token");
  }
  if (payload.nonce !== expectedNonce) {
    throw new Error("nonce inválido no id_token");
  }
 
  return payload;
}
