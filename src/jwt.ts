import * as cookie from 'cookie';
import {DOMAIN} from './env';

// The following code is a modified version of https://gist.github.com/bcnzer/e6a7265fd368fa22ef960b17b9a76488

// Validate JWT
export async function isValidJwt(request: Request) {
  const encodedToken = getJwt(request);
  if (encodedToken === null) {
    return false;
  }
  const token = decodeJwt(encodedToken);

  // Check expiry
  let expiryDate = new Date(token.payload.exp * 1000);
  let currentDate = new Date(Date.now());
  if (expiryDate <= currentDate) {
    return false;
  }

  return isValidJwtSignature(token);
}

function getJwt(request: Request) {
  const rawCookieHeader = request.headers.get('Cookie');
  if (!rawCookieHeader) {
    return '';
  }

  const cookies = cookie.parse(rawCookieHeader);
  if (!cookies) {
    return '';
  }

  const authJWT = cookies['CF_Authorization'];
  if (!authJWT) {
    return '';
  }

  return authJWT;
}

/**
 * Parse and decode a JWT.
 * A JWT is three, base64 encoded, strings concatenated with ‘.’:
 *   a header, a payload, and the signature.
 * The signature is “URL safe”, in that ‘/+’ characters have been replaced by ‘_-’
 *
 * Steps:
 * 1. Split the token at the ‘.’ character
 * 2. Base64 decode the individual parts
 * 3. Retain the raw Bas64 encoded strings to verify the signature
 */
function decodeJwt(token: string) {
  const parts = token.split('.');
  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  const signature = atob(parts[2].replace(/_/g, '/').replace(/-/g, '+'));
  return {
    header: header,
    payload: payload,
    signature: signature,
    raw: {header: parts[0], payload: parts[1], signature: parts[2]},
  };
}

/**
 * Validate the JWT.
 *
 * Steps:
 * Reconstruct the signed message from the Base64 encoded strings.
 * Load the RSA public key into the crypto library.
 * Verify the signature with the message and the key.
 */
async function isValidJwtSignature(token: any) {
  const encoder = new TextEncoder();
  const data = encoder.encode([token.raw.header, token.raw.payload].join('.'));
  const signature = new Uint8Array(
    Array.from(token.signature).map((c: any) => c.charCodeAt(0)),
  );

  const upToDateJWKReq = await fetch(
    `https://${DOMAIN}.cloudflareaccess.com/cdn-cgi/access/certs`,
  );
  const upToDateJWKJson = await upToDateJWKReq.json();

  for (var i = 0; i < upToDateJWKJson.keys.length; i++) {
    const jwk = Object.assign({key_ops: ['verify']}, upToDateJWKJson.keys[i]);
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'},
      false,
      ['verify'],
    );
    if (crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data)) {
      return true;
    }
  }
  return false;
}
