'use strict';

const crypto = require('crypto');

/**
 * Sign a token payload using HMAC-SHA256.
 * Returns: base64url(payload).base64url(signature)
 */
function signToken(payload, secret) {
  const payloadStr = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadStr).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
  return payloadB64 + '.' + sig;
}

/**
 * Verify and decode a signed token. Returns payload object or null.
 */
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
  // Use timing-safe comparison to prevent timing attacks
  const sigBuf = Buffer.from(sig, 'base64url');
  const expectedBuf = Buffer.from(expectedSig, 'base64url');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
  try {
    const payloadStr = Buffer.from(payloadB64, 'base64url').toString('utf-8');
    const payload = JSON.parse(payloadStr);
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

/**
 * Generate a random session token.
 */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hash a Discord user ID using HMAC-SHA256 for privacy-safe storage.
 * Raw Discord snowflake IDs are never stored in the database â only these
 * 64-character hex digests.  The HMAC key is TOKEN_SECRET from the .env file.
 */
function hashUserId(rawDiscordId) {
  const secret = process.env.TOKEN_SECRET;
  if (!secret) throw new Error('TOKEN_SECRET not set | cannot hash user ID');
  return crypto.createHmac('sha256', secret).update(String(rawDiscordId)).digest('hex');
}

module.exports = { signToken, verifyToken, generateSessionToken, hashUserId };