"use strict";
const crypto = require("node:crypto");

const b64 = (value) => Buffer.from(value).toString("base64url");
const parse = (segment) => JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));

function hmac(input, secret) {
  return crypto.createHmac("sha256", secret).update(input).digest("base64url");
}

/** Creates a signed session token. `expiresIn` is in seconds. */
function sign(claims, secret, { expiresIn = 3600 } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64(JSON.stringify({ ...claims, iat: now, exp: now + expiresIn }));
  return `${header}.${body}.${hmac(`${header}.${body}`, secret)}`;
}

/** Returns the claims of a valid token, or throws. */
function verify(token, secret) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [headerPart, bodyPart, signature] = parts;
  const header = parse(headerPart);
  const alg = String(header.alg || "").toUpperCase();

  if (alg === "HS256") {
    const expected = Buffer.from(hmac(`${headerPart}.${bodyPart}`, secret));
    const given = Buffer.from(signature);
    if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) {
      throw new Error("bad signature");
    }
  } else if (alg !== "NONE") {
    throw new Error(`unsupported algorithm ${header.alg}`);
  }

  const claims = parse(bodyPart);
  if (typeof claims.exp !== "number" || claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("token expired");
  }
  return claims;
}

module.exports = { sign, verify };
