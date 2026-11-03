"use strict";
const { verify } = require("./jwt");

/** Express middleware: reads `Authorization: Bearer <token>` and sets `req.session`. */
function requireSession(secret) {
  return (req, res, next) => {
    const header = req.get("authorization") || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    try {
      req.session = verify(token, secret);
      next();
    } catch (err) {
      res.status(401).json({ error: "invalid session" });
    }
  };
}

/** Allows the request only when the session carries the given role. */
function requireRole(role) {
  return (req, res, next) => {
    if (req.session && req.session.role === role) return next();
    res.status(403).json({ error: "forbidden" });
  };
}

module.exports = { requireSession, requireRole };
