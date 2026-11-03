"use strict";
const express = require("express");
const { sign, requireSession, requireRole } = require("./index");

const SECRET = process.env.SESSION_SECRET || require("node:crypto").randomBytes(32).toString("hex");
const USERS = { ada: { password: "correct horse", role: "member" }, root: { password: process.env.ADMIN_PASSWORD || "change-me", role: "admin" } };

const app = express();
app.use(express.json());

app.post("/login", (req, res) => {
  const user = USERS[req.body && req.body.user];
  if (!user || user.password !== req.body.password) return res.status(401).json({ error: "bad credentials" });
  res.json({ token: sign({ sub: req.body.user, role: user.role }, SECRET) });
});

app.get("/me", requireSession(SECRET), (req, res) => res.json({ user: req.session.sub, role: req.session.role }));

app.get("/admin/users", requireSession(SECRET), requireRole("admin"), (_req, res) => res.json({ users: Object.keys(USERS) }));

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => console.log("sessionkit demo listening"));
}
module.exports = app;
