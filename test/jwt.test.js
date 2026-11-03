"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { sign, verify } = require("../src/jwt");

test("round trip", () => {
  const token = sign({ sub: "ada", role: "member" }, "secret");
  assert.equal(verify(token, "secret").sub, "ada");
});

test("rejects a wrong secret", () => {
  const token = sign({ sub: "ada" }, "secret");
  assert.throws(() => verify(token, "other"), /bad signature/);
});

test("rejects an expired token", () => {
  const token = sign({ sub: "ada" }, "secret", { expiresIn: -10 });
  assert.throws(() => verify(token, "secret"), /expired/);
});

test("rejects a tampered payload", () => {
  const [h, , s] = sign({ sub: "ada", role: "member" }, "secret").split(".");
  const forged = Buffer.from(JSON.stringify({ sub: "ada", role: "admin", exp: 9999999999 })).toString("base64url");
  assert.throws(() => verify(`${h}.${forged}.${s}`, "secret"), /bad signature/);
});
