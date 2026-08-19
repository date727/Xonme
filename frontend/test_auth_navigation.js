"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const app = fs.readFileSync(path.join(__dirname, "js", "app.js"), "utf8");
const auth = fs.readFileSync(path.join(__dirname, "js", "auth.js"), "utf8");

assert.match(
  app,
  /const authRequiredTabs = new Set\(\["collector", "profile"\]\);/,
  "online monitoring and profile must share the authenticated-only route guard",
);
assert.match(
  app,
  /if \(authRequiredTabs\.has\(tabName\) && !currentUser\)/,
  "guest navigation to a protected tab must redirect to login",
);
assert.match(
  app,
  /if \(authRequiredTabs\.has\(routeState\.tab\)\) switchTab\(routeState\.tab/,
  "direct protected hashes must be checked again after session resolution",
);
assert.match(
  app,
  /event\.stopImmediatePropagation\(\)/,
  "guest clicks must not initialize the online-monitoring module before redirecting",
);
assert.match(
  auth,
  /window\.location\.href = "index\.html#home"/,
  "successful login or registration must enter the home page",
);
assert.doesNotMatch(auth, /index\.html#tool|destination.*#tool/, "authentication must not default to detection center");

console.log("authentication navigation: OK");
