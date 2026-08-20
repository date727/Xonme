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
  /\["collector", "profile"\]\.includes\(requestedDestination\) \? `#\$\{requestedDestination\}` : "#home"/,
  "successful authentication must return to a protected destination or default to home",
);
assert.match(auth, /target\.searchParams\.set\("next", requestedDestination\)/, "switching between login and registration must preserve the destination");
assert.match(app, /openAuthModal\("login", tabName\)/, "protected navigation must preserve its destination");
assert.match(app, /login\.html\$\{next\}/, "initial authentication redirect must preserve its destination");
assert.doesNotMatch(auth, /index\.html#tool|destination.*#tool/, "authentication must not default to detection center");

console.log("authentication navigation: OK");
