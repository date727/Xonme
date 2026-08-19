"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const source = fs.readFileSync(path.join(__dirname, "js", "collector.js"), "utf8");
const styles = fs.readFileSync(path.join(__dirname, "styles", "collector.css"), "utf8");

assert.match(
  source,
  /const activeStorageKey = "c2s\.collectorActiveSessionId";/,
  "an active collector session must survive a refresh",
);
assert.match(
  source,
  /window\.localStorage\.removeItem\(legacyResultStorageKey\);/,
  "legacy completed-result persistence must be cleared",
);
assert.doesNotMatch(
  source,
  /setItem\(legacyResultStorageKey|setItem\(resultStorageKey/,
  "completed analysis ids must not be persisted again",
);
assert.match(
  source,
  /if\(data\.status==="completed"&&!sessionStartedHere&&!sessionWasActive&&!sessionObservedActive\)\{resetRealtimeTask\(\);return;\}/,
  "a stale completed cloud session must reset the realtime panel",
);
assert.match(
  source,
  /if\(cloudStatus==="completed"&&lastLocalCaptureStatus==="completed"\)resetRealtimeTask\(\)/,
  "leaving the page may clear results only after both capture and cloud analysis have completed",
);
assert.doesNotMatch(
  source,
  /if\(cloudStatus==="completed"\)resetRealtimeTask\(\)/,
  "cloud completion alone must never clear a still-capturing task",
);
assert.match(
  source,
  /const restoreActiveCollectorTask = \(\) => \{if\(sessionId\)startCloudPolling\(\);\};/,
  "running capture or analysis must resume after returning to online monitoring",
);
assert.match(
  styles,
  /\.collector-stage-strip \.done b \{[^}]*border: 1px solid #75d1b7;[^}]*background: #c9f1e5;/,
  "completed stages must remain visibly green while the current stage stays highlighted",
);

console.log("collector current-task lifecycle: OK");
