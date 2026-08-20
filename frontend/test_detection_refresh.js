"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const frontend = fs.readFileSync(path.join(__dirname, "js", "app.js"), "utf8");
const backend = fs.readFileSync(path.join(root, "backend", "app", "main.py"), "utf8");
const lifecycle = fs.readFileSync(path.join(root, "backend", "app", "stream_lifecycle.py"), "utf8");

assert.match(frontend, /activeAnalysisRecordId: "c2s\.activeAnalysisRecordId"/);
assert.match(frontend, /persistActiveAnalysis\(activeAnalysisRecordId\)/);
assert.match(frontend, /const resumeDetachedAnalysis = async \(\) =>/);
assert.match(frontend, /if \(currentUser\) \{\s*void loadAnalysisHistory\(\);\s*void resumeDetachedAnalysis\(\);/);
assert.match(frontend, /if \(eventName === "result"\) \{\s*const payload = JSON\.parse\(data\);\s*applyCompletedStreamResult\(payload\);/);
assert.match(frontend, /const applyCompletedStreamResult = \(payload\) => \{[\s\S]*?streamResultReceived = true;/);
assert.match(frontend, /\/analyses\/\$\{recordId\}\/status/);
assert.match(frontend, /\/analyses\/\$\{activeAnalysisRecordId\}\/cancel/);
assert.match(frontend, /find\(\(item\) => item\.status === "processing"\)/);

assert.match(backend, /_run_stream_in_background\(\s*stream\(\),\s*analysis_id,/);
assert.match(backend, /@app\.get\("\/analyses\/\{record_id\}\/status"\)/);
assert.match(backend, /@app\.delete\("\/analyses\/\{record_id\}\/cancel"\)/);
assert.match(lifecycle, /def run_stream_in_background\(/);
assert.match(lifecycle, /Stop forwarding only\. The producer deliberately keeps running\./);

console.log("detection center refresh recovery contract: OK");
