"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const source = fs.readFileSync(path.join(__dirname, "js", "visualization.js"), "utf8");
const styles = fs.readFileSync(path.join(__dirname, "styles", "visualization.css"), "utf8");
const unifiedMetrics = source.slice(
  source.indexOf("const modelJudgement"),
  source.indexOf("const chart = $(\"unified-behavior-chart\")"),
);

assert.match(
  source,
  /<span class="unified-metric-name">.*<strong class="unified-metric-value">.*<small class="unified-metric-description">/,
  "every metric card must render in name-value-description order",
);
assert.match(
  source,
  /return metric\(label, value, hasRita \? note : unavailableNote\);/,
  "communication behaviour cards must use the shared metric template",
);
assert.doesNotMatch(source, /class="unified-score"/, "behaviour cards must not use a separate color template");
assert.doesNotMatch(styles, /\.unified-score\b/, "obsolete green score-card styling must be removed");
assert.match(source, /域名控制通道风险评分/, "metric names must be Chinese");
assert.doesNotMatch(unifiedMetrics, /潜在 Beacon|未发现 Beacon|Beacon 通信规律评分/, "metric card copy must not mix English names into Chinese labels or descriptions");
assert.match(source, /const setMetricValue = .*\? "—" : String\(value\)/, "overview cards must use a dash for unavailable values");
assert.match(source, /const lstmResults = list\.filter/, "LSTM overview results must be defined before they are used");
assert.match(source, /setMetricValue\("viz-lstm-max", lstmResults\.length/, "LSTM confidence must only be shown when an LSTM result exists");
assert.doesNotMatch(source, /暂无 RITA 结果|暂无 LSTM 告警|暂无归因结果/, "completed overview cards must state a negative detection conclusion instead of suggesting missing data");
for (const conclusion of ["未检出周期性通信风险", "未检出时序异常风险", "未发现需溯源的威胁"]) {
  assert.match(source, new RegExp(conclusion), `negative detection conclusion must remain explicit: ${conclusion}`);
}

console.log("visualization metric cards: OK");
