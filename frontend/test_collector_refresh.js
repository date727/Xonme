"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "js", "collector.js"), "utf8");
const completedLoader = source.slice(
  source.indexOf("const loadCompletedResult"),
  source.indexOf("const pollCloud"),
);

assert.match(
  source,
  /const resultStorageKey = "c2s\.collectorAnalysisId";/,
  "completed analysis id must survive a page refresh",
);
assert.match(
  source,
  /window\.localStorage\.setItem\(resultStorageKey,String\(completedAnalysisId\)\)/,
  "completed result must be persisted before the page can be refreshed",
);
assert.doesNotMatch(
  completedLoader,
  /window\.localStorage\.removeItem\(storageKey\)/,
  "loading a completed result must not discard its recoverable cloud session",
);
assert.match(
  source,
  /const restoreCollectorResult = async \(\) => \{if\(sessionId\)\{startCloudPolling\(\);return;\}if\(!completedAnalysisId\)return;/,
  "collector page must restore the cloud session or its completed analysis",
);
assert.match(
  source,
  /recent_alerts:finalAlerts\(threats\)/,
  "final dashboard threats must be adapted to realtime alert fields",
);
assert.match(
  source,
  /if\(state==="completed"&&cloudStatus==="completed"\)setStage\("result"\);/,
  "a completed local status refresh must preserve stage 5 instead of reverting to stage 4",
);

class FakeClassList {
  constructor() { this.values = new Set(); }
  add(...values) { values.forEach((value) => this.values.add(value)); }
  remove(...values) { values.forEach((value) => this.values.delete(value)); }
  toggle(value, force) {
    if (force === true) this.values.add(value);
    else if (force === false) this.values.delete(value);
    else if (this.values.has(value)) this.values.delete(value);
    else this.values.add(value);
  }
  contains(value) { return this.values.has(value); }
}

class FakeElement {
  constructor() {
    this.classList = new FakeClassList();
    this.style = {};
    this.parentElement = { setAttribute() {} };
    this.children = [];
    this.value = "";
    this.textContent = "";
    this.disabled = false;
    this.hidden = false;
  }
  addEventListener() {}
  setAttribute(name, value) { this[name] = value; }
  removeAttribute(name) { delete this[name]; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  querySelector() { return new FakeElement(); }
  querySelectorAll() { return []; }
}

async function runRefreshRecovery(hasStoredSession) {
  const elements = new Map();
  const stageElements = Array.from({ length: 5 }, () => new FakeElement());
  const element = (selector) => {
    if (!elements.has(selector)) elements.set(selector, new FakeElement());
    return elements.get(selector);
  };
  const storage = new Map(hasStoredSession ? [["c2s.collectorSessionId", "session-1234"]] : []);
  const dashboardPayload = {
    analysis: { id: 42, file_size: 4096, status: "completed", completed_at: "2026-08-19T08:00:00Z" },
    dashboard: {
      connection_count: 12,
      threats: [{
        src_ip: "192.0.2.10",
        dst_ip: "198.51.100.20",
        dst_port: "443",
        threat_category: "high",
        detection_sources: ["RITA"],
        beacon_score: 97.2,
      }],
    },
  };
  const jsonResponse = (body) => ({ ok: true, status: 200, json: async () => body });
  const context = {
    console,
    setInterval,
    clearInterval,
    setTimeout,
    clearTimeout,
    EventSource: class {},
    fetch: async (url) => {
      if (url.includes("/collector/sessions/")) {
        return jsonResponse({
          status: "completed",
          analysis_record_id: 42,
          received_bytes: 4096,
          file_size: 4096,
          updated_at: "2026-08-19T08:00:00Z",
        });
      }
      if (url.includes("/analyses/42/dashboard")) return jsonResponse(dashboardPayload);
      if (url.includes("127.0.0.1:8766/status")) {
        return jsonResponse({
          ready: true,
          dumpcap_available: true,
          npcap_available: true,
          interfaces: [],
          capture_status: "completed",
          captured_bytes: 4096,
          elapsed_seconds: 8,
          cloud_session_id: "session-1234",
        });
      }
      throw new Error(`unexpected request: ${url}`);
    },
    document: {
      querySelector: element,
      querySelectorAll: (selector) => selector === "[data-collector-stage]" ? stageElements : [],
      createElement: () => new FakeElement(),
    },
    window: {
      confirm: () => true,
      location: { protocol: "https:", hostname: "example.test", hash: "#collector" },
      localStorage: {
        getItem: (key) => storage.get(key) ?? null,
        setItem: (key, value) => storage.set(key, String(value)),
        removeItem: (key) => storage.delete(key),
      },
      setInterval,
      clearInterval,
    },
  };
  vm.runInNewContext(source, context, { filename: "collector.js" });
  await new Promise((resolve) => setTimeout(resolve, 30));

  assert.equal(storage.get("c2s.collectorSessionId"), "session-1234");
  assert.equal(storage.get("c2s.collectorAnalysisId"), "42");
  assert.equal(element("#collector-live-status").textContent, "检测完成");
  assert.equal(element("#collector-connection-count").textContent, "12");
  assert.equal(element("#collector-open-data-btn").disabled, false);
  assert.equal(context.window.C2SherlockCollectorResult, dashboardPayload);
  assert.equal(stageElements[4].classList.contains("active"), true);
  assert.equal(stageElements.filter((item) => item.classList.contains("active")).length, 1);
  assert.equal(stageElements.slice(0, 4).every((item) => item.classList.contains("done")), true);
  const alert = element("#collector-alert-list").children[0];
  assert.equal(alert.children[0].children[0].textContent, "192.0.2.10 → 198.51.100.20:443");
}

Promise.all([runRefreshRecovery(true), runRefreshRecovery(false)])
  .then(() => console.log("collector refresh recovery: OK"))
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
