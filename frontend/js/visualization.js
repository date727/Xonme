(() => {
  let topologyChart = null, ritaChart = null, dashboard = null, analysis = null, selected = null, lstmSection = null;
  const $ = (id) => document.getElementById(id);
  const num = (v) => Number.isFinite(Number(v)) ? Number(v) : 0;
  const escapeHtml = (value) => String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
  const renderIntelText = (value) => {
    // 知识库条目中的 Citation 是 MITRE 保存的底层参考文献；前端统一
    // 标示知识库来源即可，不将这些对普通用户无帮助的引用逐条呈现。
    const body = String(value || "")
      .replace(/\s+/g, " ")
      .replace(/\s*\(Citation:\s*[^)]+\)/gi, "")
      .replace(/\s{2,}/g, " ")
      .trim();
    const html = escapeHtml(body).replace(
      /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
      (_, label, url) => `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${label}</a>`,
    );
    return { html };
  };
  const text = (id, value) => { const el = $(id); if (el) el.textContent = value == null || value === "" ? "暂无数据" : String(value); };
  const risk = (t) => ({ critical: "高", high: "高", medium: "中", low: "低" }[String(t).toLowerCase()] || "待研判");
  const color = (t) => ({ critical: "#dc2626", high: "#dc2626", medium: "#f59e0b" }[String(t).toLowerCase()] || "#16a34a");
  const formatSize = (bytes) => bytes == null ? "暂无数据" : `${(Number(bytes) / 1024).toFixed(1)} KB`;
  const fmtTime = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "暂无数据";
  const threats = () => Array.isArray(dashboard?.threats) ? dashboard.threats : [];
  const rawRitaResults = () => Array.isArray(dashboard?.engine_results?.rita) ? dashboard.engine_results.rita : [];
  const getEvidence = (item) => item?.rita || {};
  const setDataCenterState = (hasData) => {
    const module = $("visualization-module");
    const emptyState = $("data-center-empty");
    if (module) {
      module.hidden = !hasData;
      module.style.display = hasData ? "grid" : "none";
      module.setAttribute("aria-hidden", String(!hasData));
    }
    if (emptyState) {
      emptyState.hidden = hasData;
      emptyState.style.display = hasData ? "none" : "grid";
      emptyState.setAttribute("aria-hidden", String(hasData));
    }
  };
  const switchPage = (page) => {
    document.querySelectorAll(".data-nav").forEach((button) => button.classList.toggle("active", button.dataset.dataPage === page));
    document.querySelectorAll(".data-page").forEach((section) => {
      const active = section.dataset.dataContent === page;
      section.classList.toggle("active", active);
      section.hidden = !active;
      if (active) section.scrollTop = 0;
    });
    if (page === "dual-engine") { renderRitaWithDisplayStatus(); renderLstmWithStatus(); }
    if (page === "attribution") renderAttributionPretty();
  };
  const ensureReportPage = () => {
    const content = $("data-center-new"), legacy = document.querySelector("[data-legacy-report-panel]");
    if (!content || !legacy || content.querySelector('[data-data-content="report"]')) return;
    const page = document.createElement("section"); page.className = "data-page report-page"; page.dataset.dataContent = "report";
    const title = document.createElement("h2"); title.textContent = "分析报告"; page.append(title);
    const header = document.createElement("div"); header.className = "report-page-heading";
    const legacyHead = legacy.querySelector(".result-head");
    header.append(title);
    if (legacyHead) header.append(legacyHead);
    legacy.hidden = false; legacy.classList.remove("panel"); page.append(header, legacy); content.append(page);
  };
  const renderOverview = () => {
    const list = threats(), primary = list[0], attribution = dashboard?.attribution || {};
    const maxBeacon = Math.max(0, ...list.map((x) => num(x.beacon_score)));
    const maxLstm = Math.max(0, ...list.map((x) => num(x.lstm_confidence)));
    text("viz-threat-count", list.length); text("viz-beacon-max", maxBeacon ? maxBeacon.toFixed(1) : null); text("viz-lstm-max", maxLstm ? `${maxLstm.toFixed(1)}%` : null); text("viz-rag-confidence", attribution.confidence == null ? null : `${num(attribution.confidence).toFixed(1)}%`);
    const meta = $("analysis-meta"); if (meta) meta.innerHTML = [["分析文件名", analysis?.original_filename || dashboard?.display_name], ["文件大小", formatSize(analysis?.file_size)], ["分析时间", fmtTime(analysis?.completed_at || analysis?.created_at)], ["分析状态", analysis?.status === "completed" ? "已完成" : analysis?.status || "暂无数据"], ["综合风险等级", primary ? risk(primary.threat_category) : "未发现可疑连接"]].map(([k, v]) => `<div><span>${escapeHtml(k)}</span><strong>${escapeHtml(v || "暂无数据")}</strong></div>`).join("");
    text("overview-summary", list.length ? `检测到 ${list.length} 条重点可疑连接。综合 RITA、LSTM 与知识库检索结果，建议优先核查下列通信及其关联主机。` : "当前分析未形成可展示的可疑连接。");
    const tbody = $("overview-threats"); if (tbody) tbody.innerHTML = list.slice(0, 10).map((x) => `<tr><td>${escapeHtml(x.src_ip || "-")}</td><td>${escapeHtml(x.dst_ip || "-")}:${escapeHtml(x.dst_port || "-")}</td><td>${escapeHtml((x.detection_sources || []).join(" / ") || "-")}</td><td>${num(x.beacon_score).toFixed(1)}</td><td>${num(x.lstm_confidence).toFixed(1)}%</td><td>${escapeHtml(risk(x.threat_category))}</td></tr>`).join("") || '<tr><td colspan="6">暂无重点可疑连接</td></tr>';
  };
  const renderDetectionOverview = () => {
    const list = threats(), rawRita = rawRitaResults(), primary = selected || list[0], attribution = dashboard?.attribution || {};
    // `threats` deliberately contains only alert-level connections.  A benign
    // sample can still have a real RITA result in `engine_results.rita`, which
    // must contribute to the overview KPI without becoming a suspicious row.
    const ritaResults = [...list.filter((item) => (item.detection_sources || []).includes("RITA")), ...rawRita];
    const maxBeacon = Math.max(0, ...ritaResults.map((item) => num(item.beacon_score)));
    const maxLstm = Math.max(0, ...list.map((item) => num(item.lstm_confidence)));
    const hasLstmValue = list.some((item) => Number.isFinite(Number(item.lstm_confidence)));
    const attributionConfidence = attribution.confidence == null ? null : num(attribution.confidence);
    const lstmStatus = dashboard?.lstm?.status;
    const attributionStatus = dashboard?.attribution_status;
    const lstmStatusNote = {
      insufficient_sequence: "时序样本不足",
      completed: "未发现 Beacon 异常",
      unavailable: "模型不可用",
      failed: "检测失败，请查看任务日志",
    }[lstmStatus] || "未参与本次评估";
    const attributionStatusNote = {
      no_threat: "当前无待归因威胁",
      no_candidate: "未检索到归因候选",
      unavailable: "归因服务不可用",
      failed: "归因失败，请查看任务日志",
    }[attributionStatus] || "未参与本次评估";
    const riskKey = String(primary?.threat_category || "low").toLowerCase();
    const riskLabel = primary ? `${risk(riskKey)}风险` : "未发现风险";
    const statusLabel = analysis?.status === "completed" ? "已完成" : (analysis?.status || "暂无数据");
    const filename = analysis?.original_filename || dashboard?.display_name || "暂无数据";
    const setValue = (id, value) => { const el = $(id); if (el) el.textContent = value == null || value === "" ? "暂无数据" : String(value); };
    const setMetricValue = (id, value) => { const el = $(id); if (el) el.textContent = value == null || value === "" ? "—" : String(value); };
    const setRiskBadge = (id, label, key = "low") => { const el = $(id); if (!el) return; el.textContent = label; el.className = `overview-badge risk ${["critical", "high", "medium", "low"].includes(key) ? key : "low"}`; };

    setValue("overview-file-name", filename);
    const filenameEl = $("overview-file-name"); if (filenameEl) filenameEl.title = filename;
    setValue("overview-file-size", formatSize(analysis?.file_size));
    setValue("overview-file-time", fmtTime(analysis?.completed_at || analysis?.created_at));
    const statusBadge = $("overview-status-badge"); if (statusBadge) { statusBadge.textContent = statusLabel; statusBadge.className = `overview-badge status ${analysis?.status === "completed" ? "complete" : "pending"}`; }
    setRiskBadge("overview-risk-badge", riskLabel, riskKey);
    setRiskBadge("overview-conclusion-risk", riskLabel, riskKey);

    setMetricValue("viz-threat-count", list.length);
    setMetricValue("viz-beacon-max", ritaResults.length ? maxBeacon.toFixed(1) : null);
    setMetricValue("viz-lstm-max", lstmResults.length ? `${maxLstm.toFixed(1)}%` : null);
    setMetricValue("viz-rag-confidence", attributionConfidence == null ? null : `${attributionConfidence.toFixed(1)}%`);
    setValue("viz-threat-note", list.length ? `${list.length} 条需重点关注` : "未发现重点可疑连接");
    setValue("viz-beacon-note", ritaResults.length ? (list.length ? (maxBeacon >= 80 ? "强周期特征" : maxBeacon >= 50 ? "中等周期特征" : "低周期特征") : "原始 RITA 结果，未达告警阈值") : "暂无 RITA 结果");
    setValue("viz-lstm-note", hasLstmValue ? (maxLstm >= 80 ? "高置信异常" : maxLstm >= 50 ? "中等置信异常" : "低置信异常") : lstmStatusNote);
    setValue("viz-rag-note", attributionConfidence == null ? attributionStatusNote : (attributionConfidence >= 70 ? "较高归因可信度" : attributionConfidence >= 40 ? "中等归因可信度" : "低归因可信度"));

    const dualEngineCount = list.filter((item) => ["RITA", "LSTM"].every((engine) => (item.detection_sources || []).includes(engine))).length;
    const target = primary ? `${primary.src_ip || "-"} → ${primary.dst_ip || "-"}:${primary.dst_port || "-"}` : "当前样本";
    const conclusion = !list.length
      ? "当前分析未发现需要展示的重点可疑连接。"
      : `检测到 ${list.length} 条重点可疑连接${dualEngineCount ? `，其中 ${dualEngineCount} 条由 RITA 与 LSTM 共同发现异常。` : "。"}`;
    const advice = !list.length
      ? "建议结合业务基线持续观察后续通信行为。"
      : `建议优先核查 ${target} 的通信目的、关联主机与业务合理性。`;
    setValue("overview-summary-main", conclusion);
    setValue("overview-summary-advice", advice);
    setValue("overview-evidence-count", `${list.length} 条`);

    const tbody = $("overview-threats");
    if (tbody) tbody.innerHTML = list.slice(0, 10).map((item) => {
      const itemRisk = String(item.threat_category || "low").toLowerCase();
      const engines = item.detection_sources || [];
      const engineHtml = engines.length ? engines.map((engine) => `<span class="overview-engine">${escapeHtml(engine)}</span>`).join('<i class="overview-engine-plus">+</i>') : "-";
      return `<tr><td><code>${escapeHtml(item.src_ip || "-")}</code></td><td><span class="overview-flow"><code>${escapeHtml(item.dst_ip || "-")}</code><span>:</span><code>${escapeHtml(item.dst_port || "-")}</code></span></td><td><span class="overview-engine-set">${engineHtml}</span></td><td>${num(item.beacon_score).toFixed(1)}</td><td>${num(item.lstm_confidence).toFixed(1)}%</td><td><span class="overview-table-risk ${["critical", "high", "medium", "low"].includes(itemRisk) ? itemRisk : "low"}">${escapeHtml(risk(itemRisk))}风险</span></td></tr>`;
    }).join("") || '<tr><td colspan="6" class="overview-table-empty">暂无重点可疑连接</td></tr>';
  };
  const updateSelected = (item) => { selected = item; renderRitaWithDisplayStatus(); renderLstmWithStatus(); };
  const renderConnection = () => { const body = $("topology-evidence-body"), x = selected; if (!body) return; if (!x) { body.textContent = "暂无可选连接"; return; } body.innerHTML = [["源 IP", x.src_ip], ["目标 IP / 端口", `${x.dst_ip || "-"}:${x.dst_port || "-"}`], ["协议", getEvidence(x).protocol || "暂无数据"], ["检测来源", (x.detection_sources || []).join(" / ") || "暂无数据"], ["Beacon Score", num(x.beacon_score).toFixed(1)], ["LSTM 置信度", `${num(x.lstm_confidence).toFixed(1)}%`], ["风险等级", risk(x.threat_category)]].map(([k, v]) => `<div><span>${escapeHtml(k)}</span><strong>${escapeHtml(v)}</strong></div>`).join(""); };
  const renderTopology = () => { const el = $("network-topology-chart"); if (!el || !window.echarts) return; topologyChart?.dispose(); topologyChart = echarts.init(el); const nodes = new Map(), links = threats().map((x) => { nodes.set(x.src_ip, { name: x.src_ip, category: 0, symbolSize: 44 }); nodes.set(x.dst_ip, { name: x.dst_ip, category: 1, symbolSize: 36 }); return { source: x.src_ip, target: x.dst_ip, value: x, evidence: x, lineStyle: { color: color(x.threat_category), width: 3 } } }); topologyChart.setOption({ tooltip: { formatter: p => p.dataType === 'edge' ? `${p.data.source} → ${p.data.target}` : p.name }, legend: [{ data: ["源主机", "目标主机"] }], series: [{ type: "graph", layout: "force", roam: true, draggable: true, data: [...nodes.values()], links, categories: [{ name: "源主机" }, { name: "目标主机" }], label: { show: true, position: "right" }, force: { repulsion: 280, edgeLength: [110, 200] } }] }); topologyChart.on("click", p => { if (p.dataType === "edge") updateSelected(p.data.evidence); }); };
  const renderRita = () => { const box = $("rita-content"), x = selected, e = getEvidence(x); if (!box) return; if (!x || !(x.detection_sources || []).includes("RITA")) { box.className = "visualization-empty"; box.textContent = "当前连接暂无 RITA 明细数据。"; return; } const score = [['时间规律性', 'timestamp_score'], ['数据量规律性', 'datasize_score'], ['持续性', 'duration_score'], ['分布规律性', 'histogram_score']]; const components = score.map(([label, key]) => `<div><span>${label}<small>${key}</small></span><strong>${e[key] == null ? "暂无数据" : num(e[key]).toFixed(3)}</strong></div>`).join(""); box.className = "rita-detail"; box.innerHTML = `<div class="analysis-meta"><div><span>综合 Beacon Score</span><strong>${num(x.beacon_score).toFixed(1)}</strong></div><div><span>风险等级</span><strong>${risk(x.threat_category)}</strong></div><div><span>连接次数</span><strong>${e.connection_count ?? x.connection_count ?? "暂无数据"}</strong></div><div><span>累计持续时间</span><strong>${e.total_duration == null ? "暂无数据" : `${num(e.total_duration).toFixed(1)} 秒`}</strong></div></div><div class="rita-components">${components}</div><article class="visualization-card"><div class="rita-chart-head"><h3>Beacon 行为特征</h3><div class="rita-chart-tabs"><button type="button" class="active" data-rita-chart="interval">通信间隔</button><button type="button" data-rita-chart="frequency">连接频率</button><button type="button" data-rita-chart="size">数据大小</button></div></div><p id="rita-chart-note" class="rita-chart-note"></p><div id="rita-behavior-chart" class="echart-canvas compact-chart"></div></article><div class="analysis-meta"><div><span>Long Connection</span><strong>${e.long_connection ?? x.long_conn_value ?? "暂无数据"}</strong></div><div><span>C2 over DNS</span><strong>${e.c2_over_dns ?? x.c2_over_dns_value ?? "暂无数据"}</strong></div><div><span>子域名数量</span><strong>${e.subdomain_count ?? "暂无数据"}</strong></div><div><span>Threat Intelligence</span><strong>${e.threat_intelligence ?? "暂无数据"}</strong></div></div>`; const chart = $("rita-behavior-chart"); const note = $("rita-chart-note"); if (!chart || !window.echarts) return; const draw = (kind) => { const sequence = e.connection_sequence || {}; const isSize = kind === "size", isFrequency = kind === "frequency"; const values = isFrequency ? sequence.frequency_per_minute : (isSize ? sequence.total_bytes : sequence.interval_seconds); const labels = sequence.indexes; if (!Array.isArray(labels) || !Array.isArray(values) || !labels.length || labels.length !== values.length) { ritaChart?.dispose(); chart.textContent = "未形成可展示的 Zeek 逐连接行为序列。"; if (note) note.textContent = "需要当前连接在 Zeek conn.log 中有可匹配的记录。"; return; } chart.textContent = ""; const axisName = isFrequency ? "连接频率（次/分钟）" : (isSize ? "双向数据大小（B）" : "通信间隔（秒）"); if (note) note.textContent = isFrequency ? "由相邻两条 Zeek 连接的真实时间间隔换算。" : (isSize ? "每条连接的 Zeek 双向字节总量。" : "每条连接相对于前一条连接的真实时间间隔。首条连接间隔记为 0。 "); ritaChart?.dispose(); ritaChart = echarts.init(chart); ritaChart.setOption({ tooltip: { trigger: "axis", formatter: p => `连接序号：${p[0].axisValue}<br/>${axisName}：${num(p[0].data).toFixed(isFrequency ? 2 : 0)}` }, xAxis: { type: "category", name: "连接序号", data: labels }, yAxis: { type: "value", name: axisName, min: 0 }, series: [{ type: "line", smooth: false, symbol: "circle", symbolSize: 6, data: values.map(v => num(v)), areaStyle: { opacity: .12 }, itemStyle: { color: "#14b88a" } }] }); }; box.querySelectorAll("[data-rita-chart]").forEach(button => button.addEventListener("click", () => { box.querySelectorAll("[data-rita-chart]").forEach(tab => tab.classList.toggle("active", tab === button)); draw(button.dataset.ritaChart); })); draw("interval"); };
  const renderLstm = () => { const box = $("lstm-content"), x = selected; if (!box) return; if (!x || !(x.detection_sources || []).includes("LSTM")) { box.className = "visualization-empty"; box.textContent = "当前连接没有 LSTM 告警，或未形成可预测的 10 步序列。"; return; } box.className = "lstm-detail"; box.innerHTML = `<div class="analysis-meta"><div><span>当前连接</span><strong>${escapeHtml(x.src_ip)} → ${escapeHtml(x.dst_ip)}:${escapeHtml(x.dst_port)}</strong></div><div><span>模型判断</span><strong>潜在 Beacon</strong></div><div><span>置信度</span><strong>${num(x.lstm_confidence).toFixed(1)}%</strong></div><div><span>风险等级</span><strong>${escapeHtml(x.lstm_risk || risk(x.threat_category))}</strong></div></div><p></p>`; };
  const restoreLstmMetrics = () => {
    const box = $("lstm-content");
    if (!box) return null;
    if (!lstmSection) lstmSection = box.closest(".dual-engine-section");
    if (lstmSection && !lstmSection.contains(box)) lstmSection.append(box);
    if (lstmSection) lstmSection.hidden = false;
    return box;
  };
  const mountLstmMetrics = () => {
    const box = $("lstm-content"), ritaMeta = $("rita-content")?.querySelector(".analysis-meta");
    if (!box || !ritaMeta) return box;
    if (!lstmSection) lstmSection = box.closest(".dual-engine-section");
    ritaMeta.insertAdjacentElement("afterend", box);
    if (lstmSection) lstmSection.hidden = true;
    return box;
  };
  const renderUnifiedDetection = () => {
    const box = $("rita-content"), x = selected, evidence = getEvidence(x);
    if (!box) return;
    if (!x) {
      box.className = "visualization-empty unified-no-data";
      box.textContent = "本次未形成可用检测结果。";
      return;
    }

    const hasRita = (x.detection_sources || []).includes("RITA") || Object.keys(evidence).length > 0;
    const hasLstm = (x.detection_sources || []).includes("LSTM") && x.lstm_confidence != null;
    const unavailable = "—";
    const unavailableNote = "未参与本次评估";
    const displayNumber = (value, digits = 1) => value == null ? unavailable : num(value).toFixed(digits);
    const formatBytes = (value) => value == null ? unavailable : `${(num(value) / 1024).toFixed(1)} KB`;
    const destinationIp = x.dst_ip && x.dst_ip !== "::" ? x.dst_ip : "";
    const hostname = evidence.destination_host || x.dst_host || "";
    const destination = hostname || destinationIp || "未记录";
    // 域名已能清楚表达通信对象；仅在同时获得有效 IP 时补充展示，避免把 RITA 的 "::" 暴露为无意义地址。
    const destinationDetail = hostname && destinationIp ? destinationIp : "";
    const connectionCount = evidence.connection_count ?? x.connection_count;
    const port = x.dst_port || "—";
    const protocol = evidence.protocol || x.protocol || "—";
    const service = evidence.service || "";
    const severity = hasRita ? risk(x.threat_category) : unavailable;
    const modelJudgement = hasLstm ? (num(x.lstm_confidence) >= 50 ? "疑似周期性通信" : "未发现周期性通信") : unavailable;
    const metric = (label, value, note = "") => `<article class="unified-metric"><span class="unified-metric-name">${escapeHtml(label)}</span><strong class="unified-metric-value">${escapeHtml(value)}</strong><small class="unified-metric-description">${escapeHtml(note || unavailableNote)}</small></article>`;
    const scoreFields = [
      ["时间规律性", "timestamp_score", "通信时间规律评分"],
      ["数据量规律性", "datasize_score", "通信数据量规律评分"],
      ["持续性", "duration_score", "通信时长规律评分"],
      ["分布规律性", "histogram_score", "通信分布规律评分"],
    ];
    const behaviorScores = scoreFields.map(([label, key, note]) => {
      const value = hasRita && evidence[key] != null ? displayNumber(evidence[key], 3) : unavailable;
      return metric(label, value, hasRita ? note : unavailableNote);
    }).join("");

    box.className = "unified-detection";
    box.innerHTML = `
      <section class="unified-connection-strip" aria-label="通信对象信息">
        <div><span>源地址</span><strong>${escapeHtml(x.src_ip || unavailable)}</strong></div>
        <div><span>通信目标</span><strong>${escapeHtml(destination)}</strong>${destinationDetail ? `<small>${escapeHtml(destinationDetail)}</small>` : ""}</div>
        <div><span>端口 / 协议 / 服务</span><strong>${escapeHtml(`${port} / ${protocol}${service ? ` / ${service}` : ""}`)}</strong></div>
        <div><span>连接次数</span><strong>${escapeHtml(connectionCount == null ? unavailable : String(connectionCount))}</strong></div>
      </section>
      <section class="unified-section">
        <h3>核心检测指标</h3>
        <div class="unified-metric-grid">
          ${metric("周期性通信评分", hasRita ? displayNumber(x.beacon_score) : unavailable, hasRita ? "周期性通信规律评分" : "未参与本次评估")}
          ${metric("时序异常置信度", hasLstm ? `${displayNumber(x.lstm_confidence)}%` : unavailable, hasLstm ? "时序模型评估结果" : "未参与本次评估")}
          ${metric("综合风险等级", severity, hasRita ? "通信行为风险" : "未参与本次评估")}
          ${metric("模型判断", modelJudgement, hasLstm ? "时序检测结论" : "未参与本次评估")}
        </div>
      </section>
      <section class="unified-section">
        <h3>通信与风险指标</h3>
        <div class="unified-metric-grid">
          ${metric("累计通信时长", hasRita ? `${displayNumber(evidence.total_duration, 1)} 秒` : unavailable, hasRita ? "聚合通信时长" : "未参与本次评估")}
          ${metric("总通信数据量", hasRita ? formatBytes(evidence.total_bytes) : unavailable, hasRita ? "双向累计数据量" : "未参与本次评估")}
          ${metric("域名控制通道风险评分", hasRita ? displayNumber(evidence.c2_over_dns, 3) : unavailable, hasRita ? "域名控制通道风险" : "未参与本次评估")}
          ${metric("长连接风险评分", hasRita ? displayNumber(evidence.long_connection, 3) : unavailable, hasRita ? "持续连接风险" : "未参与本次评估")}
        </div>
      </section>
      <section class="unified-section">
        <h3>通信行为特征</h3>
        <div class="unified-metric-grid">${behaviorScores}</div>
      </section>
      <article class="visualization-card unified-chart-card">
        <div class="rita-chart-head"><h3>通信行为趋势</h3><div class="rita-chart-tabs"><button type="button" class="active" data-unified-chart="interval">通信间隔</button><button type="button" data-unified-chart="frequency">连接频率</button><button type="button" data-unified-chart="size">数据大小</button></div></div>
        <p id="unified-chart-note" class="rita-chart-note"></p><div id="unified-behavior-chart" class="echart-canvas compact-chart"></div>
      </article>`;

    const chart = $("unified-behavior-chart"), note = $("unified-chart-note");
    if (!chart || !window.echarts) return;
    const draw = (kind) => {
      const sequence = evidence.connection_sequence || {};
      const isFrequency = kind === "frequency", isSize = kind === "size";
      const values = isFrequency ? sequence.frequency_per_minute : (isSize ? sequence.total_bytes : sequence.interval_seconds);
      const labels = sequence.indexes;
      if (!Array.isArray(labels) || !Array.isArray(values) || !labels.length || labels.length !== values.length) {
        ritaChart?.dispose();
        chart.textContent = "暂无可展示的通信行为趋势。";
        if (note) note.textContent = "当前通信组未提供逐连接行为数据。";
        return;
      }
      const axisName = isFrequency ? "连接频率（次/分钟）" : (isSize ? "双向数据大小（B）" : "通信间隔（秒）");
      if (note) note.textContent = isFrequency ? "按相邻连接的时间间隔换算。" : (isSize ? "每条连接的双向总数据量。" : "每条连接相对前一条连接的时间间隔。");
      chart.textContent = "";
      ritaChart?.dispose();
      ritaChart = echarts.init(chart);
      ritaChart.setOption({
        tooltip: { trigger: "axis", formatter: points => `连接序号：${points[0].axisValue}<br/>${axisName}：${num(points[0].data).toFixed(isFrequency ? 2 : 0)}` },
        xAxis: { type: "category", name: "连接序号", data: labels },
        yAxis: { type: "value", name: axisName, min: 0 },
        series: [{ type: "line", smooth: false, symbol: "circle", symbolSize: 6, data: values.map(value => num(value)), areaStyle: { opacity: .12 }, itemStyle: { color: "#14b88a" } }],
      });
    };
    box.querySelectorAll("[data-unified-chart]").forEach(button => button.addEventListener("click", () => {
      box.querySelectorAll("[data-unified-chart]").forEach(tab => tab.classList.toggle("active", tab === button));
      draw(button.dataset.unifiedChart);
    }));
    draw("interval");
  };
  const renderRitaWithDisplayStatus = () => {
    renderUnifiedDetection();
  };
  const renderLstmWithStatus = () => {
    const section = $("lstm-content")?.closest(".dual-engine-section");
    if (section) section.hidden = true;
  };
  const renderAttribution = () => { const box = $("attribution-content"), a = dashboard?.attribution; if (!box) return; if (!a?.candidates?.length) { box.className = "visualization-empty"; box.textContent = "暂无候选归因结果。"; return; } const excerpt = value => String(value || "").replace(/\s+/g, " ").trim().slice(0, 520); box.className = "attribution-detail"; box.innerHTML = `<article class="visualization-card"><p><b>首要候选：</b>${escapeHtml(a.primary_candidate?.name || "暂无数据")}　<b>检索置信度：</b>${num(a.confidence).toFixed(1)}%</p><p>该分数表示当前网络行为与 ATT&CK 知识库条目的匹配强弱及其与下一候选的区分度，不代表已确认攻击者身份。</p></article>${a.candidates.map((c, i) => { const m = c.metadata || {}, techniques = m.matched_technique_details || [], background = excerpt(m.background), aliases = (m.aliases || []).filter(Boolean), software = m.associated_software || ""; const techniqueHtml = techniques.length ? techniques.map(t => `<li><b>${escapeHtml(t.id || "ATT&CK")}</b>${t.name ? ` · ${escapeHtml(t.name)}` : ""}${t.evidence ? `<small>${escapeHtml(excerpt(t.evidence))}</small>` : ""}</li>`).join("") : `<li>${escapeHtml((m.c2_techniques || []).join("、") || "暂无关联技术")}</li>`; return `<article class="visualization-card attribution-candidate"><div class="attribution-candidate-head"><h3>候选 ${i + 1}：${escapeHtml(c.name || "暂无数据")}</h3><span>相似度 ${c.score == null ? "暂无数据" : num(c.score).toFixed(3)}</span></div>${aliases.length ? `<p><b>别名：</b>${escapeHtml(aliases.join("、"))}</p>` : ""}${background ? `<p><b>组织背景：</b>${escapeHtml(background)}${String(m.background || "").length > 520 ? "…" : ""}</p>` : ""}<div><b>本次命中的 ATT&CK 技术</b><ul class="attribution-techniques">${techniqueHtml}</ul></div>${software && software !== "(none)" ? `<p><b>关联工具：</b>${escapeHtml(software)}</p>` : ""}${m.mitre_url ? `<a class="attribution-link" href="${escapeHtml(m.mitre_url)}" target="_blank" rel="noopener noreferrer">查看 MITRE ATT&CK 组织档案</a>` : ""}</article>`; }).join("")}`; };
  const renderAttributionPretty = () => {
    const box = $("attribution-content"), attribution = dashboard?.attribution;
    if (!box) return;
    if (!attribution?.candidates?.length) {
      box.className = "visualization-empty";
      box.textContent = "暂无候选归因结果。";
      return;
    }
    box.className = "attribution-detail";
    const candidates = attribution.candidates.map((candidate, index) => {
      const metadata = candidate.metadata || {};
      const aliases = (metadata.aliases || []).filter(Boolean);
      const background = renderIntelText(metadata.background_zh || metadata.background);
      const techniques = metadata.matched_technique_details || [];
      const techniqueHtml = techniques.length
        ? techniques.map((technique) => {
          const evidence = renderIntelText(technique.evidence_zh || technique.evidence);
          const techniqueName = technique.name_zh || technique.name;
          return `<li><b>${escapeHtml(technique.id || "ATT&CK")}</b>${techniqueName ? ` · ${escapeHtml(techniqueName)}` : ""}${evidence.html ? `<small>${evidence.html}</small>` : ""}</li>`;
        }).join("")
        : `<li>${escapeHtml((metadata.c2_techniques || []).join("、") || "暂无关联技术")}</li>`;
      return `<article class="visualization-card attribution-candidate"><div class="attribution-candidate-head"><h3>候选 ${index + 1}：${escapeHtml(candidate.name || "暂无数据")}</h3><span>相似度 ${candidate.score == null ? "暂无数据" : num(candidate.score).toFixed(3)}</span></div>${aliases.length ? `<p><b>别名：</b>${escapeHtml(aliases.join("、"))}</p>` : ""}${background.html ? `<div class="attribution-background"><b>组织背景</b><p>${background.html}</p></div>` : ""}<div><b>本次命中的 ATT&CK 技术</b><ul class="attribution-techniques">${techniqueHtml}</ul></div>${metadata.associated_software && metadata.associated_software !== "(none)" ? `<p><b>关联工具：</b>${escapeHtml(metadata.associated_software)}</p>` : ""}<p class="attribution-source">信息来源：MITRE ATT&amp;CK</p>${metadata.mitre_url ? `<a class="attribution-link" href="${escapeHtml(metadata.mitre_url)}" target="_blank" rel="noopener noreferrer">查看 MITRE ATT&CK 组织档案</a>` : ""}</article>`;
    }).join("");
    box.innerHTML = `<article class="visualization-card"><p><b>首要候选：</b>${escapeHtml(attribution.primary_candidate?.name || "暂无数据")}　<b>检索置信度：</b>${num(attribution.confidence).toFixed(1)}%</p><p>该分数表示当前网络行为与 ATT&CK 知识库条目的匹配强弱及其与下一候选的区分度，不代表已确认攻击者身份。</p></article>${candidates}`;
  };
  const render = (nextDashboard, nextAnalysis = null) => {
    if (!nextDashboard || typeof nextDashboard !== "object") {
      clear();
      return;
    }
    dashboard = nextDashboard;
    analysis = nextAnalysis || analysis;
    ensureReportPage();
    setDataCenterState(true);
    const rawRita = rawRitaResults()[0];
    selected = threats()[0] || (rawRita ? {
      ...rawRita,
      detection_sources: ["RITA"],
      threat_category: "low",
      is_raw_engine_result: true,
    } : null);
    renderDetectionOverview();
    renderRitaWithDisplayStatus();
    renderLstmWithStatus();
    renderAttributionPretty();
    switchPage("overview");
  };
  const refresh = () => {};
  const clear = () => {
    dashboard = null;
    analysis = null;
    selected = null;
    topologyChart?.dispose();
    ritaChart?.dispose();
    setDataCenterState(false);
  };
  document.addEventListener("click", e => { const b = e.target.closest(".data-nav"); if (b) switchPage(b.dataset.dataPage); }); window.addEventListener("resize", () => { topologyChart?.resize(); ritaChart?.resize(); }); window.C2SherlockVisualization = { render, refresh, clear };
})();
