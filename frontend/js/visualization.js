(() => {
  let topologyChart = null, intervalChart = null, dashboard = null, analysis = null, selected = null;
  const $ = (id) => document.getElementById(id);
  const num = (v) => Number.isFinite(Number(v)) ? Number(v) : 0;
  const escapeHtml = (value) => String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
  const text = (id, value) => { const el = $(id); if (el) el.textContent = value == null || value === "" ? "暂无数据" : String(value); };
  const risk = (t) => ({ critical: "高", high: "高", medium: "中", low: "低" }[String(t).toLowerCase()] || "待研判");
  const color = (t) => ({ critical: "#dc2626", high: "#dc2626", medium: "#f59e0b" }[String(t).toLowerCase()] || "#16a34a");
  const formatSize = (bytes) => bytes == null ? "暂无数据" : `${(Number(bytes) / 1024).toFixed(1)} KB`;
  const fmtTime = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "暂无数据";
  const threats = () => Array.isArray(dashboard?.threats) ? dashboard.threats : [];
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
    document.querySelectorAll(".data-page").forEach((section) => section.classList.toggle("active", section.dataset.dataContent === page));
    if (page === "topology") renderTopology();
    if (page === "rita") renderRita();
    if (page === "lstm") renderLstm();
    if (page === "attribution") renderAttribution();
  };
  const ensureReportPage = () => {
    const content = $("data-center-new"), legacy = document.querySelector("[data-legacy-report-panel]");
    if (!content || !legacy || content.querySelector('[data-data-content="report"]')) return;
    const page = document.createElement("section"); page.className = "data-page report-page"; page.dataset.dataContent = "report";
    const title = document.createElement("h2"); title.textContent = "AI 分析报告"; page.append(title);
    legacy.hidden = false; legacy.classList.remove("panel"); page.append(legacy); content.append(page);
  };
  const renderOverview = () => {
    const list = threats(), primary = selected || list[0], attribution = dashboard?.attribution || {};
    const maxBeacon = Math.max(0, ...list.map((x) => num(x.beacon_score)));
    const maxLstm = Math.max(0, ...list.map((x) => num(x.lstm_confidence)));
    text("viz-threat-count", list.length); text("viz-beacon-max", maxBeacon ? maxBeacon.toFixed(1) : null); text("viz-lstm-max", maxLstm ? `${maxLstm.toFixed(1)}%` : null); text("viz-rag-confidence", attribution.confidence == null ? null : `${num(attribution.confidence).toFixed(1)}%`);
    const meta = $("analysis-meta"); if (meta) meta.innerHTML = [["分析文件名", analysis?.original_filename || dashboard?.display_name], ["文件大小", formatSize(analysis?.file_size)], ["分析时间", fmtTime(analysis?.completed_at || analysis?.created_at)], ["分析状态", analysis?.status === "completed" ? "已完成" : analysis?.status || "暂无数据"], ["综合风险等级", primary ? risk(primary.threat_category) : "未发现可疑连接"]].map(([k, v]) => `<div><span>${escapeHtml(k)}</span><strong>${escapeHtml(v || "暂无数据")}</strong></div>`).join("");
    text("overview-summary", list.length ? `检测到 ${list.length} 条重点可疑连接。综合 RITA、LSTM 与知识库检索结果，建议优先核查下列通信及其关联主机。` : "当前分析未形成可展示的可疑连接。");
    const tbody = $("overview-threats"); if (tbody) tbody.innerHTML = list.slice(0, 10).map((x) => `<tr><td>${escapeHtml(x.src_ip || "-")}</td><td>${escapeHtml(x.dst_ip || "-")}:${escapeHtml(x.dst_port || "-")}</td><td>${escapeHtml((x.detection_sources || []).join(" / ") || "-")}</td><td>${num(x.beacon_score).toFixed(1)}</td><td>${num(x.lstm_confidence).toFixed(1)}%</td><td>${escapeHtml(risk(x.threat_category))}</td></tr>`).join("") || '<tr><td colspan="6">暂无重点可疑连接</td></tr>';
  };
  const updateSelected = (item) => { selected = item; renderConnection(); renderRita(); renderLstm(); };
  const renderConnection = () => { const body = $("topology-evidence-body"), x = selected; if (!body) return; if (!x) { body.textContent = "暂无可选连接"; return; } body.innerHTML = [["源 IP", x.src_ip], ["目标 IP / 端口", `${x.dst_ip || "-"}:${x.dst_port || "-"}`], ["协议", getEvidence(x).protocol || "暂无数据"], ["检测来源", (x.detection_sources || []).join(" / ") || "暂无数据"], ["Beacon Score", num(x.beacon_score).toFixed(1)], ["LSTM 置信度", `${num(x.lstm_confidence).toFixed(1)}%`], ["风险等级", risk(x.threat_category)]].map(([k, v]) => `<div><span>${escapeHtml(k)}</span><strong>${escapeHtml(v)}</strong></div>`).join(""); };
  const renderTopology = () => { const el = $("network-topology-chart"); if (!el || !window.echarts) return; topologyChart?.dispose(); topologyChart = echarts.init(el); const nodes = new Map(), links = threats().map((x) => { nodes.set(x.src_ip, { name: x.src_ip, category: 0, symbolSize: 44 }); nodes.set(x.dst_ip, { name: x.dst_ip, category: 1, symbolSize: 36 }); return { source: x.src_ip, target: x.dst_ip, value: x, evidence: x, lineStyle: { color: color(x.threat_category), width: 3 } } }); topologyChart.setOption({ tooltip: { formatter: p => p.dataType === 'edge' ? `${p.data.source} → ${p.data.target}` : p.name }, legend: [{ data: ["源主机", "目标主机"] }], series: [{ type: "graph", layout: "force", roam: true, draggable: true, data: [...nodes.values()], links, categories: [{ name: "源主机" }, { name: "目标主机" }], label: { show: true, position: "right" }, force: { repulsion: 280, edgeLength: [110, 200] } }] }); topologyChart.on("click", p => { if (p.dataType === "edge") updateSelected(p.data.evidence); }); };
  const renderRita = () => { const box = $("rita-content"), x = selected, e = getEvidence(x); if (!box) return; if (!x || !(x.detection_sources || []).includes("RITA")) { box.className = "visualization-empty"; box.textContent = "当前连接暂无 RITA 明细数据。"; return; } const score = [['时间规律性', 'timestamp_score'], ['数据量规律性', 'datasize_score'], ['持续性', 'duration_score'], ['分布规律性', 'histogram_score']]; const components = score.map(([label, key]) => `<div><span>${label}<small>${key}</small></span><strong>${e[key] == null ? "暂无数据" : num(e[key]).toFixed(3)}</strong></div>`).join(""); box.className = "rita-detail"; box.innerHTML = `<div class="analysis-meta"><div><span>综合 Beacon Score</span><strong>${num(x.beacon_score).toFixed(1)}</strong></div><div><span>风险等级</span><strong>${risk(x.threat_category)}</strong></div><div><span>连接次数</span><strong>${e.connection_count ?? x.connection_count ?? "暂无数据"}</strong></div><div><span>累计持续时间</span><strong>${e.total_duration == null ? "暂无数据" : `${num(e.total_duration).toFixed(1)} 秒`}</strong></div></div><div class="rita-components">${components}</div><article class="visualization-card"><h3>Beacon 行为：通信间隔分布</h3><div id="rita-interval-chart" class="echart-canvas compact-chart"></div></article><div class="analysis-meta"><div><span>Long Connection</span><strong>${e.long_connection ?? x.long_conn_value ?? "暂无数据"}</strong></div><div><span>C2 over DNS</span><strong>${e.c2_over_dns ?? x.c2_over_dns_value ?? "暂无数据"}</strong></div><div><span>子域名数量</span><strong>${e.subdomain_count ?? "暂无数据"}</strong></div><div><span>Threat Intelligence</span><strong>${e.threat_intelligence ?? "暂无数据"}</strong></div></div>`; const chart = $("rita-interval-chart"); if (!chart || !window.echarts || !Array.isArray(e.ts_intervals) || !Array.isArray(e.ts_interval_counts)) { return; } intervalChart?.dispose(); intervalChart = echarts.init(chart); intervalChart.setOption({ tooltip: { trigger: "axis" }, xAxis: { type: "category", name: "间隔", data: e.ts_intervals }, yAxis: { type: "value", name: "次数" }, series: [{ type: "line", smooth: false, data: e.ts_interval_counts, areaStyle: { opacity: .12 } }] }); };
  const renderLstm = () => { const box = $("lstm-content"), x = selected; if (!box) return; if (!x || !(x.detection_sources || []).includes("LSTM")) { box.className = "visualization-empty"; box.textContent = "当前连接没有 LSTM 告警，或未形成可预测的 10 步序列。"; return; } box.className = "lstm-detail"; box.innerHTML = `<div class="analysis-meta"><div><span>当前连接</span><strong>${escapeHtml(x.src_ip)} → ${escapeHtml(x.dst_ip)}:${escapeHtml(x.dst_port)}</strong></div><div><span>模型判断</span><strong>潜在 Beacon</strong></div><div><span>置信度</span><strong>${num(x.lstm_confidence).toFixed(1)}%</strong></div><div><span>风险等级</span><strong>${escapeHtml(x.lstm_risk || risk(x.threat_category))}</strong></div></div><p>当前后端仅保存按连接去重后的真实 LSTM 输出，未保存逐时间窗预测曲线，因此不绘制伪造曲线。</p>`; };
  const renderAttribution = () => { const box = $("attribution-content"), a = dashboard?.attribution; if (!box) return; if (!a?.candidates?.length) { box.className = "visualization-empty"; box.textContent = "暂无候选归因结果。"; return; } box.className = "attribution-detail"; box.innerHTML = `<article class="visualization-card"><p><b>候选归因：</b>${escapeHtml(a.primary_candidate?.name || "暂无数据")}　<b>置信度：</b>${num(a.confidence).toFixed(1)}%</p><p>该结果为基于行为特征与 ATT&CK 知识库的辅助研判，不代表确定攻击者。</p></article>${a.candidates.map((c, i) => `<article class="visualization-card"><h3>候选 ${i + 1}：${escapeHtml(c.name || "暂无数据")}</h3><p>相似度：${c.score == null ? "暂无数据" : num(c.score).toFixed(3)}</p><p>MITRE ATT&CK：${escapeHtml((c.metadata?.c2_techniques || []).join("、") || "暂无数据")}</p></article>`).join("")}`; };
  const render = (nextDashboard, nextAnalysis = null) => {
    if (!nextDashboard || typeof nextDashboard !== "object") {
      clear();
      return;
    }
    dashboard = nextDashboard;
    analysis = nextAnalysis || analysis;
    ensureReportPage();
    setDataCenterState(true);
    selected = threats()[0] || null;
    renderOverview();
    renderConnection();
    renderRita();
    renderLstm();
    renderAttribution();
    switchPage("overview");
  };
  const refresh = () => { if (dashboard) renderTopology(); };
  const clear = () => {
    dashboard = null;
    analysis = null;
    selected = null;
    topologyChart?.dispose();
    intervalChart?.dispose();
    setDataCenterState(false);
  };
  document.addEventListener("click", e => { const b = e.target.closest(".data-nav"); if (b) switchPage(b.dataset.dataPage); }); window.addEventListener("resize", () => { topologyChart?.resize(); intervalChart?.resize(); }); window.C2SherlockVisualization = { render, refresh, clear };
})();
