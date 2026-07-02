const STORAGE_KEYS = {
  apiBase: "c2s.apiBase",
  modelName: "c2s.modelName",
};

const defaultApiBase =
  window.location.protocol === "file:"
    ? "http://127.0.0.1:8765"
    : `${window.location.protocol}//${window.location.hostname}:8765`;

const normalizeMarkdown = (value) => {
  let text = typeof value === "string" ? value : String(value ?? "");
  text = text.replace(/\r\n/g, "\n");
  if (text.includes("\\n") && !text.includes("\n")) {
    text = text.replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\t/g, "\t");
  }
  const fenced = text.trim().match(/^```(?:markdown|md)?\s*\n([\s\S]*?)\n```$/i);
  if (fenced) text = fenced[1];
  return text.trim();
};

// Safe markdown renderer — falls back to plain-text <pre> when marked is unavailable
const renderMarkdown = (text) => {
  const normalized = normalizeMarkdown(text);
  if (typeof marked !== "undefined" && typeof marked.parse === "function") {
    return marked.parse(normalized);
  }
  const escaped = normalized
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return `<pre style="white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word">${escaped}</pre>`;
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const dropZone = $("#drop-zone");
const pcapInput = $("#pcap-input");
const fileName = $("#file-name");
const analyzeBtn = $("#analyze-btn");
const cancelBtn = $("#cancel-btn");
const statusEl = $("#status");
const resultEl = $("#result");
const stepsEl = $("#steps");
const apiBaseInput = $("#api-base-input");
const modelSelect = $("#model-select");
const currentEndpoint = $("#current-endpoint");
const caseTableBody = $("#case-table-body");
const reportFormat = $("#report-format");
const downloadReportBtn = $("#download-report-btn");
const printReportBtn = $("#print-report-btn");

let selectedFile = null;
let analysisRunning = false;
let currentStep = null;
let latestReportMarkdown = "";
let activeController = null;

const stepOrder = ["zeek", "rita", "lstm", "rag", "ai"];
const stepLabels = {
  zeek: "正在进行日志解析...",
  rita: "正在运行规则引擎...",
  lstm: "正在进行 LSTM 时序检测...",
  rag: "正在进行 RAG 溯源归因...",
  ai: "正在生成大模型研判报告...",
};

const normalizeApiBase = (value) => value.trim().replace(/\/+$/, "");

const getApiBase = () => normalizeApiBase(apiBaseInput.value || defaultApiBase);

const updateEndpointDisplay = () => {
  const base = getApiBase();
  currentEndpoint.textContent = `${base || "请填写后端地址"}/analyze/stream`;
};

const setStatus = (message, isError = false) => {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
};

const setReportDownloadEnabled = (enabled) => {
  if (downloadReportBtn) downloadReportBtn.disabled = !enabled;
  if (printReportBtn) printReportBtn.disabled = !enabled;
};

const setRunControls = (running) => {
  analyzeBtn.disabled = running;
  if (cancelBtn) cancelBtn.disabled = !running;
};

const resetSteps = () => {
  stepOrder.forEach((step) => {
    const item = stepsEl.querySelector(`[data-step="${step}"]`);
    if (item) item.classList.remove("active", "done", "error");
  });
};

const markStep = (step) => {
  currentStep = step;
  const stepIndex = stepOrder.indexOf(step);
  stepOrder.forEach((current, index) => {
    const item = stepsEl.querySelector(`[data-step="${current}"]`);
    if (!item) return;
    item.classList.remove("active", "done", "error");
    if (index < stepIndex) item.classList.add("done");
    if (index === stepIndex) item.classList.add("active");
  });
};

const markAllDone = () => {
  stepOrder.forEach((step) => {
    const item = stepsEl.querySelector(`[data-step="${step}"]`);
    if (item) {
      item.classList.remove("active", "error");
      item.classList.add("done");
    }
  });
};

const markError = (step) => {
  const item = step ? stepsEl.querySelector(`[data-step="${step}"]`) : null;
  if (item) {
    item.classList.remove("active", "done");
    item.classList.add("error");
  }
};

const clearActiveStep = () => {
  stepOrder.forEach((step) => {
    const item = stepsEl.querySelector(`[data-step="${step}"]`);
    if (item) item.classList.remove("active", "error");
  });
};

const setFile = (file) => {
  selectedFile = file;
  fileName.textContent = file ? `${file.name} · ${Math.ceil(file.size / 1024)} KB` : "未选择文件";
  if (file) setStatus("文件已选择，可以开始分析。");
};

const getReportBaseName = () => {
  const sourceName = selectedFile?.name ? selectedFile.name.replace(/\.[^.]+$/, "") : "c2sherlock-report";
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  return `${sourceName}-${stamp}`;
};

const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
};

const markdownToPlainText = (markdown) =>
  normalizeMarkdown(markdown)
    .replace(/```[\s\S]*?```/g, (block) => block.replace(/```[a-zA-Z0-9_-]*/g, "").replace(/```/g, ""))
    .replace(/`([^`]+)`/g, "$1")
    .replace(/!\[[^\]]*]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^[>*+-]\s+/gm, "")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

const toUtf16Hex = (text) =>
  Array.from(text)
    .map((char) => {
      const code = char.codePointAt(0);
      if (code > 0xffff) {
        const high = Math.floor((code - 0x10000) / 0x400) + 0xd800;
        const low = ((code - 0x10000) % 0x400) + 0xdc00;
        return [high, low].map((item) => item.toString(16).padStart(4, "0")).join("");
      }
      return code.toString(16).padStart(4, "0");
    })
    .join("");

const wrapText = (text, maxChars = 48) => {
  const lines = [];
  text.split("\n").forEach((paragraph) => {
    const source = paragraph.trimEnd();
    if (!source) {
      lines.push("");
      return;
    }
    let line = "";
    source.split(/(\s+)/).forEach((part) => {
      if (!part) return;
      if ((line + part).length > maxChars && line.trim()) {
        lines.push(line.trimEnd());
        line = part.trimStart();
      } else {
        line += part;
      }
      while (line.length > maxChars) {
        lines.push(line.slice(0, maxChars));
        line = line.slice(maxChars);
      }
    });
    if (line.trim()) lines.push(line.trimEnd());
  });
  return lines;
};

const createPdfBlob = (markdown) => {
  const lines = wrapText(`C2Sherlock Analysis Report\n\n${markdownToPlainText(markdown)}`);
  const pages = [];
  const linesPerPage = 36;
  for (let index = 0; index < lines.length; index += linesPerPage) {
    pages.push(lines.slice(index, index + linesPerPage));
  }

  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pages.map((_, index) => `${3 + index * 2} 0 R`).join(" ")}] /Count ${pages.length} >>`,
  ];

  pages.forEach((pageLines, index) => {
    const pageObject = 3 + index * 2;
    const contentObject = pageObject + 1;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 ${3 + pages.length * 2} 0 R >> >> /Contents ${contentObject} 0 R >>`);
    const textOps = pageLines
      .map((line, lineIndex) => `1 0 0 1 50 ${790 - lineIndex * 20} Tm <${toUtf16Hex(line)}> Tj`)
      .join("\n");
    const stream = `BT\n/F1 11 Tf\n${textOps}\nET`;
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  });

  objects.push("<< /Type /Font /Subtype /Type0 /BaseFont /STSong-Light /Encoding /UniGB-UCS2-H /DescendantFonts [ << /Type /Font /Subtype /CIDFontType0 /BaseFont /STSong-Light /CIDSystemInfo << /Registry (Adobe) /Ordering (GB1) /Supplement 2 >> /FontDescriptor << /Type /FontDescriptor /FontName /STSong-Light /Flags 6 /FontBBox [0 -200 1000 900] /ItalicAngle 0 /Ascent 880 /Descent -120 /CapHeight 700 /StemV 80 >> >> ] >>");

  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return new Blob([pdf], { type: "application/pdf" });
};

const createReportHtml = () => `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>C2Sherlock 分析报告</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; color: #0f172a; line-height: 1.75; padding: 32px; }
    h1, h2, h3 { color: #064e3b; line-height: 1.35; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0; }
    th, td { border: 1px solid #d8e4ed; padding: 8px 10px; text-align: left; }
    th { background: #ecfdf5; }
    pre, code { font-family: Menlo, Consolas, monospace; white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <h1>C2Sherlock 分析报告</h1>
  ${renderMarkdown(latestReportMarkdown)}
</body>
</html>`;

const printReport = () => {
  const printWindow = window.open("", "_blank");
  if (!printWindow) {
    setStatus("浏览器拦截了打印窗口，请允许弹窗后重试。", true);
    return;
  }
  printWindow.document.open();
  printWindow.document.write(createReportHtml());
  printWindow.document.close();
  window.setTimeout(() => {
    printWindow.focus();
    printWindow.print();
  }, 200);
};

const downloadReport = () => {
  if (!latestReportMarkdown.trim()) {
    setStatus("当前还没有可下载的分析报告。", true);
    return;
  }

  const baseName = getReportBaseName();
  const format = reportFormat?.value || "md";

  if (format === "md") {
    downloadBlob(new Blob([latestReportMarkdown], { type: "text/markdown;charset=utf-8" }), `${baseName}.md`);
    return;
  }

  if (format === "doc") {
    downloadBlob(new Blob([createReportHtml()], { type: "application/msword;charset=utf-8" }), `${baseName}.doc`);
    return;
  }

  downloadBlob(createPdfBlob(latestReportMarkdown), `${baseName}.pdf`);
};

const cancelAnalysis = () => {
  if (!analysisRunning || !activeController) return;
  setStatus("正在取消当前分析...");
  cancelBtn.disabled = true;
  activeController.abort();
};

const preventDefaults = (event) => {
  event.preventDefault();
  event.stopPropagation();
};

const switchTab = (tabName) => {
  $$(".nav-btn").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tabName);
  });
  $$(".tab-page").forEach((page) => {
    page.classList.toggle("active", page.dataset.page === tabName);
  });
  if (history.replaceState) {
    history.replaceState(null, "", `#${tabName}`);
  }
};

const setupTabs = () => {
  $$("[data-tab]").forEach((control) => {
    control.addEventListener("click", () => switchTab(control.dataset.tab));
  });
  $$("[data-tab-link]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      switchTab(link.dataset.tabLink);
    });
  });
  const initial = window.location.hash.replace("#", "") || "home";
  if ($(`[data-page="${initial}"]`)) switchTab(initial);
};

const setupPrincipleTabs = () => {
  $$(".principle-link").forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.target;
      const activeSection = document.getElementById(target);
      $$(".principle-link").forEach((item) => item.classList.toggle("active", item === button));
      $$(".principle-section").forEach((section) => {
        section.classList.toggle("active", section === activeSection);
      });
      activeSection?.scrollIntoView({ block: "start", behavior: "smooth" });
    });
  });
};

const setupApiConfig = () => {
  apiBaseInput.value = window.localStorage.getItem(STORAGE_KEYS.apiBase) || defaultApiBase;
  modelSelect.value = window.localStorage.getItem(STORAGE_KEYS.modelName) || modelSelect.value;
  updateEndpointDisplay();

  apiBaseInput.addEventListener("input", () => {
    window.localStorage.setItem(STORAGE_KEYS.apiBase, getApiBase());
    updateEndpointDisplay();
  });

  modelSelect.addEventListener("change", () => {
    window.localStorage.setItem(STORAGE_KEYS.modelName, modelSelect.value);
  });

  $$(".chip[data-api]").forEach((button) => {
    button.addEventListener("click", () => {
      apiBaseInput.value = button.dataset.api;
      window.localStorage.setItem(STORAGE_KEYS.apiBase, getApiBase());
      updateEndpointDisplay();
    });
  });
};

const setupUpload = () => {
  ["dragenter", "dragover", "dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, preventDefaults, false);
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, () => dropZone.classList.add("dragover"));
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, () => dropZone.classList.remove("dragover"));
  });

  dropZone.addEventListener("drop", (event) => {
    const [file] = event.dataTransfer.files;
    if (file) setFile(file);
  });

  pcapInput.addEventListener("change", (event) => {
    const [file] = event.target.files;
    if (file) setFile(file);
  });
};

const handleStreamEvent = (eventName, data) => {
  if (eventName === "step") {
    markStep(data);
    setStatus(stepLabels[data] || "正在分析...");
    return;
  }

  if (eventName === "result") {
    const payload = JSON.parse(data);
    const markdown = normalizeMarkdown(payload.analysis_markdown || "后端未返回分析报告。");
    latestReportMarkdown = markdown;
    resultEl.innerHTML = renderMarkdown(markdown);
    setReportDownloadEnabled(true);
    markAllDone();
    setStatus("分析完成。");
    return;
  }

  if (eventName === "error") {
    markError(currentStep);
    throw new Error(data || "分析失败");
  }
};

const processSseBuffer = (state) => {
  const parts = state.buffer.split("\n\n");
  state.buffer = parts.pop() || "";
  parts.forEach((part) => {
    if (!part.trim()) return;
    let eventName = "message";
    let data = "";
    part.split("\n").forEach((line) => {
      if (line.startsWith("event:")) eventName = line.slice(6).trim();
      if (line.startsWith("data:")) data += line.slice(5).trim();
    });
    handleStreamEvent(eventName, data);
  });
};

const analyzeSelectedFile = async () => {
  if (analysisRunning) return;
  if (!selectedFile) {
    setStatus("请先选择 PCAP 文件。", true);
    return;
  }

  const apiBase = getApiBase();
  if (!apiBase) {
    setStatus("请先配置后端 API 地址。", true);
    return;
  }

  analysisRunning = true;
  activeController = new AbortController();
  setRunControls(true);
  currentStep = null;
  window.localStorage.setItem(STORAGE_KEYS.apiBase, apiBase);
  window.localStorage.setItem(STORAGE_KEYS.modelName, modelSelect.value);
  updateEndpointDisplay();

  setStatus("正在上传样本，请勿关闭页面。切换栏目不会中断当前分析。");
  latestReportMarkdown = "";
  setReportDownloadEnabled(false);
  resultEl.textContent = "分析任务运行中...";
  resetSteps();

  const formData = new FormData();
  formData.append("pcap", selectedFile);
  formData.append("model_name", modelSelect.value);

  try {
    const response = await fetch(`${apiBase}/analyze/stream`, {
      method: "POST",
      body: formData,
      signal: activeController.signal,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `后端返回 ${response.status}`);
    }

    if (!response.body) {
      throw new Error("当前浏览器不支持流式响应。");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const streamState = { buffer: "" };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      streamState.buffer += decoder.decode(value, { stream: true });
      processSseBuffer(streamState);
    }

    if (streamState.buffer.trim()) {
      streamState.buffer += "\n\n";
      processSseBuffer(streamState);
    }
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      latestReportMarkdown = "";
      setReportDownloadEnabled(false);
      resultEl.textContent = "分析已取消。可以重新选择 PCAP 文件并开始新的分析。";
      setStatus("当前分析已取消，可以重新选择文件。");
      clearActiveStep();
      return;
    }
    const message = error instanceof Error ? error.message : "分析请求失败";
    latestReportMarkdown = "";
    setReportDownloadEnabled(false);
    resultEl.textContent = "分析失败，请检查后端地址、网络连通性和后端日志。";
    setStatus(message, true);
    markError(currentStep);
  } finally {
    analysisRunning = false;
    activeController = null;
    setRunControls(false);
  }
};

const renderCaseTable = () => {
  const cases = [
    {
      no: 1,
      pcap: "benign_cdn_update.pcap",
      src: "10.0.3.21",
      dst: "cdn.example.net",
      time: "2026-06-29 10:15",
      status: "低风险 12%",
      type: "low",
      note: "软件更新与 CDN 访问，周期性弱。",
    },
    {
      no: 2,
      pcap: "cs2_dns_default_with_amazon.pcap",
      src: "192.168.56.104",
      dst: "45.77.***.21",
      time: "2026-06-29 11:08",
      status: "高风险 91%",
      type: "high",
      note: "稳定 Beacon 间隔，目标异常。",
    },
    {
      no: 3,
      pcap: "office_login_noise.pcapng",
      src: "10.0.8.45",
      dst: "login.microsoftonline.com",
      time: "2026-06-29 13:22",
      status: "低风险 18%",
      type: "low",
      note: "认证流量正常，连接分布不稳定。",
    },
    {
      no: 4,
      pcap: "dns_tunnel_suspect.pcap",
      src: "172.16.4.9",
      dst: "x9a-control.example",
      time: "2026-06-29 15:46",
      status: "高风险 86%",
      type: "high",
      note: "DNS 子域异常且请求频率稳定。",
    },
  ];

  caseTableBody.innerHTML = cases.map((item) => `
    <tr>
      <td>${item.no}</td>
      <td>${item.pcap}</td>
      <td>${item.src}</td>
      <td>${item.dst}</td>
      <td>${item.time}</td>
      <td><span class="status-pill status-${item.type}">${item.status}</span></td>
      <td>${item.note}</td>
    </tr>
  `).join("");
};

setupTabs();
setupPrincipleTabs();
setupApiConfig();
setupUpload();
renderCaseTable();
analyzeBtn.addEventListener("click", analyzeSelectedFile);
cancelBtn?.addEventListener("click", cancelAnalysis);
downloadReportBtn?.addEventListener("click", downloadReport);
printReportBtn?.addEventListener("click", printReport);
