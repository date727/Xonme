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
const caseRecommendation = $("#case-recommendation");
const caseToast = $("#case-toast");

let selectedFile = null;
let analysisRunning = false;
let currentStep = null;
let latestReportMarkdown = "";
let activeController = null;

const caseExamples = {
  benign5_smashburger: {
    id: "benign5_smashburger",
    fileName: "benign5_smashburger.pcapng",
    samplePath: "public/examples/benign5_smashburger.pcapng",
  },
  cs4_amazon_http: {
    id: "cs4_amazon_http",
    fileName: "cs4_amazon_http.pcapng",
    samplePath: "public/examples/cs4_amazon_http.pcapng",
  },
};

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

const cleanMarkdownInline = (text) =>
  text
    .replace(/!\[[^\]]*]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/__([^_]+)__/g, "$1")
    .replace(/_([^_]+)_/g, "$1")
    .trim();

const normalizePdfText = (text) =>
  cleanMarkdownInline(text)
    .replace(/[‐‑‒–—―]/g, "-")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/→/g, "->")
    .replace(/←/g, "<-")
    .replace(/≥/g, ">=")
    .replace(/≤/g, "<=")
    .replace(/≈/g, "~")
    .replace(/·/g, "-")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "")
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "");

const pdfEscape = (text) => normalizePdfText(text).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");

const markdownToPdfBlocks = (markdown) => {
  const blocks = [{ type: "title", text: "C2Sherlock Analysis Report" }];
  const lines = normalizeMarkdown(markdown).split("\n");
  let paragraph = [];

  const flushParagraph = () => {
    const text = normalizePdfText(paragraph.join(" "));
    if (text) blocks.push({ type: "paragraph", text });
    paragraph = [];
  };

  lines.forEach((rawLine) => {
    const line = rawLine.trim();
    if (!line) {
      flushParagraph();
      return;
    }

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      flushParagraph();
      blocks.push({ type: `h${Math.min(heading[1].length, 3)}`, text: normalizePdfText(heading[2]) });
      return;
    }

    const bullet = line.match(/^[-*+]\s+(.+)$/);
    if (bullet) {
      flushParagraph();
      blocks.push({ type: "bullet", text: normalizePdfText(bullet[1]) });
      return;
    }

    const numbered = line.match(/^(\d+)[.)]\s+(.+)$/);
    if (numbered) {
      flushParagraph();
      blocks.push({ type: "numbered", marker: `${numbered[1]}.`, text: normalizePdfText(numbered[2]) });
      return;
    }

    if (/^\|.+\|$/.test(line)) {
      flushParagraph();
      const cells = line.split("|").map((cell) => normalizePdfText(cell)).filter(Boolean);
      if (cells.length) blocks.push({ type: "paragraph", text: cells.join("  |  ") });
      return;
    }

    paragraph.push(line);
  });

  flushParagraph();
  return blocks;
};

const getTextMeasurer = () => {
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d");
  return (text, fontSize, fontFamily = "Helvetica") => {
    if (context) {
      context.font = `${fontSize}px ${fontFamily}, Arial, sans-serif`;
      return context.measureText(text).width * 0.74;
    }
    return text.length * fontSize * 0.52;
  };
};

const wrapPdfText = (text, maxWidth, fontSize, fontFamily, measureText) => {
  const words = normalizePdfText(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let line = "";

  words.forEach((word) => {
    const candidate = line ? `${line} ${word}` : word;
    if (line && measureText(candidate, fontSize, fontFamily) > maxWidth) {
      lines.push(line);
      line = word;
      while (measureText(line, fontSize, fontFamily) > maxWidth && line.length > 1) {
        let cut = line.length - 1;
        while (cut > 1 && measureText(`${line.slice(0, cut)}-`, fontSize, fontFamily) > maxWidth) cut -= 1;
        lines.push(`${line.slice(0, cut)}-`);
        line = line.slice(cut);
      }
    } else {
      line = candidate;
    }
  });

  if (line) lines.push(line);
  return lines;
};

const createPdfBlob = (markdown) => {
  const pageWidth = 595;
  const pageHeight = 842;
  const marginX = 54;
  const marginTop = 64;
  const marginBottom = 58;
  const contentWidth = pageWidth - marginX * 2;
  const green = "0.02 0.31 0.23";
  const ink = "0.06 0.09 0.16";
  const muted = "0.39 0.45 0.55";
  const measureText = getTextMeasurer();
  const pages = [[]];
  let y = pageHeight - marginTop;

  const currentPage = () => pages[pages.length - 1];
  const newPage = () => {
    pages.push([]);
    y = pageHeight - marginTop;
  };
  const ensureSpace = (height) => {
    if (y - height < marginBottom) newPage();
  };
  const drawLine = (text, x, font, size, color) => {
    currentPage().push(`BT /${font} ${size} Tf ${color} rg 1 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)} Tm (${pdfEscape(text)}) Tj ET`);
  };
  const drawRule = () => {
    currentPage().push(`q 0.83 0.89 0.93 RG 0.8 w ${marginX} ${y.toFixed(2)} m ${pageWidth - marginX} ${y.toFixed(2)} l S Q`);
  };

  markdownToPdfBlocks(markdown).forEach((block) => {
    if (!block.text) return;

    if (block.type === "title") {
      ensureSpace(54);
      drawLine(block.text, marginX, "F2", 24, green);
      y -= 18;
      drawRule();
      y -= 28;
      return;
    }

    const styleMap = {
      h1: { font: "F2", size: 22, color: green, before: 8, after: 15, lineHeight: 28 },
      h2: { font: "F2", size: 17, color: green, before: 12, after: 12, lineHeight: 22 },
      h3: { font: "F2", size: 13.5, color: green, before: 8, after: 8, lineHeight: 18 },
      paragraph: { font: "F1", size: 11.5, color: ink, before: 0, after: 12, lineHeight: 17 },
      bullet: { font: "F1", size: 11.5, color: ink, before: 0, after: 8, lineHeight: 17 },
      numbered: { font: "F1", size: 11.5, color: ink, before: 0, after: 8, lineHeight: 17 },
    };
    const style = styleMap[block.type] || styleMap.paragraph;
    const indent = block.type === "bullet" || block.type === "numbered" ? 24 : 0;
    const marker = block.type === "bullet" ? "-" : block.type === "numbered" ? block.marker : "";
    const markerWidth = marker ? 18 : 0;
    const lines = wrapPdfText(block.text, contentWidth - indent - markerWidth, style.size, style.font === "F2" ? "Helvetica-Bold" : "Helvetica", measureText);
    const blockHeight = style.before + lines.length * style.lineHeight + style.after;

    ensureSpace(blockHeight);
    y -= style.before;
    lines.forEach((line, lineIndex) => {
      if (marker && lineIndex === 0) drawLine(marker, marginX + indent, "F2", style.size, style.color);
      drawLine(line, marginX + indent + markerWidth, style.font, style.size, style.color);
      y -= style.lineHeight;
    });
    y -= style.after;
  });

  pages.forEach((page, index) => {
    page.push(`BT /F1 9 Tf ${muted} rg 1 0 0 1 ${marginX} 32 Tm (C2Sherlock Analysis Report) Tj ET`);
    page.push(`BT /F1 9 Tf ${muted} rg 1 0 0 1 ${pageWidth - marginX - 42} 32 Tm (Page ${index + 1}) Tj ET`);
  });

  const pageObjectsStart = 3;
  const fontObjectStart = pageObjectsStart + pages.length * 2;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pages.map((_, index) => `${pageObjectsStart + index * 2} 0 R`).join(" ")}] /Count ${pages.length} >>`,
  ];

  pages.forEach((pageOps, index) => {
    const pageObject = pageObjectsStart + index * 2;
    const contentObject = pageObject + 1;
    const stream = pageOps.join("\n");
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 ${fontObjectStart} 0 R /F2 ${fontObjectStart + 1} 0 R >> >> /Contents ${contentObject} 0 R >>`);
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  });

  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");

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

const getHashState = () => {
  const rawHash = window.location.hash.replace(/^#/, "");
  const [tab = "", query = ""] = rawHash.split("?");
  return {
    tab: tab || "home",
    params: new URLSearchParams(query),
  };
};

const getCurrentCaseId = () => {
  const fromSearch = new URLSearchParams(window.location.search).get("case");
  if (fromSearch) return fromSearch;
  return getHashState().params.get("case");
};

const buildTabHash = (tabName, params = new URLSearchParams()) => {
  const query = params.toString();
  return `#${tabName}${query ? `?${query}` : ""}`;
};

const switchTab = (tabName, options = {}) => {
  $$(".nav-btn").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tabName);
  });
  $$(".tab-page").forEach((page) => {
    page.classList.toggle("active", page.dataset.page === tabName);
  });
  if (history.replaceState) {
    const params = options.params || new URLSearchParams();
    const method = options.push ? "pushState" : "replaceState";
    history[method](null, "", buildTabHash(tabName, params));
  }
  renderCaseRecommendation();
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
  const hashState = getHashState();
  const initial = window.location.pathname.replace(/\/+$/, "").endsWith("/analyze") ? "tool" : hashState.tab;
  switchTab($(`[data-page="${initial}"]`) ? initial : "home", { params: hashState.params });
  window.addEventListener("popstate", () => {
    const state = getHashState();
    switchTab($(`[data-page="${state.tab}"]`) ? state.tab : "home", { params: state.params });
  });
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

const goToAnalyzeCase = (caseId) => {
  const params = new URLSearchParams();
  params.set("case", caseId);
  switchTab("tool", { params, push: true });
  document.getElementById("tool")?.scrollIntoView({ block: "start", behavior: "smooth" });
};

const downloadCaseSample = (item) => {
  const link = document.createElement("a");
  link.href = item.samplePath;
  link.download = item.fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  showCaseToast(item.id);
};

const showCaseToast = (caseId) => {
  if (!caseToast) return;
  caseToast.hidden = false;
  caseToast.innerHTML = `
    <div>
      <strong>样本已开始下载。</strong>
      <p>你可以前往检测中心上传该文件，体验完整分析流程。</p>
    </div>
    <div class="case-toast-actions">
      <button class="secondary" type="button" data-toast-close>留在当前页</button>
      <button class="primary" type="button" data-toast-analyze="${caseId}">前往检测中心</button>
    </div>
  `;
};

const hideCaseToast = () => {
  if (caseToast) caseToast.hidden = true;
};

const renderCaseRecommendation = () => {
  if (!caseRecommendation) return;
  const caseId = getCurrentCaseId();
  const item = caseId ? caseExamples[caseId] : null;
  if (!item) {
    caseRecommendation.hidden = true;
    caseRecommendation.innerHTML = "";
    return;
  }
  caseRecommendation.hidden = false;
  caseRecommendation.innerHTML = `
    <strong>当前推荐分析样本：${item.fileName}</strong>
    <span>请先在能力页下载该样本文件，再在下方上传并开始分析。</span>
  `;
};

const setupCaseExamples = () => {
  $$(".explain-card[data-case]").forEach((card) => {
    const item = caseExamples[card.dataset.case];
    if (!item) return;
    const actions = document.createElement("div");
    actions.className = "case-card-actions";
    actions.innerHTML = `
      <button class="primary" type="button" data-case-analyze="${item.id}">去检测中心分析</button>
      <button class="secondary" type="button" data-case-download="${item.id}">下载样本</button>
    `;
    card.appendChild(actions);
  });

  document.addEventListener("click", (event) => {
    const analyze = event.target.closest("[data-case-analyze]");
    if (analyze) {
      goToAnalyzeCase(analyze.dataset.caseAnalyze);
      return;
    }

    const download = event.target.closest("[data-case-download]");
    if (download) {
      const item = caseExamples[download.dataset.caseDownload];
      if (item) downloadCaseSample(item);
      return;
    }

    if (event.target.closest("[data-toast-close]")) {
      hideCaseToast();
      return;
    }

    const toastAnalyze = event.target.closest("[data-toast-analyze]");
    if (toastAnalyze) {
      hideCaseToast();
      goToAnalyzeCase(toastAnalyze.dataset.toastAnalyze);
    }
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
setupCaseExamples();
renderCaseTable();
analyzeBtn.addEventListener("click", analyzeSelectedFile);
cancelBtn?.addEventListener("click", cancelAnalysis);
downloadReportBtn?.addEventListener("click", downloadReport);
printReportBtn?.addEventListener("click", printReport);
