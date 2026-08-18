const STORAGE_KEYS = {
  modelName: "c2s.modelName",
};

let currentUser = null;
let sessionResolved = false;

// The frontend can run on any host (for example :5500); the backend is always
// reached through that same host on its fixed service port.
const apiBase = `${window.location.protocol}//${window.location.hostname}:8765`;

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
    const parsed = marked.parse(normalized);
    const documentFragment = new DOMParser().parseFromString(parsed, "text/html");
    documentFragment.querySelectorAll("script, iframe, object, embed, form, input, button, meta, link, style").forEach((node) => node.remove());
    documentFragment.querySelectorAll("*").forEach((node) => {
      Array.from(node.attributes).forEach((attribute) => {
        const name = attribute.name.toLowerCase();
        const value = attribute.value.trim().toLowerCase();
        if (name.startsWith("on") || name === "style" || ((name === "href" || name === "src") && value.startsWith("javascript:"))) {
          node.removeAttribute(attribute.name);
        }
      });
    });
    return documentFragment.body.innerHTML;
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
const selectedFileEl = $("#selected-file");
const clearFileBtn = $("#clear-file-btn");
const dropHint = $("#drop-hint");
const analyzeBtn = $("#analyze-btn");
const cancelBtn = $("#cancel-btn");
const statusEl = $("#status");
const resultEl = $("#result");
const reportPanel = $("#report-panel");
const stepsEl = $("#steps");
const openCurrentDataBtn = $("#open-current-data-btn");
const modelSelect = $("#model-select");
const caseTableBody = $("#case-table-body");
const reportFormat = $("#report-format");
const downloadReportBtn = $("#download-report-btn");
const printReportBtn = $("#print-report-btn");
const caseRecommendation = $("#case-recommendation");
const caseToast = $("#case-toast");
const historyEmpty = $("#history-empty");
const historyTableWrap = $("#history-table-wrap");
const analysisHistoryBody = $("#analysis-history-body");
const analysisHistorySearch = $("#analysis-history-search");
const analysisHistoryKeyword = $("#analysis-history-keyword");
const analysisHistoryPagination = $("#analysis-history-pagination");
const dataCenterHistoryBtn = $("#data-center-history-btn");

let selectedFile = null;
let analysisRunning = false;
let currentStep = null;
let latestReportMarkdown = "";
let activeController = null;
let activeAnalysisId = null;
let displayedAnalysisId = null;
let latestVisualization = null;
const HISTORY_PAGE_SIZE = 10;
let historyPage = 1;
let historyKeyword = "";

const setCurrentDataAvailable = (available) => {
  if (!openCurrentDataBtn) return;
  openCurrentDataBtn.disabled = !available;
  openCurrentDataBtn.classList.toggle("ready", available);
};

const createAnalysisId = () =>
  window.crypto?.randomUUID?.() ||
  `analysis-${Date.now()}-${Math.random().toString(36).slice(2)}`;

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

const setStatus = (message, isError = false) => {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
};

const setReportDownloadEnabled = (enabled) => {
  if (downloadReportBtn) downloadReportBtn.disabled = !enabled;
  if (printReportBtn) printReportBtn.disabled = !enabled;
};

const setReportVisible = (visible) => {
  // Detection center deliberately has no report surface. The report is moved to
  // the data-center's dedicated page when a completed dashboard is rendered.
  void visible;
};

const setUploadLocked = (locked) => {
  dropZone.classList.toggle("locked", locked);
  pcapInput.disabled = locked;
  if (clearFileBtn) clearFileBtn.disabled = locked;
  if (dropHint) {
    dropHint.textContent = locked
      ? "任务执行中，暂不可更换文件"
      : selectedFile
        ? "拖拽新文件可替换当前文件"
        : "或点击选择 .pcap / .pcapng / .cap 文件";
  }
};

const setRunControls = (running) => {
  analyzeBtn.disabled = running;
  analyzeBtn.textContent = running ? "分析中…" : "开始分析";
  if (cancelBtn) cancelBtn.disabled = !running;
  setUploadLocked(running);
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
  if (selectedFileEl) selectedFileEl.hidden = !file;
  setUploadLocked(false);
  setStatus(file ? "文件已选择，可以开始分析。" : "当前未选择文件。");
};

const clearSelectedFile = () => {
  if (analysisRunning) return;
  selectedFile = null;
  pcapInput.value = "";
  fileName.textContent = "未选择文件";
  if (selectedFileEl) selectedFileEl.hidden = true;
  setUploadLocked(false);
  setStatus("当前未选择文件。");
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
  const safeMaxWidth = maxWidth * 0.96;

  const pushWrappedWord = (word) => {
    let rest = word;
    while (measureText(rest, fontSize, fontFamily) > safeMaxWidth && rest.length > 1) {
      let cut = rest.length - 1;
      while (cut > 1 && measureText(`${rest.slice(0, cut)}-`, fontSize, fontFamily) > safeMaxWidth) cut -= 1;
      lines.push(`${rest.slice(0, cut)}-`);
      rest = rest.slice(cut);
    }
    line = rest;
  };

  words.forEach((word) => {
    const candidate = line ? `${line} ${word}` : word;
    if (line && measureText(candidate, fontSize, fontFamily) > safeMaxWidth) {
      lines.push(line);
      pushWrappedWord(word);
    } else if (!line && measureText(candidate, fontSize, fontFamily) > safeMaxWidth) {
      pushWrappedWord(word);
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
  const bottomSafety = 8;
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
    if (y - height < marginBottom + bottomSafety) newPage();
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
    const pageContentHeight = pageHeight - marginTop - marginBottom - bottomSafety;

    if (blockHeight <= pageContentHeight) {
      ensureSpace(blockHeight);
    } else {
      ensureSpace(style.before + style.lineHeight);
    }
    y -= style.before;
    lines.forEach((line, lineIndex) => {
      ensureSpace(style.lineHeight + (lineIndex === lines.length - 1 ? style.after : 0));
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

const createReportHtml = (markdown = latestReportMarkdown) => `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>C2Sherlock AI分析报告</title>
  <style>
    @page { margin: 16mm 14mm; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; color: #0f172a; line-height: 1.75; padding: 32px; }
    h1, h2, h3 { color: #064e3b; line-height: 1.35; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0; }
    th, td { border: 1px solid #d8e4ed; padding: 8px 10px; text-align: left; }
    th { background: #ecfdf5; }
    pre, code { font-family: Menlo, Consolas, monospace; white-space: pre-wrap; word-break: break-word; }
    img { max-width: 100%; }
    @media print {
      body { padding: 0; }
    }
  </style>
</head>
<body>
  ${renderMarkdown(markdown)}
</body>
</html>`;

const openReportWindow = (markdown = latestReportMarkdown, callback) => {
  const printWindow = window.open("", "_blank");
  if (!printWindow) {
    setStatus("浏览器拦截了打印窗口，请允许弹窗后重试。", true);
    return null;
  }
  printWindow.document.open();
  printWindow.document.write(createReportHtml(markdown));
  printWindow.document.close();
  window.setTimeout(() => {
    callback?.(printWindow);
  }, 200);
  return printWindow;
};

const printReport = () => {
  openReportWindow(latestReportMarkdown, (printWindow) => {
    printWindow.focus();
    printWindow.print();
  });
};

const downloadGeneratedReport = async (format, baseName) => {
  const response = await fetch(`${apiBase}/reports/${format}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ markdown: latestReportMarkdown, filename: baseName }),
  });

  if (!response.ok) {
    throw new Error(await getApiError(response));
  }

  const blob = await response.blob();
  downloadBlob(blob, `${baseName}.${format}`);
};

const downloadReport = async () => {
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

  downloadReportBtn.disabled = true;
  try {
    await downloadGeneratedReport(format, baseName);
    setStatus(`报告已下载为 ${format.toUpperCase()} 文件。`);
  } catch (error) {
    const message = error instanceof Error ? error.message : "报告导出失败";
    setStatus(message, true);
  } finally {
    downloadReportBtn.disabled = false;
  }
};

const cancelAnalysis = async () => {
  if (!analysisRunning || !activeController || !activeAnalysisId) return;
  setStatus("正在请求后端取消分析...");
  cancelBtn.disabled = true;
  try {
    const response = await fetch(`${apiBase}/analyze/${activeAnalysisId}`, {
      method: "DELETE",
      credentials: "include",
      keepalive: true,
    });
    if (!response.ok) {
      throw new Error(`后端未能取消任务（${response.status}）`);
    }
    activeController.abort();
  } catch (error) {
    const message = error instanceof Error ? error.message : "取消请求失败";
    setStatus(`${message}；分析仍可能在后端运行。`, true);
    cancelBtn.disabled = false;
  }
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

const loadAnalysisFromRoute = async (params) => {
  if (!currentUser) return;
  const recordId = Number(params?.get("analysis"));
  if (!Number.isInteger(recordId) || recordId <= 0) return;
  if (displayedAnalysisId === recordId && latestVisualization) {
    window.C2SherlockVisualization?.render(latestVisualization);
    return;
  }
  try {
    const payload = await loadSavedAnalysisDashboard(recordId);
    window.C2SherlockVisualization?.render(payload.dashboard, payload.analysis);
  } catch (error) {
    window.C2SherlockVisualization?.clear();
    console.error("加载历史分析详情失败", error);
  }
};

const switchTab = (tabName, options = {}) => {
  if (tabName === "profile" && !currentUser) {
    if (!sessionResolved) return;
    openAuthModal("login");
    return;
  }
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
  if (tabName === "capability") {
    const routeAnalysisId = Number(options.params?.get("analysis"));
    if (!options.skipAnalysisLoad && Number.isInteger(routeAnalysisId) && routeAnalysisId > 0) {
      void loadAnalysisFromRoute(options.params);
    } else {
      window.C2SherlockVisualization?.refresh();
    }
  }
  if (tabName === "profile" && currentUser) {
    void loadAnalysisHistory();
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
  const hashState = getHashState();
  const initial = window.location.pathname.replace(/\/+$/, "").endsWith("/analyze") ? "tool" : hashState.tab;
  switchTab($(`[data-page="${initial}"]`) ? initial : "home", { params: hashState.params });
  window.addEventListener("popstate", () => {
    const state = getHashState();
    switchTab($(`[data-page="${state.tab}"]`) ? state.tab : "home", { params: state.params });
  });
};

const setupPrincipleTabs = () => {
  const links = $$(".principle-link");
  const sections = $$(".principle-section");
  const setActivePrincipleSection = (activeSection) => {
    if (!activeSection) return;

    links.forEach((link) => {
      link.classList.toggle("active", link.dataset.target === activeSection.id);
    });
    sections.forEach((section) => {
      section.classList.toggle("active", section === activeSection);
    });
  };

  const syncPrincipleNavigation = () => {
    const principlePage = document.getElementById("principle");
    if (!principlePage?.classList.contains("active")) return;

    // Keep the section whose heading has most recently crossed the fixed header
    // as the active item, including while smooth scrolling from a navigation click.
    const readingLine = 108;
    let activeSection = sections[0];
    for (const section of sections) {
      if (section.getBoundingClientRect().top <= readingLine) {
        activeSection = section;
      } else {
        break;
      }
    }
    setActivePrincipleSection(activeSection);
  };

  links.forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.target;
      const activeSection = document.getElementById(target);
      setActivePrincipleSection(activeSection);
      activeSection?.scrollIntoView({ block: "start", behavior: "smooth" });
    });
  });

  let scrollFrame = null;
  window.addEventListener("scroll", () => {
    if (scrollFrame) return;
    scrollFrame = window.requestAnimationFrame(() => {
      scrollFrame = null;
      syncPrincipleNavigation();
    });
  }, { passive: true });
  window.addEventListener("resize", syncPrincipleNavigation);
  syncPrincipleNavigation();
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
  document.addEventListener("click", (event) => {
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
  modelSelect.value = window.localStorage.getItem(STORAGE_KEYS.modelName) || modelSelect.value;

  modelSelect.addEventListener("change", () => {
    window.localStorage.setItem(STORAGE_KEYS.modelName, modelSelect.value);
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
    if (analysisRunning) return;
    const [file] = event.dataTransfer.files;
    if (file) setFile(file);
  });

  pcapInput.addEventListener("change", (event) => {
    const [file] = event.target.files;
    if (file) setFile(file);
  });

  clearFileBtn?.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    clearSelectedFile();
  });
};

const handleStreamEvent = (eventName, data) => {
  if (eventName === "step") {
    markStep(data);
    setStatus(stepLabels[data] || "正在分析...");
    return;
  }

  if (eventName === "delta") {
    const payload = JSON.parse(data);
    latestReportMarkdown += payload.content || "";
    resultEl.innerHTML = renderMarkdown(latestReportMarkdown);
    return;
  }

  if (eventName === "result") {
    const payload = JSON.parse(data);
    const markdown = normalizeMarkdown(payload.analysis_markdown || "后端未返回分析报告。");
    latestReportMarkdown = markdown;
    resultEl.innerHTML = renderMarkdown(markdown);
    setReportDownloadEnabled(true);
    latestVisualization = payload.visualization || null;
    window.C2SherlockVisualization?.render(latestVisualization, {
      original_filename: selectedFile?.name || payload.display_name,
      file_size: selectedFile?.size,
      status: "completed",
      completed_at: new Date().toISOString(),
      report_markdown: markdown,
    });
    setCurrentDataAvailable(Boolean(latestVisualization));
    markAllDone();
    setStatus("分析完成。");
    return;
  }

  if (eventName === "cancelled") {
    throw new DOMException("分析已由后端取消", "AbortError");
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

  analysisRunning = true;
  activeController = new AbortController();
  activeAnalysisId = createAnalysisId();
  setRunControls(true);
  currentStep = null;
  window.localStorage.setItem(STORAGE_KEYS.modelName, modelSelect.value);

  setStatus("正在上传样本，请勿关闭页面。切换栏目不会中断当前分析。");
  latestReportMarkdown = "";
  latestVisualization = null;
  setCurrentDataAvailable(false);
  setReportDownloadEnabled(false);
  setReportVisible(false);
  resultEl.textContent = "分析任务运行中，报告将实时显示...";
  resetSteps();

  const formData = new FormData();
  formData.append("pcap", selectedFile);
  formData.append("model_id", modelSelect.value);
  formData.append("analysis_id", activeAnalysisId);

  try {
    const response = await fetch(`${apiBase}/analyze/stream`, {
      method: "POST",
      credentials: "include",
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
    const decoder = new TextDecoder("utf-8");
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
      setReportVisible(false);
      resultEl.textContent = "分析已取消。可以重新选择 PCAP 文件并开始新的分析。";
      setStatus("分析已取消，可重新开始或上传新文件。");
      clearActiveStep();
      return;
    }
    const message = error instanceof Error ? error.message : "分析请求失败";
    latestReportMarkdown = "";
    setReportDownloadEnabled(false);
    setReportVisible(false);
    resultEl.textContent = "分析失败，请检查后端地址、网络连通性和后端日志。";
    setStatus(message, true);
    markError(currentStep);
  } finally {
    analysisRunning = false;
    activeController = null;
    activeAnalysisId = null;
    setRunControls(false);
  }
};

const renderCaseTable = () => {
  if (!caseTableBody) return;
  const cases = [
    {
      no: 1,
      pcap: "benign5_smashburger.pcap",
      src: "192.168.46.84",
      dst: "smashburger.com",
      time: "2026-07-03 12:54",
      status: "正常",
      score: 35,
      type: "low",
      note: "商业域名访问，存在轻微Beacon行为，无威胁情报命中。",
    },
    {
      no: 2,
      pcap: "cs2_amazon_https.pcap",
      src: "192.168.56.5",
      dst: "192.168.56.4:443",
      time: "2026-07-03 13:01",
      status: "高危",
      score: 95,
      type: "high",
      note: "HTTPS周期性Beacon通信，疑似APT3相关C2活动。",
    },
    {
      no: 3,
      pcap: "cs2_jquery_http.pcap",
      src: "192.168.56.5",
      dst: "192.168.56.4:80",
      time: "2026-06-30 15:38",
      status: "高危",
      score: 92,
      type: "high",
      note: "HTTP异常连接及可疑参数，存在明显数据外传风险。",
    },
    {
      no: 4,
      pcap: "cs4_amazon_http.pcap",
      src: "192.168.56.5",
      dst: "192.168.56.4:80",
      time: "2026-07-03 12:58",
      status: "高危",
      score: 100,
      type: "high",
      note: "高置信度Beacon通信，匹配APT18攻击特征，建议立即处置。",
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
      <td>${item.score}</td>
      <td>${item.note}</td>
    </tr>
  `).join("");
};

const authModal = $("#auth-modal");
const loginEntryBtn = $("#login-entry-btn");
const guestModeBadge = $("#guest-mode-badge");
const avatarBtn = $("#avatar-btn");
const logoutBtn = $("#logout-btn");
const loginForm = $("#login-form");
const registerForm = $("#register-form");
const changePasswordForm = $("#change-password-form");
const changePasswordModal = $("#change-password-modal");
const changePasswordOpenBtn = $("#change-password-open-btn");
const changePasswordCloseBtn = $("#change-password-close-btn");

const setFormMessage = (element, message = "", type = "") => {
  if (!element) return;
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
};

const getApiError = async (response) => {
  try {
    const payload = await response.json();
    return payload.detail || "请求失败，请稍后重试";
  } catch {
    return "请求失败，请稍后重试";
  }
};

const formatFileSize = (bytes) => {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unitIndex]}`;
};

const formatAnalysisTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "-" : date.toLocaleString("zh-CN", { hour12: false });
};

const historyPageNumbers = (currentPage, totalPages) => {
  if (totalPages <= 7) return Array.from({ length: totalPages }, (_, index) => index + 1);
  const pages = [1];
  if (currentPage > 4) pages.push("…");
  for (let page = Math.max(2, currentPage - 1); page <= Math.min(totalPages - 1, currentPage + 1); page += 1) pages.push(page);
  if (currentPage < totalPages - 3) pages.push("…");
  pages.push(totalPages);
  return [...new Set(pages)];
};

const renderHistoryPagination = ({ page, total, totalPages }) => {
  if (!analysisHistoryPagination) return;
  analysisHistoryPagination.hidden = total === 0;
  if (total === 0) {
    analysisHistoryPagination.replaceChildren();
    return;
  }
  const summary = document.createElement("span");
  summary.className = "analysis-history-total";
  summary.textContent = `共 ${total} 条记录`;
  const controls = document.createElement("div");
  controls.className = "analysis-history-pages";
  const addButton = (label, targetPage, { current = false, disabled = false } = {}) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `history-page-button${current ? " active" : ""}`;
    button.textContent = label;
    button.disabled = disabled;
    if (!disabled) button.dataset.historyPage = String(targetPage);
    controls.appendChild(button);
  };
  addButton("上一页", page - 1, { disabled: page <= 1 });
  historyPageNumbers(page, totalPages).forEach((item) => {
    if (item === "…") {
      const ellipsis = document.createElement("span");
      ellipsis.className = "history-page-ellipsis";
      ellipsis.textContent = item;
      controls.appendChild(ellipsis);
      return;
    }
    addButton(String(item), item, { current: item === page, disabled: item === page });
  });
  addButton("下一页", page + 1, { disabled: page >= totalPages });
  analysisHistoryPagination.replaceChildren(summary, controls);
};

const renderAnalysisHistory = (analyses, { page = 1, total = 0, totalPages = 1, keyword = "" } = {}) => {
  if (!analysisHistoryBody || !historyEmpty || !historyTableWrap) return;
  const hasRecords = analyses.length > 0;
  const isSearchResult = Boolean(keyword);
  historyEmpty.hidden = hasRecords || isSearchResult;
  historyTableWrap.hidden = !hasRecords && !isSearchResult;
  if (!hasRecords && isSearchResult) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "analysis-history-no-match";
    cell.textContent = "未找到匹配的分析记录。";
    row.appendChild(cell);
    analysisHistoryBody.replaceChildren(row);
    renderHistoryPagination({ page, total, totalPages });
    return;
  }
  historyEmpty.textContent = "暂无历史分析任务，请前往检测中心进行检测。";
  analysisHistoryBody.replaceChildren(...analyses.map((analysis, index) => {
    const row = document.createElement("tr");
    const conclusion = analysis.conclusion || { kind: "failed", label: "未知" };
    const cells = [String((page - 1) * HISTORY_PAGE_SIZE + index + 1), analysis.original_filename || "-", formatFileSize(analysis.file_size), formatAnalysisTime(analysis.created_at)];
    cells.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    });
    const conclusionCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = `conclusion-pill ${conclusion.kind || "failed"}`;
    pill.textContent = conclusion.label || "未知";
    conclusionCell.appendChild(pill);
    row.appendChild(conclusionCell);

    const detailCell = document.createElement("td");
    const detailButton = document.createElement("button");
    detailButton.type = "button";
    detailButton.className = "history-action";
    detailButton.dataset.historyDetail = String(analysis.id);
    detailButton.textContent = "详细数据";
    detailButton.disabled = analysis.status !== "completed";
    detailCell.appendChild(detailButton);
    row.appendChild(detailCell);

    const deleteCell = document.createElement("td");
    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "history-action delete";
    deleteButton.dataset.historyDelete = String(analysis.id);
    deleteButton.textContent = "删除";
    deleteButton.disabled = analysis.status === "processing";
    deleteCell.appendChild(deleteButton);
    row.appendChild(deleteCell);
    return row;
  }));
  renderHistoryPagination({ page, total, totalPages });
};

const loadAnalysisHistory = async ({ page = historyPage, keyword = historyKeyword } = {}) => {
  if (!currentUser || !analysisHistoryBody) return;
  try {
    const params = new URLSearchParams({ page: String(page) });
    if (keyword) params.set("keyword", keyword);
    const response = await fetch(`${apiBase}/analyses?${params.toString()}`, { credentials: "include" });
    if (!response.ok) throw new Error(await getApiError(response));
    const payload = await response.json();
    const analyses = Array.isArray(payload.analyses) ? payload.analyses : [];
    const total = Number(payload.total) || 0;
    const totalPages = Math.max(1, Number(payload.total_pages) || 1);
    if (total > 0 && page > totalPages) {
      historyPage = totalPages;
      return loadAnalysisHistory({ page: totalPages, keyword });
    }
    historyPage = page;
    historyKeyword = keyword;
    renderAnalysisHistory(analyses, { page, total, totalPages, keyword });
  } catch (error) {
    if (historyEmpty) {
      historyEmpty.hidden = false;
      historyEmpty.textContent = error instanceof Error ? `加载分析历史失败：${error.message}` : "加载分析历史失败，请稍后重试。";
    }
    if (historyTableWrap) historyTableWrap.hidden = true;
    if (analysisHistoryPagination) analysisHistoryPagination.hidden = true;
  }
};

const loadSavedAnalysisDashboard = async (recordId) => {
  const response = await fetch(`${apiBase}/analyses/${recordId}/dashboard`, { credentials: "include" });
  if (!response.ok) throw new Error(await getApiError(response));
  const payload = await response.json();
  if (!payload.dashboard || typeof payload.dashboard !== "object") {
    throw new Error("该任务未返回有效的可视化数据。");
  }
  displayedAnalysisId = recordId;
  latestVisualization = payload.dashboard;
  latestReportMarkdown = normalizeMarkdown(payload.analysis?.report_markdown || "");
  if (resultEl) resultEl.innerHTML = renderMarkdown(latestReportMarkdown || "暂无 AI 分析报告。");
  setReportDownloadEnabled(Boolean(latestReportMarkdown));
  return payload;
};

const openSavedAnalysisDashboard = async (recordId) => {
  const payload = await loadSavedAnalysisDashboard(recordId);
  const params = new URLSearchParams();
  params.set("analysis", String(recordId));
  switchTab("capability", { params, push: true, skipAnalysisLoad: true });
  if (!window.C2SherlockVisualization) {
    throw new Error("数据中心组件未正确加载，请刷新页面后重试。");
  }
  window.C2SherlockVisualization.render(payload.dashboard, payload.analysis);
};

const deleteSavedAnalysis = async (recordId) => {
  if (!window.confirm("删除后将永久移除该任务的 Zeek、RITA、LSTM、RAG、报告和可视化数据，确定继续吗？")) return;
  const response = await fetch(`${apiBase}/analyses/${recordId}`, { method: "DELETE", credentials: "include" });
  if (!response.ok) throw new Error(await getApiError(response));
  if (displayedAnalysisId === recordId) {
    displayedAnalysisId = null;
    window.C2SherlockVisualization?.clear();
  }
  await loadAnalysisHistory();
};

const setupAnalysisHistory = () => {
  analysisHistorySearch?.addEventListener("submit", (event) => {
    event.preventDefault();
    void loadAnalysisHistory({ page: 1, keyword: analysisHistoryKeyword?.value.trim() || "" });
  });
  analysisHistoryKeyword?.addEventListener("input", () => {
    if (!analysisHistoryKeyword.value && historyKeyword) {
      void loadAnalysisHistory({ page: 1, keyword: "" });
    }
  });
  analysisHistoryPagination?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-history-page]");
    const page = Number(button?.dataset.historyPage);
    if (Number.isInteger(page) && page > 0 && page !== historyPage) {
      void loadAnalysisHistory({ page, keyword: historyKeyword });
    }
  });
  analysisHistoryBody?.addEventListener("click", async (event) => {
    const detailButton = event.target.closest("[data-history-detail]");
    const deleteButton = event.target.closest("[data-history-delete]");
    const button = detailButton || deleteButton;
    if (!button) return;
    button.disabled = true;
    try {
      if (detailButton) await openSavedAnalysisDashboard(Number(detailButton.dataset.historyDetail));
      if (deleteButton) await deleteSavedAnalysis(Number(deleteButton.dataset.historyDelete));
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "操作失败，请稍后重试。");
    } finally {
      button.disabled = false;
    }
  });
};

const setAuthMode = (mode) => {
  const isLogin = mode === "login";
  $$(".auth-tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.authMode === mode));
  if (loginForm) loginForm.hidden = !isLogin;
  if (registerForm) registerForm.hidden = isLogin;
  setFormMessage($("#login-message"));
  setFormMessage($("#register-message"));
};

const openAuthModal = (mode = "login") => {
  const next = getHashState().tab === "profile" ? "?next=profile" : "";
  window.location.href = `${mode === "register" ? "register.html" : "login.html"}${next}`;
};

const closeAuthModal = () => {
  if (authModal) authModal.hidden = true;
};

const openChangePasswordModal = () => {
  if (!changePasswordModal) return;
  changePasswordModal.hidden = false;
  changePasswordModal.setAttribute("aria-hidden", "false");
  changePasswordForm?.querySelector("input")?.focus();
};

const closeChangePasswordModal = () => {
  if (!changePasswordModal) return;
  changePasswordModal.hidden = true;
  changePasswordModal.setAttribute("aria-hidden", "true");
  changePasswordForm?.reset();
  setFormMessage($("#change-password-message"));
};

const renderAccount = () => {
  const isLoggedIn = Boolean(currentUser);
  if (guestModeBadge) guestModeBadge.hidden = isLoggedIn;
  if (loginEntryBtn) loginEntryBtn.hidden = isLoggedIn;
  if (avatarBtn) {
    avatarBtn.hidden = !isLoggedIn;
    avatarBtn.textContent = isLoggedIn ? currentUser.username.slice(0, 1).toUpperCase() : "";
    avatarBtn.title = isLoggedIn ? `${currentUser.username} 的个人中心` : "";
  }
  if (logoutBtn) logoutBtn.hidden = !isLoggedIn;
  if (isLoggedIn) {
    if (dataCenterHistoryBtn) dataCenterHistoryBtn.hidden = false;
    $("#profile-avatar").textContent = currentUser.username.slice(0, 1).toUpperCase();
    $("#profile-username").textContent = currentUser.username;
    $("#profile-email").textContent = currentUser.email;
    const date = new Date(currentUser.created_at);
    $("#profile-created-at").textContent = Number.isNaN(date.valueOf()) ? "" : `注册时间：${date.toLocaleString("zh-CN")}`;
  }
  if (!isLoggedIn && dataCenterHistoryBtn) dataCenterHistoryBtn.hidden = true;
};

const loadSession = async () => {
  try {
    const response = await fetch(`${apiBase}/auth/me`, { credentials: "include" });
    currentUser = response.ok ? await response.json() : null;
  } catch {
    currentUser = null;
  }
  sessionResolved = true;
  document.documentElement.classList.remove("auth-pending");
  renderAccount();
  if (currentUser) void loadAnalysisHistory();
  const routeState = getHashState();
  if (currentUser && routeState.tab === "capability") {
    void loadAnalysisFromRoute(routeState.params);
  }
  if (getHashState().tab === "profile") switchTab("profile");
};

const submitAuthForm = async (form, endpoint, messageElement, successMessage, afterSuccess) => {
  const payload = Object.fromEntries(new FormData(form).entries());
  setFormMessage(messageElement);
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const response = await fetch(`${apiBase}${endpoint}`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(await getApiError(response));
    currentUser = await response.json();
    renderAccount();
    setFormMessage(messageElement, successMessage, "success");
    form.reset();
    afterSuccess?.();
  } catch (error) {
    setFormMessage(messageElement, error instanceof Error ? error.message : "请求失败，请稍后重试", "error");
  } finally {
    button.disabled = false;
  }
};

const setupAuthentication = () => {
  loginEntryBtn?.addEventListener("click", () => openAuthModal("login"));
  changePasswordOpenBtn?.addEventListener("click", openChangePasswordModal);
  changePasswordCloseBtn?.addEventListener("click", closeChangePasswordModal);
  changePasswordModal?.addEventListener("click", (event) => {
    if (event.target === changePasswordModal) closeChangePasswordModal();
  });
  $("#auth-close-btn")?.addEventListener("click", closeAuthModal);
  authModal?.addEventListener("click", (event) => {
    if (event.target === authModal) closeAuthModal();
  });
  $$(".auth-tab").forEach((tab) => tab.addEventListener("click", () => setAuthMode(tab.dataset.authMode)));
  avatarBtn?.addEventListener("click", () => switchTab("profile", { push: true }));
  logoutBtn?.addEventListener("click", async () => {
    logoutBtn.disabled = true;
    try {
      const response = await fetch(`${apiBase}/auth/logout`, { method: "POST", credentials: "include" });
      if (!response.ok) throw new Error("退出登录失败，请稍后重试");
      currentUser = null;
      renderAccount();
      window.location.href = "login.html";
    } catch (error) {
      window.alert(error instanceof Error ? error.message : "退出登录失败，请稍后重试");
    } finally {
      logoutBtn.disabled = false;
    }
  });
  loginForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    submitAuthForm(loginForm, "/auth/login", $("#login-message"), "登录成功", closeAuthModal);
  });
  registerForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    submitAuthForm(registerForm, "/auth/register", $("#register-message"), "注册成功，已登录", () => {
      closeAuthModal();
      switchTab("home", { push: true });
    });
  });
  changePasswordForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const message = $("#change-password-message");
    const payload = Object.fromEntries(new FormData(changePasswordForm).entries());
    if (payload.new_password !== payload.confirm_new_password) {
      setFormMessage(message, "两次输入的新密码不一致", "error");
      return;
    }
    const button = changePasswordForm.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const response = await fetch(`${apiBase}/auth/change-password`, {
        method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(await getApiError(response));
      changePasswordForm.reset();
      currentUser = null;
      renderAccount();
      setFormMessage(message, "密码已更新，请重新登录", "success");
      window.setTimeout(() => { switchTab("home", { push: true }); openAuthModal("login"); }, 700);
    } catch (error) {
      setFormMessage(message, error instanceof Error ? error.message : "修改失败，请稍后重试", "error");
    } finally {
      button.disabled = false;
    }
  });
  loadSession();
};

setupTabs();
setupPrincipleTabs();
setupApiConfig();
setupUpload();
setupCaseExamples();
renderCaseTable();
setupAnalysisHistory();
setupAuthentication();
setReportVisible(false);
openCurrentDataBtn?.addEventListener("click", () => {
  if (!latestVisualization) return;
  switchTab("capability", { push: true });
  window.C2SherlockVisualization?.render(latestVisualization);
});
analyzeBtn.addEventListener("click", analyzeSelectedFile);
cancelBtn?.addEventListener("click", cancelAnalysis);
downloadReportBtn?.addEventListener("click", downloadReport);
printReportBtn?.addEventListener("click", printReport);
