const API_BASE_URL = `${window.location.protocol}//${window.location.hostname}:8000`;

const dropZone = document.getElementById("drop-zone");
const pcapInput = document.getElementById("pcap-input");
const fileName = document.getElementById("file-name");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

let selectedFile = null;

const setStatus = (message) => {
  statusEl.textContent = message;
};

const setFile = (file) => {
  selectedFile = file;
  fileName.textContent = file ? file.name : "No file selected";
};

const preventDefaults = (event) => {
  event.preventDefault();
  event.stopPropagation();
};

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
  if (file) {
    setFile(file);
    setStatus("Ready to analyze.");
  }
});

pcapInput.addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) {
    setFile(file);
    setStatus("Ready to analyze.");
  }
});

analyzeBtn.addEventListener("click", async () => {
  if (!selectedFile) {
    setStatus("Please choose a PCAP file first.");
    return;
  }

  setStatus("Uploading and analyzing... this may take a while.");
  resultEl.textContent = "Working...";

  const formData = new FormData();
  formData.append("pcap", selectedFile);

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: "POST",
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Analysis failed");
    }

    const markdown = data.analysis_markdown || "No analysis returned.";
    resultEl.innerHTML = marked.parse(markdown);
    setStatus("Analysis complete.");
  } catch (error) {
    resultEl.textContent = "An error occurred while analyzing the PCAP.";
    setStatus(error.message);
  }
});
