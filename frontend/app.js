const API_BASE_URL = `${window.location.protocol}//${window.location.hostname}:8765`;

const dropZone = document.getElementById("drop-zone");
const pcapInput = document.getElementById("pcap-input");
const fileName = document.getElementById("file-name");
const analyzeBtn = document.getElementById("analyze-btn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const stepsEl = document.getElementById("steps");

let selectedFile = null;

const stepOrder = ["zeek", "rita", "ai"];
const stepLabels = {
  zeek: "Running Zeek...",
  rita: "Running RITA...",
  ai: "Sending to AI...",
};

const setStatus = (message) => {
  statusEl.textContent = message;
};

const resetSteps = () => {
  stepOrder.forEach((step) => {
    const item = stepsEl.querySelector(`[data-step="${step}"]`);
    if (item) {
      item.classList.remove("active", "done", "error");
    }
  });
};

const markStep = (step) => {
  const stepIndex = stepOrder.indexOf(step);
  stepOrder.forEach((current, index) => {
    const item = stepsEl.querySelector(`[data-step="${current}"]`);
    if (!item) {
      return;
    }
    item.classList.remove("active", "done", "error");
    if (index < stepIndex) {
      item.classList.add("done");
    } else if (index === stepIndex) {
      item.classList.add("active");
    }
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
  if (!step) {
    return;
  }
  const item = stepsEl.querySelector(`[data-step="${step}"]`);
  if (item) {
    item.classList.remove("active", "done");
    item.classList.add("error");
  }
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

  analyzeBtn.disabled = true;
  setStatus("Uploading... this may take a while.");
  resultEl.textContent = "Working...";
  resetSteps();

  const formData = new FormData();
  formData.append("pcap", selectedFile);

  let currentStep = null;

  try {
    const response = await fetch(`${API_BASE_URL}/analyze/stream`, {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || "Analysis failed");
    }

    if (!response.body) {
      throw new Error("Streaming not supported by the browser.");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    const handleEvent = (eventName, data) => {
      if (eventName === "step") {
        currentStep = data;
        markStep(data);
        setStatus(stepLabels[data] || "Working...");
        return;
      }

      if (eventName === "result") {
        const payload = JSON.parse(data);
        const markdown = payload.analysis_markdown || "No analysis returned.";
        resultEl.innerHTML = marked.parse(markdown);
        markAllDone();
        setStatus("Analysis complete.");
        return;
      }

      if (eventName === "error") {
        markError(currentStep);
        throw new Error(data || "Analysis failed");
      }
    };

    const processBuffer = () => {
      const parts = buffer.split("\n\n");
      buffer = parts.pop();
      parts.forEach((part) => {
        if (!part.trim()) {
          return;
        }
        let eventName = "message";
        let data = "";
        part.split("\n").forEach((line) => {
          if (line.startsWith("event:")) {
            eventName = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            data += line.slice(5).trim();
          }
        });
        handleEvent(eventName, data);
      });
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      processBuffer();
    }

    if (buffer.trim()) {
      buffer += "\n\n";
      processBuffer();
    }
  } catch (error) {
    resultEl.textContent = "An error occurred while analyzing the PCAP.";
    setStatus(error.message);
  } finally {
    analyzeBtn.disabled = false;
  }
});
