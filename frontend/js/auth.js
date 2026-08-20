const apiBase = `${window.location.protocol}//${window.location.hostname}:8765`;
const form = document.querySelector("#auth-form");
const toast = document.querySelector("#auth-toast");
const toastMessage = document.querySelector("#auth-toast-message");
const toastCloseButton = document.querySelector("#auth-toast-close");
const submitButton = form?.querySelector("button[type=submit]");
const fillDemoAccountButton = document.querySelector("#fill-demo-account");
const passwordToggles = document.querySelectorAll("[data-password-toggle]");
const guestModeLink = document.querySelector(".header-actions .outline");
const authPageSwitchLink = document.querySelector(".switch-link a");

const requestedDestination = new URLSearchParams(window.location.search).get("next");
if (authPageSwitchLink && ["collector", "profile"].includes(requestedDestination)) {
  const target = new URL(authPageSwitchLink.href, window.location.href);
  target.searchParams.set("next", requestedDestination);
  authPageSwitchLink.href = `${target.pathname.split("/").pop()}${target.search}`;
}

guestModeLink?.addEventListener("click", (event) => {
  event.preventDefault();
  window.location.href = "index.html?mode=guest";
});

const setMessage = (text = "", type = "") => {
  if (!toast || !toastMessage) return;
  toastMessage.textContent = text;
  toast.className = `auth-toast${type ? ` ${type}` : ""}`;
  toast.hidden = !text;
};

toastCloseButton?.addEventListener("click", () => setMessage());

const readError = async (response) => {
  try {
    const body = await response.json();
    return body.detail || "请求失败，请稍后重试";
  } catch {
    return "请求失败，请稍后重试";
  }
};

passwordToggles.forEach((toggle) => {
  toggle.addEventListener("click", () => {
    const passwordInput = document.getElementById(toggle.getAttribute("aria-controls"));
    if (!(passwordInput instanceof HTMLInputElement)) return;
    const shouldShow = passwordInput.type === "password";
    passwordInput.type = shouldShow ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(shouldShow));
    toggle.setAttribute("aria-label", shouldShow ? "隐藏密码" : "显示密码");
  });
});

fillDemoAccountButton?.addEventListener("click", () => {
  const identifier = form?.elements.namedItem("identifier");
  const password = form?.elements.namedItem("password");
  if (!(identifier instanceof HTMLInputElement) || !(password instanceof HTMLInputElement)) return;
  identifier.value = "admin";
  password.value = "12345678";
  setMessage("已自动填入演示账户信息", "success");
  identifier.focus();
});

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const endpoint = form.dataset.endpoint;
  const payload = Object.fromEntries(new FormData(form).entries());
  if (endpoint === "/auth/register" && payload.password !== payload.confirm_password) {
    setMessage("两次输入的密码不一致", "error");
    return;
  }
  setMessage();
  submitButton.disabled = true;
  try {
    const response = await fetch(`${apiBase}${endpoint}`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(await readError(response));
    setMessage(endpoint === "/auth/login" ? "登录成功，正在进入系统…" : "注册成功，正在进入系统…", "success");
    // Home is the default route. Omitting `#home` prevents the browser from
    // initially aligning the home section below the sticky header.
    const destination = ["collector", "profile"].includes(requestedDestination) ? `#${requestedDestination}` : "";
    window.setTimeout(() => { window.location.href = `index.html${destination}`; }, 450);
  } catch (error) {
    setMessage(error instanceof Error ? error.message : "请求失败，请稍后重试", "error");
  } finally {
    submitButton.disabled = false;
  }
});
