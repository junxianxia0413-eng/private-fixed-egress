(() => {
  function fallbackCopy(value) {
    const previous = document.activeElement;
    const field = document.createElement("textarea");
    field.value = value;
    field.readOnly = true;
    field.className = "clipboard-helper";
    document.body.appendChild(field);
    try {
      field.select();
      return document.execCommand("copy");
    } finally {
      field.remove();
      if (previous && typeof previous.focus === "function") previous.focus();
    }
  }

  document.addEventListener("click", async (event) => {
    const action = event.target.closest("[data-copy-ip], [data-copy-target]");
    if (!action) return;
    const status = action.closest("[data-copy-scope]")?.querySelector("[data-copy-status]");
    const field = document.getElementById(action.dataset.copyTarget || "");
    const value = action.dataset.copyIp || field?.value;
    if (!status || !value) return;
    let copied = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        copied = true;
      }
    } catch (_) {
      // Clipboard permissions vary between mobile and desktop browsers.
    }
    if (!copied) {
      try { copied = fallbackCopy(value); } catch (_) { /* Report failure below. */ }
    }
    const label = action.dataset.copyIp ? `IP：${value}` : "订阅链接";
    status.textContent = copied ? `已复制${label}。` : `浏览器未允许复制，请手动复制上方的${label}。`;
    // Links keep their native new-tab action, even if copying is denied or JS is disabled.
  });
})();
