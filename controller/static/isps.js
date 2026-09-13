function decodePart(value) {
  try {
    return decodeURIComponent(value);
  } catch (_) {
    throw new Error("链接中包含无法识别的转义字符");
  }
}

function parseSocks5(value) {
  const match = value.trim().match(/^socks5:\/\/([^:@/\s]+):([^@/\s]+)@([^:/\s]+):(\d{1,5})\/?$/i);
  if (!match) throw new Error("格式应为 socks5://用户名:密码@地址:端口");
  const port = Number(match[4]);
  if (port < 1 || port > 65535) throw new Error("端口需为 1–65535");
  return {username: decodePart(match[1]), password: decodePart(match[2]), host: match[3], port: String(port)};
}

for (const form of document.querySelectorAll("[data-socks-form]")) {
  const source = form.querySelector("[data-socks-uri]");
  const message = form.querySelector("[data-socks-message]");
  if (!source || !message) continue;
  source.addEventListener("input", () => {
    if (!source.value.trim()) {
      message.textContent = "粘贴后会自动识别并填写下面四项；也可以直接手动填写。";
      return;
    }
    try {
      const values = parseSocks5(source.value);
      for (const [key, value] of Object.entries(values)) {
        const field = form.querySelector(`[data-socks-field="${key}"]`);
        if (field) field.value = value;
      }
      message.textContent = "已识别地址、端口、用户名和密码，请确认后保存。";
    } catch (error) {
      message.textContent = error.message;
    }
  });
}
