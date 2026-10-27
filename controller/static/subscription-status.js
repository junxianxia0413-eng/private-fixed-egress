// Refresh a completed background apply without discarding an edited form.
(() => {
  if (!document.querySelector('[data-apply-pending="true"]')) return;
  let dirty = false;
  let busy = false;
  document.addEventListener("input", () => { dirty = true; });
  document.addEventListener("change", () => { dirty = true; });
  const timer = window.setInterval(async () => {
    if (busy || dirty || document.hidden) return;
    busy = true;
    try {
      const response = await fetch("/api/groups", {cache: "no-store", credentials: "same-origin"});
      if (!response.ok) return;
      const data = await response.json();
      const pending = [...document.querySelectorAll('[data-apply-pending="true"]')];
      if (!dirty && pending.some(card => !data.groups.some(group =>
        String(group.id) === card.dataset.groupId && group.applying))) {
        window.clearInterval(timer);
        window.location.reload();
      }
    } catch (_) {
      // Keep the page usable when a polling request fails.
    } finally {
      busy = false;
    }
  }, 5000);
})();
