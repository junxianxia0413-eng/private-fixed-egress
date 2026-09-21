document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-confirm-delete]");
  if (!button) return;
  if (!window.confirm(button.dataset.confirmMessage)) event.preventDefault();
});
