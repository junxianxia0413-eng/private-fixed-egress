document.querySelectorAll('[data-exit-form]').forEach(form => {
  const type = form.elements.exit_type;
  const isp = form.elements.isp_id;
  function sync() {
    const proxy = type.value === 'ISP_PROXY';
    isp.closest('label').hidden = !proxy;
    isp.required = proxy;
    isp.disabled = !proxy;
  }
  type.addEventListener('change', sync);
  sync();
});

document.addEventListener('click', event => {
  const edit = event.target.closest('[data-edit-exit]');
  if (!edit) return;
  const editor = edit.closest('[data-card-id]').querySelector('[data-exit-editor]');
  edit.closest('.card-menu').open = false;
  editor.open = true;
  editor.querySelector('input[name="name"]').focus();
});
