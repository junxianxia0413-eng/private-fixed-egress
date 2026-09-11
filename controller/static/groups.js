(() => {
  const maximum = 20;
  const template = document.querySelector('#device-row-template');

  function synchronize(form) {
    const rows = [...form.querySelectorAll('[data-device-row]')];
    rows.forEach((row, index) => {
      row.querySelector('[data-device-label]').textContent = `设备 ${index + 1}`;
      const menu = row.querySelector('.device-menu summary');
      menu.setAttribute('aria-label', `设备 ${index + 1} 操作`);
      row.querySelector('[data-remove-device]').disabled = rows.length === 1;
    });
    form.querySelector('[data-add-device]').disabled = rows.length >= maximum;
  }

  document.querySelectorAll('[data-device-form]').forEach(synchronize);
  document.addEventListener('click', (event) => {
    const add = event.target.closest('[data-add-device]');
    if (add) {
      const form = add.closest('[data-device-form]');
      const list = form.querySelector('[data-device-list]');
      if (list.querySelectorAll('[data-device-row]').length < maximum) {
        list.append(template.content.firstElementChild.cloneNode(true));
        synchronize(form);
        list.lastElementChild.querySelector('input[name="device_name"]').focus();
      }
      return;
    }
    const remove = event.target.closest('[data-remove-device]');
    if (remove && !remove.disabled) {
      const form = remove.closest('[data-device-form]');
      remove.closest('[data-device-row]').remove();
      synchronize(form);
    }
  });
})();
