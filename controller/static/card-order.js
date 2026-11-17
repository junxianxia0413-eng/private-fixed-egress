(() => {
  const list = document.querySelector('[data-card-list]');
  if (!list) return;
  const status = document.querySelector('[data-card-order-status]');
  let drag = null;
  let saving = false;
  let frame = 0;
  const cards = () => [...list.querySelectorAll(':scope > [data-card-id]')];
  const clearTarget = () => list.querySelector('.card-drop-target')?.classList.remove('card-drop-target');

  async function move(card, to) {
    if (saving) return;
    const original = cards();
    const from = original.indexOf(card);
    if (from < 0 || to === from || to < 0 || to >= original.length) return;
    const target = original[to];
    target.insertAdjacentElement(to < from ? 'beforebegin' : 'afterend', card);
    const handle = card.querySelector('[data-card-handle]');
    handle.focus({preventScroll: true});
    saving = true;
    list.dispatchEvent(new Event('input', {bubbles: true}));
    status.textContent = '正在保存顺序…';
    try {
      const response = await fetch(`/api/cards/${list.dataset.cardList}/order`, {
        method: 'POST',
        body: new URLSearchParams({
          csrf: list.dataset.csrf,
          order: JSON.stringify(cards().map(item => Number(item.dataset.cardId)))
        })
      });
      if (!response.ok) {
        const message = await response.json().catch(() => ({}));
        throw new Error(typeof message.detail === 'string' ? message.detail : '请重试。');
      }
      status.textContent = '顺序已保存。';
    } catch (error) {
      original.forEach(item => list.appendChild(item));
      handle.focus({preventScroll: true});
      status.textContent = `排序未保存：${error.message}`;
    } finally {
      saving = false;
    }
  }

  list.addEventListener('pointerdown', event => {
    const handle = event.target.closest('[data-card-handle]');
    if (!handle || saving || !event.isPrimary || event.button !== 0) return;
    const card = handle.closest('[data-card-id]');
    handle.setPointerCapture(event.pointerId);
    drag = {card, handle, id: event.pointerId, x: event.clientX, y: event.clientY, active: false};
  });
  function highlight(x, y) {
    clearTarget();
    drag.target = document.elementFromPoint(x, y)?.closest('[data-card-id]');
    if (drag.target && drag.target !== drag.card) drag.target.classList.add('card-drop-target');
  }
  function scrollEdge() {
    if (!drag?.active) return;
    const {x, y} = drag.position;
    const edge = 52;
    const delta = y < edge ? -12 : y > window.innerHeight - edge ? 12 : 0;
    if (delta) {
      window.scrollBy(0, delta);
      highlight(x, y);
    }
    frame = requestAnimationFrame(scrollEdge);
  }
  list.addEventListener('pointermove', event => {
    if (!drag || event.pointerId !== drag.id) return;
    if (!drag.active && Math.hypot(event.clientX - drag.x, event.clientY - drag.y) < 6) return;
    drag.position = {x: event.clientX, y: event.clientY};
    if (!drag.active) {
      drag.active = true;
      frame = requestAnimationFrame(scrollEdge);
    }
    highlight(event.clientX, event.clientY);
  });
  function finish(event, dropped) {
    if (!drag || event.pointerId !== drag.id) return;
    const {card, target, active} = drag;
    drag = null;
    cancelAnimationFrame(frame);
    clearTarget();
    if (dropped && active && target) void move(card, cards().indexOf(target));
  }
  list.addEventListener('pointerup', event => finish(event, true));
  list.addEventListener('pointercancel', event => finish(event, false));
  list.addEventListener('lostpointercapture', event => finish(event, false));
  list.addEventListener('click', event => {
    const step = event.target.closest('[data-card-step]');
    if (!step) return;
    const card = step.closest('[data-card-id]');
    void move(card, cards().indexOf(card) + Number(step.dataset.cardStep));
  });
  list.addEventListener('keydown', event => {
    if (!event.target.matches('[data-card-handle]')) return;
    const step = {ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1}[event.key];
    if (!step) return;
    event.preventDefault();
    const card = event.target.closest('[data-card-id]');
    void move(card, cards().indexOf(card) + step);
  });
})();
