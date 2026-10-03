// 원본 JSON 보기. 값을 클릭하면 onPick(path, value) — 보통 "이 값으로 검색" 에 쓴다.
import { html } from './util.js';

function leaf(value, path) {
  const text = typeof value === 'string' ? JSON.stringify(value) : String(value);
  const cls = value === null ? 'j-null' : typeof value === 'string' ? 'j-str' : typeof value === 'number' ? 'j-num' : 'j-bool';
  const filterValue = typeof value === 'string' ? value : JSON.stringify(value);
  return html`<button type="button" class="j-val ${cls}" data-path="${path.join('.')}" data-value="${filterValue}" title="클릭: 이 값으로 검색">${text}</button>`;
}

function node(value, path) {
  if (Array.isArray(value)) {
    if (!value.length) return html`<span class="j-punct">[]</span>`;
    return html`<span class="j-punct">[</span><div class="j-nest">${value.map((v, i) =>
      html`<div>${typeof v === 'object' && v !== null ? node(v, [...path, String(i)]) : leaf(v, [...path, String(i)])}<span class="j-punct">${i < value.length - 1 ? ',' : ''}</span></div>`)}</div><span class="j-punct">]</span>`;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (!entries.length) return html`<span class="j-punct">{}</span>`;
    return html`<span class="j-punct">{</span><div class="j-nest">${entries.map(([k, v], i) => html`<div><span class="j-key">${k}</span><span class="j-punct">: </span>${
      typeof v === 'object' && v !== null ? node(v, [...path, k]) : leaf(v, [...path, k])}<span class="j-punct">${i < entries.length - 1 ? ',' : ''}</span></div>`)}</div><span class="j-punct">}</span>`;
  }
  return leaf(value, path);
}

export function jsonView(el, value, onPick) {
  el.classList.add('json');
  el.innerHTML = node(value, []);
  if (onPick) {
    el.addEventListener('click', (ev) => {
      const btn = ev.target.closest('.j-val');
      if (btn && btn.dataset.path) onPick(btn.dataset.path, btn.dataset.value);
    });
  }
}
