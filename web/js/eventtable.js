// 이벤트 목록 표 (검색 화면, 실시간 화면, 대시보드 위젯에서 공용).
import { eventDoc } from './catalog.js';
import { openEvent } from './drawer.js';
import { categoryLabel, levelBadge, sourceLabel } from './levels.js';
import { html } from './util.js';

const pad = (n) => String(n).padStart(2, '0');
export function shortTime(value) {
  const d = new Date(value);
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export const EVENT_HEAD = html`<tr>
  <th class="nowrap">발생 시각</th><th>수준</th><th>PC</th><th>분류</th><th>이벤트</th><th>메시지</th></tr>`;

export function eventRow(ev, key, { flash = false } = {}) {
  const doc = eventDoc(ev.event_id, ev.source);
  const firstLine = (ev.message || '').split(/\r?\n/, 1)[0];
  return html`<tr class="clickable${flash ? ' flash' : ''}" data-k="${key}">
    <td class="nowrap num muted">${shortTime(ev.ts)}</td>
    <td class="nowrap">${levelBadge(ev.level)}</td>
    <td class="nowrap">${ev.host}</td>
    <td class="nowrap ink-2" title="${[ev.channel, ev.provider].filter(Boolean).join(' · ')}">${ev.category ? categoryLabel(ev.category) : ev.channel || sourceLabel(ev.source)}</td>
    <td class="nowrap">${ev.event_id != null ? html`<span class="num">${ev.event_id}</span>${doc ? html` <span class="muted">${doc}</span>` : ''}` : html`<span class="muted">${ev.provider ?? ''}</span>`}</td>
    <td class="msg" title="${firstLine}">${firstLine}</td>
  </tr>`;
}

/** 표 전체를 그린다. items 는 최신순. 행 클릭 시 상세 패널. */
export function eventTable(el, items, { emptyText = '조건에 맞는 이벤트가 없습니다' } = {}) {
  if (!items.length) {
    el.innerHTML = html`<div class="empty">${emptyText}</div>`;
    return;
  }
  el.innerHTML = html`<div class="table-wrap"><table class="table">
    <thead>${EVENT_HEAD}</thead>
    <tbody>${items.map((ev, i) => eventRow(ev, i))}</tbody></table></div>`;
  bindRows(el, (k) => items[Number(k)]);
}

/** tbody 안 행 클릭 → 상세. lookup(key) 로 이벤트를 찾는다 */
export function bindRows(el, lookup) {
  el.addEventListener('click', (ev) => {
    const tr = ev.target.closest('tr[data-k]');
    if (!tr) return;
    const item = lookup(tr.dataset.k);
    if (item) openEvent(item.raw ? item : item.id);
  });
}
