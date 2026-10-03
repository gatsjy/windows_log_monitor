// 오른쪽에서 열리는 상세 패널 + 이벤트 상세 보기.
import * as api from './api.js';
import { eventDoc } from './catalog.js';
import { jsonView } from './jsonview.js';
import { categoryLabel, levelBadge, sourceLabel } from './levels.js';
import { errorBox, fmtRelative, fmtTime, html, navigate } from './util.js';

let current = null;

export function closeDrawer() {
  current?.();
  current = null;
}

/** @returns {HTMLElement} 본문 요소 */
export function openDrawer({ title, subtitle = '', actions = '' }) {
  closeDrawer();
  const root = document.getElementById('drawer-root');
  root.innerHTML = html`
    <div class="drawer-overlay"></div>
    <aside class="drawer" role="dialog" aria-modal="true">
      <div class="drawer-head">
        <div><h2>${title}</h2>${subtitle ? html`<div class="page-sub">${subtitle}</div>` : ''}</div>
        <div class="toolbar">${actions}<button class="btn ghost sm" data-close aria-label="닫기">닫기 ✕</button></div>
      </div>
      <div class="drawer-body"></div>
    </aside>`;
  const onKey = (ev) => { if (ev.key === 'Escape') closeDrawer(); };
  document.addEventListener('keydown', onKey);
  root.querySelector('.drawer-overlay').addEventListener('click', closeDrawer);
  root.querySelector('[data-close]').addEventListener('click', closeDrawer);
  current = () => { document.removeEventListener('keydown', onKey); root.innerHTML = ''; };
  return root.querySelector('.drawer-body');
}

function searchBy(params) {
  closeDrawer();
  navigate('events', params);
}

/** 이벤트 하나의 상세. ev 에 raw 가 있으면(실시간 화면) 그대로, 아니면 id 로 조회 */
export async function openEvent(evOrId) {
  const body = openDrawer({ title: '이벤트 상세' });
  body.innerHTML = '<div class="skeleton"></div>';
  let ev;
  try {
    ev = typeof evOrId === 'object' && evOrId.raw ? evOrId : await api.get(`/api/events/${typeof evOrId === 'object' ? evOrId.id : evOrId}`);
  } catch (err) {
    body.innerHTML = errorBox(err);
    return;
  }

  const doc = eventDoc(ev.event_id, ev.source);
  const row = (label, value, filter) => html`
    <dt>${label}</dt>
    <dd>${value ?? '–'}${filter ? html` <a href="#" class="filter-link" data-filter='${JSON.stringify(filter)}'>이 값으로 검색</a>` : ''}</dd>`;

  body.innerHTML = html`
    <div class="toolbar" style="margin-bottom:14px">
      ${levelBadge(ev.level)}
      <span class="muted">·</span>
      <b>${ev.provider || ev.channel || sourceLabel(ev.source)}</b>
      ${ev.event_id != null ? html`<span class="muted">이벤트 ${ev.event_id}${doc ? ` · ${doc}` : ''}</span>` : ''}
    </div>
    <dl class="kv">
      ${row('발생 시각', html`${fmtTime(ev.ts)} <span class="muted">(${fmtRelative(ev.ts)})</span>`)}
      ${row('수집 시각', fmtTime(ev.received_at))}
      ${row('PC', ev.host, { host: ev.host })}
      ${row('분류', categoryLabel(ev.category), ev.category ? { category: ev.category } : null)}
      ${row('소스', sourceLabel(ev.source), { source: ev.source })}
      ${row('채널', ev.channel, ev.channel ? { channel: ev.channel } : null)}
      ${row('공급자', ev.provider, ev.provider ? { provider: ev.provider } : null)}
      ${row(ev.source === 'iis' ? 'HTTP 상태' : '이벤트 ID', ev.event_id, ev.event_id != null ? { event_id: ev.event_id } : null)}
      ${row('수준', levelBadge(ev.level), { level: ev.level })}
      ${ev.username ? row('사용자', ev.username, { user: ev.username }) : ''}
      ${ev.src_ip ? row('접속 IP', ev.src_ip, { ip: ev.src_ip }) : ''}
    </dl>
    <div class="section-title">메시지</div>
    <pre class="message-box">${ev.message || '(메시지 없음)'}</pre>
    <div class="section-title" style="display:flex;justify-content:space-between;align-items:center">
      <span>원본 데이터 (에이전트가 보낸 그대로)</span>
      <button class="btn sm" data-copy>JSON 복사</button>
    </div>
    <div class="hint-box" style="margin-bottom:8px">값을 클릭하면 그 값을 가진 이벤트만 검색합니다.</div>
    <div data-json></div>`;

  body.querySelectorAll('[data-filter]').forEach((a) => a.addEventListener('click', (e) => {
    e.preventDefault();
    searchBy(JSON.parse(a.dataset.filter));
  }));
  jsonView(body.querySelector('[data-json]'), ev.raw, (path, value) => searchBy({ [`f.${path}`]: value }));
  body.querySelector('[data-copy]').addEventListener('click', async (e) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(ev.raw, null, 2));
      e.target.textContent = '복사됨';
    } catch {
      e.target.textContent = '복사 실패';
    }
  });
}
