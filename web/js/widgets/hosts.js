// PC 현황 카드 격자. 오류가 많은 PC 가 앞에 온다. 카드를 누르면 그 PC 의 이벤트 검색.
// 실시간: 로그가 들어온 PC 카드가 깜빡이고 오류/경고/전체 수와 '마지막 수신'이 바로 바뀐다.
import * as api from '../api.js';
import { levelIcon, sourceLabel, statusBadge } from '../levels.js';
import { fmtCompact, fmtNum, fmtRelative, html } from '../util.js';

const STATUS_ORDER = { online: 0, stale: 1, offline: 2 };

function draw(body, ctx, st, touched = new Set()) {
  if (!st.items.length) {
    body.innerHTML = html`<div class="empty">아직 로그를 보낸 PC 가 없습니다. '수집 PC' 화면의 설치 안내를 참고하세요.</div>`;
    return;
  }
  const sorted = [...st.items].sort((a, b) =>
    b.errors - a.errors || b.warnings - a.warnings
    || STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || a.host.localeCompare(b.host));
  body.innerHTML = html`<div class="hosts">${sorted.map((a) => html`
    <button type="button" class="host-card ${a.errors ? 'has-errors' : ''} ${touched.has(a.host) ? 'touched' : ''}" data-host="${a.host}">
      <div class="host-top"><span class="host-name" title="${a.host}">${a.host}</span>${statusBadge(a.status)}</div>
      <div class="host-sub">
        <span>${a.sources.length ? a.sources.map(sourceLabel).join(', ') : '이벤트 없음'}</span>
        <span title="마지막 수신">${fmtRelative(a.last_seen)}</span>
      </div>
      <div class="host-counts">
        <span title="심각+오류">${levelIcon(2)}<b>${fmtNum(a.errors)}</b></span>
        <span title="경고">${levelIcon(3)}<b>${fmtNum(a.warnings)}</b></span>
        <span title="전체 이벤트">전체 <b>${fmtCompact(a.events)}</b></span>
      </div>
    </button>`)}</div>`;
  body.querySelectorAll('[data-host]').forEach((card) =>
    card.addEventListener('click', () => ctx.drill({ host: card.dataset.host })));
}

export default {
  label: 'PC 현황',
  async render(body, cfg, ctx) {
    const { items } = await api.get('/api/agents', { since: ctx.query(cfg).since });
    body._live = { items };
    draw(body, ctx, body._live);
  },

  live(body, cfg, ctx, events) {
    const st = body._live;
    if (!st || !events.length) return;
    const touched = new Set();
    const now = new Date().toISOString();
    for (const ev of events) {
      const agent = st.items.find((a) => a.host === ev.host);
      if (!agent) { ctx.resync(body); return; } // 처음 보는 PC
      agent.events += 1;
      if (ev.level <= 2) agent.errors += 1;
      if (ev.level === 3) agent.warnings += 1;
      if (!agent.sources.includes(ev.source)) agent.sources.push(ev.source);
      agent.last_seen = now;
      agent.status = 'online';
      touched.add(agent.host);
    }
    draw(body, ctx, st, touched);
  },
};
