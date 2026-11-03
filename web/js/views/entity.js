// 개체 페이지 (B-67, ADR-064): PC·계정·IP 하나에 걸린 알림과 로그를 한 화면에서. 주소 #/entity/host|user|ip/<값>?since=7d
// 알림은 /api/entities (개체 열·조회 범위·접속기록), 로그는 검색 API 를 서버가 준 문장으로 부른다 — 조회 범위·시간 상한·접속기록이
// 그쪽에서 그대로 붙는다. 계정은 표기 통일 열쇠(account:)로 — HOSP\kim·kim@hosp.local 이 한 화면.
import * as api from '../api.js';
import { alertRows, bindAlertRows } from '../alertdetail.js';
import { barList, columnChart, legend, seriesColors, seriesLabel } from '../charts.js';
import { EVENT_HEAD, bindRows, eventRow } from '../eventtable.js';
import { categoryLabel, statusBadge } from '../levels.js';
import { ENTITY_LABELS, entityHash, errorBox, fmtNum, fmtRelative, fmtTime, html, qs, replaceParams, tzOffset } from '../util.js';

const PERIODS = [['24h', '24시간'], ['7d', '7일'], ['30d', '30일']];
// 이 개체의 로그에 함께 나온 다른 개체: [검색 필드, 개체 종류, 제목]
const PEERS = {
  host: [['account', 'user', '로그에 나온 계정'], ['ip', 'ip', '접속해 온 IP']],
  user: [['host', 'host', '이 계정이 쓰인 PC'], ['ip', 'ip', '접속해 온 IP']],
  ip: [['host', 'host', '이 IP 가 접속한 PC'], ['account', 'user', '쓰인 계정']],
};
const RECENT = 20;

export async function mount(root, params, sub) {
  const slash = sub.indexOf('/');
  const kind = slash > 0 ? sub.slice(0, slash) : sub;
  let value = '';
  try { value = decodeURIComponent(sub.slice(slash + 1)); } catch { /* 잘린 % 표기 — 아래에서 잘못된 주소로 */ }
  if (!ENTITY_LABELS[kind] || slash <= 0 || !value) {
    root.innerHTML = html`<div class="error-box">개체 주소가 잘못되었습니다 — #/entity/host|user|ip/&lt;값&gt;</div>`;
    return null;
  }
  let since = PERIODS.some(([v]) => v === params.since) ? params.since : '7d';
  let alive = true;
  let token = 0;
  let recent = [];   // 최근 로그 표의 행 — 클릭 처리는 한 번만 붙이고 이 값만 바꾼다

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title"><span class="muted" style="font-weight:550">${ENTITY_LABELS[kind]}</span> <span data-title>${value}</span></h1>
        <p class="page-sub">이 ${ENTITY_LABELS[kind]}에 걸린 알림과 로그를 한 곳에서 봅니다.${kind === 'user'
          ? ' 계정은 표기를 통일해 찾습니다(HOSP\\kim·kim@hosp.local·KIM 이 같은 계정).' : ''} 알림은 조건에 맞은 로그에 이 값이 나온 것까지 포함합니다.</p></div>
      <div class="toolbar">
        <div class="seg" data-period>${PERIODS.map(([v, l]) => html`<button type="button" data-v="${v}" class="${v === since ? 'on' : ''}">${l}</button>`)}</div>
        <a class="btn" data-search href="#/events">로그 검색에서 보기 →</a>
      </div>
    </div>
    <div data-agent></div>
    <div class="grid" style="margin-bottom:16px" data-stats></div>
    <section class="card" style="margin-bottom:16px"><div class="card-head"><h3 class="card-title">알림</h3><span class="muted" data-alert-note></span></div>
      <div class="card-body" data-alerts><div class="skeleton"></div></div></section>
    <section class="card" style="margin-bottom:16px"><div class="card-head"><h3 class="card-title">로그 흐름</h3></div>
      <div class="card-body" data-hist><div class="skeleton" style="height:150px"></div></div></section>
    <div class="grid" style="margin-bottom:16px">
      ${[['category', '분류'], ...PEERS[kind].map(([f, , t]) => [f, t])].map(([f, t]) => html`
        <section class="card" style="grid-column: span 4"><div class="card-head"><h3 class="card-title">${t}</h3></div>
          <div class="card-body" data-top="${f}"><div class="skeleton" style="height:120px"></div></div></section>`)}
    </div>
    <section class="card"><div class="card-head"><h3 class="card-title">최근 로그 <span class="muted" style="font-weight:400">${RECENT}건</span></h3></div>
      <div class="table-wrap"><table class="table ev-table"><thead>${EVENT_HEAD}</thead><tbody data-events>
        <tr><td colspan="6"><div class="skeleton"></div></td></tr></tbody></table></div></section>`;

  // 행 클릭은 한 번만 붙인다 — load 마다 붙이면 기간을 바꾸거나 알림을 처리한 뒤 한 번 누를 때 지난 목록의 로그까지 열려
  // 보지 않은 로그의 열람 기록(events.view, 고칠 수 없음)이 남았다(검토에서 재현)
  bindRows(root.querySelector('[data-events]'), (k) => recent[Number(k)]);
  bindAlertRows(root.querySelector('[data-alerts]'), () => load());

  async function load() {
    const my = ++token;
    const stale = () => !alive || my !== token;
    recent = [];
    let data;
    try {
      data = await api.get(`/api/entities/${kind}/${encodeURIComponent(value)}`, { since });
    } catch (err) {
      if (!stale()) root.querySelector('[data-alerts]').innerHTML = errorBox(err);
      return;
    }
    if (stale()) return;
    const q = { query: data.query, since };
    root.querySelector('[data-title]').textContent = data.value;   // 계정은 표기 통일 열쇠로 바뀐다
    root.querySelector('[data-search]').href = `#/events?${qs(q)}`;
    renderAgent(data.agent);
    renderAlerts(data);
    const open = data.alerts.filter((a) => a.status !== 'resolved').length;
    root.querySelector('[data-stats]').innerHTML = html`
      ${stat('알림', data.alerts.length, data.truncated ? '건 넘음' : '건', `해결 안 됨 ${fmtNum(open)}건`)}
      <section class="card" style="grid-column: span 4"><div class="card-body"><div class="stat"><div class="stat-meta">로그</div>
        <div class="stat-value" data-count>…</div></div></div></section>
      <section class="card" style="grid-column: span 4"><div class="card-body"><div class="stat"><div class="stat-meta">경고 이상</div>
        <div class="stat-value" data-warn>…</div></div></div></section>`;
    // 로그 쪽은 서로 기다리지 않는다 — 하나가 시간 초과여도 나머지는 그린다
    const part = async (fn, box) => {
      try { await fn(); } catch (err) { if (!stale() && box) box.innerHTML = errorBox(err); }
    };
    part(async () => {
      const [all, warn] = await Promise.all([api.get('/api/stats/count', q), api.get('/api/stats/count', { ...q, query: `${data.query} level:심각,오류,경고` })]);
      if (stale()) return;
      root.querySelector('[data-count]').innerHTML = html`${fmtNum(all.current)}<small>건</small>`;
      root.querySelector('[data-warn]').innerHTML = html`${fmtNum(warn.current)}<small>건</small>`;
    }, root.querySelector('[data-stats]'));
    part(async () => {
      const series = await api.get('/api/stats/timeseries', { ...q, group: 'level', buckets: 48, tz_offset: tzOffset() });
      if (stale()) return;
      const colors = seriesColors('level', series.series.map((s) => s.key));
      const ser = series.series.map((s) => ({ key: s.key, label: seriesLabel('level', s.key), color: colors[s.key], values: s.values, total: s.total }));
      const hist = root.querySelector('[data-hist]');
      hist.innerHTML = html`${legend(ser)}<div data-chart></div>`;
      columnChart(hist.querySelector('[data-chart]'), { buckets: series.buckets, intervalSec: series.interval_sec, series: [...ser].reverse(), height: 130 });
    }, root.querySelector('[data-hist]'));
    for (const [field, peer] of [['category', null], ...PEERS[kind].map(([f, k]) => [f, k])]) {
      const box = root.querySelector(`[data-top="${field}"]`);
      part(async () => {
        const top = await api.get('/api/stats/top', { ...q, field, limit: 8 });
        if (stale()) return;
        barList(box, top.items.map((t) => ({ label: field === 'category' ? categoryLabel(t.value) : t.value, value: t.n, raw: t.value })),
          (row) => { location.hash = peer ? entityHash(peer, row.raw) : `#/events?${qs({ ...q, query: `${data.query} category:${row.raw}` })}`; });
      }, box);
    }
    part(async () => {
      const page = await api.get('/api/events', { ...q, limit: RECENT });
      if (stale()) return;
      recent = page.items;
      root.querySelector('[data-events]').innerHTML = page.items.length ? html`${page.items.map((ev, i) => eventRow(ev, i))}`
        : html`<tr><td colspan="6" class="empty">이 기간에 로그가 없습니다</td></tr>`;
    }, root.querySelector('[data-events]'));
  }

  function stat(label, n, unit, meta) {
    return html`<section class="card" style="grid-column: span 4"><div class="card-body"><div class="stat"><div class="stat-meta">${label}</div>
      <div class="stat-value">${fmtNum(n)}<small>${unit}</small></div><div class="stat-meta">${meta}</div></div></div></section>`;
  }

  function renderAgent(agent) {
    const box = root.querySelector('[data-agent]');
    box.innerHTML = agent ? html`<div class="hint-box" style="margin-bottom:16px;display:flex;gap:6px 18px;flex-wrap:wrap;align-items:center">
      ${statusBadge(agent.status)}<span>마지막 수신 <b>${fmtRelative(agent.last_seen)}</b></span>
      <span class="muted">처음 수신 ${fmtTime(agent.first_seen, { seconds: false })}</span>
      ${agent.last_ip ? html`<span>보낸 곳 IP <a href="${entityHash('ip', agent.last_ip)}">${agent.last_ip}</a></span>` : ''}
      <a href="#/agents">수집 PC 화면 →</a></div>` : '';
  }

  function renderAlerts(data) {
    const box = root.querySelector('[data-alerts]');
    root.querySelector('[data-alert-note]').textContent = data.truncated ? `최근 ${fmtNum(data.alerts.length)}건까지` : '';
    if (!data.alerts.length) {
      box.innerHTML = html`<div class="empty">이 기간에 이 ${ENTITY_LABELS[kind]}가 걸린 알림이 없습니다</div>`;
      return;
    }
    box.innerHTML = alertRows(data.alerts);
  }

  root.querySelectorAll('[data-period] button').forEach((b) => b.addEventListener('click', () => {
    since = b.dataset.v;
    root.querySelectorAll('[data-period] button').forEach((x) => x.classList.toggle('on', x === b));
    replaceParams(`entity/${kind}/${encodeURIComponent(value)}`, { since });
    load();
  }));
  load();
  return () => { alive = false; };
}
