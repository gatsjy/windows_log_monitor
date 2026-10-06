// 대시보드 화면. config/dashboards/<이름>.json 을 읽어 위젯을 12칸 격자에 배치한다.
//
// 실시간 동작 방식:
//   1) 처음과 refresh_sec(기본 60초)마다 위젯별로 API 를 조회해 정확한 값으로 맞춘다 (전체 동기화).
//   2) 그 사이에는 /api/live (SSE) 로 들어오는 새 이벤트를 1초 단위로 모아서
//      각 위젯의 live(body, cfg, ctx, events) 로 넘긴다 → 숫자/막대/표가 제자리에서 갱신된다.
//   DB 를 몇 초마다 다시 조회하지 않으므로 화면을 여러 개 띄워도 부하가 거의 없다.
import * as api from '../api.js';
import { can } from '../auth.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { levelIcon } from '../levels.js';
import { matchesQuery } from '../livefilter.js';
import { WIDGETS } from '../widgets/index.js';
import { TIME_RANGES, errorBox, fmtNum, html, navigate, replaceParams, store } from '../util.js';

const FLUSH_MS = 1000; // 실시간 이벤트를 모아서 화면에 반영하는 주기

const REFERENCE = html`
  <div class="section-title">위젯 종류 (type)</div>
  <ul class="ref-list">
    <li><code>stat</code> 숫자 카드 — <code>metric</code>: count | agents | rate, <code>up_is_good</code>, <code>color</code></li>
    <li><code>timeseries</code> 시간대별 막대 — <code>group</code>: level | channel | host | source | event_id | f.경로</li>
    <li><code>top</code> 상위 값 — <code>field</code>: host | event_id | provider | channel | level | f.경로, <code>limit</code></li>
    <li><code>events</code> 최근 이벤트 표 — <code>limit</code></li>
    <li><code>hosts</code> PC 현황 카드</li>
    <li><code>text</code> 안내문 — <code>text</code></li>
    <li><code>alerts</code> 최근 알림 — <code>limit</code></li>
  </ul>
  <div class="section-title">공통 옵션</div>
  <ul class="ref-list">
    <li><code>title</code> 제목, <code>w</code> 너비(1~12칸)</li>
    <li><code>query</code> 조건 — <code>{"level":"1,2", "host":"WEB-01", "channel":"Security", "event_id":"4625", "q":"timeout", "f.StringInserts.5":"admin"}</code></li>
    <li><code>since</code> 이 위젯만 다른 기간 (예: "7d")</li>
  </ul>
  <div class="section-title">대시보드 옵션</div>
  <ul class="ref-list">
    <li><code>time_range</code> 기본 기간, <code>refresh_sec</code> 전체 동기화 주기(초, 기본 60). 그 사이에는 실시간 스트림으로 갱신</li>
  </ul>
  <p class="muted" style="font-size:12.5px">파일 위치: <code>config/dashboards/&lt;이름&gt;.json</code> — 편집기로 직접 고쳐도 된다.</p>`;

function iconFor(cfg) {
  const level = cfg.icon_level ?? Math.min(...String(cfg.query?.level || '').split(',').filter(Boolean).map(Number));
  return Number.isFinite(level) && level <= 3 ? levelIcon(level) : '';
}

export async function mount(root, params, sub) {
  const name = sub || 'overview';
  let doc;
  let timer;
  let since = params.since;
  let source = null;
  let liveOn = store.get('wlm.dashboard.live', true);
  let pending = [];
  let flushTimer = null;
  const arrivals = []; // [수신 시각 ms, 건수] — 분당 속도

  async function load() {
    const [list, dashboard] = await Promise.all([api.get('/api/dashboards'), api.get(`/api/dashboards/${name}`)]);
    doc = dashboard;
    since ||= doc.time_range || '24h';
    render(list.items);
  }

  const ctx = {
    query: (cfg) => ({ since: cfg.since || since, ...(cfg.query || {}) }),
    drill: (q) => navigate('events', { since, ...q }),
    /** 위젯이 실시간으로 맞출 수 없는 변화(새 구간, 새 PC 등)를 만나면 그 위젯만 다시 조회 */
    resync: (body) => renderOne(Number(body.dataset.w)),
    ratePerMin: () => {
      const cutoff = Date.now() - 60_000;
      return arrivals.filter(([t]) => t >= cutoff).reduce((a, [, n]) => a + n, 0);
    },
  };

  // ------------------------------------------------------------ 실시간
  function setLiveBadge(state) {
    const el = root.querySelector('[data-live]');
    if (!el) return;
    const text = !liveOn ? '실시간 꺼짐'
      : state === 'error' ? '재연결 중…'
        : state === 'connecting' ? '연결 중…'
          : `실시간 · ${fmtNum(ctx.ratePerMin())}건/분`;
    const dot = !liveOn || state === 'connecting' ? 'off' : state === 'error' ? 'bad' : '';
    el.innerHTML = html`<span class="pulse ${dot}"></span>${text}`;
    el.title = liveOn ? '클릭하면 실시간 갱신을 멈춥니다' : '클릭하면 실시간 갱신을 켭니다';
  }

  function connectLive() {
    source?.close();
    source = null;
    if (!liveOn) { setLiveBadge('off'); return; }
    setLiveBadge('connecting');
    source = new EventSource('/api/live');
    source.onopen = () => setLiveBadge('ok');
    source.onerror = () => setLiveBadge('error');
    source.addEventListener('events', (e) => {
      const batch = JSON.parse(e.data);
      arrivals.push([Date.now(), batch.length]);
      pending = pending.concat(batch);
      flushTimer ??= setTimeout(flush, FLUSH_MS);
    });
  }

  function flush() {
    flushTimer = null;
    const batch = pending;
    pending = [];
    const cutoff = Date.now() - 60_000;
    while (arrivals.length && arrivals[0][0] < cutoff) arrivals.shift();
    setLiveBadge('ok');
    if (document.hidden) return; // 안 보이는 동안은 건너뛰고, 다시 보일 때 동기화가 맞춘다
    (doc.widgets || []).forEach((cfg, i) => {
      const widget = WIDGETS[cfg.type];
      const body = root.querySelector(`[data-w="${i}"]`);
      if (!widget?.live || !body || body._syncing) return;
      const q = ctx.query(cfg);
      try {
        widget.live(body, cfg, ctx, batch.filter((ev) => matchesQuery(q, ev)));
      } catch (err) {
        console.warn('위젯 실시간 갱신 실패', cfg, err);
      }
    });
  }

  function render(dashboards) {
    const refresh = doc.refresh_sec ?? 60;
    root.innerHTML = html`
      <div class="page-head">
        <div>
          <h1 class="page-title">${doc.title || name}</h1>
          ${doc.description ? html`<p class="page-sub">${doc.description}</p>` : ''}
        </div>
        <div class="toolbar">
          <select class="select" data-dash aria-label="대시보드">
            ${dashboards.map((d) => html`<option value="${d.name}" ${d.name === name ? 'selected' : ''}>${d.title}</option>`)}
          </select>
          <select class="select" data-since aria-label="기간">
            ${TIME_RANGES.map(([v, label]) => html`<option value="${v}" ${v === since ? 'selected' : ''}>${label}</option>`)}
          </select>
          <button class="live-badge" data-live type="button"></button>
          <button class="btn" data-refresh title="${refresh ? `${refresh}초마다 전체 동기화 (그 사이는 실시간 갱신)` : ''}">
            <svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5"/></svg>새로고침</button>
          ${can('dashboards.edit') ? html`<button class="btn" data-edit><svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z"/></svg>편집</button>` : ''}
        </div>
      </div>
      <div class="grid">${(doc.widgets || []).map((w, i) => html`
        <section class="card" style="grid-column: span ${Math.min(12, Math.max(1, w.w || 12))}">
          ${w.title ? html`<div class="card-head"><h2 class="card-title">${iconFor(w)}${w.title}</h2></div>` : ''}
          <div class="card-body ${WIDGETS[w.type]?.flush ? 'flush' : ''}" data-w="${i}"><div class="skeleton" style="height:${w.type === 'stat' ? 70 : 140}px"></div></div>
        </section>`)}
      </div>`;

    root.querySelector('[data-dash]').addEventListener('change', (e) => navigate(`dashboard/${e.target.value}`));
    root.querySelector('[data-since]').addEventListener('change', (e) => {
      since = e.target.value;
      replaceParams(`dashboard/${name}`, { since });
      renderWidgets();
    });
    root.querySelector('[data-refresh]').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const svg = btn.querySelector('svg');
      svg?.classList.add('spin');
      try {
        await renderWidgets();
      } finally {
        setTimeout(() => svg?.classList.remove('spin'), 450);
      }
    });
    root.querySelector('[data-edit]')?.addEventListener('click', openEditor);
    root.querySelector('[data-live]').addEventListener('click', () => {
      liveOn = !liveOn;
      store.set('wlm.dashboard.live', liveOn);
      connectLive();
      if (liveOn) renderWidgets(); // 꺼져 있던 동안의 변화를 맞춘다
    });

    renderWidgets();
    connectLive();
    clearInterval(timer);
    if (refresh > 0) timer = setInterval(() => { if (!document.hidden) renderWidgets(); }, refresh * 1000);
  }

  async function renderOne(i) {
    const cfg = doc.widgets?.[i];
    const body = root.querySelector(`[data-w="${i}"]`);
    if (!cfg || !body || body._syncing) return;
    const widget = WIDGETS[cfg.type];
    if (!widget) {
      body.innerHTML = errorBox(new Error(`알 수 없는 위젯 type: ${cfg.type}`));
      return;
    }
    body._syncing = true;
    try {
      await widget.render(body, cfg, ctx);
    } catch (err) {
      body._live = null;
      body.innerHTML = errorBox(err);
    } finally {
      body._syncing = false;
    }
  }

  function renderWidgets() {
    (doc.widgets || []).forEach((_, i) => renderOne(i));
  }

  function openEditor() {
    const body = openDrawer({ title: '대시보드 편집', subtitle: `config/dashboards/${name}.json` });
    body.innerHTML = html`
      <textarea class="input editor" spellcheck="false" data-json>${JSON.stringify(doc, null, 2)}</textarea>
      <div class="toolbar" style="margin:10px 0">
        <button class="btn primary" data-save>저장</button>
        <input class="input" data-newname placeholder="다른 이름으로 저장 (영문 소문자)" style="width:220px">
        <button class="btn" data-saveas>새 대시보드로 저장</button>
      </div>
      <div data-msg></div>
      ${REFERENCE}`;
    const msg = body.querySelector('[data-msg]');
    const save = async (target) => {
      let parsed;
      try {
        parsed = JSON.parse(body.querySelector('[data-json]').value);
      } catch (err) {
        msg.innerHTML = errorBox(new Error(`JSON 문법 오류: ${err.message}`));
        return;
      }
      try {
        await api.put(`/api/dashboards/${target}`, parsed);
        closeDrawer();
        if (target === name) { doc = parsed; await load(); } else navigate(`dashboard/${target}`);
      } catch (err) {
        msg.innerHTML = errorBox(err);
      }
    };
    body.querySelector('[data-save]').addEventListener('click', () => save(name));
    body.querySelector('[data-saveas]').addEventListener('click', () => {
      const target = body.querySelector('[data-newname]').value.trim();
      if (target) save(target);
    });
  }

  root.innerHTML = '<div class="skeleton" style="height:40px;margin-bottom:16px"></div><div class="skeleton" style="height:320px"></div>';
  try {
    await load();
  } catch (err) {
    root.innerHTML = errorBox(err);
  }
  return () => {
    clearInterval(timer);
    clearTimeout(flushTimer);
    source?.close();
  };
}
