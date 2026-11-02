// 이벤트 검색 화면: 필터(검색 문장) → 시간대 분포 → 결과 표 (더 보기).
// 옛 링크(host=…&q=a|b)로 들어오면 문장으로 접어 주소를 바꾼다 (filterState). 같은 주소 = 같은 조건.
import * as api from '../api.js';
import { columnChart, legend, seriesColors, seriesLabel } from '../charts.js';
import { openEvent, setSearchContext } from '../drawer.js';
import { EVENT_HEAD, bindRows, eventRow } from '../eventtable.js';
import { filterBar, filterState } from '../filterbar.js';
import { exportCsv } from '../exportcsv.js';
import { addTerm, parseTerms } from '../querylang.js';
import { errorBox, fmtDuration, fmtNum, fmtTime, html, replaceParams, tzOffset } from '../util.js';

// 로그온 세션 (B-63): LogonType → 방식
const LOGON_TYPES = { 2: '대화형', 3: '네트워크', 4: '배치', 5: '서비스', 7: '잠금 해제', 8: '네트워크(평문)', 9: '새 자격 증명', 10: '원격 데스크톱', 11: '캐시' };

// 통계 탭 (B-62): 묶을 칸. 원본 필드는 f.<경로> 를 직접 적는다(예: f.EventData.LogonType)
const STATS_FIELDS = [['user', '사용자'], ['host', 'PC'], ['ip', 'IP'], ['event_id', '이벤트 ID'], ['category', '분류'],
  ['source', '소스'], ['channel', '채널'], ['provider', '공급자'], ['level', '수준']];
const FIELD_LABEL = Object.fromEntries(STATS_FIELDS);
const INT_FIELDS = new Set(['event_id', 'level']);

export async function mount(root, params) {
  const initial = filterState({ since: '24h', ...params }, { showTime: true });
  let state = initial.state;
  if (initial.changed) replaceParams('events', state);
  let bar = null;        // 필터 막대는 PC·채널 목록을 받은 뒤에 생긴다 — 그 전의 조작은 state 로 받고 생기면 맞춘다
  let disposed = false;
  let loadedAt = null;   // 지금 보이는 결과를 불러온 시각 ('링크 복사'가 그 구간으로 고정)
  let items = [];
  let cursor = null;
  let token = 0;

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">이벤트 검색</h1>
        <p class="page-sub">조건을 고르면 바로 검색됩니다. 막대를 누르면 그 시간대만, 행을 누르면 원본 데이터를 봅니다.</p></div>
      <div class="toolbar"><span class="muted num" data-count></span></div>
    </div>
    <div data-filter></div>
    <section class="card" style="margin-bottom:14px"><div class="card-body" data-hist><div class="skeleton" style="height:150px"></div></div></section>
    <div class="toolbar" style="margin-bottom:10px;justify-content:space-between">
      <div class="seg" data-tab><button data-v="list" class="on">목록</button><button data-v="stats">통계</button><button data-v="sessions">세션</button></div>
      <button class="btn sm" type="button" data-csv>CSV 내려받기</button>
    </div>
    <section class="card" data-list>
      <div class="table-wrap"><table class="table ev-table"><thead>${EVENT_HEAD}</thead><tbody data-rows></tbody></table></div>
      <div data-foot style="padding:12px;text-align:center"></div>
    </section>
    <section class="card" data-stats hidden>
      <div class="card-body">
        <p class="muted" style="font-size:12.5px;margin:0 0 10px">지금 조건의 로그를 칸 조합으로 묶어 건수·처음/마지막 시각·서로 다른 값 수를 봅니다
          (예: 사용자 + 서로 다른 PC 수 = 계정별 로그온한 PC 수, IP + 서로 다른 사용자 수 = IP 별 시도한 계정 수). 행을 누르면 그 조합으로 좁힌 목록.</p>
        <div class="toolbar" style="flex-wrap:wrap;gap:8px">
          ${[0, 1, 2].map((i) => html`<input class="input" list="stats-fields" data-by="${i}" placeholder="${i ? '더 묶을 칸 (선택)' : '묶을 칸 (예: 사용자)'}" style="width:170px">`)}
          <input class="input" list="stats-fields" data-distinct placeholder="서로 다른 값 수 (선택)" style="width:190px">
          <button class="btn primary sm" type="button" data-stats-run>보기</button>
        </div>
        <datalist id="stats-fields">${STATS_FIELDS.map(([v, l]) => html`<option value="${v}">${l}</option>`)}</datalist>
        <div data-stats-out style="margin-top:12px"></div>
      </div>
    </section>
    <section class="card" data-sessions hidden>
      <div class="card-body">
        <p class="muted" style="font-size:12.5px;margin:0 0 10px">지금 조건의 Windows 로그온(4624)마다 같은 PC 의 로그오프(4634·4647)를 로그온 ID 로 짝지어
          누가·언제·어느 PC 에·어떤 방식으로·얼마나 접속했는지 봅니다. 로그오프가 없으면 아직 접속 중이거나, 기록이 빠졌거나, 찾는 시간을 넘었습니다.
          검색 문장에 다른 이벤트 ID 조건이 있으면 결과가 없습니다. 행을 누르면 로그온 로그의 상세.</p>
        <div class="toolbar" style="gap:8px;flex-wrap:wrap">
          <label class="muted" style="font-size:13px">로그오프를 찾는 시간 <select class="select" data-sess-hours>
            <option value="24">하루</option><option value="72">사흘</option><option value="168">7일</option></select></label>
          <button class="btn primary sm" type="button" data-sess-run>보기</button></div>
        <div data-sess-out style="margin-top:12px"></div>
      </div>
    </section>`;

  const rowsEl = root.querySelector('[data-rows]');
  const footEl = root.querySelector('[data-foot]');
  bindRows(rowsEl, (k) => items[Number(k)]);

  function renderFoot() {
    footEl.innerHTML = cursor
      ? html`<button class="btn" data-more>더 보기</button>`
      : html`<span class="muted">${items.length ? '마지막 결과입니다' : '조건에 맞는 이벤트가 없습니다'}</span>`;
    footEl.querySelector('[data-more]')?.addEventListener('click', loadMore);
  }

  async function loadMore() {
    const my = token;
    let page;
    try {
      page = await api.get('/api/events', { ...state, limit: 100, cursor });
    } catch (err) {
      if (my !== token) return;
      // 이미 받은 결과는 두고 안내 + 다시 시도 단추 (뒤 페이지일수록 오래 걸려 시간 상한에 걸릴 수 있다)
      footEl.innerHTML = html`${errorBox(err)}<button class="btn" data-more>다시 시도</button>`;
      footEl.querySelector('[data-more]').addEventListener('click', loadMore);
      return;
    }
    if (my !== token) return;
    const start = items.length;
    items = items.concat(page.items);
    cursor = page.next_cursor;
    rowsEl.insertAdjacentHTML('beforeend', String(html`${page.items.map((ev, i) => eventRow(ev, start + i))}`));
    renderFoot();
  }

  // 결과를 못 얻었을 때 이전 검색의 건수·막대가 새 조건의 결과처럼 남지 않게 비운다
  function clearResults() {
    root.querySelector('[data-count]').textContent = '';
    root.querySelector('[data-hist]').innerHTML = '<div class="empty">결과를 불러오지 못했습니다.</div>';
  }

  async function load() {
    const my = ++token;
    loadedAt = new Date();
    rowsEl.innerHTML = '';
    // 문장이 틀렸으면 서버에 묻지 않는다 (입력 칸이 틀린 곳을 보여 준다) — 옛 링크·손으로 고친 주소로 들어온 경우
    try { parseTerms(state.query ?? ''); } catch {
      clearResults();
      footEl.innerHTML = html`<span class="muted">검색 문장을 고치면 결과가 보입니다.</span>`;
      return;
    }
    footEl.innerHTML = '<div class="skeleton" style="height:120px"></div>';
    try {
      const [series, count, page] = await Promise.all([
        api.get('/api/stats/timeseries', { ...state, group: 'level', buckets: 60, tz_offset: tzOffset() }),
        api.get('/api/stats/count', state),
        api.get('/api/events', { ...state, limit: 100 }),
      ]);
      if (my !== token) return;
      root.querySelector('[data-count]').textContent = `${fmtNum(count.current)}건`;

      const colors = seriesColors('level', series.series.map((s) => s.key));
      const ser = series.series.map((s) => ({ key: s.key, label: seriesLabel('level', s.key), color: colors[s.key], values: s.values, total: s.total }));
      const hist = root.querySelector('[data-hist]');
      hist.innerHTML = html`${legend(ser)}<div data-chart></div>`;
      columnChart(hist.querySelector('[data-chart]'), {
        buckets: series.buckets, intervalSec: series.interval_sec, series: [...ser].reverse(), height: 150,
        onSelect: (range) => { state = { ...state, ...range }; replaceParams('events', state); bar?.setState(state); load(); },
      });

      items = page.items;
      cursor = page.next_cursor;
      rowsEl.innerHTML = items.length
        ? html`${items.map((ev, i) => eventRow(ev, i))}`
        : html`<tr><td colspan="6" class="empty" style="padding:48px 16px;">조건에 일치하는 이벤트가 없습니다. 상단 필터를 조정해보세요.</td></tr>`;
      renderFoot();
    } catch (err) {
      if (my !== token) return;
      clearResults();
      footEl.innerHTML = errorBox(err);
      bar?.showServerError(err);   // 문장 오류면 입력 칸에서 틀린 곳을 칠한다
    }
  }

  // ---- 목록 | 통계 탭, CSV (B-62)
  let tab = 'list';
  let lastStats = null;   // 지금 보이는 통계의 by·distinct (CSV 가 같은 표를 받게)
  const statsOut = root.querySelector('[data-stats-out]');
  root.querySelectorAll('[data-tab] button').forEach((b) => b.addEventListener('click', () => {
    tab = b.dataset.v;
    root.querySelectorAll('[data-tab] button').forEach((x) => x.classList.toggle('on', x === b));
    root.querySelector('[data-list]').hidden = tab !== 'list';
    root.querySelector('[data-stats]').hidden = tab !== 'stats';
    root.querySelector('[data-sessions]').hidden = tab !== 'sessions';
  }));
  root.querySelector('[data-csv]').addEventListener('click', () => {
    if (tab === 'stats' && lastStats) exportCsv('/api/stats/group', { ...state, ...lastStats }, { what: '통계 표' });
    else exportCsv('/api/events', state, { what: '로그 목록(최대 1만 건)' });
  });
  const fieldOf = (text) => {
    const v = text.trim();
    return STATS_FIELDS.find(([key, label]) => v === key || v === label)?.[0] ?? v;
  };
  async function runStats() {
    const by = [...root.querySelectorAll('[data-by]')].map((i) => fieldOf(i.value)).filter(Boolean);
    const distinct = fieldOf(root.querySelector('[data-distinct]').value);
    if (!by.length) { statsOut.innerHTML = html`<p class="muted">묶을 칸을 하나 이상 고르세요.</p>`; return; }
    statsOut.innerHTML = '<div class="skeleton" style="height:120px"></div>';
    let res;
    try {
      res = await api.get('/api/stats/group', { ...state, by: by.join(','), distinct, limit: 200 });
    } catch (err) {
      statsOut.innerHTML = errorBox(err);
      return;
    }
    lastStats = { by: by.join(','), distinct };
    const label = (f) => FIELD_LABEL[f] || f;
    statsOut.innerHTML = res.items.length ? html`
      <div class="table-wrap"><table class="table"><thead><tr>${res.by.map((f) => html`<th>${label(f)}</th>`)}<th class="r">건수</th>
        ${res.distinct.map((f) => html`<th class="r">서로 다른 ${label(f)}</th>`)}<th>처음</th><th>마지막</th></tr></thead>
        <tbody>${res.items.map((it, n) => html`<tr data-stats-row="${n}" title="이 조합으로 좁힌 목록 보기" style="cursor:pointer">
          ${it.keys.map((k) => html`<td class="nowrap">${k ?? html`<span class="muted">(없음)</span>`}</td>`)}
          <td class="r num"><b>${fmtNum(it.n)}</b></td>${it.distinct.map((d) => html`<td class="r num">${fmtNum(d)}</td>`)}
          <td class="nowrap muted">${fmtTime(it.first_ts)}</td><td class="nowrap">${fmtTime(it.last_ts)}</td></tr>`)}</tbody></table></div>
      ${res.truncated ? html`<p class="muted" style="font-size:12.5px">건수가 많은 ${fmtNum(res.limit)}개 조합만 보입니다 — 조건을 좁히거나 CSV(최대 1천 행)로 받으세요.</p>` : ''}`
      : html`<p class="muted">조건에 맞는 로그가 없습니다.</p>`;
    statsOut.querySelectorAll('[data-stats-row]').forEach((tr) => tr.addEventListener('click', () => {
      // 그 조합으로 좁힌 목록: 값이 있는 칸만 조건으로 (빈 값을 고르는 문장은 아직 없다 — B-29)
      const it = res.items[Number(tr.dataset.statsRow)];
      let text = bar?.query ?? state.query ?? '';
      res.by.forEach((f, i) => {
        const v = it.keys[i];
        if (v == null || v === '') return;
        const term = f.startsWith('f.') ? { key: 'f', path: f.slice(2).split('.'), values: [v] }
          : { key: f, values: [INT_FIELDS.has(f) ? Number(v) : v] };
        text = addTerm(text, term);
      });
      root.querySelector('[data-tab] button[data-v="list"]').click();
      if (bar) bar.applySentence(text); else { state = { ...state, query: text }; replaceParams('events', state); load(); }
    }));
  }
  root.querySelector('[data-stats-run]').addEventListener('click', runStats);

  // ---- 세션 탭 (B-63)
  const sessOut = root.querySelector('[data-sess-out]');
  async function runSessions() {
    sessOut.innerHTML = '<div class="skeleton" style="height:120px"></div>';
    let res;
    try {
      res = await api.get('/api/stats/sessions', { ...state, max_hours: root.querySelector('[data-sess-hours]').value, limit: 200 });
    } catch (err) {
      sessOut.innerHTML = errorBox(err);
      return;
    }
    const kind = (t) => (t == null ? '–' : LOGON_TYPES[t] ? `${LOGON_TYPES[t]} (${t})` : String(t));
    sessOut.innerHTML = res.items.length ? html`
      <div class="table-wrap"><table class="table"><thead><tr><th>로그온</th><th>PC</th><th>사용자</th><th>방식</th><th>출발지 IP</th>
        <th>로그오프</th><th class="r">길이</th></tr></thead>
        <tbody>${res.items.map((s, n) => html`<tr data-sess-row="${n}" title="로그온 로그 상세" style="cursor:pointer">
          <td class="nowrap">${fmtTime(s.ts)}</td><td class="nowrap">${s.host}</td><td class="nowrap">${s.username ?? '–'}</td>
          <td class="nowrap">${kind(s.logon_type)}</td><td class="nowrap num">${s.src_ip ?? '–'}</td>
          <td class="nowrap">${s.end_ts ? html`${fmtTime(s.end_ts)} <span class="muted">${s.end_event === 4647 ? '사용자가 로그오프' : ''}</span>`
            : html`<span class="muted">로그오프 기록 없음</span>`}</td>
          <td class="r num">${s.duration_sec == null ? '–' : fmtDuration(s.duration_sec)}</td></tr>`)}</tbody></table></div>
      ${res.truncated ? html`<p class="muted" style="font-size:12.5px">최근 로그온 ${fmtNum(res.limit)}개만 보입니다 — 기간이나 조건을 좁히세요.</p>` : ''}`
      : html`<p class="muted">조건에 맞는 로그온(4624)이 없습니다.</p>`;
    sessOut.querySelectorAll('[data-sess-row]').forEach((tr) => tr.addEventListener('click', () => openEvent(res.items[Number(tr.dataset.sessRow)].id)));
  }
  root.querySelector('[data-sess-run]').addEventListener('click', runSessions);

  filterBar(root.querySelector('[data-filter]'), state, {
    onChange: (next) => { state = next; replaceParams('events', state); load(); },
    loadedAt: () => loadedAt,
  }).then((b) => {
    if (disposed) { b.destroy(); return; }
    bar = b;
    b.setState(state);   // 막대가 생기기 전에 막대 그래프로 구간을 골랐을 수 있다
  });
  // 상세 패널의 '좁히기·제외'가 이 화면의 문장을 고치게 (막대가 아직 없으면 state 로 바로)
  setSearchContext({
    query: () => bar?.query ?? state.query ?? '',
    apply: (text) => {
      if (bar) { bar.applySentence(text); return; }
      state = { ...state, query: text };
      replaceParams('events', state);
      load();
    },
  });
  load();
  return () => { disposed = true; token++; bar?.destroy(); setSearchContext(null); };
}
