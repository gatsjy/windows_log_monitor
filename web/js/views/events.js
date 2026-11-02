// 이벤트 검색 화면: 필터(검색 문장) → 시간대 분포 → 결과 표 (더 보기).
// 옛 링크(host=…&q=a|b)로 들어오면 문장으로 접어 주소를 바꾼다 (filterState). 같은 주소 = 같은 조건.
import * as api from '../api.js';
import { columnChart, legend, seriesColors, seriesLabel } from '../charts.js';
import { closeDrawer, openDrawer, openEvent, setSearchContext } from '../drawer.js';
import { bindRows, eventHead, eventRow } from '../eventtable.js';
import { filterBar, filterState } from '../filterbar.js';
import { exportCsv } from '../exportcsv.js';
import { categoryLabel, levelLabel, sourceLabel } from '../levels.js';
import { addTerm, parseTerms } from '../querylang.js';
import { errorBox, fmtDuration, fmtNum, fmtTime, html, pushParams, replaceParams, toast, tzOffset } from '../util.js';

// 로그온 세션 (B-63): LogonType → 방식
const LOGON_TYPES = { 2: '대화형', 3: '네트워크', 4: '배치', 5: '서비스', 7: '잠금 해제', 8: '네트워크(평문)', 9: '새 자격 증명', 10: '원격 데스크톱', 11: '캐시' };

// 통계 탭 (B-62): 묶을 칸. 원본 필드는 f.<경로> 를 직접 적는다(예: f.EventData.LogonType)
const STATS_FIELDS = [['user', '사용자'], ['host', 'PC'], ['ip', 'IP'], ['event_id', '이벤트 ID'], ['category', '분류'],
  ['source', '소스'], ['channel', '채널'], ['provider', '공급자'], ['level', '수준']];
const FIELD_LABEL = Object.fromEntries(STATS_FIELDS);
const INT_FIELDS = new Set(['event_id', 'level']);
// 목록에 더 볼 열 (B-65 3단계, URL cols=): 기본 열(시각·수준·PC·분류·이벤트·메시지)에 없는 것과 원본 필드 f.<경로>. 서버도 6개까지
const COL_CHOICES = [['user', '사용자'], ['ip', 'IP'], ['channel', '채널'], ['provider', '공급자'], ['source', '소스']];
const MAX_COLS = 6;
const RAW_COL = /^f\.(?=[^\s,]*[^.\s,])[^\s,]+$/;   // 점만 있는 경로('f..')는 서버가 400 — 화면에서 먼저 막는다
const colLabel = (c) => Object.fromEntries(COL_CHOICES)[c] ?? c.replace(/^f\./, '');
function parseCols(text) {
  const ok = (c) => COL_CHOICES.some(([k]) => k === c) || RAW_COL.test(c);
  return [...new Set(String(text || '').split(',').map((c) => c.trim()).filter(ok))].slice(0, MAX_COLS);
}

export async function mount(root, params) {
  const initial = filterState({ since: '24h', ...params }, { showTime: true });
  let state = initial.state;
  let cols = parseCols(params.cols);
  const urlParams = () => ({ ...state, cols: cols.join(',') });   // 열은 검색 조건이 아니라 state 밖에 — 주소에만
  if (initial.changed) replaceParams('events', urlParams());
  let bar = null;        // 필터 막대는 PC·채널 목록을 받은 뒤에 생긴다 — 그 전의 조작은 state 로 받고 생기면 맞춘다
  let disposed = false;
  let loadedAt = null;   // 지금 보이는 결과를 불러온 시각 ('링크 복사'가 그 구간으로 고정)
  let items = [];
  let cursor = null;
  let token = 0;

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">이벤트 검색</h1>
        <p class="page-sub">조건을 고르면 바로 검색됩니다. 막대를 누르거나 끌면 그 시간대만(브라우저 '뒤로' = 이전 구간), 행을 누르면 원본 데이터를 봅니다.</p></div>
      <div class="toolbar"><button class="btn ghost sm" type="button" data-back hidden title="브라우저 '뒤로'와 같습니다">← 이전 구간</button>
        <span class="muted num" data-count></span></div>
    </div>
    <div data-filter></div>
    <section class="card" style="margin-bottom:14px"><div class="card-body" data-hist><div class="skeleton" style="height:150px"></div></div></section>
    <div class="toolbar" style="margin-bottom:10px;justify-content:space-between">
      <div class="seg" data-tab><button data-v="list" class="on">목록</button><button data-v="stats">통계</button><button data-v="sessions">세션</button><button data-v="fields">필드</button></div>
      <div class="toolbar" style="gap:6px"><button class="btn sm" type="button" data-cols title="목록에 사용자·IP·원본 필드 열 더하기">열</button>
        <button class="btn sm" type="button" data-csv>CSV 내려받기</button></div>
    </div>
    <section class="card" data-list>
      <div class="table-wrap"><table class="table ev-table"><thead data-head></thead><tbody data-rows></tbody></table></div>
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
    <section class="card" data-fields hidden>
      <div class="card-body">
        <p class="muted" style="font-size:12.5px;margin:0 0 10px" data-fields-note></p>
        <div class="field-grid" data-fields-out></div>
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
  const headEl = root.querySelector('[data-head]');
  const extraOf = (ev) => cols.map((c, j) => ({ label: colLabel(c), value: ev.cols?.[j] ?? null }));
  function renderHead() {
    headEl.innerHTML = eventHead(cols.map((c) => html`${colLabel(c)}<button type="button" class="btn ghost sm x" data-col-remove="${c}"
      aria-label="${colLabel(c)} 열 빼기" title="열 빼기">✕</button>`));
  }
  renderHead();
  headEl.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-col-remove]');
    if (b) setCols(cols.filter((c) => c !== b.dataset.colRemove));
  });
  function setCols(next) {
    cols = next;
    renderHead();
    replaceParams('events', urlParams());
    load();
  }
  // 이전 구간 (B-65): 막대로 고를 때마다 기록을 하나 쌓는다 — 뒤로 가면 화면이 그 주소로 다시 열린다
  const backBtn = root.querySelector('[data-back]');
  const updateBack = () => { backBtn.hidden = !(history.state?.zoom > 0); };
  updateBack();
  // 주소가 같아진 기록(구간을 고른 뒤 구간을 다시 해제)으로 돌아가면 hashchange 가 없어 화면이 그대로다 — 단추도 따라 맞춘다(검토에서 재현)
  window.addEventListener('popstate', updateBack);
  backBtn.addEventListener('click', () => { if (history.state?.zoom > 0) history.back(); else updateBack(); });

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
      page = await api.get('/api/events', { ...state, cols: cols.join(','), limit: 100, cursor });
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
    rowsEl.insertAdjacentHTML('beforeend', String(html`${page.items.map((ev, i) => eventRow(ev, start + i, { extra: extraOf(ev) }))}`));
    renderFoot();
  }

  // 결과를 못 얻었을 때 이전 검색의 건수·막대가 새 조건의 결과처럼 남지 않게 비운다
  function clearResults() {
    const count = root.querySelector('[data-count]');
    if (!count) return;   // 세션이 끝나 로그인 화면이 화면을 갈아 끼운 뒤 끝난 요청 (콘솔 오류로 발견)
    count.textContent = '';
    root.querySelector('[data-hist]').innerHTML = '<div class="empty">결과를 불러오지 못했습니다.</div>';
    if (tab === 'fields') renderFields();
  }

  async function load() {
    // 화면을 떠나는 중에 검색 칸이 포커스를 잃으며 확정하면 떠난 화면이 다시 불러 주소까지 바꿨다 (콘솔 오류로 발견)
    if (disposed) return;
    const my = ++token;
    loadedAt = new Date();
    rowsEl.innerHTML = '';
    // 새 조건의 결과가 오기 전(또는 실패하면) 필드 탭이 옛 조건의 값을 지금 것처럼 보이고 +/− 로 문장에 넣지 않게 (검토에서 재현)
    items = [];
    cursor = null;
    Object.keys(full).forEach((k) => delete full[k]);
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
        api.get('/api/events', { ...state, cols: cols.join(','), limit: 100 }),
      ]);
      if (my !== token || disposed) return;
      root.querySelector('[data-count]').textContent = `${fmtNum(count.current)}건`;

      const colors = seriesColors('level', series.series.map((s) => s.key));
      const ser = series.series.map((s) => ({ key: s.key, label: seriesLabel('level', s.key), color: colors[s.key], values: s.values, total: s.total }));
      const hist = root.querySelector('[data-hist]');
      hist.innerHTML = html`${legend(ser)}<div data-chart></div>`;
      columnChart(hist.querySelector('[data-chart]'), {
        buckets: series.buckets, intervalSec: series.interval_sec, series: [...ser].reverse(), height: 150,
        onSelect: (range) => { state = { ...state, ...range }; pushParams('events', urlParams()); updateBack(); bar?.setState(state); load(); },
      });

      items = page.items;
      cursor = page.next_cursor;
      Object.keys(full).forEach((k) => delete full[k]);
      if (tab === 'fields') renderFields();
      rowsEl.innerHTML = items.length
        ? html`${items.map((ev, i) => eventRow(ev, i, { extra: extraOf(ev) }))}`
        : html`<tr><td colspan="6" class="empty" style="padding:48px 16px;">조건에 일치하는 이벤트가 없습니다. 상단 필터를 조정해보세요.</td></tr>`;
      renderFoot();
    } catch (err) {
      if (my !== token || disposed) return;
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
    root.querySelector('[data-fields]').hidden = tab !== 'fields';
    if (tab === 'fields') renderFields();
  }));
  root.querySelector('[data-csv]').addEventListener('click', () => {
    if (tab === 'stats' && lastStats) exportCsv('/api/stats/group', { ...state, ...lastStats }, { what: '통계 표' });
    else exportCsv('/api/events', { ...state, cols: cols.join(',') }, { what: '로그 목록(최대 1만 건)' });
  });
  root.querySelector('[data-cols]').addEventListener('click', openCols);

  // ---- 열 고르기 (B-65 3단계)
  async function openCols() {
    const body = openDrawer({ title: '목록 열', subtitle: `기본 열 말고 더 볼 열 — ${MAX_COLS}개까지, 주소(cols=)에 남아 링크로 나눌 수 있습니다` });
    let picked = [...cols];
    const known = await api.get('/api/fields').then((r) => r.items.map((f) => `f.${f.path}`)).catch(() => []);
    const draw = () => {
      body.innerHTML = html`
        <div class="field-grid" style="grid-template-columns:repeat(auto-fill,minmax(120px,1fr))">${COL_CHOICES.map(([k, l]) => html`
          <label><input type="checkbox" data-col="${k}" ${picked.includes(k) ? 'checked' : ''}> ${l}</label>`)}</div>
        <div class="section-title">원본 필드</div>
        <div class="toolbar" style="gap:6px;flex-wrap:wrap">
          <input class="input" data-raw list="col-raw-fields" placeholder="f.EventData.LogonType" style="flex:1;min-width:200px" aria-label="원본 필드 경로">
          <button class="btn sm" type="button" data-raw-add>더하기</button></div>
        <datalist id="col-raw-fields">${known.slice(0, 300).map((p) => html`<option value="${p}"></option>`)}</datalist>
        ${picked.filter((c) => RAW_COL.test(c)).length ? html`<ul class="ref-list">${picked.filter((c) => RAW_COL.test(c)).map((c) => html`
          <li>${c} <button class="btn ghost sm" type="button" data-raw-remove="${c}">빼기</button></li>`)}</ul>` : ''}
        <p class="muted" style="font-size:12.5px">${picked.length}/${MAX_COLS}개 — 열 순서는 고른 순서입니다. 목록 머리글의 ✕ 로도 뺄 수 있습니다.</p>
        <div class="toolbar"><button class="btn primary" type="button" data-apply>적용</button><button class="btn ghost" type="button" data-clear>모두 빼기</button></div>`;
      body.querySelectorAll('[data-col]').forEach((c) => c.addEventListener('change', () => {
        picked = c.checked ? [...picked, c.dataset.col] : picked.filter((x) => x !== c.dataset.col);
        draw();
      }));
      const addRaw = () => {
        let v = body.querySelector('[data-raw]').value.trim();
        if (v && !v.startsWith('f.')) v = `f.${v}`;
        if (!RAW_COL.test(v)) { toast('원본 필드는 f.<경로> 로 적습니다 (예: f.EventData.LogonType)', { type: 'error' }); return; }
        if (!picked.includes(v)) picked = [...picked, v];
        draw();
      };
      body.querySelector('[data-raw-add]').addEventListener('click', addRaw);
      body.querySelector('[data-raw]').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addRaw(); } });
      body.querySelectorAll('[data-raw-remove]').forEach((b) => b.addEventListener('click', () => {
        picked = picked.filter((x) => x !== b.dataset.rawRemove);
        draw();
      }));
      body.querySelector('[data-clear]').addEventListener('click', () => { picked = []; draw(); });
      body.querySelector('[data-apply]').addEventListener('click', () => {
        if (picked.length > MAX_COLS) { toast(`열은 ${MAX_COLS}개까지입니다`, { type: 'error' }); return; }
        closeDrawer();
        setCols(picked);
      });
    };
    draw();
  }
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
      if (bar) bar.applySentence(text); else { state = { ...state, query: text }; replaceParams('events', urlParams()); load(); }
    }));
  }
  root.querySelector('[data-stats-run]').addEventListener('click', runStats);

  // ---- 필드 탭 (B-65): 필드마다 많은 값 — 불러온 로그 기준(바로), '전체 기준'은 서버가 지금 조건 전체로(/api/stats/top).
  // 값을 누르면 좁히기(+)·제외(−) — 실제 표기(대소문자·도메인)를 몰라 0건이 나오던 것을 줄인다
  const EVENT_KEY = { user: 'username', ip: 'src_ip' };
  const SHOW = { category: categoryLabel, level: (v) => levelLabel(Number(v)), source: sourceLabel };
  const fieldsOut = root.querySelector('[data-fields-out]');
  const full = {};   // 필드 → 서버 결과 (조건이 바뀌면 비운다)
  function topOfLoaded(field) {
    const counts = new Map();
    for (const ev of items) {
      const v = ev[EVENT_KEY[field] || field];
      if (v == null || v === '') continue;
      counts.set(v, (counts.get(v) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([value, n]) => ({ value, n }));
  }
  function renderFields() {
    root.querySelector('[data-fields-note]').textContent = `불러온 로그 ${fmtNum(items.length)}건 기준입니다 — '전체 기준'은 지금 조건의 모든 로그로 셉니다. `
      + '값의 + 는 그 값으로 좁히고, − 는 뺍니다.';
    fieldsOut.innerHTML = html`${STATS_FIELDS.map(([field, label]) => {
      const rows = full[field] ?? topOfLoaded(field);
      const total = full[field] ? null : items.length;
      return html`<div class="field-card"><div class="field-card-head"><b>${label}</b>
          ${full[field] ? html`<span class="muted">전체 기준</span>` : html`<button type="button" class="btn ghost sm" data-full="${field}">전체 기준</button>`}</div>
        ${rows.length ? html`<ul>${rows.map((r) => html`<li><span class="field-val" title="${r.value}">${SHOW[field] ? SHOW[field](r.value) : r.value}</span>
          <span class="num muted">${fmtNum(r.n)}${total ? ` · ${Math.round((r.n / total) * 100)}%` : ''}</span>
          <button type="button" class="btn ghost sm" data-narrow="${field}" data-v="${r.value}" title="이 값으로 좁히기">+</button>
          <button type="button" class="btn ghost sm" data-exclude="${field}" data-v="${r.value}" title="이 값 빼기">−</button></li>`)}</ul>`
          : html`<p class="muted" style="margin:6px 0 0">값 없음</p>`}</div>`;
    })}`;
    fieldsOut.querySelectorAll('[data-full]').forEach((b) => b.addEventListener('click', async () => {
      b.disabled = true;
      const my = token;   // 그 사이 조건이 바뀌면(막대 선택·새 검색) 늦게 온 결과를 새 조건의 '전체 기준'으로 보이지 않게
      try {
        const res = await api.get('/api/stats/top', { ...state, field: b.dataset.full, limit: 6 });
        if (my !== token || disposed) return;
        // 값이 없는 로그(syslog 의 이벤트 ID·채널 등)는 서버가 빈 값 한 줄로 센다 — +/− 가 event_id:0·channel:"" 이 되므로 뺀다
        full[b.dataset.full] = res.items.filter((i) => i.value != null && i.value !== '').slice(0, 5).map((i) => ({ value: i.value, n: i.n }));
        renderFields();
      } catch (err) {
        if (my !== token || disposed) return;
        b.disabled = false;
        b.replaceWith(Object.assign(document.createElement('span'), { className: 'tag-bad', textContent: err.message }));
      }
    }));
    const apply = (field, value, neg) => {
      if (value === '') return;
      const term = { key: field, values: [INT_FIELDS.has(field) ? Number(value) : value], ...(neg ? { neg: true } : {}) };
      const text = addTerm(bar?.query ?? state.query ?? '', term);
      root.querySelector('[data-tab] button[data-v="list"]').click();
      if (bar) bar.applySentence(text); else { state = { ...state, query: text }; replaceParams('events', urlParams()); load(); }
    };
    fieldsOut.querySelectorAll('[data-narrow]').forEach((b) => b.addEventListener('click', () => apply(b.dataset.narrow, b.dataset.v, false)));
    fieldsOut.querySelectorAll('[data-exclude]').forEach((b) => b.addEventListener('click', () => apply(b.dataset.exclude, b.dataset.v, true)));
  }

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
    onChange: (next) => { if (disposed) return; state = next; replaceParams('events', urlParams()); load(); },
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
      replaceParams('events', urlParams());
      load();
    },
  });
  load();
  return () => { disposed = true; token++; bar?.destroy(); setSearchContext(null); window.removeEventListener('popstate', updateBack); };
}
