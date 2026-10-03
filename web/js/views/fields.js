// 필드 탐색: 에이전트가 보내는 원본 JSON 에 어떤 필드가 있고, 실제로 어떤 값이 들어오는지.
import * as api from '../api.js';
import { barList } from '../charts.js';
import { fieldDoc } from '../catalog.js';
import { sourceLabel } from '../levels.js';
import { errorBox, fmtCompact, fmtNum, fmtRelative, fmtTime, html, navigate, replaceParams } from '../util.js';

export async function mount(root, params) {
  let all = [];
  let source = params.source || '';
  let search = '';
  let selected = params.path ? `${params.source}|${params.path}` : null;
  let since = '24h';

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">필드 탐색</h1>
        <p class="page-sub">에이전트가 보내는 원본 데이터에 어떤 필드가 있는지 보여줍니다. 필드를 누르면 실제 값의 분포를 봅니다.</p></div>
    </div>
    <div class="split">
      <section class="card">
        <div class="card-head">
          <div class="seg" data-sources></div>
          <input class="input" data-search placeholder="필드 이름 찾기" style="width:180px">
        </div>
        <div class="card-body flush" data-list><div class="skeleton"></div></div>
      </section>
      <section class="card sticky-card"><div class="card-body" data-detail>
        <div class="empty">왼쪽에서 필드를 고르세요.</div></div></section>
    </div>`;

  const listEl = root.querySelector('[data-list]');
  const detailEl = root.querySelector('[data-detail]');

  function renderSources() {
    const sources = [...new Set(all.map((f) => f.source))];
    const seg = root.querySelector('[data-sources]');
    seg.innerHTML = html`<button data-v="" class="${source ? '' : 'on'}">전체</button>${sources.map((s) =>
      html`<button data-v="${s}" class="${s === source ? 'on' : ''}">${sourceLabel(s)}</button>`)}`;
    seg.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
      source = b.dataset.v;
      renderSources();
      renderList();
    }));
  }

  function renderList() {
    const rows = all.filter((f) => (!source || f.source === source) && (!search || f.path.toLowerCase().includes(search)));
    if (!rows.length) {
      listEl.innerHTML = '<div class="empty">필드가 없습니다. 아직 수집된 로그가 없을 수 있습니다.</div>';
      return;
    }
    listEl.innerHTML = html`<div class="table-wrap"><table class="table">
      <thead><tr><th>필드</th><th>타입</th><th class="r">수신</th><th>마지막</th><th>예시 값</th></tr></thead>
      <tbody>${rows.map((f) => {
        const key = `${f.source}|${f.path}`;
        return html`<tr class="clickable field-row ${key === selected ? 'sel' : ''}" data-key="${key}">
          <td class="nowrap"><span class="mono">${f.path}</span>${source ? '' : html` <span class="muted" style="font-size:11.5px">${sourceLabel(f.source)}</span>`}</td>
          <td><span class="type-tag">${f.json_type}</span></td>
          <td class="r num nowrap">${fmtCompact(f.seen)}</td>
          <td class="nowrap muted">${fmtRelative(f.last_seen)}</td>
          <td class="msg mono" title="${f.sample ?? ''}">${f.sample ?? ''}</td>
        </tr>`;
      })}</tbody></table></div>`;
    listEl.querySelectorAll('[data-key]').forEach((tr) => tr.addEventListener('click', () => {
      selected = tr.dataset.key;
      listEl.querySelectorAll('.field-row').forEach((r) => r.classList.toggle('sel', r === tr));
      renderDetail();
    }));
  }

  async function renderDetail() {
    const field = all.find((f) => `${f.source}|${f.path}` === selected);
    if (!field) return;
    replaceParams('fields', { source: field.source, path: field.path });
    const doc = fieldDoc(field.source, field.path);
    detailEl.innerHTML = html`
      <div class="toolbar" style="justify-content:space-between;margin-bottom:10px">
        <div><div class="mono" style="font-size:15px;font-weight:600">${field.path}</div>
          <div class="muted" style="font-size:12.5px">${sourceLabel(field.source)} · <span class="type-tag">${field.json_type}</span></div></div>
        <div class="seg" data-since>${[['1h', '1시간'], ['24h', '24시간'], ['7d', '7일']].map(([v, l]) =>
          html`<button data-v="${v}" class="${v === since ? 'on' : ''}">${l}</button>`)}</div>
      </div>
      ${doc ? html`<div class="hint-box" style="margin-bottom:12px">${doc}</div>` : ''}
      <dl class="kv">
        <dt>누적 수신</dt><dd class="num">${fmtNum(field.seen)}회</dd>
        <dt>처음 본 시각</dt><dd>${fmtTime(field.first_seen)}</dd>
        <dt>마지막</dt><dd>${fmtTime(field.last_seen)} (${fmtRelative(field.last_seen)})</dd>
      </dl>
      <div class="section-title">자주 나오는 값 — 누르면 그 값으로 검색</div>
      <div data-values><div class="skeleton"></div></div>`;
    detailEl.querySelectorAll('[data-since] button').forEach((b) => b.addEventListener('click', () => {
      since = b.dataset.v;
      renderDetail();
    }));
    const valuesEl = detailEl.querySelector('[data-values]');
    if (field.json_type === 'object') {
      valuesEl.innerHTML = '<div class="empty">객체 필드는 하위 필드를 선택하세요.</div>';
      return;
    }
    try {
      const data = await api.get('/api/stats/top', { field: `f.${field.path}`, source: field.source, since, limit: 15 });
      barList(valuesEl, data.items.map((it) => ({
        label: it.value == null ? '(없음)' : it.value.length > 80 ? `${it.value.slice(0, 80)}…` : it.value,
        title: it.value ?? '', value: it.n, raw: it.value,
      })), (row) => {
        if (row.raw != null) navigate('events', { since, source: field.source, [`f.${field.path}`]: row.raw });
      });
    } catch (err) {
      valuesEl.innerHTML = errorBox(err);
    }
  }

  root.querySelector('[data-search]').addEventListener('input', (e) => {
    search = e.target.value.trim().toLowerCase();
    renderList();
  });

  try {
    all = (await api.get('/api/fields')).items;
    renderSources();
    renderList();
    if (selected) renderDetail();
  } catch (err) {
    listEl.innerHTML = errorBox(err);
  }
}
