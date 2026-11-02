// 검색 화면의 [대시보드에 추가] (B-07 1단계): 지금 검색 문장으로 위젯 하나를 만들어 고른 대시보드 맨 뒤에 붙인다.
// 서버가 파일을 읽어 덧붙인다(POST /api/dashboards/<이름>/widgets) — 옛 JSON 을 통째로 덮지 않게.
// 기간은 기본으로 대시보드의 기간을 따른다(위젯에 since 를 박으면 대시보드 기간을 바꿔도 그 위젯만 그대로라 헷갈린다).
import * as api from './api.js';
import { closeDrawer, openDrawer } from './drawer.js';
import { errorBox, html, navigate, toast } from './util.js';

const KINDS = [
  ['timeseries', '시간대별 막대', 12], ['events', '최근 로그 표', 12], ['top', '상위 값', 4], ['stat', '건수 숫자', 3],
];
const TOP_FIELDS = [['host', 'PC'], ['user', '사용자'], ['ip', 'IP'], ['event_id', '이벤트 ID'], ['channel', '채널'],
  ['provider', '공급자'], ['category', '분류'], ['source', '소스'], ['level', '수준']];
const RELATIVE = /^\d+[mhd]$/;

/** 위젯 JSON (화면·시험 공용) */
export function buildWidget({ kind, title, query, extra = {}, field, since, keepSince }) {
  const w = KINDS.find(([k]) => k === kind)?.[2] ?? 12;
  // extra: 문장으로 옮기지 못한 옛 조건(filterbar 의 '서버는 그대로 적용' 칩) — 빼면 위젯이 검색보다 넓게 센다
  const cond = { ...extra, ...(query ? { query } : {}) };
  const widget = { type: kind, title: title.trim(), w, ...(Object.keys(cond).length ? { query: cond } : {}) };
  if (kind === 'timeseries') widget.group = 'level';
  if (kind === 'events') widget.limit = 20;
  if (kind === 'top') Object.assign(widget, { field, limit: 8 });
  if (kind === 'stat') widget.metric = 'count';
  if (keepSince && RELATIVE.test(since || '')) widget.since = since;
  return widget;
}

export async function openAddToDashboard({ query = '', extra = {}, since = '', kind = 'timeseries', field = 'host' } = {}) {
  const body = openDrawer({ title: '대시보드에 추가', subtitle: '지금 검색 문장으로 위젯 하나를 만들어 대시보드 맨 뒤에 붙입니다' });
  body.innerHTML = '<div class="skeleton"></div>';
  let list;
  try {
    list = (await api.get('/api/dashboards')).items;
  } catch (err) {
    body.innerHTML = errorBox(err);
    return;
  }
  const relative = RELATIVE.test(since);
  body.innerHTML = html`
    <form class="auth-form" data-form>
      <label>대시보드<select class="select" name="dash">${list.map((d) => html`<option value="${d.name}">${d.title}</option>`)}</select></label>
      <label>위젯<select class="select" name="kind">${KINDS.map(([k, l]) => html`<option value="${k}" ${k === kind ? 'selected' : ''}>${l}</option>`)}</select></label>
      <label data-field-row ${kind === 'top' ? '' : 'hidden'}>상위 값을 볼 필드<select class="select" name="field">${TOP_FIELDS.map(([k, l]) => html`
        <option value="${k}" ${k === field ? 'selected' : ''}>${l}</option>`)}</select></label>
      <label>제목<input class="input" name="title" maxlength="80" required value="${query ? Array.from(query).slice(0, 60).join('') : '전체 로그'}"></label>
      <p class="muted" style="font-size:12.5px;margin:0">조건: <code>${query || (Object.keys(extra).length ? '' : '(조건 없음 — 모든 로그)')}</code>
        ${Object.entries(extra).map(([k, v]) => html` <span class="chip on">${k} = ${v}</span>`)}</p>
      ${relative ? html`<label class="check"><input type="checkbox" name="keep"> 이 기간(${since})으로 고정 — 끄면 대시보드의 기간을 따릅니다</label>`
        : since ? html`<p class="muted" style="font-size:12.5px;margin:0">고른 구간(절대 시각)은 저장하지 않고 대시보드의 기간을 따릅니다.</p>` : ''}
      <div class="toolbar"><button class="btn primary" type="submit">추가</button></div>
      <div data-msg></div>
    </form>`;
  const form = body.querySelector('[data-form]');
  const f = form.elements;   // form.title 은 폼 자신의 title 속성이다 — 칸은 elements 로
  f.kind.addEventListener('change', () => { form.querySelector('[data-field-row]').hidden = f.kind.value !== 'top'; });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const widget = buildWidget({ kind: f.kind.value, title: f.title.value, query, extra, field: f.field.value, since,
      keepSince: f.keep?.checked });
    try {
      await api.send('POST', `/api/dashboards/${encodeURIComponent(f.dash.value)}/widgets`, widget);
      const target = f.dash.value;
      closeDrawer();
      toast('대시보드에 추가했습니다.', { type: 'success', action: { label: '열기', onClick: () => navigate(`dashboard/${target}`) } });
    } catch (err) {
      body.querySelector('[data-msg]').innerHTML = errorBox(err);
    }
  });
}
