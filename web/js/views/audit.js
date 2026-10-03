// 감사 로그 (관리자 전용): 누가 언제 어디서 무엇을 했는지. CSV 로 내려받아 심사 증적으로 제출.
import * as api from '../api.js';
import { errorBox, fmtNum, fmtTime, html, qs, replaceParams } from '../util.js';

const RANGES = [['24h', '24시간'], ['7d', '7일'], ['30d', '30일'], ['90d', '90일'], ['365d', '1년']];
const GROUPS = [
  ['', '전체 행위'], ['auth.', '로그인·세션'], ['user.', '사용자 관리'], ['events.', '로그 조회'],
  ['alerts.', '알림 설정'], ['dashboard.', '대시보드'], ['settings.', '환경설정'], ['retention.', '보관기간 만료 삭제'], ['audit.', '감사로그 내려받기'],
];
const BAD = new Set(['auth.login_failed', 'auth.account_locked', 'auth.password_change_failed']);

function detailText(detail) {
  const entries = Object.entries(detail || {}).filter(([k]) => k !== 'user_agent');
  if (!entries.length) return '';
  return entries.map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · ');
}

export async function mount(root, params) {
  let state = { since: params.since || '7d', action: params.action || '', actor: params.actor || '', q: params.q || '' };

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">감사 로그</h1>
        <p class="page-sub">로그인·계정 변경·로그 조회·설정 변경 기록입니다. 수정·삭제할 수 없으며(DB 에서 차단), 보관기간이 지나면 자동 파기됩니다.</p></div>
      <div class="toolbar"><a class="btn" data-csv download>CSV 내려받기</a></div>
    </div>
    <div class="card filterbar" data-filter></div>
    <section class="card"><div class="card-head"><h2 class="card-title">기록</h2><span class="muted num" data-count style="font-size:12.5px"></span></div>
      <div class="card-body flush" data-table><div class="skeleton"></div></div></section>`;

  function renderFilter() {
    const el = root.querySelector('[data-filter]');
    el.innerHTML = html`
      <select class="select" data-k="since">${RANGES.map(([v, l]) => html`<option value="${v}" ${v === state.since ? 'selected' : ''}>최근 ${l}</option>`)}</select>
      <select class="select" data-k="action">${GROUPS.map(([v, l]) => html`<option value="${v}" ${v === state.action ? 'selected' : ''}>${l}</option>`)}</select>
      <input class="input" data-k="actor" placeholder="사용자 아이디" value="${state.actor}" style="width:160px">
      <input class="input grow" data-k="q" placeholder="대상·상세·IP 검색 (Enter)" value="${state.q}">`;
    el.querySelectorAll('[data-k]').forEach((input) => {
      const commit = () => { state = { ...state, [input.dataset.k]: input.value.trim() }; load(); };
      input.addEventListener('change', commit);
      if (input.tagName === 'INPUT') input.addEventListener('keydown', (e) => { if (e.key === 'Enter') commit(); });
    });
  }

  async function load() {
    replaceParams('audit', state);
    root.querySelector('[data-csv]').href = `/api/audit?${qs({ ...state, format: 'csv', limit: 10000 })}`;
    const table = root.querySelector('[data-table]');
    try {
      const { items, labels } = await api.get('/api/audit', { ...state, limit: 500 });
      root.querySelector('[data-count]').textContent = `${fmtNum(items.length)}건${items.length >= 500 ? ' (최근 500건 — 전체는 CSV)' : ''}`;
      if (!items.length) {
        table.innerHTML = '<div class="empty">기록이 없습니다.</div>';
        return;
      }
      table.innerHTML = html`<div class="table-wrap"><table class="table">
        <thead><tr><th>일시</th><th>사용자</th><th>접속 IP</th><th>행위</th><th>대상</th><th>상세</th></tr></thead>
        <tbody>${items.map((r) => html`<tr>
          <td class="nowrap num muted">${fmtTime(r.at)}</td>
          <td class="nowrap"><b>${r.actor}</b></td>
          <td class="nowrap num ink-2">${r.actor_ip || '–'}</td>
          <td class="nowrap ${BAD.has(r.action) ? 'tag-bad' : ''}" title="${r.action}">${labels[r.action] || r.action}</td>
          <td class="nowrap">${r.target || ''}</td>
          <td class="msg mono" title="${detailText(r.detail)}" style="font-size:12px">${detailText(r.detail)}</td>
        </tr>`)}</tbody></table></div>`;
    } catch (err) {
      table.innerHTML = errorBox(err);
    }
  }

  renderFilter();
  await load();
}
