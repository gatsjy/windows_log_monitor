// 운영 준비도 점검표 (B-75): 아직 안 된 것을 한 화면에 — 빨강(고쳐야 함)·노랑(확인)·초록. 관리자만.
// 판정은 서버(app/readiness.py)가 각 화면·점검 보고서와 같은 원천으로 한다. 여기서는 그리기만.
import * as api from '../api.js';
import { errorBox, fmtTime, html } from '../util.js';

const MARK = { bad: ['!', '고쳐야 함'], warn: ['?', '확인'], ok: ['✓', '정상'], skip: ['–', '해당 없음'] };

export async function mount(root) {
  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">운영 준비도</h1>
        <p class="page-sub">설치·운영에서 아직 안 된 것을 모았습니다. 항목을 누르면 고치는 화면으로 갑니다 — 판정은 각 화면·점검 보고서와 같은 원천입니다.</p></div>
      <div class="toolbar"><button class="btn" data-reload>다시 점검</button></div>
    </div>
    <div data-summary style="margin-bottom:14px"></div>
    <section class="card"><div class="card-body" data-list><div class="skeleton"></div></div></section>`;
  let alive = true;

  async function load() {
    const list = root.querySelector('[data-list]');
    try {
      const data = await api.get('/api/readiness');
      if (!alive) return;
      const s = data.summary;
      root.querySelector('[data-summary]').innerHTML = html`<div class="ready-summary">
        <span class="ready-chip bad">고쳐야 함 ${s.bad}</span><span class="ready-chip warn">확인 ${s.warn}</span>
        <span class="ready-chip ok">정상 ${s.ok}</span><span class="muted">점검 ${fmtTime(data.checked_at)}</span></div>`;
      const groups = [...new Set(data.items.map((i) => i.group))];
      list.innerHTML = groups.map((g) => html`
        <div class="section-title" style="margin-top:${g === groups[0] ? 0 : 18}px">${g}</div>
        <ul class="ready-list">${data.items.filter((i) => i.group === g).map((i) => html`
          <li class="ready-item ${i.status}">
            <span class="ready-mark" title="${MARK[i.status][1]}">${MARK[i.status][0]}</span>
            <div class="ready-body"><b>${i.label}</b><div class="ready-detail">${i.detail}</div>
              ${i.doc ? html`<div class="muted ready-doc">${i.doc}</div>` : ''}</div>
            ${i.link ? html`<a class="btn sm" href="${i.link}">열기 →</a>` : ''}
          </li>`)}</ul>`).join('');
    } catch (err) {
      if (alive) list.innerHTML = errorBox(err);
    }
  }
  root.querySelector('[data-reload]').addEventListener('click', load);
  await load();
  return () => { alive = false; };
}
