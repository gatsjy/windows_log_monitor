// 심사 대응 (B-73): 규칙 태그 'ISMS x.y.z' 항목별 탐지·처리 현황과 기간 증적 묶음(zip + MANIFEST SHA-256).
// 판정·집계는 서버(app/compliance.py). 점검 보고서와 같은 권한(reports.view, 조회 범위 없는 사용자).
import * as api from '../api.js';
import { exportCsv } from '../exportcsv.js';
import { errorBox, fmtDuration, fmtNum, html } from '../util.js';

const PERIODS = [['30d', '30일'], ['90d', '90일'], ['180d', '180일'], ['365d', '1년']];

export async function mount(root) {
  let since = '90d';
  let alive = true;
  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">심사 대응</h1>
        <p class="page-sub">알림 규칙의 ISMS 태그로 항목마다 탐지 규칙·알림·처리 현황을 봅니다. 기간 증적 묶음(zip)에는 항목별 규칙 정의·알림 처리 기록과
          모든 파일의 SHA-256(MANIFEST)이 들어 있고, MANIFEST 의 해시는 감사로그에 남습니다.</p></div>
      <div class="toolbar">
        <div class="seg" data-period>${PERIODS.map(([v, l]) => html`<button type="button" data-v="${v}" class="${v === since ? 'on' : ''}">${l}</button>`)}</div>
        <button class="btn primary" data-bundle>증적 묶음 내려받기</button>
      </div>
    </div>
    <section class="card"><div class="table-wrap" data-table><div class="skeleton"></div></div></section>`;

  async function load() {
    const box = root.querySelector('[data-table]');
    box.innerHTML = '<div class="skeleton"></div>';
    try {
      const data = await api.get('/api/compliance/isms', { since });
      if (!alive) return;
      box.innerHTML = data.items.length ? html`<table class="table">
        <thead><tr><th>ISMS 항목</th><th>탐지 규칙</th><th class="r">알림</th><th class="r">해결</th><th class="r">미해결</th>
          <th class="r">해결 시간(중앙값)</th><th class="r">정탐 · 오탐</th></tr></thead>
        <tbody>${data.items.map((i) => html`<tr>
          <td class="nowrap"><b>${i.item}</b></td>
          <td>${i.rules.length ? html`<span class="num">${fmtNum(i.enabled)}/${fmtNum(i.rules.length)}</span> 켜짐
              <div class="muted" style="font-size:12px">${i.rules.map((r) => r.name).join(', ')}</div>` : html`<span class="muted">지금 이 태그의 규칙 없음</span>`}
            ${i.no_data.length ? html`<div class="tag-bad" style="font-size:12px">데이터 없음: ${i.no_data.join(', ')}</div>` : ''}</td>
          <td class="r num">${fmtNum(i.alerts)}</td>
          <td class="r num">${fmtNum(i.resolved)}</td>
          <td class="r num ${i.unresolved ? 'tag-bad' : ''}">${fmtNum(i.unresolved)}</td>
          <td class="r num">${i.median_resolve_sec == null ? '–' : fmtDuration(i.median_resolve_sec)}</td>
          <td class="r num">${fmtNum(i.true_positive)} · ${fmtNum(i.false_positive)}</td></tr>`)}</tbody></table>`
        : html`<div class="empty">ISMS 태그가 달린 규칙이나 알림이 없습니다 — 규칙의 tags 에 'ISMS 2.11.3' 처럼 적습니다.</div>`;
    } catch (err) {
      if (alive) box.innerHTML = errorBox(err);
    }
  }

  root.querySelectorAll('[data-period] button').forEach((b) => b.addEventListener('click', () => {
    since = b.dataset.v;
    root.querySelectorAll('[data-period] button').forEach((x) => x.classList.toggle('on', x === b));
    load();
  }));
  root.querySelector('[data-bundle]').addEventListener('click', () => exportCsv('/api/compliance/isms/bundle', { since },
    { what: '증적 묶음(알림 대상 PC·사용자 이름 포함)', format: null, title: '심사 증적 묶음 내려받기' }));
  load();
  return () => { alive = false; };
}
