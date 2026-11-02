// 접속기록 점검 결과서 (BACKLOG B-72 3단계, ISMS 2.9.5, ADR-060): 점검 보고서 화면의 '접속기록 점검' 탭(#/reports/inspections).
// 항목마다 근거(시작 때 모은 그 기간의 숫자)를 보고 적정·부적정·해당 없음과 조치를 적는다 → 점검자 서명 → 다른 사람이 승인·반려.
import * as api from '../api.js';
import { currentUser } from '../auth.js';
import { openDrawer } from '../drawer.js';
import { exportCsv } from '../exportcsv.js';
import { errorBox, fmtTime, html, promptModal, toast } from '../util.js';

export const REPORT_TABS = (on) => html`<div class="tabs" role="tablist">
  <a role="tab" href="#/reports" class="${on === '' ? 'on' : ''}" aria-selected="${on === ''}">보고서</a>
  <a role="tab" href="#/reports/inspections" class="${on === 'inspections' ? 'on' : ''}" aria-selected="${on === 'inspections'}">접속기록 점검</a></div>`;

const STATUS = { open: ['stale', '진행 중'], signed: ['stale', '서명 — 승인 대기'], approved: ['online', '승인됨'] };
const RESULTS = [['ok', '적정'], ['issue', '부적정'], ['na', '해당 없음']];
const RESULT_LABEL = Object.fromEntries(RESULTS);
const ENTRY_LABEL = { result: '결과', sign: '서명', approve: '승인', reject: '반려' };

function statusChip(status) {
  const [cls, label] = STATUS[status] ?? ['offline', status];
  return html`<span class="status ${cls}"><span class="dot"></span>${label}</span>`;
}

export async function mountInspections(root) {
  let disposed = false;
  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">점검 보고서</h1>
        <p class="page-sub">내부 관리계획의 주기마다 접속기록을 점검하고 항목별 결과·조치를 남깁니다 — 점검자가 서명하면 다른 사람이 승인합니다 (ISMS 2.9.5).</p></div>
      <div class="toolbar"><button class="btn primary" data-start>지난달 점검 시작</button></div>
    </div>
    ${REPORT_TABS('inspections')}
    <div data-list><div class="skeleton"></div></div>`;

  let defaults = null;
  async function load() {
    let data;
    try {
      data = await api.get('/api/inspections');
    } catch (err) {
      root.querySelector('[data-list]').innerHTML = errorBox(err);
      return;
    }
    if (disposed) return;
    defaults = data.default_period;
    root.querySelector('[data-list]').innerHTML = html`<section class="card"><div class="card-body flush">
      ${data.items.length ? html`<div class="table-wrap"><table class="table">
        <thead><tr><th>점검</th><th>기간</th><th>상태</th><th class="r">결과</th><th class="r">부적정</th><th>서명</th><th>승인</th></tr></thead>
        <tbody>${data.items.map((r) => html`<tr class="clickable" data-insp="${r.id}">
          <td><b>${r.title}</b></td>
          <td class="nowrap muted">${fmtTime(r.period_start, { seconds: false })} ~ ${fmtTime(r.period_end, { seconds: false })}</td>
          <td class="nowrap">${statusChip(r.status)}</td>
          <td class="r num">${r.done}/${r.items}</td>
          <td class="r num">${r.issues ? html`<span class="tag-bad">${r.issues}</span>` : '–'}</td>
          <td class="nowrap">${r.signed_by || html`<span class="muted">–</span>`}</td>
          <td class="nowrap">${r.approved_by ? html`${r.approved_by} <span class="muted">${fmtTime(r.approved_at, { seconds: false })}</span>` : html`<span class="muted">–</span>`}</td>
        </tr>`)}</tbody></table></div>` : html`<div class="empty">아직 접속기록 점검이 없습니다 — '지난달 점검 시작'</div>`}
    </div></section>
    ${data.days ? html`<p class="muted rule-foot">점검 주기 ${data.days}일 (WLM_ACCESS_LOG_INSPECTION_DAYS) — 마지막 승인한 점검의 기간 끝 뒤 한 주기와 여유 ${data.grace_days}일이 지나도록 다음 점검을 승인하지 않으면 운영 준비도·점검 보고서가 알립니다.</p>` : ''}`;
    root.querySelectorAll('[data-insp]').forEach((tr) => tr.addEventListener('click', () => open(Number(tr.dataset.insp))));
  }

  root.querySelector('[data-start]').addEventListener('click', async () => {
    const title = await promptModal({ title: '접속기록 점검 시작', message: '지난달(표시 시간대 1일~말일)의 점검 근거를 모아 시작합니다.',
      defaultValue: defaults?.title ?? '접속기록 점검', confirmText: '시작' });
    if (title == null) return;
    try {
      const res = await api.send('POST', '/api/inspections', { title: title.trim() });
      toast('접속기록 점검을 시작했습니다.', { type: 'success' });
      await load();
      open(res.id);
    } catch (err) {
      toast(err.message, { type: 'error' });
    }
  });

  async function post(id, body) {
    await api.send('POST', `/api/inspections/${id}/entries`, body);
    await load();
    await open(id, true);
  }

  async function open(id, keep = false) {
    let r;
    try {
      r = await api.get(`/api/inspections/${id}`);
    } catch (err) {
      toast(err.message, { type: 'error' });
      return;
    }
    if (disposed) return;
    const scroll = keep ? document.querySelector('.drawer-body')?.scrollTop : 0;
    const body = openDrawer({ title: r.title, subtitle: `${fmtTime(r.period_start, { seconds: false })} ~ ${fmtTime(r.period_end, { seconds: false })} · ${r.started_by} 시작`,
      actions: html`<button class="btn sm" data-csv>결과서 CSV</button>` });
    const editable = r.status === 'open';
    const signedByMe = r.signed && r.signed.author === currentUser().username;
    body.innerHTML = html`
      <p>${statusChip(r.status)} <span class="muted">${r.items.length - r.missing.length}/${r.items.length}개 항목 결과</span>
        ${r.issues.length ? html` <span class="tag-bad">부적정 ${r.issues.length}개</span>` : ''}</p>
      ${r.rejected && editable ? html`<div class="hint-box">반려됨 — ${r.rejected.author}: ${r.rejected.note}</div>` : ''}
      ${r.items.map((it) => html`<section class="card" style="margin-bottom:10px"><div class="card-body">
        <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><b>${it.label}</b><span class="muted" style="font-size:12px">${it.basis}</span></div>
        <p class="muted" style="font-size:13px;margin:6px 0">${it.summary}</p>
        ${it.evidence?.problems?.length > 3 ? html`<details style="font-size:12.5px;margin-bottom:6px"><summary>기간 중 문제 ${it.evidence.problem_count ?? it.evidence.problems.length}건 ${(it.evidence.problem_count ?? 0) > it.evidence.problems.length ? `(앞 ${it.evidence.problems.length}건 — 빈 구간 먼저)` : '모두'} 보기</summary>
          <ul class="ref-list">${it.evidence.problems.map((p) => html`<li>${fmtTime(p.at, { seconds: false })} · ${p.text}</li>`)}</ul></details>` : ''}
        ${editable ? html`<div class="toolbar" style="flex-wrap:wrap;gap:6px">
            <select class="input" data-result="${it.key}" aria-label="${it.label} 결과"><option value="">결과…</option>
              ${RESULTS.map(([v, l]) => html`<option value="${v}" ${it.result?.result === v ? 'selected' : ''}>${l}</option>`)}</select>
            <input class="input" data-note="${it.key}" maxlength="2000" placeholder="조치·의견 (부적정은 필수)" value="${it.result?.note || ''}" style="flex:1;min-width:180px" aria-label="${it.label} 조치">
            <button class="btn sm" data-save="${it.key}">저장</button></div>`
          : it.result ? html`<div><b>${RESULT_LABEL[it.result.result]}</b>${it.result.note ? html` — ${it.result.note}` : ''}</div>` : html`<span class="muted">결과 없음</span>`}
        ${it.result ? html`<div class="muted" style="font-size:12px;margin-top:4px">${it.result.author} · ${fmtTime(it.result.at, { seconds: false })}</div>` : ''}
      </div></section>`)}
      <div class="section-title">결재</div>
      ${r.status === 'open' ? html`<div class="toolbar" style="flex-wrap:wrap">
          <input class="input" data-sign-note maxlength="2000" placeholder="점검 의견 (선택)" style="flex:1;min-width:200px">
          <button class="btn primary" data-sign ${r.missing.length ? 'disabled' : ''}>점검 완료 — 서명</button></div>
          ${r.missing.length ? html`<p class="muted" style="font-size:12.5px">결과를 정하지 않은 항목 ${r.missing.length}개</p>` : ''}`
        : r.status === 'signed' ? html`<p>${r.signed.author} 서명 · ${fmtTime(r.signed.at, { seconds: false })}${r.signed.note ? ` — ${r.signed.note}` : ''}</p>
          ${signedByMe ? html`<p class="muted">서명한 사람이 아닌 다른 사람이 승인·반려합니다.</p>` : html`<div class="toolbar" style="flex-wrap:wrap">
            <input class="input" data-approve-note maxlength="2000" placeholder="의견 (반려는 필수)" style="flex:1;min-width:200px">
            <button class="btn primary" data-approve>승인</button><button class="btn" data-reject>반려</button></div>`}`
        : html`<p>${r.signed?.author} 서명 → <b>${r.approved.author}</b> 승인 · ${fmtTime(r.approved.at, { seconds: false })}${r.approved.note ? ` — ${r.approved.note}` : ''}</p>`}
      <div class="section-title">기록</div>
      <ul class="ref-list" style="font-size:12.5px">${r.entries.slice().reverse().map((e) => html`<li>${fmtTime(e.at)} · ${e.author} · <b>${ENTRY_LABEL[e.kind]}</b>
        ${e.item ? ` ${r.items.find((i) => i.key === e.item)?.label ?? e.item} → ${RESULT_LABEL[e.result]}` : ''}${e.note ? html` <span class="muted">— ${e.note}</span>` : ''}</li>`)}</ul>`;
    if (scroll) body.scrollTop = scroll;

    const run = async (fn) => { try { await fn(); } catch (err) { toast(err.message, { type: 'error' }); } };
    body.querySelectorAll('[data-save]').forEach((b) => b.addEventListener('click', () => run(async () => {
      const key = b.dataset.save;
      const result = body.querySelector(`[data-result="${key}"]`).value;
      if (!result) { toast('적정·부적정·해당 없음 중 하나를 고르세요', { type: 'error' }); return; }
      await post(id, { kind: 'result', item: key, result, note: body.querySelector(`[data-note="${key}"]`).value });
    })));
    body.querySelector('[data-sign]')?.addEventListener('click', () => run(() => post(id, { kind: 'sign', note: body.querySelector('[data-sign-note]').value })));
    body.querySelector('[data-approve]')?.addEventListener('click', () => run(() => post(id, { kind: 'approve', note: body.querySelector('[data-approve-note]').value })));
    body.querySelector('[data-reject]')?.addEventListener('click', () => run(() => post(id, { kind: 'reject', note: body.querySelector('[data-approve-note]').value })));
    document.querySelector('.drawer [data-csv]')?.addEventListener('click', () =>
      exportCsv(`/api/inspections/${id}/csv`, {}, { what: '접속기록 점검 결과서', format: '' }));
  }

  await load();
  return () => { disposed = true; };
}
