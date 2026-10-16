// 점검 보고서 (BACKLOG B-05, ADR-032): 일간·주간 보고서 이력, 열람(메일과 같은 HTML), 점검 확인, 지금 만들기, 다시 보내기.
// 하위 주소: #/reports/<번호> = 그 보고서를 바로 연다 (메일·메신저의 링크)
// 보고서 내용은 서버가 만든 HTML 을 sandbox iframe 으로 보여 준다 — 메일·인쇄본과 화면이 같은 내용이 되게.
import * as api from '../api.js';
import { can } from '../auth.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { confirmModal, errorBox, fmtRelative, fmtTime, html, toast } from '../util.js';

const WEEKDAYS = ['', '월', '화', '수', '목', '금', '토', '일'];
const DELIVERY = { sent: ['✓', '전송됨', 'sent'], failed: ['!', '실패', 'gave_up'], pending: ['…', '보내는 중', 'skipped'] };

// 받는 곳마다 마지막 결과. 전송 기록은 다시 보낼 때마다 덧붙으므로(첫 발송 결과도 남김) 화면에는 마지막 것만
function latest(list = []) {
  const by = new Map();
  for (const d of list) by.set(d.target, { ...d, tries: (by.get(d.target)?.tries ?? 0) + 1 });
  return [...by.values()];
}

function deliveries(list = []) {
  if (!list.length) return html`<span class="muted">보내지 않음</span>`;
  return html`${latest(list).map((d) => {
    const [mark, label, cls] = DELIVERY[d.status] ?? ['?', d.status, ''];
    const tip = `${label}${d.error ? `: ${d.error}` : ''}${d.tries > 1 ? ` (${d.tries}번 보냄)` : ''}`;
    return html`<span class="dlv ${cls}" title="${tip}">${mark} ${d.target}</span>`;
  })}`;
}

function attentionChip(n) {
  return n ? html`<span class="ast open">점검 필요 ${n}건</span>` : html`<span class="ast resolved">특이 사항 없음</span>`;
}

export async function mount(root, params, sub) {
  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">점검 보고서</h1>
        <p class="page-sub">정해진 시각에 로그·보안 이벤트·알림 처리·수집 PC·보관·백업 상태를 모아 저장하고 보냅니다. 내용은 고칠 수 없고, 담당자가 점검 확인을 남깁니다 (ISMS 2.9.5).</p></div>
      <div class="toolbar">
        <button class="btn" data-make="daily" title="어제 하루 보고서를 지금 만듭니다 (보내지 않음)">일간 지금 만들기</button>
        <button class="btn" data-make="weekly" title="지난주 보고서를 지금 만듭니다 (보내지 않음)">주간 지금 만들기</button>
        ${can('settings.manage') ? html`<a class="btn ghost" href="#/settings/reports">일정·받는 곳</a>` : ''}
      </div>
    </div>
    <div data-status style="margin-bottom:14px"></div>
    <section class="card"><div class="card-body flush" data-list><div class="skeleton"></div></div></section>`;

  let data = null;
  // 화면을 떠난 뒤에 끝난 요청(지금 만들기 등)이 다른 화면의 [data-list] 를 덮어쓰거나 서랍을 열지 않게
  let alive = true;

  function renderStatus() {
    const s = data.schedule;
    const plan = [s.daily.enabled && `매일 ${s.daily.time}(어제)`, s.weekly.enabled && `매주 ${WEEKDAYS[s.weekly.weekday]} ${s.weekly.time}(지난주)`]
      .filter(Boolean).join(' · ') || '정기 보고서 꺼짐';
    root.querySelector('[data-status]').innerHTML = html`
      <div class="card status-strip">
        <span class="status ${data.unreviewed_30d ? 'stale' : 'online'}"><span class="dot"></span>${data.unreviewed_30d ? `확인 안 한 보고서 ${data.unreviewed_30d}건 (30일)` : '모든 보고서 확인됨'}</span>
        <span class="muted">${plan} · ${data.tz} · 받는 곳 ${s.targets.length ? s.targets.join(', ') : '없음 (저장만)'}</span>
      </div>
      ${data.scheduler.last_error ? html`<div class="error-box" style="margin-top:8px">보고서 작업 오류: ${data.scheduler.last_error}</div>` : ''}`;
  }

  function renderList() {
    const el = root.querySelector('[data-list]');
    if (!data.items.length) {
      el.innerHTML = html`<div class="empty">아직 보고서가 없습니다. 정해진 시각에 자동으로 만들어지고, '지금 만들기'로 바로 만들 수도 있습니다.</div>`;
      return;
    }
    el.innerHTML = html`<div class="table-wrap"><table class="table">
      <thead><tr><th>보고서</th><th>점검 필요</th><th>전송</th><th>점검 확인</th><th>만든 시각</th></tr></thead>
      <tbody>${data.items.map((r) => html`<tr class="clickable ${r.reviewed_at ? 'row-done' : ''}" data-id="${r.id}">
        <td><b>${r.title ?? `보고서 #${r.id}`}</b>${r.scheduled ? '' : html` <span class="type-tag" title="${r.created_by}">지금 만듦</span>`}</td>
        <td class="nowrap">${attentionChip(r.attention)}</td>
        <td class="dlv-cell">${deliveries(r.deliveries)}</td>
        <td class="nowrap">${r.reviewed_at ? html`<span class="ast resolved" title="${r.review_note}">${r.reviewed_by}</span> <span class="muted">${fmtRelative(r.reviewed_at)}</span>`
          : html`<span class="ast open">확인 필요</span>`}</td>
        <td class="nowrap muted num">${fmtTime(r.created_at, { seconds: false })}</td>
      </tr>`)}</tbody></table></div>`;
    el.querySelectorAll('tr[data-id]').forEach((tr) => tr.addEventListener('click', () => openReport(tr.dataset.id)));
  }

  async function load() {
    try {
      const res = await api.get('/api/reports', { limit: 200 });
      if (!alive) return;
      data = res;
      renderStatus();
      renderList();
    } catch (err) {
      if (alive) root.querySelector('[data-list]').innerHTML = errorBox(err);
    }
  }

  async function openReport(id) {
    if (!alive) return;
    const body = openDrawer({ title: '점검 보고서', subtitle: `보고서 #${id}` });
    body.innerHTML = '<div class="skeleton"></div>';
    let r;
    try {
      r = await api.get(`/api/reports/${id}`);
    } catch (err) {
      if (alive) body.innerHTML = errorBox(err);
      return;
    }
    if (!alive) return;
    // 보내기: 기본은 아직 못 받은 곳만 (이미 받은 곳에 또 보내지 않게). 모두 받았으면 '모두 다시 보내기'
    const targets = data?.schedule.targets ?? [];
    const got = new Set(latest(r.deliveries).filter((d) => d.status === 'sent').map((d) => d.target));
    const unsent = targets.filter((t) => !got.has(t));
    const sendButton = !can('settings.manage') ? ''
      : targets.length && !unsent.length ? html`<button class="btn sm" data-send="all">모두 다시 보내기</button>`
        : html`<button class="btn sm" data-send title="${unsent.join(', ')}">${targets.some((t) => got.has(t)) ? '못 받은 곳으로 다시 보내기' : '설정된 받는 곳으로 보내기'}${unsent.length ? ` (${unsent.length}곳)` : ''}</button>`;
    body.innerHTML = html`
      <div class="toolbar" style="margin-bottom:8px"><b>${r.payload.title}</b> ${attentionChip(r.attention)}</div>
      <div class="handle-box">
        ${r.reviewed_at ? html`<div class="handle-state"><span class="ast resolved">점검 확인</span>
            <span class="muted">${r.reviewed_by} · ${fmtTime(r.reviewed_at)}</span></div>
            ${r.review_note ? html`<div class="tl-text">${r.review_note}</div>` : ''}`
          : html`<label class="field"><span>점검 확인 — 무엇을 보았고 어떻게 조치했는지 (선택, 남기면 고칠 수 없음)</span>
              <textarea class="input" rows="3" maxlength="4000" data-note placeholder="예: 로그 삭제 1건은 정기 작업(변경 CR-77)으로 확인. 연락 끊긴 PC 2대는 폐기 예정 장비."></textarea></label>
            <div class="toolbar"><button class="btn primary" data-review>점검 확인 남기기</button><span data-msg></span></div>`}
      </div>
      <div class="toolbar" style="margin:0 0 8px">
        <a class="btn sm" href="/api/reports/${r.id}/html" target="_blank" rel="noopener">인쇄용으로 열기</a>
        ${sendButton}
        <span class="muted" style="font-size:12px" title="${r.sha256}">내용 해시 ${r.sha256.slice(0, 12)}… · 전송 ${r.deliveries.length ? '' : '없음'}</span>
        ${r.deliveries.length ? deliveries(r.deliveries) : ''}
      </div>
      <iframe class="report-frame" sandbox="allow-same-origin" title="보고서 내용" src="/api/reports/${r.id}/html"></iframe>`;
    body.querySelector('[data-review]')?.addEventListener('click', async (e) => {
      e.target.disabled = true;
      try {
        await api.send('POST', `/api/reports/${r.id}/review`, { note: body.querySelector('[data-note]').value.trim() });
        toast('점검 확인을 남겼습니다.', { type: 'success' });
        await load();
        openReport(r.id);
      } catch (err) {
        if (!alive) return;
        e.target.disabled = false;
        body.querySelector('[data-msg]').innerHTML = errorBox(err);
      }
    });
    body.querySelector('[data-send]')?.addEventListener('click', async (e) => {
      const all = e.target.dataset.send === 'all';
      if (all && !await confirmModal({ title: '모두 다시 보내기', message: '이미 받은 곳에도 이 보고서를 다시 보냅니다.', confirmText: '보내기' })) return;
      e.target.disabled = true;
      try {
        const res = await api.send('POST', `/api/reports/${r.id}/send`, { all });
        toast(res.ok ? '보냈습니다.' : '일부 받는 곳으로 보내지 못했습니다 — 전송 칩에 마우스를 올려 사유를 보세요.', { type: res.ok ? 'success' : 'error' });
        await load();
        openReport(r.id);
      } catch (err) {
        if (!alive) return;
        e.target.disabled = false;
        toast(err.message, { type: 'error' });
      }
    });
  }

  root.querySelectorAll('[data-make]').forEach((b) => b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const res = await api.send('POST', '/api/reports', { kind: b.dataset.make });
      await load();
      openReport(res.id);
    } catch (err) {
      toast(err.message, { type: 'error' });   // 다른 화면에 있어도 실패는 알린다 (만들기는 서버에서 끝났거나 실패했다)
    } finally {
      b.disabled = false;
    }
  }));

  await load();
  if (/^\d+$/.test(sub)) openReport(sub);
  return () => {
    alive = false;
    closeDrawer();
  };
}
