// 알림 화면: 엔진 상태와 심각도별 수, 그리고 탭 4개
//   이력(#/alerts?status=)    — 발생한 알림, 처리 상태(처리 안 됨·확인함·해결됨), 전송 상태. 일괄 확인·해결, CSV
//   규칙 관리(#/alerts/rules) — Snort 처럼 규칙 묶음(왼쪽) + 규칙 표(오른쪽). 켜기/끄기, 추가·수정은 오른쪽 패널(ruleform.js)
//   알림 대상(#/alerts/targets) — 수신 그룹·외부 연동, 테스트 발송
//   무음(#/alerts/silences)   — 점검 시간대 등 알림을 잠시 보내지 않는 기간 (발생 기록은 남음)
import * as api from '../api.js';
import { can } from '../auth.js';
import {
  ALERT_STATUS, GROUP_LABELS, SILENCE_DURATIONS, deliveryChips, matchText, openAlert, resolutionSelect, silenceScope,
  statusChip,
} from '../alertdetail.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { exportCsv } from '../exportcsv.js';
import { SEVERITIES, severityBadge } from '../levels.js';
import { openRuleEditor } from '../ruleform.js';
import { confirmModal, errorBox, fmtDuration, fmtNum, fmtRelative, fmtTime, html, replaceParams, store, toast } from '../util.js';

const TYPE_LABELS = { email: '수신 그룹 (메일)', webhook: '웹훅', oracle: 'Oracle DB', '-': '설정 오류' };
// '전체' = 보관기간 안 전부 (서버 보관기간보다 넉넉한 10년) — 사이드바 숫자(확인 안 된 알림 전체)와 맞추려고
const RANGES = [['24h', '24시간'], ['7d', '7일'], ['30d', '30일'], ['365d', '1년'], ['3650d', '전체']];
const TABS = [['', '알림 이력'], ['rules', '규칙 관리'], ['targets', '알림 대상'], ['silences', '무음'], ['exceptions', '예외']];
const EXCEPTION_STATE = { active: ['online', '적용 중'], expired: ['stale', '만료'], ended: ['offline', '끝냄'] };
const STATUS_FILTERS = [['open', ALERT_STATUS.open], ['acked', ALERT_STATUS.acked], ['resolved', ALERT_STATUS.resolved], ['', '전체']];
const EMPTY_TEXT = { open: '확인하지 않은 알림이 없습니다 ✓', acked: '확인만 하고 해결하지 않은 알림이 없습니다 ✓',
  resolved: '이 기간에 해결한 알림이 없습니다.', '': '이 기간에 발생한 알림이 없습니다.' };
const SILENCE_STATE = { active: ['online', '적용 중'], upcoming: ['stale', '예정'], ended: ['offline', '끝남'] };
const HISTORY_LIMIT = 200;

export async function mount(root, params, sub) {
  // 예외 탭(B-46)은 규칙을 관리하는 사람만 — 서버도 alerts.manage 로 막는다
  const tabs = TABS.filter(([k]) => k !== 'exceptions' || can('alerts.manage'));
  const tab = tabs.some(([k]) => k === sub) ? sub : '';
  let status = STATUS_FILTERS.some(([k]) => k === params.status) ? params.status : '';
  // 처리할 알림 목록(처리 안 됨·확인함)은 오래된 것까지 봐야 하므로 기본 기간을 '전체'로 (사이드바 숫자와 맞춤)
  let since = params.since || (status === 'open' || status === 'acked' ? '3650d' : '7d');
  // 규칙 하나만 (B-41): 묶음 알림 메일·메신저의 '자세히 보기'가 그 규칙의 알림 목록으로 온다
  let ruleFilter = tab ? '' : (params.rule || '');
  let config = null;
  let timer;
  const selected = new Set(); // 이력에서 체크한 알림 id (자동 새로고침해도 유지)
  // 이력 보기 (B-44): 알림마다 | 규칙 › 대상으로 묶어 — 장애 때 같은 규칙이 수십 PC 에서 터져도 다른 심각 알림이 묻히지 않게
  let view = store.get('wlm.alerts.view') === 'groups' ? 'groups' : 'list';
  // 규칙 관리 화면 상태 (묶음 선택·검색은 브라우저에 기억)
  const ui = { group: store.get('wlm.rules.group') || '', q: '', state: 'all' };

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">알림</h1>
        <p class="page-sub">규칙에 맞는 로그가 들어오면 메일·웹훅·Oracle 로 알립니다.</p></div>
      <div class="toolbar">
        <div class="seg" data-seg aria-label="기간">${RANGES.map(([v, l]) => html`<button data-v="${v}" class="${v === since ? 'on' : ''}">${l}</button>`)}</div>
      </div>
    </div>
    <div data-status style="margin-bottom:14px"></div>
    <div class="grid" data-summary style="margin-bottom:16px"></div>
    <div class="tabs" role="tablist">${tabs.map(([k, l]) => html`
      <a role="tab" href="#/alerts${k ? `/${k}` : ''}?since=${since}${!k && status ? `&status=${status}` : ''}" class="${k === tab ? 'on' : ''}" aria-selected="${k === tab}">${l}<span class="tab-count" data-tabcount="${k}"></span></a>`)}</div>
    <div data-tab></div>`;

  root.querySelectorAll('[data-seg] button').forEach((b) => b.addEventListener('click', () => {
    since = b.dataset.v;
    root.querySelectorAll('[data-seg] button').forEach((x) => x.classList.toggle('on', x === b));
    replaceParams(`alerts${tab ? `/${tab}` : ''}`, { since, status: tab ? '' : status, rule: tab ? '' : ruleFilter });
    root.querySelectorAll('.tabs a').forEach((a) => { a.href = a.href.replace(/since=[^&]*/, `since=${since}`); });
    load();
  }));

  // ----------------------------------------------------------- 상단 공통
  // 상태 띠 (ADR-045): 예전에는 설정 오류·마지막 오류가 비어 있으면 늘 초록이었다 — 평가가 멈춰도, 메일이 하루 종일 실패해도
  const HEALTH = { ok: ['online', '알림 엔진 동작 중'], warn: ['stale', '확인 필요'], down: ['down', '알림 멈춤'] };

  function renderStatus() {
    const el = root.querySelector('[data-status]');
    const health = config.health || { status: 'ok', problems: [] };
    const problems = [
      ...(config.config_error ? [{ level: 'bad', text: `설정 파일 오류: ${config.config_error}` }] : []),
      ...(config.last_error ? [{ level: 'bad', text: `평가 오류: ${config.last_error}` }] : []),
      ...health.problems,
    ];
    const status = problems.some((p) => p.level === 'bad') ? 'down' : problems.length ? 'warn' : 'ok';
    const [cls, label] = HEALTH[status];
    const active = config.rules.filter((r) => r.enabled).length;
    const waiting = config.notifiers.reduce((n, t) => n + (t.health?.queued || 0), 0);
    el.innerHTML = html`
      <div class="card status-strip">
        <span class="status ${cls}"><span class="dot"></span>${label}</span>
        <span class="muted">${config.interval_sec}초마다 평가 · 마지막 평가 ${config.last_run_at ? fmtRelative(config.last_run_at) : '대기 중'}
          ${config.cycle_sec != null ? html`(한 바퀴 ${config.cycle_sec < 10 ? config.cycle_sec.toFixed(1) : Math.round(config.cycle_sec)}초)` : ''}
          · 전송 대기 ${fmtNum(waiting)}건 · 규칙 ${active}/${config.rules.length}개 사용 중 · 알림 대상 ${config.notifiers.length}개
          ${config.grouping ? html`· <span title="메일·메신저는 같은 규칙 알림을 모아 한 통으로 보냅니다 (심각은 바로, 간격 1분). json 웹훅·Oracle 은 알림마다">${config.grouping.interval_sec
            ? `묶어 보내기 ${fmtDuration(config.grouping.wait_sec)} 모음·${fmtDuration(config.grouping.interval_sec)} 간격` : '묶지 않음'}</span>` : ''}</span>
        ${config.silences_active ? html`<a class="ast silenced" href="#/alerts/silences?since=${since}">무음 ${config.silences_active}개 적용 중</a>` : ''}
      </div>
      ${problems.map((p) => html`<div class="${p.level === 'bad' ? 'error-box' : 'hint-box'}" style="margin-top:8px">${p.text}</div>`)}`;
    root.querySelector('[data-tabcount="rules"]').textContent = String(config.rules.length);
    root.querySelector('[data-tabcount="targets"]').textContent = String(config.notifiers.length);
    root.querySelector('[data-tabcount="silences"]').textContent = config.silences_active ? String(config.silences_active) : '';
  }

  function renderSummary() {
    root.querySelector('[data-summary]').innerHTML = html`${Object.entries(SEVERITIES).map(([key]) => html`
      <section class="card" style="grid-column: span 3"><div class="card-body"><div class="stat">
        <div class="stat-meta">${severityBadge(key)}</div>
        <div class="stat-value">${fmtNum(config.by_severity[key] || 0)}<small>건</small></div>
      </div></div></section>`)}`;
  }

  // ---------------------------------------------------------------- 이력
  function viewToggle() {
    return html`<div class="seg" data-view aria-label="보기">${[['list', '알림마다'], ['groups', '규칙 › 대상으로 묶어']].map(([v, l]) => html`
      <button type="button" data-v="${v}" class="${v === view ? 'on' : ''}">${l}</button>`)}</div>
      ${ruleFilter ? html`<span class="chip on">규칙: ${ruleFilter}
        <button type="button" class="btn ghost sm x" data-rule-clear aria-label="규칙 조건 해제">✕</button></span>` : ''}`;
  }

  function bindHistoryToolbar(el) {
    el.querySelectorAll('[data-status] button').forEach((b) => b.addEventListener('click', () => {
      status = b.dataset.v;
      selected.clear();
      replaceParams('alerts', { since, status, rule: ruleFilter });
      root.querySelector('.tabs a').href = `#/alerts?since=${since}${status ? `&status=${status}` : ''}`;
      load();
    }));
    el.querySelectorAll('[data-view] button').forEach((b) => b.addEventListener('click', () => {
      if (view === b.dataset.v) return;
      view = b.dataset.v;
      store.set('wlm.alerts.view', view);
      selected.clear();
      load();
    }));
    el.querySelector('[data-rule-clear]')?.addEventListener('click', () => {
      ruleFilter = '';
      selected.clear();
      replaceParams('alerts', { since, status });
      load();
    });
  }

  /** 묶어 보기 (B-44): 규칙 › 대상마다 한 줄. 행을 누르면 그 묶음의 가장 최근 알림 — 상세의 '함께 해결'이 묶음 전체를 처리한다 */
  function renderGroups(res, counts) {
    const el = root.querySelector('[data-tab]');
    const total = counts.open + counts.acked + counts.resolved;
    const items = res?.items ?? [];
    el.innerHTML = html`<section class="card">
      <div class="rule-toolbar">
        <div class="seg" data-status aria-label="처리 상태">${STATUS_FILTERS.map(([v, l]) => html`
          <button type="button" data-v="${v}" class="${v === status ? 'on' : ''}">${l}<span class="seg-count num">${fmtNum(v ? counts[v] : total)}</span></button>`)}</div>
        ${viewToggle()}
      </div>
      ${items.length ? html`<div class="table-wrap"><table class="table alert-table">
        <thead><tr><th>심각도</th><th>규칙</th><th>대상</th><th class="r">알림</th><th>처리</th><th>마지막 발생</th><th></th></tr></thead>
        <tbody>${items.map((g, i) => html`<tr class="clickable ${g.open + g.acked ? '' : 'row-done'}" data-g="${i}">
          <td class="nowrap">${severityBadge(g.severity)}</td>
          <td class="nowrap"><b>${g.rule}</b></td>
          <td class="nowrap">${g.group_key || '–'}</td>
          <td class="r num">${fmtNum(g.n)}</td>
          <td class="nowrap">${g.open ? html`<span class="ast open">처리 안 됨 ${fmtNum(g.open)}</span> ` : ''}${g.acked ? html`<span class="ast acked">확인함 ${fmtNum(g.acked)}</span> ` : ''}${g.resolved ? html`<span class="ast resolved">해결됨 ${fmtNum(g.resolved)}</span>` : ''}</td>
          <td class="nowrap num muted" title="처음 ${fmtTime(g.first_fired_at)}">${fmtTime(g.last_fired_at)}</td>
          <td class="r nowrap">${g.open ? html`<button class="btn sm" data-g-ack="${i}" title="이 묶음의 처리 안 된 알림을 모두 확인">모두 확인</button>` : ''}</td>
        </tr>`)}</tbody></table></div>
        ${res.truncated ? html`<p class="muted rule-foot">처리 안 된·심각한 묶음부터 ${fmtNum(res.limit)}개까지 보입니다.</p>` : ''}
        <p class="muted rule-foot">행을 누르면 그 묶음의 가장 최근 알림 — 상세의 '해결…'에서 같은 규칙·대상의 다른 알림도 함께 해결합니다.</p>`
        : html`<div class="empty">${EMPTY_TEXT[status]}</div>`}
    </section>`;
    bindHistoryToolbar(el);
    el.querySelectorAll('tr[data-g]').forEach((tr) => tr.addEventListener('click', (e) => {
      if (e.target.closest('[data-g-ack]')) return;
      openAlert(items[Number(tr.dataset.g)].last_id, { onChange: load });
    }));
    el.querySelectorAll('[data-g-ack]').forEach((b) => b.addEventListener('click', async () => {
      const g = items[Number(b.dataset.gAck)];
      b.disabled = true;
      try {
        const r = await api.send('POST', '/api/alerts/handle', { ids: [g.last_id], action: 'ack', with_related: true });
        toast(`${g.rule} · ${g.group_key || '전체'} — ${fmtNum(r.changed.length)}건 확인`, { type: 'success' });
        load();
      } catch (err) {
        b.disabled = false;
        toast(err.message, { type: 'error' });
      }
    }));
  }

  function renderHistory(items, counts) {
    const el = root.querySelector('[data-tab]');
    const total = counts.open + counts.acked + counts.resolved;
    const shown = new Set(items.map((a) => a.id));
    [...selected].forEach((id) => { if (!shown.has(id)) selected.delete(id); });
    el.innerHTML = html`<section class="card">
      <div class="rule-toolbar">
        <div class="seg" data-status aria-label="처리 상태">${STATUS_FILTERS.map(([v, l]) => html`
          <button type="button" data-v="${v}" class="${v === status ? 'on' : ''}">${l}<span class="seg-count num">${fmtNum(v ? counts[v] : total)}</span></button>`)}</div>
        ${viewToggle()}
        <span style="flex:1"></span>
        <button type="button" class="btn ghost" data-csv title="처리 상태·처리한 사람·처리 기록 포함 (감사 증적)">CSV 내려받기</button>
      </div>
      <div class="bulk-bar" data-bulk hidden>
        <b data-bulk-count></b>
        <input class="input" data-bulk-note maxlength="2000" placeholder="조치 내용 (선택, 처리 기록에 남음)" aria-label="조치 내용">
        <button class="btn" data-bulk-act="ack">확인</button>
        ${can('alerts.handle') ? html`${resolutionSelect('bulk')}<button class="btn primary" data-bulk-act="resolve">해결</button>` : ''}
        <button class="btn ghost" data-bulk-clear>선택 해제</button>
        <span data-bulk-msg></span>
      </div>
      ${items.length ? html`<div class="table-wrap"><table class="table alert-table">
        <thead><tr><th class="pick"><input type="checkbox" data-all aria-label="보이는 알림 모두 선택"></th><th>발생 시각</th><th>심각도</th><th>규칙</th><th>대상</th><th class="r">건수</th><th>처리</th><th>전송</th></tr></thead>
        <tbody>${items.map((a) => html`<tr class="clickable ${a.status === 'resolved' ? 'row-done' : ''}" data-id="${a.id}">
          <td class="pick"><input type="checkbox" data-sel="${a.id}" ${selected.has(a.id) ? 'checked' : ''} aria-label="알림 #${a.id} 선택"></td>
          <td class="nowrap num muted" title="${fmtRelative(a.fired_at)}">${fmtTime(a.fired_at)}</td>
          <td class="nowrap">${severityBadge(a.severity)}</td>
          <td class="nowrap"><b>${a.rule}</b></td>
          <td class="nowrap">${a.group_key || '–'}</td>
          <td class="r num">${a.event_count ? fmtNum(a.event_count) : '–'}</td>
          <td class="nowrap">${statusChip(a)}${a.note_count ? html` <span class="muted note-count" title="메모 ${a.note_count}개">메모 ${a.note_count}</span>` : ''}</td>
          <td class="dlv-cell">${deliveryChips(a.deliveries)}</td>
        </tr>`)}</tbody></table></div>
        ${items.length >= HISTORY_LIMIT ? html`<p class="muted rule-foot">최근 ${HISTORY_LIMIT}건까지 보입니다. 기간 안의 목록은 CSV 로 내려받으세요(최대 1만 건).</p>` : ''}`
        : html`<div class="empty">${EMPTY_TEXT[status]}</div>`}
    </section>`;

    el.querySelector('[data-csv]').addEventListener('click', () => exportCsv('/api/alerts', { since, status }, { what: '알림 이력' }));
    bindHistoryToolbar(el);
    el.querySelectorAll('tr[data-id]').forEach((tr) => tr.addEventListener('click', (e) => {
      if (e.target.closest('.pick')) return;
      openAlert(tr.dataset.id, { onChange: load });
    }));
    const bar = el.querySelector('[data-bulk]');
    const boxes = [...el.querySelectorAll('[data-sel]')];
    const all = el.querySelector('[data-all]');
    const sync = () => {
      bar.hidden = !selected.size;
      bar.querySelector('[data-bulk-count]').textContent = `${fmtNum(selected.size)}건 선택`;
      if (all) {
        all.checked = selected.size > 0 && selected.size === boxes.length;
        all.indeterminate = selected.size > 0 && selected.size < boxes.length;
      }
    };
    boxes.forEach((cb) => cb.addEventListener('change', () => {
      if (cb.checked) selected.add(Number(cb.dataset.sel)); else selected.delete(Number(cb.dataset.sel));
      sync();
    }));
    all?.addEventListener('change', () => {
      boxes.forEach((cb) => { cb.checked = all.checked; if (all.checked) selected.add(Number(cb.dataset.sel)); else selected.delete(Number(cb.dataset.sel)); });
      sync();
    });
    bar.querySelector('[data-bulk-clear]').addEventListener('click', () => { selected.clear(); boxes.forEach((cb) => { cb.checked = false; }); sync(); });
    bar.querySelectorAll('[data-bulk-act]').forEach((b) => b.addEventListener('click', async () => {
      const action = b.dataset.bulkAct;
      const label = action === 'resolve' ? '해결로 표시' : '확인으로 표시';
      const resolution = action === 'resolve' ? bar.querySelector('[data-bulk-resolution]').value : null;
      if (action === 'resolve' && !resolution) {
        bar.querySelector('[data-bulk-msg]').innerHTML = errorBox(new Error('종료 분류를 고르세요'));
        bar.querySelector('[data-bulk-resolution]').focus();
        return;
      }
      const ok = await confirmModal({ title: `알림 ${label}`, message: `선택한 알림 ${selected.size}건을 ${label}할까요?`, confirmText: label });
      if (!ok) return;
      b.disabled = true;
      try {
        const res = await api.send('POST', '/api/alerts/handle', { ids: [...selected], action, resolution,
          note: bar.querySelector('[data-bulk-note]').value.trim() });
        selected.clear();
        await load();
        const skipped = res.unchanged.length ? ` · 이미 처리된 ${res.unchanged.length}건은 그대로` : '';
        root.querySelector('[data-tab] .rule-toolbar')?.insertAdjacentHTML('afterend',
          String(html`<div class="hint-box bulk-done">✓ ${res.changed.length}건 ${action === 'resolve' ? '해결' : '확인'}${skipped}</div>`));
      } catch (err) {
        b.disabled = false;
        bar.querySelector('[data-bulk-msg]').innerHTML = errorBox(err);
      }
    }));
    sync();
  }

  // ------------------------------------------------------------------ 무음
  function renderSilences(data) {
    const el = root.querySelector('[data-tab]');
    const handler = can('alerts.handle');
    const order = { active: 0, upcoming: 1, ended: 2 };
    const items = [...data.items].sort((a, b) => order[a.state] - order[b.state] || new Date(b.starts_at) - new Date(a.starts_at));
    el.innerHTML = html`<section class="card">
      <div class="rule-toolbar">
        <p class="muted" style="margin:0;font-size:13px;flex:1 1 320px">무음 동안 발생한 알림은 이력에 '무음'으로 남고 보내지 않습니다.
          무음이 끝난 뒤에도 문제가 계속되면(새 로그가 들어오면) 재알림 간격과 상관없이 바로 다시 알립니다. 지금부터 ${data.max_days}일 안에 끝나야 합니다.</p>
        ${handler ? html`<button class="btn primary" data-new><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>무음 추가</button>` : ''}
      </div>
      ${items.length ? html`<div class="table-wrap"><table class="table">
        <thead><tr><th>상태</th><th>범위</th><th>기간</th><th>사유</th><th class="r">보내지 않은 알림</th><th>만든 사람</th><th></th></tr></thead>
        <tbody>${items.map((m) => {
          const [cls, label] = SILENCE_STATE[m.state];
          return html`<tr class="${m.state === 'ended' ? 'row-done' : ''}">
            <td class="nowrap"><span class="status ${cls}"><span class="dot"></span>${label}</span></td>
            <td><b>${silenceScope(m)}</b></td>
            <td class="nowrap num">${fmtTime(m.starts_at, { seconds: false })} ~ ${fmtTime(m.ends_at, { seconds: false })}
              ${m.ended_by ? html`<div class="muted" style="font-size:12px">${m.ended_by} 님이 일찍 해제</div>` : ''}</td>
            <td class="ink-2">${m.reason}</td>
            <td class="r num">${fmtNum(m.suppressed)}</td>
            <td class="nowrap">${m.created_by}<div class="muted" style="font-size:12px">${fmtRelative(m.created_at)}</div></td>
            <td class="r">${handler && m.state !== 'ended' ? html`<button class="btn sm" data-end="${m.id}">${m.state === 'active' ? '해제' : '취소'}</button>` : ''}</td>
          </tr>`;
        })}</tbody></table></div>`
        : html`<div class="empty">적용 중이거나 최근(${RANGES.find(([v]) => v === since)?.[1]})에 끝난 무음이 없습니다.</div>`}
    </section>`;
    el.querySelector('[data-new]')?.addEventListener('click', openSilenceEditor);
    el.querySelectorAll('[data-end]').forEach((b) => b.addEventListener('click', async () => {
      const m = items.find((x) => String(x.id) === b.dataset.end);
      const verb = m.state === 'active' ? '해제' : '취소';
      // 확인창 기본 '취소' 버튼과 '무음 취소'가 같은 글자가 되지 않게 닫기 버튼 문구를 바꾼다
      const ok = await confirmModal({ title: `무음 ${verb}`, message: `무음 '${silenceScope(m)}' 을 지금 ${verb}할까요?`,
        confirmText: `무음 ${verb}`, cancelText: '그대로 두기', danger: m.state === 'active' });
      if (!ok) return;
      b.disabled = true;
      try {
        await api.send('DELETE', `/api/alerts/silences/${m.id}`);
        toast(`무음을 ${verb}했습니다.`, { type: 'success' });
        load();
      } catch (err) {
        b.disabled = false;
        toast(err.message, { type: 'error' });
      }
    }));
  }

  function openSilenceEditor() {
    const toInput = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    const start = new Date();
    const body = openDrawer({ title: '무음 추가', subtitle: '점검·배포 시간대에 예상되는 알림을 보내지 않습니다' });
    body.innerHTML = html`<div class="inline-form">
      <div class="form-row">
        <label class="field"><span>규칙</span><select class="select" data-rule>
          <option value="">모든 규칙</option>
          ${[...config.rules].sort((a, b) => (a.sid ?? 1e9) - (b.sid ?? 1e9)).map((r) => html`<option value="${r.name}">${r.sid ? `${r.sid} · ` : ''}${r.name}</option>`)}
        </select></label>
        <label class="field"><span>대상 (비우면 모든 대상)</span><input class="input" data-key maxlength="500" placeholder="예: WEB-01 — 규칙의 묶음 기준 값(PC·IP·사용자)"></label>
      </div>
      <div class="form-row">
        <label class="field"><span>시작</span><input class="input" type="datetime-local" data-start value="${toInput(start)}"></label>
        <label class="field"><span>끝</span><input class="input" type="datetime-local" data-end value="${toInput(new Date(start.getTime() + 3600e3))}"></label>
      </div>
      <div class="toolbar" data-quick><span class="muted" style="font-size:12.5px">시작부터</span>${SILENCE_DURATIONS.map(([sec, label]) => html`
        <button type="button" class="btn sm" data-sec="${sec}">${label}</button>`)}</div>
      <label class="field"><span>사유 <em>*</em></span><input class="input" data-reason maxlength="500" placeholder="예: 정기 패치 작업 (변경 요청 CR-1234)"></label>
      <p class="muted" style="margin:0;font-size:12.5px">모든 규칙·모든 대상이면 그 시간 동안 어떤 알림도 보내지 않습니다. 감사 로그에 기록됩니다.</p>
      <div class="toolbar"><button class="btn primary" data-save>무음 걸기</button></div>
      <div data-msg></div></div>`;
    const startEl = body.querySelector('[data-start]');
    const endEl = body.querySelector('[data-end]');
    body.querySelectorAll('[data-sec]').forEach((b) => b.addEventListener('click', () => {
      const from = startEl.value ? new Date(startEl.value) : new Date();
      endEl.value = toInput(new Date(from.getTime() + Number(b.dataset.sec) * 1000));
    }));
    body.querySelector('[data-save]').addEventListener('click', async (e) => {
      const reason = body.querySelector('[data-reason]').value.trim();
      if (!reason) { body.querySelector('[data-reason]').focus(); return; }
      if (!endEl.value) { endEl.focus(); return; }
      const key = body.querySelector('[data-key]').value.trim();
      e.target.disabled = true;
      try {
        await api.send('POST', '/api/alerts/silences', {
          rule: body.querySelector('[data-rule]').value || null, group_key: key || null, reason,
          starts_at: startEl.value ? new Date(startEl.value).toISOString() : null, ends_at: new Date(endEl.value).toISOString(),
        });
        closeDrawer();
        load();
      } catch (err) {
        e.target.disabled = false;
        body.querySelector('[data-msg]').innerHTML = errorBox(err);
      }
    });
  }

  // ------------------------------------------------------------ 규칙 관리
  function groupsOf(rules) {
    const order = [];
    rules.forEach((r) => { if (!order.includes(r.group)) order.push(r.group); });
    return order.map((g) => {
      const items = rules.filter((r) => r.group === g);
      return { name: g, total: items.length, on: items.filter((r) => r.enabled).length };
    });
  }

  /** 규칙별 데이터 유무 (B-37 2단계): '채널 82/120 PC' — 빠진 PC 가 있으면 경고 색, 이벤트 ID 는 드물 수 있어 숫자만 */
  function coverageBadge(r) {
    const c = r.coverage;
    if (!c || !c.pcs) return '';
    const parts = [];
    if (c.channel_pcs != null) parts.push(`${c.channels.join(', ')} ${fmtNum(c.channel_pcs)}/${fmtNum(c.pcs)} PC`);
    // 규칙이 채널을 정하지 않으면 그 이벤트 ID 가 실제로 오는 채널로 본다 (4625 → Security)
    if (c.event_pcs != null) parts.push(`이벤트 ${fmtNum(c.event_pcs)}/${fmtNum(c.pcs)} PC`);
    const tip = [
      `대상 PC ${fmtNum(c.pcs)}대 (최근 7일 같은 소스를 보낸 PC)`,
      c.channel_pcs != null ? `채널 ${c.channels.join(', ')} 을(를) 7일 안에 보낸 PC ${fmtNum(c.channel_pcs)}대${c.channels_implied ? ' (규칙에 채널이 없어 이벤트 ID 가 오는 채널로 봄)' : ''}` : '',
      c.event_pcs != null ? `이벤트 ${c.event_ids.join(', ')} 을(를) 30일 안에 보낸 PC ${fmtNum(c.event_pcs)}대 — 드물게 나는 이벤트는 적어도 정상` : '',
      c.missing_total ? `채널을 보내지 않는 PC ${fmtNum(c.missing_total)}대: ${c.missing.join(', ')}${c.missing_total > c.missing.length ? ' …' : ''} — 감사 정책·에이전트 설정을 확인하세요` : '',
    ].filter(Boolean).join('\n');
    return html`<div class="rule-coverage ${c.missing_total ? 'gap' : ''}" title="${tip}">데이터 ${parts.join(' · ')}</div>`;
  }

  function criteria(r) {
    if (r.kind === 'agent_silent') return `${fmtDuration(r.silent_for_sec)} 이상 수신 없음`;
    if (r.kind === 'stream_silent') return '늘 오던 채널이 평소보다 오래 조용함 (PC 는 살아 있음)';
    if (r.kind === 'new_terms') {
      return `처음 보는 ${r.fields.map((k) => GROUP_LABELS[k] ?? k.replace(/^f\./, '')).join(' + ')} · ${fmtDuration(r.history_sec)} 동안 없던 값`;
    }
    const by = r.group_by === 'none' ? '전체 합산' : `${GROUP_LABELS[r.group_by] ?? r.group_by.replace(/^f\./, '')}별`;
    const distinct = r.distinct?.field ? ` · 서로 다른 ${GROUP_LABELS[r.distinct.field] ?? r.distinct.field} ${fmtNum(r.distinct.min)}↑` : '';
    return `${fmtDuration(r.window_sec)} 동안 ${fmtNum(r.threshold)}건↑${distinct} · ${by}`;
  }

  // 규칙 평가 상태 (ADR-045)
  const RUN_LEVEL = { error: 'bad', timeout: 'bad', stale: 'bad', truncated: 'warn', slow: 'warn', ok: 'ok' };

  function runChip(r) {
    const run = r.run || {};
    const tip = run.last_run_at ? `마지막 평가 ${fmtRelative(run.last_run_at)} · ${(run.duration_ms / 1000).toFixed(2)}초`
      + ` · 기준 넘은 묶음 ${fmtNum(run.candidates || 0)}개 · 알림 ${fmtNum(run.fired || 0)}건` : '';
    return html`<span class="run-chip ${RUN_LEVEL[run.state] ?? ''}" title="${tip}">${run.label ?? '–'}</span>${r.kind === 'new_terms' && r.enabled ? termsChip(run.terms) : ''}`;
  }

  // 처음 보는 값 규칙(B-47): 배우는 중이면 알리지 않는다는 것을 보여 준다 — '조용함'을 '처음 보는 값 없음'으로 읽지 않게
  function termsChip(t) {
    if (!t) return '';
    const held = `값 ${fmtNum(t.terms)} / ${fmtNum(t.max)}`;
    if (t.backfilling) {
      // 남은 구간 — 주기마다 남은 것 기준의 % 는 거의 끝날 때까지 몇 %에 머물렀다(검토)
      return html`<div class="run-chip warn" title="${t.reason ?? ''} — 지난 로그로 배우는 동안 알림을 미룹니다">거슬러 배우는 중 (${fmtDuration(t.backfill_left_sec)} 치 남음) · ${held}</div>`;
    }
    const learning = t.learn_until && new Date(t.learn_until) > new Date();
    if (learning) {
      const days = Math.ceil((new Date(t.learn_until) - new Date()) / 86400000);
      return html`<div class="run-chip warn" title="배우는 동안 처음 본 값은 알리지 않고 기억만 합니다">배우는 중 (${days}일 남음) · ${held}</div>`;
    }
    return html`<div class="run-chip ${t.overflow ? 'bad' : ''}">${held}${t.overflow ? ` · 이번 평가에서 상한 넘음 ${fmtNum(t.overflow)}` : ''}</div>`;
  }

  function runError(r) {
    const run = r.run || {};
    if (run.state !== 'error' && run.state !== 'timeout') return '';
    const since = run.error_since ? `${fmtRelative(run.error_since).replace(/ 전$/, '')}째 ` : '';
    return html`<div class="rule-run-error">⚠ ${since}동작하지 않음: ${run.error}${run.state === 'timeout'
      ? ' — 조건을 좁히고 미리보기로 확인하세요' : ''}</div>`;
  }

  // 규칙 탭은 입력 중일 수 있어 표를 다시 그리지 않고 상태 띠와 평가 칸만 바꾼다
  async function refreshRuns() {
    try {
      config = await api.get('/api/alerts/config', { since });
    } catch {
      return;
    }
    renderStatus();
    for (const r of config.rules) {
      const cell = root.querySelector(`[data-run="${CSS.escape(r.name)}"]`);
      if (cell) cell.innerHTML = runChip(r);
      const err = root.querySelector(`[data-run-error="${CSS.escape(r.name)}"]`);
      if (err) err.innerHTML = runError(r);
    }
  }

  function renderRules() {
    const el = root.querySelector('[data-tab]');
    const admin = can('alerts.manage');
    const groups = groupsOf(config.rules);
    if (ui.group && !groups.some((g) => g.name === ui.group)) ui.group = '';
    const q = ui.q.trim().toLowerCase();
    const shown = config.rules.filter((r) => (!ui.group || r.group === ui.group)
      && (ui.state === 'all' || (ui.state === 'observe' ? r.mode === 'observe' : (ui.state === 'on') === r.enabled))
      && (!q || [r.name, r.description, String(r.sid ?? ''), ...r.tags, matchText(r.match)].join(' ').toLowerCase().includes(q)));
    const allOn = config.rules.filter((r) => r.enabled).length;
    const observing = shown.filter((r) => r.mode === 'observe');

    el.innerHTML = html`<div class="rules-layout">
      <section class="card rule-groups">
        <div class="card-head"><h2 class="card-title">규칙 묶음</h2></div>
        <div class="group-list">
          <button type="button" class="group-item ${ui.group ? '' : 'on'}" data-group="">
            <span class="group-name">전체</span><span class="group-count num">${allOn}/${config.rules.length}</span></button>
          ${groups.map((g) => html`<div class="group-item ${ui.group === g.name ? 'on' : ''}" data-group="${g.name}" role="button" tabindex="0">
            <span class="group-name">${g.name}</span><span class="group-count num">${g.on}/${g.total}</span>
            ${admin ? html`<button type="button" class="switch sm ${g.on === g.total ? 'on' : g.on ? 'part' : ''}" role="switch"
              aria-checked="${g.on === g.total ? 'true' : g.on ? 'mixed' : 'false'}" data-group-toggle="${g.name}"
              title="${g.on === g.total ? '묶음 전체 끄기' : '묶음 전체 켜기'}"></button>` : ''}
          </div>`)}
        </div>
      </section>
      <section class="card rule-main">
        <div class="rule-toolbar">
          <input class="input" type="search" data-q value="${ui.q}" placeholder="이름·SID·태그·조건 검색" aria-label="규칙 검색">
          <div class="seg" data-state>${[['all', '전체'], ['on', '사용'], ['observe', '관찰'], ['off', '꺼짐']].map(([k, l]) => html`
            <button type="button" data-v="${k}" class="${ui.state === k ? 'on' : ''}">${l}</button>`)}</div>
          <span style="flex:1"></span>
          ${admin && observing.length ? html`<button class="btn" data-promote title="관찰 중인 규칙이 알림을 보내게 합니다">관찰 끝내기 (${observing.length})</button>` : ''}
          ${admin ? html`<button class="btn ghost" data-yaml title="config/alerts.yaml 을 직접 편집">YAML 편집</button>
            <button class="btn primary" data-new><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>규칙 추가</button>` : ''}
        </div>
        ${config.routes?.length ? html`<div class="hint-box" style="margin:0 0 10px">
          <b>받는 곳 경로</b> — 규칙의 받는 곳에 더하거나(또는 갈아 끼우거나) 위에서부터 맞는 것을 적용합니다 (YAML 편집의 <code>routes</code>).
          <ul style="margin:4px 0 0;padding-left:18px">${config.routes.map((r) => html`<li><b>${r.name}</b>
            <span class="muted">${[r.groups.length ? `묶음 ${r.groups.join(', ')}` : '', r.tags.length ? `태그 ${r.tags.join(', ')}` : '',
              r.severities.length ? r.severities.map((s) => SEVERITIES[s]?.label ?? s).join('·') : '', r.rules.length ? `규칙 ${r.rules.join(', ')}` : '',
              r.hosts.length ? `PC ${r.hosts.join(', ')}` : ''].filter(Boolean).join(' · ') || '모든 알림'}</span>
            → ${r.replace ? '대신 ' : '더함 '}${r.notify.join(', ')}${r.continue ? ' (다음 경로도 봄)' : ''}</li>`)}</ul></div>` : ''}
        ${config.escalations?.length ? html`<div class="hint-box" style="margin:0 0 10px">
          <b>에스컬레이션</b> — 확인(또는 해결)되지 않은 알림을 기한이 지나면 다른 받는 곳에 다시 알립니다 (YAML 편집의 <code>escalations</code>).
          <ul style="margin:4px 0 0;padding-left:18px">${config.escalations.map((p) => html`<li><b>${p.name}</b>
            <span class="muted">${p.severities.length ? p.severities.map((s) => SEVERITIES[s]?.label ?? s).join('·') : '모든 심각도'}${p.rules.length ? ` · 규칙 ${p.rules.join(', ')}` : ''}</span>:
            ${p.steps.map((s) => `${fmtDuration(s.after_sec)} ${s.unless === 'acked' ? '미확인' : '미해결'} → ${s.notify.join(', ')}`).join(' / ')}
            ${p.ack_timeout_sec ? ` / 확인한 뒤 ${fmtDuration(p.ack_timeout_sec)} 미해결 → 다시 엶·${p.steps[0].notify.join(', ')}` : ''}</li>`)}</ul></div>` : ''}
        ${shown.length ? html`<div class="table-wrap"><table class="table rules-table">
          <thead><tr><th>사용</th><th>SID</th><th>규칙</th><th>조건 · 기준</th><th>받는 곳</th><th>평가</th><th class="r">발생</th></tr></thead>
          <tbody>${shown.sort((a, b) => (a.sid ?? 1e9) - (b.sid ?? 1e9)).map((r) => html`
            <tr class="${admin ? 'clickable' : ''} ${r.enabled ? '' : 'rule-off'}" data-rule="${r.name}">
              <td>${admin ? html`<button type="button" class="switch ${r.enabled ? 'on' : ''}" role="switch" aria-checked="${r.enabled}"
                  data-toggle="${r.name}" aria-label="${r.name} 사용"></button>`
                : html`<span class="muted">${r.enabled ? '사용' : '꺼짐'}</span>`}</td>
              <td class="nowrap mono muted">${r.sid ?? '–'}</td>
              <td class="rule-cell">
                <div class="rule-title">${severityBadge(r.severity)}<b>${r.name}</b>${r.mode === 'observe'
                  ? html` <span class="ast silenced" title="관찰 모드 — 알림을 기록만 하고 보내지 않습니다">관찰</span>` : ''}</div>
                ${r.description ? html`<div class="rule-desc">${r.description}</div>` : ''}
                ${r.tags.length ? html`<div class="rule-tags">${r.tags.map((t) => html`<span class="type-tag">${t}</span>`)}</div>` : ''}
                <div data-run-error="${r.name}">${runError(r)}</div>
              </td>
              <td class="rule-cond"><div class="ink-2">${r.kind === 'agent_silent' ? (r.hosts.length ? r.hosts.join(', ') : '모든 PC')
                : r.kind === 'stream_silent' ? `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'} · ${r.channels.length ? r.channels.join(', ') : '모든 채널'}`
                : matchText(r.match)}</div>
                <div class="muted rule-crit">${criteria(r)}</div>${coverageBadge(r)}</td>
              <td class="ink-2">${r.notify.join(', ')}${r.unknown_notify.length
                ? html`<div class="tag-bad" style="font-size:12px">없는 대상: ${r.unknown_notify.join(', ')}</div>` : ''}</td>
              <td class="nowrap" data-run="${r.name}">${runChip(r)}</td>
              <td class="r nowrap"><span class="num">${fmtNum(r.fired)}</span>
                ${r.last_fired_at ? html`<div class="muted" style="font-size:12px">${fmtRelative(r.last_fired_at)}</div>` : ''}${qualityLine(r.quality)}</td>
            </tr>`)}</tbody></table></div>`
          : html`<div class="empty">${config.rules.length ? '조건에 맞는 규칙이 없습니다' : '규칙이 없습니다. \'규칙 추가\'로 만드세요.'}</div>`}
        <p class="muted rule-foot">발생 수는 선택한 기간(${RANGES.find(([v]) => v === since)?.[1]}) 기준입니다.
          ${admin ? '행을 누르면 규칙을 고칩니다. 스위치는 바로 저장됩니다.' : '규칙 변경은 관리자나 알림 규칙 관리 권한이 있는 그룹만 할 수 있습니다.'}</p>
      </section>
    </div>`;

    el.querySelectorAll('[data-group]').forEach((b) => b.addEventListener('click', (e) => {
      if (e.target.closest('[data-group-toggle]')) return;
      ui.group = b.dataset.group;
      store.set('wlm.rules.group', ui.group);
      renderRules();
    }));
    el.querySelectorAll('.group-item[role="button"]').forEach((b) => b.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); b.click(); }
    }));
    const search = el.querySelector('[data-q]');
    search.addEventListener('input', () => {
      ui.q = search.value;
      const pos = search.selectionStart;
      renderRules();
      const again = root.querySelector('[data-q]');
      again.focus();
      again.setSelectionRange(pos, pos);
    });
    el.querySelectorAll('[data-state] button').forEach((b) => b.addEventListener('click', () => { ui.state = b.dataset.v; renderRules(); }));
    el.querySelector('[data-new]')?.addEventListener('click', () => openRuleEditor({
      config, onSaved: load, rule: null, defaults: { group: ui.group } }));
    el.querySelector('[data-yaml]')?.addEventListener('click', openYamlEditor);
    el.querySelector('[data-promote]')?.addEventListener('click', async (e) => {
      const names = observing.map((r) => r.name);
      const ok = await confirmModal({
        title: '관찰 끝내기',
        message: `관찰 중인 규칙 ${names.length}개(${names.slice(0, 5).join(', ')}${names.length > 5 ? ' …' : ''})가 이제 알림을 보냅니다.`,
        confirmText: '알림 보내기',
      });
      if (!ok) return;
      e.target.disabled = true;
      try {
        await api.send('POST', '/api/alerts/rules/mode', { names, mode: 'active' });
        toast(`규칙 ${names.length}개가 이제 알림을 보냅니다.`, { type: 'success' });
        load();
      } catch (err) {
        e.target.disabled = false;
        toast(err.message, { type: 'error' });
      }
    });
    el.querySelectorAll('tr[data-rule]').forEach((tr) => tr.addEventListener('click', (e) => {
      if (!admin || e.target.closest('[data-toggle]')) return;
      openRuleEditor({ config, onSaved: load, rule: config.rules.find((r) => r.name === tr.dataset.rule) });
    }));
    el.querySelectorAll('[data-toggle]').forEach((sw) => sw.addEventListener('click', () => {
      const rule = config.rules.find((r) => r.name === sw.dataset.toggle);
      toggle([rule.name], !rule.enabled, sw);
    }));
    el.querySelectorAll('[data-group-toggle]').forEach((sw) => sw.addEventListener('click', async () => {
      const items = config.rules.filter((r) => r.group === sw.dataset.groupToggle);
      const turnOn = items.some((r) => !r.enabled);
      if (!turnOn) {
        const ok = await confirmModal({
          title: '규칙 묶음 끄기',
          message: `'${sw.dataset.groupToggle}' 묶음의 규칙 ${items.length}개를 모두 끌까요?`,
          confirmText: '모두 끄기',
        });
        if (!ok) return;
      }
      toggle(items.map((r) => r.name), turnOn, sw);
    }));
  }

  /** 규칙별 90일 품질 (B-44): 오탐률(분류한 것 중, 표본 수와 함께)·사람이 해결한 평균 시간 */
  function qualityLine(q) {
    if (!q) return '';
    const judged = q.tp + q.fp;
    const parts = [];
    if (judged) parts.push(html`<span class="${q.fp_rate >= 0.5 && judged >= 5 ? 'tag-bad' : ''}">오탐 ${Math.round(q.fp_rate * 100)}%</span> <span class="muted">(${fmtNum(judged)}건 중)</span>`);
    if (q.mttr_sec != null) parts.push(html`<span class="muted">해결 평균 ${fmtDuration(q.mttr_sec)}</span>`);
    return parts.length ? html`<div style="font-size:12px" title="최근 90일: 발생 ${fmtNum(q.n)} · 정탐 ${fmtNum(q.tp)} · 오탐 ${fmtNum(q.fp)} · 판단 불가 ${fmtNum(q.undetermined)} · 자동 해소 ${fmtNum(q.auto)}">${parts.map((p, i) => html`${i ? html`<br>` : ''}${p}`)}</div>` : '';
  }

  async function toggle(names, enabled, sw) {
    sw.disabled = true;
    try {
      await api.send('POST', '/api/alerts/rules/enabled', { names, enabled });
      config.rules.forEach((r) => { if (names.includes(r.name)) r.enabled = enabled; });
      renderStatus();
      renderRules();
      toast(names.length > 1 ? `규칙 ${names.length}개가 ${enabled ? '켜졌습니다' : '꺼졌습니다'}.` : `규칙이 ${enabled ? '켜졌습니다' : '꺼졌습니다'}.`, { type: 'success' });
    } catch (err) {
      sw.disabled = false;
      toast(err.message, { type: 'error' });
    }
  }

  function openYamlEditor() {
    const body = openDrawer({ title: '규칙 파일 직접 편집 (고급)', subtitle: 'config/alerts.yaml — 저장 전에 전체를 검증합니다' });
    body.innerHTML = html`
      <p class="hint-box" style="margin:0 0 10px">대부분은 '규칙 관리' 화면으로 충분합니다. 여러 규칙을 한꺼번에 옮기거나 주석을 고칠 때만 쓰세요.</p>
      <textarea class="input editor" spellcheck="false" data-yaml>${config?.yaml ?? ''}</textarea>
      <div class="toolbar" style="margin:10px 0"><button class="btn primary" data-save>검증 후 저장</button>
        <span class="muted" style="font-size:12.5px">오류가 있으면 저장되지 않습니다.</span></div>
      <div data-msg></div>`;
    const msg = body.querySelector('[data-msg]');
    body.querySelector('[data-save]').addEventListener('click', async () => {
      try {
        const res = await api.send('PUT', '/api/alerts/config', body.querySelector('[data-yaml]').value);
        msg.innerHTML = html`<div class="hint-box">✓ 저장됨 — 규칙 ${res.rules}개</div>`;
        setTimeout(() => { closeDrawer(); load(); }, 700);
      } catch (err) {
        msg.innerHTML = errorBox(err);
      }
    });
  }

  // ------------------------------------------------------------ 알림 대상
  // 받는 곳마다 최근 전송 상태 (ADR-045, 서버를 다시 시작하면 처음부터)
  function targetLine(n) {
    const h = n.health || {};
    const waiting = h.queued ? ` · 대기 ${fmtNum(h.queued)}건` : '';
    if (h.state === 'failing') {
      return html`<div class="tag-bad" style="font-size:12.5px;margin-top:4px">● 실패 중 · ${fmtRelative(h.failing_since).replace(/ 전$/, '')}째${waiting}
        <div class="muted" style="font-weight:400">마지막 오류: ${h.last_error ?? ''}</div></div>`;
    }
    if (h.state === 'error') return '';   // 설정 오류는 아래 상자에
    return html`<div class="${h.state === 'ok' ? 'tag-good' : 'muted'}" style="font-size:12.5px;margin-top:4px">● ${h.state === 'ok'
      ? `정상 · 마지막 전송 ${fmtRelative(h.last_ok_at)}` : '아직 보낸 적 없음 (서버 시작 뒤)'}${waiting}</div>`;
  }

  function renderNotifiers() {
    const el = root.querySelector('[data-tab]');
    if (!config.notifiers.length) {
      el.innerHTML = '<section class="card"><div class="empty">알림 대상이 없습니다. 환경설정에서 수신 그룹이나 외부 연동을 만드세요.</div></section>';
      return;
    }
    el.innerHTML = html`<div class="target-grid">${config.notifiers.map((n) => html`
      <section class="card"><div class="card-body notifier">
        <div class="notifier-top"><b>${n.name}</b><span class="type-tag">${TYPE_LABELS[n.type] ?? n.type}</span>
          ${can('alerts.manage') ? html`<button class="btn sm" data-test="${n.name}">테스트 발송</button>` : ''}</div>
        <div class="muted mono" style="font-size:12px;overflow-wrap:anywhere">${n.target || '–'}</div>
        <div class="muted" style="font-size:12.5px;margin-top:4px">${n.used_by.length ? `규칙 ${n.used_by.length}개에서 사용: ${n.used_by.slice(0, 4).join(', ')}${n.used_by.length > 4 ? ' …' : ''}` : '규칙에서 사용 안 함'}</div>
        ${targetLine(n)}
        ${n.error ? html`<div class="error-box" style="margin-top:6px">${n.error}</div>` : ''}
        <div data-result="${n.name}"></div>
      </div></section>`)}</div>
      <p class="muted" style="font-size:12.5px;margin:12px 2px 0">받는 사람·그룹·메신저·Oracle·메일 서버는 ${can('settings.manage')
        ? html`<a href="#/settings/groups">환경설정</a>` : '환경설정(관리자)'}에서 관리합니다.</p>`;
    el.querySelectorAll('[data-test]').forEach((b) => b.addEventListener('click', async () => {
      const out = el.querySelector(`[data-result="${b.dataset.test}"]`);
      b.disabled = true;
      out.innerHTML = html`<div class="muted" style="font-size:12.5px;margin-top:6px">보내는 중…</div>`;
      try {
        await api.send('POST', `/api/alerts/test/${encodeURIComponent(b.dataset.test)}`);
        out.innerHTML = html`<div class="hint-box" style="margin-top:6px">✓ 전송 성공 — 받는 쪽에서 확인하세요</div>`;
      } catch (err) {
        out.innerHTML = errorBox(err);
      } finally {
        b.disabled = false;
      }
    }));
  }

  // ------------------------------------------------------------------ 규칙 예외 (B-46)
  function renderExceptions(data) {
    const el = root.querySelector('[data-tab]');
    el.innerHTML = html`<div class="toolbar" style="margin:14px 0;gap:12px;flex-wrap:wrap">
        <p class="muted" style="margin:0;font-size:13px;flex:1 1 320px">규칙에서 늘 빼야 하는 조건 하나(백업 서비스 계정, 유지보수 업체 IP 등)를 사유와 함께 둡니다 —
          규칙 문장을 고치지 않아도 되고, 누가·왜·언제까지 뺐는지 남습니다. 무음과 달리 만료가 없을 수 있으니 검토일을 정해 두세요.</p>
        <button class="btn primary" data-new><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>예외 추가</button></div>
      ${data.items.length ? html`<section class="card"><div class="table-wrap"><table class="table"><thead><tr>
          <th>상태</th><th>규칙</th><th>제외 조건</th><th>사유</th><th>만든 사람</th><th>만료</th><th>검토일</th><th></th></tr></thead>
        <tbody>${data.items.map((e) => html`<tr>
          <td class="nowrap">${statusBadgeText(EXCEPTION_STATE[e.state])}</td><td>${e.rule}</td><td class="nowrap"><code>${e.term}</code></td>
          <td class="ink-2">${e.reason}</td><td class="nowrap muted">${e.created_by} · ${fmtTime(e.created_at, { seconds: false })}</td>
          <td class="nowrap">${e.expires_at ? fmtTime(e.expires_at, { seconds: false }) : html`<span class="muted">없음</span>`}</td>
          <td class="nowrap">${e.review_at ? fmtTime(e.review_at, { seconds: false }) : '–'}</td>
          <td class="r">${e.state === 'active' ? html`<button class="btn sm" data-end="${e.id}">끝내기</button>`
            : e.ended_by ? html`<span class="muted" style="font-size:12px">${e.ended_by}</span>` : ''}</td></tr>`)}</tbody></table></div></section>`
        : html`<div class="empty">규칙 예외가 없습니다.</div>`}`;
    el.querySelector('[data-new]').addEventListener('click', () => exceptionForm(data.rules));
    el.querySelectorAll('[data-end]').forEach((b) => b.addEventListener('click', async () => {
      const e = data.items.find((x) => String(x.id) === b.dataset.end);
      const ok = await confirmModal({ title: '예외 끝내기', message: `'${e.rule}' 에서 ${e.term} 을(를) 다시 잡습니다. 끝낼까요?`,
        confirmText: '끝내기', cancelText: '그대로 두기' });
      if (!ok) return;
      try {
        await api.send('POST', `/api/alerts/exceptions/${e.id}/end`, {});
        toast('예외를 끝냈습니다 — 다음 평가부터 다시 잡습니다', { type: 'success' });
        load();
      } catch (err) {
        toast(err.message, { type: 'error' });
      }
    }));
    if (params.rule && params.term && !renderExceptions.prefilled) {   // 알림 상세의 '예외로 빼기'에서 왔으면 한 번 열어 준다
      renderExceptions.prefilled = true;
      exceptionForm(data.rules, { rule: params.rule, term: params.term });
    }
  }

  function statusBadgeText([cls, label]) {
    return html`<span class="status ${cls}"><span class="dot"></span>${label}</span>`;
  }

  function exceptionForm(rules, preset = {}) {
    const body = openDrawer({ title: '규칙 예외 추가', subtitle: '이 조건의 이벤트는 이 규칙에서 알리지 않습니다' });
    const date = (d) => (d ? new Date(`${d}T23:59:59`).toISOString() : null);
    body.innerHTML = html`<div class="form">
      <label class="field"><span>규칙</span><select class="select" data-rule>${rules.map((r) => html`<option ${r === preset.rule ? 'selected' : ''}>${r}</option>`)}</select></label>
      <label class="field"><span>제외 조건 (하나)</span><input class="input" data-term placeholder="예) user:svc_backup · ip:10.0.0.5,10.0.0.6 · host:BACKUP-01"></label>
      <label class="field"><span>사유</span><input class="input" data-reason placeholder="예) 백업 서비스 계정 — 매일 02시 정상 로그온"></label>
      <div class="toolbar" style="gap:12px;flex-wrap:wrap">
        <label class="field"><span>만료 (선택)</span><input class="input" type="date" data-expires></label>
        <label class="field"><span>검토일 (선택)</span><input class="input" type="date" data-review></label></div>
      <div data-effect class="muted" style="font-size:13px;margin:6px 0 10px"></div>
      <div class="toolbar"><button class="btn" data-preview>미리 보기 (최근 24시간)</button><button class="btn primary" data-save>예외 걸기</button></div>
    </div>`;
    body.querySelector('[data-term]').value = preset.term || '';
    const value = () => ({ rule: body.querySelector('[data-rule]').value, term: body.querySelector('[data-term]').value.trim(),
      reason: body.querySelector('[data-reason]').value.trim(), expires_at: date(body.querySelector('[data-expires]').value),
      review_at: date(body.querySelector('[data-review]').value) });
    const effect = body.querySelector('[data-effect]');
    body.querySelector('[data-preview]').addEventListener('click', async () => {
      try {
        const r = await api.send('POST', '/api/alerts/exceptions/preview', value());
        effect.textContent = `최근 ${r.hours}시간 이 규칙에 맞은 ${fmtNum(r.matched)}건 중 ${fmtNum(r.removed)}건을 뺍니다 (조건: ${r.term})`;
      } catch (err) {
        effect.textContent = err.message;
      }
    });
    body.querySelector('[data-save]').addEventListener('click', async () => {
      try {
        const r = await api.send('POST', '/api/alerts/exceptions', value());
        closeDrawer();
        toast(`예외를 걸었습니다 — 최근 24시간 기준 ${fmtNum(r.removed)}건이 빠집니다. 다른 관리자에게도 알렸습니다`, { type: 'success' });
        load();
      } catch (err) {
        effect.textContent = err.message;
      }
    });
  }

  async function load() {
    try {
      // 다른 탭에서도 이력 탭의 숫자(기간 안 전체)를 보여 주려고 counts 만 가볍게 받는다
      const [cfg, history, silences] = await Promise.all([
        api.get('/api/alerts/config', { since }),
        api.get('/api/alerts', tab || view === 'groups' ? { since, limit: 1 } : { since, status, rule: ruleFilter, limit: HISTORY_LIMIT }),
        tab === 'silences' ? api.get('/api/alerts/silences', { since })
          : tab === 'exceptions' ? api.get('/api/alerts/exceptions')
            : !tab && view === 'groups' ? api.get('/api/alerts/groups', { since, status, rule: ruleFilter }) : null,
      ]);
      config = cfg;
      renderStatus();
      renderSummary();
      const c = history.counts;
      root.querySelector('[data-tabcount=""]').textContent = fmtNum(c.open + c.acked + c.resolved);
      if (tab === 'rules') renderRules();
      else if (tab === 'targets') renderNotifiers();
      else if (tab === 'silences') renderSilences(silences);
      else if (tab === 'exceptions') renderExceptions(silences);
      else if (view === 'groups') renderGroups(silences, c);
      else renderHistory(history.items, c);
    } catch (err) {
      const box = root.querySelector('[data-tab]');
      if (box) box.innerHTML = errorBox(err); // 세션 만료로 로그인 화면이 화면을 갈아 끼운 뒤 끝난 요청이면 무시
    }
  }

  await load();
  // 규칙 관리 화면은 입력 중일 수 있어 자동 새로고침하지 않는다. 이력에서 알림을 고르는 중일 때도 멈춘다
  timer = setInterval(() => {
    if (document.hidden || document.querySelector('.drawer')) return;
    if (tab === 'rules') refreshRuns();
    else if (tab === 'exceptions') return;   // 예외는 바뀔 일이 드물고 표를 다시 그리면 끝내기 확인이 어긋난다
    else if (!selected.size) load();
  }, 15000);
  return () => clearInterval(timer);
}
