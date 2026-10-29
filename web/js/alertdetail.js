// 알림 공용 표시: 전송 상태 칩, 처리 상태 칩, 조건 요약 문구, 알림 상세 패널(처리·메모·무음).
import * as api from './api.js';
import { can } from './auth.js';
import { openDrawer } from './drawer.js';
import { EVENT_HEAD, bindRows, eventRow } from './eventtable.js';
import { categoryLabel, levelLabel, severityBadge, sourceLabel } from './levels.js';
import { describe } from './querybox.js';
import { parseTerms } from './querylang.js';
import { errorBox, fmtDuration, fmtNum, fmtRelative, fmtTime, html } from './util.js';

const DELIVERY = {
  sent: ['✓', '전송됨'],
  pending: ['…', '전송 대기'],   // 전송기가 곧 보낸다 (ADR-045). 잡고 보내는 중이면 claimed_at
  failed: ['!', '실패 · 재시도 예정'],
  gave_up: ['✕', '실패 · 재시도 중단'],
  skipped: ['–', '건너뜀'], // 사유(받을 최소 수준 미달, 무음)는 last_error 에
};

// 처리 상태 (server: alerts.status) — 확인은 알림을 볼 수 있으면 누구나, 해결·다시 열기·무음은 alerts.handle
export const ALERT_STATUS = { open: '처리 안 됨', acked: '확인함', resolved: '해결됨' };
const NOTE_ACTIONS = { note: '메모', ack: '확인', resolve: '해결', reopen: '다시 열기' };
export const SILENCE_DURATIONS = [[3600, '1시간'], [4 * 3600, '4시간'], [86400, '하루'], [3 * 86400, '사흘']];

export function statusChip(a) {
  const who = a.status === 'resolved' ? a.resolved_by : a.status === 'acked' ? a.acked_by : '';
  return html`<span class="ast ${a.status}" title="${who ? `${who} · ${fmtTime(a.status === 'resolved' ? a.resolved_at : a.acked_at)}` : ''}">${ALERT_STATUS[a.status] ?? a.status}</span>${
    a.silence_id ? html` <span class="ast silenced" title="무음 #${a.silence_id} — 보내지 않음">무음</span>` : ''}`;
}

/** 무음 범위 문구: "로그온 실패 · PC-01" / "모든 규칙 · 모든 대상" */
export function silenceScope(s) {
  return `${s.rule ?? '모든 규칙'} · ${s.group_key == null ? '모든 대상' : s.group_key || '(대상 없음)'}`;
}

/** 같은 규칙·대상의 앞 알림과의 관계, 이 알림 뒤 이어진 이벤트, 지연 수신 (B-35). 서버 message.py 의 문구와 같은 뜻 */
function lifecycle(alert, p) {
  const lines = [];
  if (p.recurred) lines.push(`해결된 알림(#${p.previous_id}) 뒤 새로 발생했습니다 — 재알림 간격과 상관없이 알렸습니다`);
  else if (p.previous_id) lines.push(`지난 알림(#${p.previous_id}, ${fmtTime(p.previous_fired_at)}) 이후 이 대상에서 ${fmtNum(p.since_previous || 0)}건`);
  const f = alert.followup;
  if (f?.n) lines.push(`이 알림 뒤 같은 조건으로 ${fmtNum(f.n)}건 더 들어왔습니다 · 마지막 ${fmtRelative(f.last_at)}`);
  if (p.kind === 'count' && p.first_event_at && p.window_sec) {
    const lag = (new Date(p.fired_at) - new Date(p.first_event_at)) / 1000;
    if (lag > Math.max(2 * p.window_sec, p.window_sec + 3600)) {
      lines.push(`지연 수신분 포함 — 발생 시각 ${fmtTime(p.first_event_at)} ~ ${fmtTime(p.last_event_at)} (밀린 로그를 한꺼번에 받았거나 PC 시계가 틀렸을 수 있습니다)`);
    }
  }
  return lines.length ? html`<div class="hint-box" style="margin:-6px 0 14px;font-size:12.5px">${lines.map((l) => html`<div>${l}</div>`)}</div>` : '';
}

export function deliveryChips(deliveries = []) {
  if (!deliveries.length) return html`<span class="muted">대상 없음</span>`;
  return html`${deliveries.map((d) => {
    const [mark, label] = d.claimed_at ? ['↗', '보내는 중'] : DELIVERY[d.status] ?? ['?', d.status];
    const next = d.status === 'failed' && d.next_attempt_at ? ` · 다음 시도 ${fmtTime(d.next_attempt_at, { date: false })}` : '';
    return html`<span class="dlv ${d.status}" title="${label}${next}${d.last_error ? `: ${d.last_error}` : ''}">${mark} ${d.notifier}</span>`;
  })}`;
}

export const GROUP_LABELS = {
  host: 'PC', channel: '채널', provider: '공급자', source: '소스', event_id: '이벤트 ID', level: '수준',
  category: '분류', user: '사용자', ip: '출발지 IP', none: '',
};

export function matchText(match = {}) {
  const parts = Object.entries(match).map(([k, v]) => {
    if (k === 'level') return `수준 ${v.split(',').map((x) => levelLabel(Number(x))).join('·')}`;
    if (k === 'event_id') return `이벤트 ${v}`;
    if (k === 'channel') return `채널 ${v}`;
    if (k === 'host') return `PC ${v}`;
    if (k === 'source') return v.split(',').map(sourceLabel).join('·');
    if (k === 'category') return v.split(',').map(categoryLabel).join('·');
    if (k === 'user') return `사용자 ${v}`;
    if (k === 'ip') return `IP ${v}`;
    if (k === 'provider') return `공급자 ${v}`;
    if (k === 'q') return `"${v}" 포함`;
    if (k === 'query') {
      try { return describe(parseTerms(v)); } catch { return `문장: ${v}`; }
    }
    return `${k.replace(/^f\./, '')} = ${v}`;
  });
  return parts.join(', ') || '모든 이벤트';
}

/** 규칙 조건을 한 줄로: "수준 오류 · 10분 동안 5건 이상 · PC별 · 재알림 1시간" */
export function ruleSummary(r) {
  if (r.kind === 'agent_silent') {
    return `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'} · ${fmtDuration(r.silent_for_sec)} 이상 수신 없음`;
  }
  const group = r.group_by === 'none' ? '전체 합산' : `${GROUP_LABELS[r.group_by] ?? r.group_by.replace(/^f\./, '')}별`;
  const distinct = r.distinct?.field ? ` · 서로 다른 ${GROUP_LABELS[r.distinct.field] ?? r.distinct.field.replace(/^f\./, '')} ${fmtNum(r.distinct.min)}개 이상` : '';
  return `${matchText(r.match)} · ${fmtDuration(r.window_sec)} 동안 ${fmtNum(r.threshold)}건 이상${distinct} · ${group} · 재알림 ${fmtDuration(r.cooldown_sec)}`;
}

/** 서버가 만든 링크(http://주소/#/events?...)를 현재 화면 기준 해시로 */
export function linkHash(link) {
  const i = (link || '').indexOf('#');
  return i >= 0 ? link.slice(i) : '';
}

/**
 * 알림 상세 패널. 처리(확인·해결·다시 열기), 메모, 무음을 여기서 한다.
 * onChange: 처리 상태가 바뀌면 부르는 함수 (목록 새로고침용)
 */
export async function openAlert(id, { onChange } = {}) {
  const body = openDrawer({ title: '알림 상세' });
  body.innerHTML = '<div class="skeleton"></div>';
  const reload = async () => {
    try {
      render(await api.get(`/api/alerts/${id}`));
    } catch (err) {
      body.innerHTML = errorBox(err);
    }
  };

  function render(alert) {
    const p = alert.payload || {};
    const samples = p.samples || [];
    const hash = linkHash(p.link);
    const handler = can('alerts.handle');
    const related = alert.related_unresolved || 0; // 같은 규칙·대상의 해결 안 된 다른 알림 수
    // 설정 변경 알림(ADR-043): 설명 첫 줄이 요약, 나머지 줄이 변경 목록. 무음으로 막을 수 없어 무음 단추가 없다
    const config = p.kind === 'config';
    const [configSummary, ...configLines] = config ? (p.description || '').split('\n') : [];
    body.innerHTML = html`
      <div class="toolbar" style="margin-bottom:6px">${severityBadge(alert.severity)}<b>${alert.rule}</b>
        ${alert.group_key ? html`<span class="muted">· ${alert.group_key}</span>` : ''}</div>
      <p class="ink-2" style="margin:0 0 14px">${config ? configSummary : p.kind === 'agent_silent'
        ? `${alert.group_key} 에서 ${fmtDuration(p.window_sec)} 이상 로그/하트비트가 들어오지 않았습니다.`
        : p.distinct_field
          ? `최근 ${fmtDuration(p.window_sec)} 동안 서로 다른 ${GROUP_LABELS[p.distinct_field] ?? p.distinct_field.replace(/^f\./, '')} ${fmtNum(p.distinct_count)}개 (기준 ${fmtNum(p.distinct_min)}개 이상) · 이벤트 ${fmtNum(alert.event_count)}건`
          : `최근 ${fmtDuration(p.window_sec)} 동안 조건에 맞는 이벤트 ${fmtNum(alert.event_count)}건 (기준 ${fmtNum(p.threshold)}건 이상)`}</p>
      ${lifecycle(alert, p)}
      ${p.distinct_values?.length ? html`<p class="muted" style="margin:-8px 0 14px;font-size:12.5px">${p.distinct_values.join(', ')}${p.distinct_count > p.distinct_values.length ? ` … 외 ${fmtNum(p.distinct_count - p.distinct_values.length)}` : ''}</p>` : ''}

      <div class="handle-box">
        <div class="handle-state">${statusChip(alert)}
          <span class="muted">${alert.status === 'resolved' ? `${alert.resolved_by} 님이 ${fmtRelative(alert.resolved_at)} 해결`
            : alert.status === 'acked' ? `${alert.acked_by} 님이 ${fmtRelative(alert.acked_at)} 확인` : '아직 아무도 확인하지 않았습니다'}</span></div>
        <div class="toolbar">
          ${alert.status === 'open' ? html`<button class="btn" data-act="ack" title="보고 있다는 기록을 남깁니다">확인</button>` : ''}
          ${handler && alert.status !== 'resolved' ? html`<button class="btn primary" data-form="resolve">해결…</button>` : ''}
          ${handler && alert.status !== 'open' ? html`<button class="btn" data-form="reopen" title="처리 안 됨으로 되돌립니다">다시 열기…</button>` : ''}
          ${handler && !config ? html`<button class="btn ghost" data-form="silence" title="점검·작업 중 이 알림을 잠시 보내지 않습니다">무음…</button>` : ''}
        </div>
        <div data-formbox></div>
      </div>
      ${alert.silence ? html`<div class="hint-box" style="margin-bottom:14px">무음 #${alert.silence.id} 중에 발생해 보내지 않았습니다 —
        ${alert.silence.reason} (${alert.silence.created_by}, ${fmtTime(alert.silence.starts_at)} ~ ${fmtTime(alert.silence.ends_at)})</div>` : ''}

      ${config ? (configLines.length ? html`<div class="hint-box" style="margin-bottom:14px;white-space:pre-line">${configLines.join('\n')}</div>` : '')
        : p.description ? html`<div class="hint-box" style="margin-bottom:14px">${p.description}</div>` : ''}
      ${p.tags?.length ? html`<div style="margin:-6px 0 12px">${p.tags.map((t) => html`<span class="type-tag" style="margin-right:4px">${t}</span>`)}</div>` : ''}
      <dl class="kv">
        <dt>발생 시각</dt><dd>${fmtTime(alert.fired_at)} <span class="muted">(${fmtRelative(alert.fired_at)})</span></dd>
        ${alert.first_event_at ? html`<dt>이벤트 시각</dt><dd>${fmtTime(alert.first_event_at)} ~ ${fmtTime(alert.last_event_at, { date: false })}</dd>` : ''}
        ${p.kind === 'agent_silent' ? html`<dt>마지막 수신</dt><dd>${fmtTime(alert.last_event_at)}</dd>` : ''}
        <dt>알림 번호</dt><dd class="num">#${alert.id}</dd>
      </dl>
      ${config ? (can('audit.view') ? html`<a class="btn" data-link href="#/audit?action=alerts.config.">감사로그에서 설정 변경 보기 →</a>` : '')
        : hash ? html`<a class="btn" data-link href="${hash}">${p.kind === 'agent_silent' ? '수집 PC 화면 열기' : '이 알림의 이벤트 검색'} →</a>` : ''}

      <div class="section-title">처리 기록</div>
      <ol class="timeline">
        <li><span class="tl-act fired">발생</span><span class="muted">${fmtTime(alert.fired_at)}</span></li>
        ${alert.notes.map((n) => html`<li>
          <span class="tl-act ${n.action}">${NOTE_ACTIONS[n.action] ?? n.action}</span><b>${n.author}</b>
          <span class="muted">${fmtTime(n.at)}</span>
          ${n.text ? html`<div class="tl-text">${n.text}</div>` : ''}</li>`)}
      </ol>
      <div class="note-form">
        <textarea class="input" rows="2" maxlength="2000" data-note placeholder="조사·조치 내용을 남깁니다 (저장 후 고칠 수 없음)" aria-label="메모"></textarea>
        <button class="btn sm" data-addnote>메모 남기기</button>
      </div>
      <div data-msg></div>

      <div class="section-title">전송 상태</div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>알림 대상</th><th>상태</th><th class="r">시도</th><th>전송 시각</th><th>마지막 오류</th></tr></thead>
        <tbody>${alert.deliveries.map((d) => html`<tr>
          <td class="nowrap"><b>${d.notifier}</b></td>
          <td class="nowrap">${deliveryChips([d])}</td>
          <td class="r num">${d.attempts}</td>
          <td class="nowrap muted">${d.sent_at ? fmtTime(d.sent_at) : '–'}</td>
          <td class="ink-2" style="overflow-wrap:anywhere">${d.last_error || ''}</td>
        </tr>`)}</tbody></table></div>
      ${samples.length ? html`
        <div class="section-title">알림에 포함된 최근 이벤트</div>
        <div class="table-wrap"><table class="table ev-table"><thead>${EVENT_HEAD}</thead>
          <tbody data-samples>${samples.map((s, i) => eventRow(s, i))}</tbody></table></div>` : ''}`;

    const tbody = body.querySelector('[data-samples]');
    if (tbody) bindRows(tbody, (k) => samples[Number(k)]?.id && { id: samples[Number(k)].id });
    body.querySelector('[data-link]')?.addEventListener('click', () => document.querySelector('.drawer-overlay')?.click());
    const msg = body.querySelector('[data-msg]');
    const formbox = body.querySelector('[data-formbox]');

    async function act(action, ids, note = '', withRelated = false) {
      await api.send('POST', '/api/alerts/handle', { ids, action, note, with_related: withRelated });
      onChange?.();
      await reload();
    }

    body.querySelector('[data-act="ack"]')?.addEventListener('click', async (e) => {
      e.target.disabled = true;
      try { await act('ack', [alert.id]); } catch (err) { e.target.disabled = false; msg.innerHTML = errorBox(err); }
    });

    body.querySelectorAll('[data-form]').forEach((b) => b.addEventListener('click', () => {
      const kind = b.dataset.form;
      if (formbox.dataset.kind === kind) { formbox.innerHTML = ''; formbox.dataset.kind = ''; return; }
      formbox.dataset.kind = kind;
      if (kind === 'silence') silenceForm(formbox, alert, () => onChange?.()); // 이미 발생한 알림은 그대로라 다시 그리지 않는다
      else handleForm(formbox, kind, related, async (note, withRelated) => act(kind, [alert.id], note, withRelated));
    }));

    body.querySelector('[data-addnote]').addEventListener('click', async (e) => {
      const text = body.querySelector('[data-note]').value.trim();
      if (!text) { body.querySelector('[data-note]').focus(); return; }
      e.target.disabled = true;
      try {
        await api.send('POST', `/api/alerts/${alert.id}/notes`, { text });
        onChange?.();
        await reload();
      } catch (err) {
        e.target.disabled = false;
        msg.innerHTML = errorBox(err);
      }
    });
  }

  await reload();
}

/** 해결 / 다시 열기 양식: 조치 내용(선택) + (해결) 같은 규칙·대상의 해결 안 된 다른 알림도 함께 */
function handleForm(box, kind, related, submit) {
  const resolve = kind === 'resolve';
  box.innerHTML = html`<div class="inline-form">
    <label class="field"><span>${resolve ? '조치 내용' : '다시 여는 이유'} <small class="muted">(선택, 처리 기록에 남음)</small></span>
      <textarea class="input" rows="2" maxlength="2000" data-text placeholder="${resolve ? '예: 계정 잠금 해제, 사용자 비밀번호 초기화' : '예: 같은 증상 재발'}"></textarea></label>
    ${resolve && related ? html`<label class="check-row"><input type="checkbox" data-related checked>
      같은 규칙·대상의 해결 안 된 다른 알림 ${fmtNum(related)}건도 함께 해결</label>` : ''}
    <div class="toolbar"><button class="btn ${resolve ? 'primary' : ''}" data-ok>${resolve ? '해결로 표시' : '다시 열기'}</button>
      <button class="btn ghost" data-cancel>취소</button></div>
    <div data-err></div></div>`;
  box.querySelector('[data-text]').focus();
  box.querySelector('[data-cancel]').addEventListener('click', () => { box.innerHTML = ''; box.dataset.kind = ''; });
  box.querySelector('[data-ok]').addEventListener('click', async (e) => {
    e.target.disabled = true;
    try {
      await submit(box.querySelector('[data-text]').value.trim(), !!box.querySelector('[data-related]')?.checked);
    } catch (err) {
      e.target.disabled = false;
      box.querySelector('[data-err]').innerHTML = errorBox(err);
    }
  });
}

/** 무음 양식 (알림 상세에서): 이 규칙·이 대상 / 이 규칙 전체, 기간, 사유 */
function silenceForm(box, alert, done) {
  const hasKey = alert.group_key !== '';
  box.innerHTML = html`<div class="inline-form">
    <p class="muted" style="margin:0;font-size:12.5px">무음 동안에도 알림은 이력에 남고, 보내기만 하지 않습니다. 끝난 뒤에도 새 로그가 들어오면 바로 다시 알립니다.</p>
    <div class="field"><span>범위</span><div class="seg" data-scope>
      ${hasKey ? html`<button type="button" data-v="one" class="on">이 규칙 · ${alert.group_key}</button>` : ''}
      <button type="button" data-v="rule" class="${hasKey ? '' : 'on'}">이 규칙 전체</button></div></div>
    <div class="field"><span>기간 (지금부터)</span><div class="seg" data-dur>${SILENCE_DURATIONS.map(([sec, label], i) => html`
      <button type="button" data-v="${sec}" class="${i === 0 ? 'on' : ''}">${label}</button>`)}</div></div>
    <label class="field"><span>사유 <em>*</em></span><input class="input" data-reason maxlength="500" placeholder="예: 정기 패치 작업 (변경 요청 CR-1234)"></label>
    <div class="toolbar"><button class="btn primary" data-ok>무음 걸기</button><button class="btn ghost" data-cancel>취소</button></div>
    <div data-err></div></div>`;
  box.querySelectorAll('.seg').forEach((seg) => seg.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
    seg.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
  })));
  box.querySelector('[data-reason]').focus();
  box.querySelector('[data-cancel]').addEventListener('click', () => { box.innerHTML = ''; box.dataset.kind = ''; });
  box.querySelector('[data-ok]').addEventListener('click', async (e) => {
    const reason = box.querySelector('[data-reason]').value.trim();
    if (!reason) { box.querySelector('[data-reason]').focus(); return; }
    const one = box.querySelector('[data-scope] .on').dataset.v === 'one';
    e.target.disabled = true;
    try {
      await api.send('POST', '/api/alerts/silences', {
        rule: alert.rule, group_key: one ? alert.group_key : null, reason,
        duration_sec: Number(box.querySelector('[data-dur] .on').dataset.v),
      });
      box.innerHTML = html`<div class="hint-box">✓ 무음을 걸었습니다. 알림 화면의 '무음' 탭에서 보거나 해제합니다.</div>`;
      box.dataset.kind = '';
      done();
    } catch (err) {
      e.target.disabled = false;
      box.querySelector('[data-err]').innerHTML = errorBox(err);
    }
  });
}
