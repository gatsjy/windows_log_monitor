// 알림 화면: 엔진 상태, 심각도별 수, 알림 이력, 규칙, 알림 대상(테스트 발송), 규칙 편집(YAML).
import * as api from '../api.js';
import { isAdmin } from '../auth.js';
import { deliveryChips, openAlert, ruleSummary } from '../alertdetail.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { SEVERITIES, severityBadge } from '../levels.js';
import { errorBox, fmtNum, fmtRelative, fmtTime, html, replaceParams } from '../util.js';

const TYPE_LABELS = { email: '수신 그룹 (메일)', webhook: '웹훅', oracle: 'Oracle DB', '-': '설정 오류' };
const RANGES = [['24h', '24시간'], ['7d', '7일'], ['30d', '30일']];

export async function mount(root, params) {
  let since = params.since || '7d';
  let config = null;
  let timer;

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">알림</h1>
        <p class="page-sub">규칙에 맞는 로그가 들어오면 메일·웹훅·Oracle 로 알립니다. 규칙 파일: <code>config/alerts.yaml</code></p></div>
      <div class="toolbar">
        <div class="seg" data-seg>${RANGES.map(([v, l]) => html`<button data-v="${v}" class="${v === since ? 'on' : ''}">${l}</button>`)}</div>
        ${isAdmin() ? html`<button class="btn" data-edit><svg viewBox="0 0 24 24"><path d="M4 20h4L19 9l-4-4L4 16z"/></svg>규칙 편집</button>` : ''}
      </div>
    </div>
    <div data-status style="margin-bottom:14px"></div>
    <div class="grid" data-summary style="margin-bottom:14px"></div>
    <section class="card" style="margin-bottom:14px">
      <div class="card-head"><h2 class="card-title">알림 이력</h2><span class="muted" data-count style="font-size:12.5px"></span></div>
      <div class="card-body flush" data-history><div class="skeleton"></div></div>
    </section>
    <div class="grid">
      <section class="card" style="grid-column: span 8"><div class="card-head"><h2 class="card-title">규칙</h2></div>
        <div class="card-body flush" data-rules><div class="skeleton"></div></div></section>
      <section class="card" style="grid-column: span 4"><div class="card-head"><h2 class="card-title">알림 대상</h2></div>
        <div class="card-body" data-notifiers><div class="skeleton"></div></div></section>
    </div>`;

  root.querySelectorAll('[data-seg] button').forEach((b) => b.addEventListener('click', () => {
    since = b.dataset.v;
    root.querySelectorAll('[data-seg] button').forEach((x) => x.classList.toggle('on', x === b));
    replaceParams('alerts', { since });
    load();
  }));
  root.querySelector('[data-edit]')?.addEventListener('click', openEditor);

  function renderStatus() {
    const el = root.querySelector('[data-status]');
    const problems = [config.config_error && `설정 파일 오류 (이전 설정으로 동작 중): ${config.config_error}`,
      config.last_error && `평가 오류: ${config.last_error}`].filter(Boolean);
    const active = config.rules.filter((r) => r.enabled).length;
    el.innerHTML = html`
      <div class="card" style="padding:12px 16px;flex-direction:row;align-items:center;gap:12px;flex-wrap:wrap">
        <span class="status ${problems.length ? 'stale' : 'online'}"><span class="dot"></span>${problems.length ? '확인 필요' : '알림 엔진 동작 중'}</span>
        <span class="muted">${config.interval_sec}초마다 평가 · 마지막 평가 ${config.last_run_at ? fmtRelative(config.last_run_at) : '대기 중'}
          · 규칙 ${active}/${config.rules.length}개 활성 · 알림 대상 ${config.notifiers.length}개</span>
      </div>
      ${problems.map((p) => html`<div class="error-box" style="margin-top:8px">${p}</div>`)}`;
  }

  function renderSummary() {
    root.querySelector('[data-summary]').innerHTML = html`${Object.entries(SEVERITIES).map(([key]) => html`
      <section class="card" style="grid-column: span 3"><div class="card-body"><div class="stat">
        <div class="stat-meta">${severityBadge(key)}</div>
        <div class="stat-value">${fmtNum(config.by_severity[key] || 0)}<small>건</small></div>
      </div></div></section>`)}`;
  }

  function renderHistory(items) {
    root.querySelector('[data-count]').textContent = `${fmtNum(items.length)}건${items.length >= 200 ? ' (최근 200건)' : ''}`;
    const el = root.querySelector('[data-history]');
    if (!items.length) {
      el.innerHTML = '<div class="empty">이 기간에 발생한 알림이 없습니다.</div>';
      return;
    }
    el.innerHTML = html`<div class="table-wrap"><table class="table">
      <thead><tr><th>발생 시각</th><th>심각도</th><th>규칙</th><th>대상</th><th class="r">건수</th><th>전송</th></tr></thead>
      <tbody>${items.map((a) => html`<tr class="clickable" data-id="${a.id}">
        <td class="nowrap num muted" title="${fmtRelative(a.fired_at)}">${fmtTime(a.fired_at)}</td>
        <td class="nowrap">${severityBadge(a.severity)}</td>
        <td class="nowrap"><b>${a.rule}</b></td>
        <td class="nowrap">${a.group_key || '–'}</td>
        <td class="r num">${a.event_count ? fmtNum(a.event_count) : '–'}</td>
        <td class="dlv-cell">${deliveryChips(a.deliveries)}</td>
      </tr>`)}</tbody></table></div>`;
    el.querySelectorAll('[data-id]').forEach((tr) => tr.addEventListener('click', () => openAlert(tr.dataset.id)));
  }

  function renderRules() {
    const el = root.querySelector('[data-rules]');
    if (!config.rules.length) {
      el.innerHTML = '<div class="empty">규칙이 없습니다. \'규칙 편집\' 으로 추가하세요.</div>';
      return;
    }
    el.innerHTML = html`<div class="table-wrap"><table class="table">
      <thead><tr><th>규칙</th><th>조건</th><th>알림 대상</th><th class="r">기간 내</th><th>최근 발생</th></tr></thead>
      <tbody>${config.rules.map((r) => html`<tr class="${r.enabled ? '' : 'muted'}">
        <td class="nowrap">${severityBadge(r.severity)} <b>${r.name}</b>${r.enabled ? '' : html` <span class="type-tag">꺼짐</span>`}
          ${r.description ? html`<div class="muted" style="font-size:12px;white-space:normal;max-width:280px">${r.description}</div>` : ''}
          ${r.tags.length ? html`<div style="margin-top:3px">${r.tags.map((t) => html`<span class="type-tag" style="margin-right:4px">${t}</span>`)}</div>` : ''}</td>
        <td class="ink-2" style="font-size:12.5px">${ruleSummary(r)}</td>
        <td class="nowrap ink-2">${r.notify.join(', ')}${r.unknown_notify.length
          ? html`<div class="tag-bad" style="font-size:12px">없는 대상: ${r.unknown_notify.join(', ')}</div>` : ''}</td>
        <td class="r num">${fmtNum(r.fired)}</td>
        <td class="nowrap muted">${r.last_fired_at ? fmtRelative(r.last_fired_at) : '–'}</td>
      </tr>`)}</tbody></table></div>`;
  }

  function renderNotifiers() {
    const el = root.querySelector('[data-notifiers]');
    if (!config.notifiers.length) {
      el.innerHTML = '<div class="empty">알림 대상이 없습니다.</div>';
      return;
    }
    el.innerHTML = html`<div class="notifier-list">${config.notifiers.map((n) => html`
      <div class="notifier">
        <div class="notifier-top"><b>${n.name}</b><span class="type-tag">${TYPE_LABELS[n.type] ?? n.type}</span>
          ${isAdmin() ? html`<button class="btn sm" data-test="${n.name}">테스트 발송</button>` : ''}</div>
        <div class="muted mono" style="font-size:12px;overflow-wrap:anywhere">${n.target || '–'}</div>
        <div class="muted" style="font-size:12px">${n.used_by.length ? `규칙 ${n.used_by.length}개에서 사용` : '규칙에서 사용 안 함'}</div>
        ${n.error ? html`<div class="error-box" style="margin-top:6px">${n.error}</div>` : ''}
        <div data-result="${n.name}"></div>
      </div>`)}</div>
      <p class="muted" style="font-size:12px;margin:12px 0 0">받는 사람·그룹·메신저·Oracle·메일 서버는 ${isAdmin()
        ? html`<a href="#/settings/groups">환경설정</a>` : '환경설정(관리자)'}에서 관리합니다. 규칙의 <code>notify</code> 에 이름을 씁니다.</p>`;
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

  function openEditor() {
    const body = openDrawer({ title: '알림 규칙 편집', subtitle: config?.file || 'config/alerts.yaml' });
    body.innerHTML = html`
      <textarea class="input editor" spellcheck="false" data-yaml>${config?.yaml ?? ''}</textarea>
      <div class="toolbar" style="margin:10px 0"><button class="btn primary" data-save>검증 후 저장</button>
        <span class="muted" style="font-size:12.5px">저장하면 바로 적용됩니다. 오류가 있으면 저장되지 않습니다.</span></div>
      <div data-msg></div>
      <div class="section-title">빠른 참고</div>
      <ul class="ref-list">
        <li><code>match</code>: 이벤트 검색과 같은 조건 — <code>{ level: "1,2", event_id: "4625", channel: Security, host: WEB-01, q: timeout }</code></li>
        <li><code>window</code> 동안 <code>threshold</code> 건 이상이면 알림, <code>group_by</code>(기본 host) 값마다 따로</li>
        <li><code>cooldown</code>: 같은 규칙·같은 대상 재알림 최소 간격</li>
        <li><code>kind: agent_silent</code> + <code>silent_for</code>: PC 수신 끊김 알림, <code>hosts</code> 로 대상 제한</li>
        <li>비밀값은 <code>\${환경변수}</code> 로 참조 (예: <code>Authorization: Bearer \${WLM_WEBHOOK_TOKEN}</code>)</li>
      </ul>`;
    const msg = body.querySelector('[data-msg]');
    body.querySelector('[data-save]').addEventListener('click', async () => {
      try {
        const res = await api.send('PUT', '/api/alerts/config', body.querySelector('[data-yaml]').value);
        msg.innerHTML = html`<div class="hint-box">✓ 저장됨 — 규칙 ${res.rules}개, 알림 대상 ${res.notifiers}개</div>`;
        setTimeout(() => { closeDrawer(); load(); }, 700);
      } catch (err) {
        msg.innerHTML = errorBox(err);
      }
    });
  }

  async function load() {
    try {
      const [cfg, history] = await Promise.all([
        api.get('/api/alerts/config', { since }),
        api.get('/api/alerts', { since, limit: 200 }),
      ]);
      config = cfg;
      renderStatus();
      renderSummary();
      renderHistory(history.items);
      renderRules();
      renderNotifiers();
    } catch (err) {
      const history = root.querySelector('[data-history]');
      if (history) history.innerHTML = errorBox(err);
    }
  }

  await load();
  timer = setInterval(() => { if (!document.hidden && !document.querySelector('.drawer')) load(); }, 15000);
  return () => clearInterval(timer);
}
