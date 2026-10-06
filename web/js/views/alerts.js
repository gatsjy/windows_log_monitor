// 알림 화면: 엔진 상태와 심각도별 수, 그리고 탭 3개
//   이력(#/alerts)        — 발생한 알림과 전송 상태
//   규칙 관리(#/alerts/rules) — Snort 처럼 규칙 묶음(왼쪽) + 규칙 표(오른쪽). 켜기/끄기, 추가·수정은 오른쪽 패널(ruleform.js)
//   알림 대상(#/alerts/targets) — 수신 그룹·외부 연동, 테스트 발송
import * as api from '../api.js';
import { can } from '../auth.js';
import { GROUP_LABELS, deliveryChips, matchText, openAlert } from '../alertdetail.js';
import { closeDrawer, openDrawer } from '../drawer.js';
import { SEVERITIES, severityBadge } from '../levels.js';
import { openRuleEditor } from '../ruleform.js';
import { confirmModal, errorBox, fmtDuration, fmtNum, fmtRelative, fmtTime, html, replaceParams, store, toast } from '../util.js';

const TYPE_LABELS = { email: '수신 그룹 (메일)', webhook: '웹훅', oracle: 'Oracle DB', '-': '설정 오류' };
const RANGES = [['24h', '24시간'], ['7d', '7일'], ['30d', '30일']];
const TABS = [['', '알림 이력'], ['rules', '규칙 관리'], ['targets', '알림 대상']];

export async function mount(root, params, sub) {
  const tab = TABS.some(([k]) => k === sub) ? sub : '';
  let since = params.since || '7d';
  let config = null;
  let timer;
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
    <div class="tabs" role="tablist">${TABS.map(([k, l]) => html`
      <a role="tab" href="#/alerts${k ? `/${k}` : ''}?since=${since}" class="${k === tab ? 'on' : ''}" aria-selected="${k === tab}">${l}<span class="tab-count" data-tabcount="${k}"></span></a>`)}</div>
    <div data-tab></div>`;

  root.querySelectorAll('[data-seg] button').forEach((b) => b.addEventListener('click', () => {
    since = b.dataset.v;
    root.querySelectorAll('[data-seg] button').forEach((x) => x.classList.toggle('on', x === b));
    replaceParams(`alerts${tab ? `/${tab}` : ''}`, { since });
    root.querySelectorAll('.tabs a').forEach((a) => { a.href = a.href.replace(/since=[^&]*/, `since=${since}`); });
    load();
  }));

  // ----------------------------------------------------------- 상단 공통
  function renderStatus() {
    const el = root.querySelector('[data-status]');
    const problems = [config.config_error && `설정 파일 오류 (이전 설정으로 동작 중): ${config.config_error}`,
      config.last_error && `평가 오류: ${config.last_error}`].filter(Boolean);
    const active = config.rules.filter((r) => r.enabled).length;
    el.innerHTML = html`
      <div class="card status-strip">
        <span class="status ${problems.length ? 'stale' : 'online'}"><span class="dot"></span>${problems.length ? '확인 필요' : '알림 엔진 동작 중'}</span>
        <span class="muted">${config.interval_sec}초마다 평가 · 마지막 평가 ${config.last_run_at ? fmtRelative(config.last_run_at) : '대기 중'}
          · 규칙 ${active}/${config.rules.length}개 사용 중 · 알림 대상 ${config.notifiers.length}개</span>
      </div>
      ${problems.map((p) => html`<div class="error-box" style="margin-top:8px">${p}</div>`)}`;
    root.querySelector('[data-tabcount="rules"]').textContent = String(config.rules.length);
    root.querySelector('[data-tabcount="targets"]').textContent = String(config.notifiers.length);
  }

  function renderSummary() {
    root.querySelector('[data-summary]').innerHTML = html`${Object.entries(SEVERITIES).map(([key]) => html`
      <section class="card" style="grid-column: span 3"><div class="card-body"><div class="stat">
        <div class="stat-meta">${severityBadge(key)}</div>
        <div class="stat-value">${fmtNum(config.by_severity[key] || 0)}<small>건</small></div>
      </div></div></section>`)}`;
  }

  // ---------------------------------------------------------------- 이력
  function renderHistory(items) {
    const el = root.querySelector('[data-tab]');
    root.querySelector('[data-tabcount=""]').textContent = items.length >= 200 ? '200+' : String(items.length);
    if (!items.length) {
      el.innerHTML = '<section class="card"><div class="empty">이 기간에 발생한 알림이 없습니다.</div></section>';
      return;
    }
    el.innerHTML = html`<section class="card"><div class="card-body flush"><div class="table-wrap"><table class="table">
      <thead><tr><th>발생 시각</th><th>심각도</th><th>규칙</th><th>대상</th><th class="r">건수</th><th>전송</th></tr></thead>
      <tbody>${items.map((a) => html`<tr class="clickable" data-id="${a.id}">
        <td class="nowrap num muted" title="${fmtRelative(a.fired_at)}">${fmtTime(a.fired_at)}</td>
        <td class="nowrap">${severityBadge(a.severity)}</td>
        <td class="nowrap"><b>${a.rule}</b></td>
        <td class="nowrap">${a.group_key || '–'}</td>
        <td class="r num">${a.event_count ? fmtNum(a.event_count) : '–'}</td>
        <td class="dlv-cell">${deliveryChips(a.deliveries)}</td>
      </tr>`)}</tbody></table></div></div></section>`;
    el.querySelectorAll('[data-id]').forEach((tr) => tr.addEventListener('click', () => openAlert(tr.dataset.id)));
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

  function criteria(r) {
    if (r.kind === 'agent_silent') return `${fmtDuration(r.silent_for_sec)} 이상 수신 없음`;
    const by = r.group_by === 'none' ? '전체 합산' : `${GROUP_LABELS[r.group_by] ?? r.group_by.replace(/^f\./, '')}별`;
    return `${fmtDuration(r.window_sec)} 동안 ${fmtNum(r.threshold)}건↑ · ${by}`;
  }

  function renderRules() {
    const el = root.querySelector('[data-tab]');
    const admin = can('alerts.manage');
    const groups = groupsOf(config.rules);
    if (ui.group && !groups.some((g) => g.name === ui.group)) ui.group = '';
    const q = ui.q.trim().toLowerCase();
    const shown = config.rules.filter((r) => (!ui.group || r.group === ui.group)
      && (ui.state === 'all' || (ui.state === 'on') === r.enabled)
      && (!q || [r.name, r.description, String(r.sid ?? ''), ...r.tags, matchText(r.match)].join(' ').toLowerCase().includes(q)));
    const allOn = config.rules.filter((r) => r.enabled).length;

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
          <div class="seg" data-state>${[['all', '전체'], ['on', '사용'], ['off', '꺼짐']].map(([k, l]) => html`
            <button type="button" data-v="${k}" class="${ui.state === k ? 'on' : ''}">${l}</button>`)}</div>
          <span style="flex:1"></span>
          ${admin ? html`<button class="btn ghost" data-yaml title="config/alerts.yaml 을 직접 편집">YAML 편집</button>
            <button class="btn primary" data-new><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>규칙 추가</button>` : ''}
        </div>
        ${shown.length ? html`<div class="table-wrap"><table class="table rules-table">
          <thead><tr><th>사용</th><th>SID</th><th>규칙</th><th>조건 · 기준</th><th>받는 곳</th><th class="r">발생</th></tr></thead>
          <tbody>${shown.sort((a, b) => (a.sid ?? 1e9) - (b.sid ?? 1e9)).map((r) => html`
            <tr class="${admin ? 'clickable' : ''} ${r.enabled ? '' : 'rule-off'}" data-rule="${r.name}">
              <td>${admin ? html`<button type="button" class="switch ${r.enabled ? 'on' : ''}" role="switch" aria-checked="${r.enabled}"
                  data-toggle="${r.name}" aria-label="${r.name} 사용"></button>`
                : html`<span class="muted">${r.enabled ? '사용' : '꺼짐'}</span>`}</td>
              <td class="nowrap mono muted">${r.sid ?? '–'}</td>
              <td class="rule-cell">
                <div class="rule-title">${severityBadge(r.severity)}<b>${r.name}</b></div>
                ${r.description ? html`<div class="rule-desc">${r.description}</div>` : ''}
                ${r.tags.length ? html`<div class="rule-tags">${r.tags.map((t) => html`<span class="type-tag">${t}</span>`)}</div>` : ''}
              </td>
              <td class="rule-cond"><div class="ink-2">${r.kind === 'agent_silent' ? (r.hosts.length ? r.hosts.join(', ') : '모든 PC') : matchText(r.match)}</div>
                <div class="muted rule-crit">${criteria(r)}</div></td>
              <td class="ink-2">${r.notify.join(', ')}${r.unknown_notify.length
                ? html`<div class="tag-bad" style="font-size:12px">없는 대상: ${r.unknown_notify.join(', ')}</div>` : ''}</td>
              <td class="r nowrap"><span class="num">${fmtNum(r.fired)}</span>
                ${r.last_fired_at ? html`<div class="muted" style="font-size:12px">${fmtRelative(r.last_fired_at)}</div>` : ''}</td>
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

  async function load() {
    try {
      const [cfg, history] = await Promise.all([
        api.get('/api/alerts/config', { since }),
        api.get('/api/alerts', { since, limit: 200 }),
      ]);
      config = cfg;
      renderStatus();
      renderSummary();
      root.querySelector('[data-tabcount=""]').textContent = history.items.length >= 200 ? '200+' : String(history.items.length);
      if (tab === 'rules') renderRules();
      else if (tab === 'targets') renderNotifiers();
      else renderHistory(history.items);
    } catch (err) {
      root.querySelector('[data-tab]').innerHTML = errorBox(err);
    }
  }

  await load();
  // 규칙 관리 화면은 입력 중일 수 있어 자동 새로고침하지 않는다
  timer = setInterval(() => {
    if (tab !== 'rules' && !document.hidden && !document.querySelector('.drawer')) load();
  }, 15000);
  return () => clearInterval(timer);
}

