// 알림 규칙 편집기 (오른쪽 패널). 입력 양식으로 규칙 한 개를 만들고, Snort 식 한 줄 규칙 문장과
// 우리말 요약을 실시간으로 보여 준다. 저장하면 서버가 config/alerts.yaml 의 그 규칙 블록만 바꾼다.
import * as api from './api.js';
import { GROUP_LABELS, matchText } from './alertdetail.js';
import { closeDrawer, openDrawer } from './drawer.js';
import { CATEGORY_LABELS, LEVELS, SEVERITIES, categoryLabel, levelIcon, severityBadge } from './levels.js';
import { confirmModal, errorBox, fmtNum, html, toast } from './util.js';

const UNITS = [['s', '초', 1], ['m', '분', 60], ['h', '시간', 3600], ['d', '일', 86400]];
const GROUP_BY = [['host', 'PC'], ['ip', '출발지 IP'], ['user', '사용자'], ['category', '분류'], ['event_id', '이벤트 ID'],
  ['channel', '채널'], ['none', '전체 합산']];
const TRACK = { host: 'by_host', ip: 'by_src', user: 'by_user', category: 'by_category', event_id: 'by_event', channel: 'by_channel', none: 'none' };
const SEV_ORDER = ['critical', 'error', 'warning', 'info'];
const MATCH_FIELDS = ['category', 'level', 'event_id', 'host', 'user', 'ip', 'source', 'channel', 'provider', 'q'];

function splitUnit(sec) {
  const [key] = [...UNITS].reverse().find(([, , size]) => sec % size === 0 && sec >= size) || UNITS[0];
  const size = UNITS.find(([k]) => k === key)[2];
  return { n: sec / size, unit: key };
}
const unitSize = (key) => UNITS.find(([k]) => k === key)[2];
const quote = (s) => `"${String(s).replace(/"/g, '\\"')}"`;
const list = (v) => String(v || '').split(',').map((x) => x.trim()).filter(Boolean);

/** 편집 중인 값 → Snort 식 한 줄 규칙 (보기 전용) */
export function signature(r) {
  const parts = [`msg:${quote(r.name || '(이름 없음)')}`];
  if (r.kind === 'agent_silent') {
    parts.push(`heartbeat:silent ${r.silent_for_sec}s`);
    parts.push(`hosts:${r.hosts.length ? r.hosts.join(',') : 'any'}`);
  } else {
    Object.entries(r.match).forEach(([k, v]) => {
      if (!v) return;
      parts.push(k.startsWith('f.') ? `field:${k.slice(2)}=${quote(v)}` : k === 'q' ? `content:${quote(v)}` : `${k}:${v}`);
    });
    parts.push(`threshold:type both, track ${TRACK[r.group_by] || `by_${r.group_by.replace(/^f\./, '')}`}, count ${r.threshold}, seconds ${r.window_sec}`);
    parts.push(`cooldown:${r.cooldown_sec}`);
  }
  if (r.notify.length) parts.push(`notify:${quote(r.notify.join(','))}`);
  r.tags.forEach((t) => parts.push(`reference:${t}`));
  if (r.group) parts.push(`classtype:${quote(r.group)}`);
  parts.push(`sid:${r.sid || 'auto'}`);
  return `${r.enabled ? 'alert' : '# alert'} ${r.severity} (${parts.join('; ')};)`;
}

/** 편집 중인 값 → 우리말 한 문장 */
export function sentence(r) {
  const sev = SEVERITIES[r.severity]?.label ?? r.severity;
  const to = r.notify.length ? `'${r.notify.join("', '")}'에` : '(받는 곳 없음)';
  if (r.kind === 'agent_silent') {
    return `${r.hosts.length ? r.hosts.join(', ') : '모든 PC'}에서 ${fmtSec(r.silent_for_sec)} 이상 로그가 오지 않으면 ${to} [${sev}] 알림.`;
  }
  const by = r.group_by === 'none' ? '전체를 합산해서' : `${GROUP_LABELS[r.group_by] ?? r.group_by.replace(/^f\./, '')}마다 따로 세어`;
  return `${matchText(r.match)} 로그가 ${fmtSec(r.window_sec)} 동안 ${fmtNum(r.threshold)}건 이상이면, ${by} ${to} [${sev}] 알림. `
    + `같은 대상은 ${fmtSec(r.cooldown_sec)} 동안 다시 알리지 않음.`;
}
function fmtSec(sec) {
  const { n, unit } = splitUnit(sec);
  return `${n}${UNITS.find(([k]) => k === unit)[1]}`;
}

function unitInput(name, sec) {
  const { n, unit } = splitUnit(sec);
  return html`<span class="unit-input"><input class="input num" type="number" min="1" data-num="${name}" value="${n}">
    <select class="select" data-unit="${name}">${UNITS.map(([k, l]) => html`<option value="${k}" ${k === unit ? 'selected' : ''}>${l}</option>`)}</select></span>`;
}

/**
 * @param {{rule?: object, config: object, onSaved: () => void, defaults?: {group?: string}}} opt
 *   rule = /api/alerts/config 의 규칙 항목 (없으면 새 규칙), config = 같은 응답 (그룹·알림 대상 목록)
 */
export async function openRuleEditor({ rule, config, onSaved, defaults = {} }) {
  const isNew = !rule;
  const r = {
    name: rule?.name ?? '', sid: rule?.sid ?? null, group: rule?.group ?? defaults.group ?? '', description: rule?.description ?? '',
    kind: rule?.kind ?? 'count', enabled: rule?.enabled ?? true, severity: rule?.severity ?? 'warning',
    match: { ...(rule?.match ?? {}) }, group_by: rule?.group_by ?? 'host',
    window_sec: rule?.window_sec ?? 300, threshold: rule?.threshold ?? 5, cooldown_sec: rule?.cooldown_sec ?? 1800,
    silent_for_sec: rule?.silent_for_sec ?? 600, hosts: [...(rule?.hosts ?? [])],
    notify: [...(rule?.notify ?? (config.notifiers[0] ? [config.notifiers[0].name] : []))], tags: [...(rule?.tags ?? [])],
  };
  const body = openDrawer({ title: isNew ? '새 알림 규칙' : '알림 규칙 수정', subtitle: isNew ? '규칙 번호(SID)는 저장할 때 자동으로 붙습니다' : `SID ${r.sid ?? '–'} · ${r.group || '기타'}` });
  body.innerHTML = '<div class="skeleton"></div>';
  const [meta, fields] = await Promise.all([
    api.get('/api/meta').catch(() => ({ categories: CATEGORY_LABELS })),
    api.get('/api/fields').catch(() => ({ items: [] })),
  ]);
  const categories = Object.keys(meta.categories || CATEGORY_LABELS);
  const groups = [...new Set(config.rules.map((x) => x.group).filter(Boolean))];
  const fieldPaths = [...new Set(fields.items.map((f) => f.path))].slice(0, 300);
  // 원본 필드 조건은 [경로, 값] 배열로 따로 둔다 (아직 경로를 안 적은 빈 행도 보여 줘야 하므로)
  r.fields = Object.entries(r.match).filter(([k]) => k.startsWith('f.')).map(([k, v]) => [k.slice(2), v]);
  Object.keys(r.match).filter((k) => k.startsWith('f.')).forEach((k) => delete r.match[k]);
  const fullMatch = () => ({
    ...r.match,
    ...Object.fromEntries(r.fields.filter(([k, v]) => k.trim() && String(v).trim()).map(([k, v]) => [`f.${k.trim().replace(/^f\./, '')}`, String(v).trim()])),
  });
  const view = () => ({ ...r, match: fullMatch() });

  function render() {
    const cats = new Set(list(r.match.category));
    const lvls = new Set(list(r.match.level));
    body.innerHTML = html`
      <div class="rule-preview">
        <div class="sig" data-sig></div>
        <p class="rule-sentence" data-sentence></p>
      </div>

      <section class="form-section">
        <h3>기본 정보</h3>
        <label class="field"><span>규칙 이름 <em>*</em></span><input class="input" data-k="name" value="${r.name}" placeholder="예: 원격 데스크톱 무차별 대입" maxlength="120"></label>
        <div class="form-row">
          <label class="field"><span>규칙 묶음</span><input class="input" data-k="group" list="rule-groups" value="${r.group}" placeholder="예: 계정·인증 공격">
            <datalist id="rule-groups">${groups.map((g) => html`<option value="${g}">`)}</datalist></label>
          <label class="field" style="max-width:160px"><span>규칙 번호 (SID)</span><input class="input num" data-k="sid" value="${r.sid ?? ''}" placeholder="자동" inputmode="numeric"></label>
        </div>
        <label class="field"><span>설명</span><input class="input" data-k="description" value="${r.description}" placeholder="무엇을 잡는 규칙인지 (알림 메일에 함께 나감)"></label>
        <div class="field"><span>심각도</span>
          <div class="seg" data-sev>${SEV_ORDER.map((k) => html`<button type="button" data-v="${k}" class="${r.severity === k ? 'on' : ''}">${severityBadge(k)}</button>`)}</div></div>
        <label class="switch-row"><button type="button" class="switch ${r.enabled ? 'on' : ''}" role="switch" aria-checked="${r.enabled}" data-enabled></button>규칙 사용</label>
      </section>

      <section class="form-section">
        <h3>무엇을 감지하나요</h3>
        <div class="seg" data-kind>
          <button type="button" data-v="count" class="${r.kind === 'count' ? 'on' : ''}">로그 건수</button>
          <button type="button" data-v="agent_silent" class="${r.kind === 'agent_silent' ? 'on' : ''}">PC 수신 끊김</button>
        </div>
      </section>

      ${r.kind === 'agent_silent' ? html`
      <section class="form-section">
        <h3>어떤 PC가 얼마나 조용하면</h3>
        <label class="field"><span>대상 PC (쉼표로 구분, 비우면 모든 PC)</span><input class="input" data-hosts value="${r.hosts.join(', ')}" placeholder="WEB-01, DB-01"></label>
        <div class="field"><span>끊김 판정</span><div class="sentence-row">${unitInput('silent_for_sec', r.silent_for_sec)}<span>이상 로그·하트비트가 없으면</span></div></div>
        ${r.hosts.length ? '' : html`<p class="hint-box">비워 두면 퇴근 시 꺼지는 PC까지 알림이 갑니다. 서버만 적는 것을 권장합니다.</p>`}
      </section>` : html`
      <section class="form-section">
        <h3>어떤 로그를</h3>
        <div class="field"><span>분류</span><div class="chips">${categories.map((c) => html`
          <button type="button" class="chip ${cats.has(c) ? 'on' : ''}" data-cat="${c}">${categoryLabel(c)}</button>`)}</div></div>
        <div class="field"><span>수준</span><div class="chips">${Object.entries(LEVELS).map(([lv, m]) => html`
          <button type="button" class="chip ${lvls.has(lv) ? 'on' : ''}" data-lvl="${lv}">${levelIcon(Number(lv))}${m.label}</button>`)}</div></div>
        <div class="form-row">
          <label class="field"><span>이벤트 ID</span><input class="input" data-m="event_id" value="${r.match.event_id ?? ''}" placeholder="4625,4771"></label>
          <label class="field"><span>PC</span><input class="input" data-m="host" value="${r.match.host ?? ''}" placeholder="WEB-01,WEB-02"></label>
        </div>
        <div class="form-row">
          <label class="field"><span>사용자</span><input class="input" data-m="user" value="${r.match.user ?? ''}" placeholder="administrator"></label>
          <label class="field"><span>출발지 IP</span><input class="input" data-m="ip" value="${r.match.ip ?? ''}" placeholder="203.0.113.5"></label>
        </div>
        <label class="field"><span>메시지에 포함 (여러 단어는 <code>a|b</code> = 둘 중 하나)</span><input class="input" data-m="q" value="${r.match.q ?? ''}" placeholder="Failed password|Invalid user"></label>
        <div class="field"><span>원본 필드 조건</span>
          <datalist id="field-paths">${fieldPaths.map((p) => html`<option value="${p}">`)}</datalist>
          <div class="cond-list">${r.fields.map(([k, v], i) => html`<div class="cond-row">
            <input class="input" data-fk="${i}" list="field-paths" value="${k}" placeholder="EventData.LogonType">
            <span class="muted">=</span><input class="input" data-fv="${i}" value="${v}" placeholder="10">
            <button type="button" class="btn ghost sm" data-fdel="${i}" aria-label="조건 삭제">✕</button></div>`)}
            <button type="button" class="btn sm" data-fadd>+ 조건 추가</button></div></div>
        ${['source', 'channel', 'provider'].some((k) => r.match[k]) ? html`<p class="muted" style="font-size:12.5px;margin:0">
          그 밖의 조건: ${['source', 'channel', 'provider'].filter((k) => r.match[k]).map((k) => `${k}=${r.match[k]}`).join(', ')}</p>` : ''}
      </section>

      <section class="form-section">
        <h3>얼마나 자주면</h3>
        <div class="sentence-row">${unitInput('window_sec', r.window_sec)}<span>동안</span>
          <input class="input num" type="number" min="1" data-k="threshold" value="${r.threshold}" style="width:90px"><span>건 이상이면 알림</span></div>
        <div class="sentence-row"><select class="select" data-k="group_by">${GROUP_BY.map(([k, l]) => html`<option value="${k}" ${r.group_by === k ? 'selected' : ''}>${l}</option>`)}
          ${GROUP_BY.some(([k]) => k === r.group_by) ? '' : html`<option value="${r.group_by}" selected>${r.group_by}</option>`}</select>
          <span>${r.group_by === 'none' ? '(모든 로그를 합쳐서 셈)' : '마다 따로 세고 따로 알림'}</span></div>
        <div class="sentence-row"><span>같은 대상은</span>${unitInput('cooldown_sec', r.cooldown_sec)}<span>동안 다시 알리지 않음</span></div>
      </section>`}

      <section class="form-section">
        <h3>누구에게</h3>
        ${config.notifiers.length ? html`<div class="check-list">${config.notifiers.map((n) => html`
          <label><input type="checkbox" data-notify="${n.name}" ${r.notify.includes(n.name) ? 'checked' : ''}>${n.name}
            <span class="muted" style="font-size:12px">${n.type === 'email' ? '메일' : n.type}</span></label>`)}</div>`
          : html`<p class="hint-box">알림 대상이 없습니다. 환경설정에서 수신 그룹이나 외부 연동을 먼저 만드세요.</p>`}
        <label class="field"><span>태그 (쉼표로 구분 — MITRE 기법, ISMS 항목)</span><input class="input" data-tags value="${r.tags.join(', ')}" placeholder="MITRE T1110, ISMS 2.11.3"></label>
      </section>

      <section class="form-section">
        <h3>미리보기</h3>
        <p class="muted" style="margin:0 0 8px;font-size:13px">최근 24시간 로그에 이 규칙을 적용했다면 알림이 몇 번 울렸을지 계산합니다 (근사치).</p>
        <button type="button" class="btn" data-preview>최근 24시간으로 시험</button>
        <div data-preview-out style="margin-top:10px"></div>
      </section>

      <div data-msg></div>
      <div class="form-actions">
        ${isNew ? '' : html`<button type="button" class="btn ghost danger" data-delete>규칙 삭제</button>`}
        <span style="flex:1"></span>
        <button type="button" class="btn" data-cancel>취소</button>
        <button type="button" class="btn primary" data-save>${isNew ? '규칙 추가' : '저장'}</button>
      </div>`;
    bind();
    refresh();
  }

  function refresh() {
    body.querySelector('[data-sig]').textContent = signature(view());
    body.querySelector('[data-sentence]').textContent = sentence(view());
  }

  function setMatch(key, value) {
    if (value) r.match[key] = value; else delete r.match[key];
  }

  function bind() {
    body.querySelectorAll('[data-k]').forEach((el) => el.addEventListener('input', () => {
      const k = el.dataset.k;
      r[k] = k === 'threshold' ? Math.max(1, Number(el.value) || 1) : k === 'sid' ? (el.value.trim() ? Number(el.value) : null) : el.value;
      if (k === 'group_by') render(); else refresh();
    }));
    body.querySelectorAll('[data-num], [data-unit]').forEach((el) => el.addEventListener('input', () => {
      const name = el.dataset.num || el.dataset.unit;
      const n = Math.max(1, Number(body.querySelector(`[data-num="${name}"]`).value) || 1);
      r[name] = n * unitSize(body.querySelector(`[data-unit="${name}"]`).value);
      refresh();
    }));
    body.querySelectorAll('[data-m]').forEach((el) => el.addEventListener('input', () => { setMatch(el.dataset.m, el.value.trim()); refresh(); }));
    body.querySelectorAll('[data-sev] button').forEach((b) => b.addEventListener('click', () => {
      r.severity = b.dataset.v;
      body.querySelectorAll('[data-sev] button').forEach((x) => x.classList.toggle('on', x === b));
      refresh();
    }));
    body.querySelectorAll('[data-kind] button').forEach((b) => b.addEventListener('click', () => { r.kind = b.dataset.v; render(); }));
    body.querySelector('[data-enabled]').addEventListener('click', (e) => {
      r.enabled = !r.enabled;
      e.currentTarget.classList.toggle('on', r.enabled);
      e.currentTarget.setAttribute('aria-checked', String(r.enabled));
      refresh();
    });
    const toggleList = (attr, key) => body.querySelectorAll(`[${attr}]`).forEach((b) => b.addEventListener('click', () => {
      const set = new Set(list(r.match[key]));
      const v = b.getAttribute(attr);
      set.has(v) ? set.delete(v) : set.add(v);
      b.classList.toggle('on', set.has(v));
      setMatch(key, [...set].sort().join(','));
      refresh();
    }));
    toggleList('data-cat', 'category');
    toggleList('data-lvl', 'level');
    // 원본 필드 조건
    body.querySelectorAll('[data-fk]').forEach((el) => el.addEventListener('input', () => { r.fields[el.dataset.fk][0] = el.value; refresh(); }));
    body.querySelectorAll('[data-fv]').forEach((el) => el.addEventListener('input', () => { r.fields[el.dataset.fv][1] = el.value; refresh(); }));
    body.querySelectorAll('[data-fdel]').forEach((b) => b.addEventListener('click', () => { r.fields.splice(Number(b.dataset.fdel), 1); render(); }));
    body.querySelector('[data-fadd]')?.addEventListener('click', () => {
      r.fields.push(['', '']);
      render();
      body.querySelector(`[data-fk="${r.fields.length - 1}"]`)?.focus();
    });
    body.querySelector('[data-hosts]')?.addEventListener('input', (e) => { r.hosts = list(e.target.value); refresh(); });
    body.querySelector('[data-tags]').addEventListener('input', (e) => { r.tags = list(e.target.value); refresh(); });
    body.querySelectorAll('[data-notify]').forEach((c) => c.addEventListener('change', () => {
      r.notify = [...body.querySelectorAll('[data-notify]:checked')].map((x) => x.dataset.notify);
      refresh();
    }));
    body.querySelector('[data-cancel]').addEventListener('click', closeDrawer);
    body.querySelector('[data-save]').addEventListener('click', save);
    body.querySelector('[data-delete]')?.addEventListener('click', remove);
    body.querySelector('[data-preview]').addEventListener('click', preview);
  }

  function payload() {
    const { fields, ...rest } = view();
    return rest;
  }

  async function preview() {
    const out = body.querySelector('[data-preview-out]');
    out.innerHTML = '<div class="skeleton" style="height:60px"></div>';
    try {
      const p = await api.send('POST', '/api/alerts/rules/preview', { rule: payload() });
      if (p.kind === 'agent_silent') {
        out.innerHTML = p.silent.length
          ? html`<div class="hint-box">지금 기준으로 <b>${p.silent.length}대</b>가 끊김 상태입니다: ${p.silent.map((s) => s.host).join(', ')}</div>`
          : html`<div class="hint-box">지금 끊김 상태인 PC가 없습니다.</div>`;
        return;
      }
      out.innerHTML = html`
        <div class="preview-stats">
          <div><b class="num">${fmtNum(p.matched)}</b><span>조건에 맞는 로그</span></div>
          <div><b class="num">${fmtNum(p.fires)}</b><span>예상 알림 횟수</span></div>
          <div><b class="num">${fmtNum(p.targets)}</b><span>알림 대상(묶음 값)</span></div>
        </div>
        ${p.groups.length ? html`<div class="table-wrap"><table class="table no-stack">
          <thead><tr><th>${GROUP_BY.find(([k]) => k === r.group_by)?.[1] ?? r.group_by}</th><th class="r">알림</th><th class="r">구간 최대 건수</th></tr></thead>
          <tbody>${p.groups.map((g) => html`<tr><td>${g.key || '(전체)'}</td><td class="r num">${fmtNum(g.fires)}</td><td class="r num">${fmtNum(g.max)}</td></tr>`)}</tbody>
        </table></div>` : ''}
        ${p.fires > 50 ? html`<p class="hint-box" style="margin-top:8px">하루 ${fmtNum(p.fires)}번은 많습니다. 건수를 올리거나 기간·조건을 좁혀 보세요.</p>` : ''}
        ${p.matched === 0 ? html`<p class="muted" style="font-size:12.5px;margin:8px 0 0">최근 24시간에는 맞는 로그가 없었습니다. 조건 이름·값을 확인하세요.</p>` : ''}`;
    } catch (err) {
      out.innerHTML = errorBox(err);
    }
  }

  async function save() {
    const msg = body.querySelector('[data-msg]');
    const btn = body.querySelector('[data-save]');
    btn.disabled = true;
    try {
      const res = await api.send('PUT', '/api/alerts/rules', { original: isNew ? null : rule.name, rule: payload() });
      msg.innerHTML = html`<div class="hint-box">✓ 저장됨 (SID ${res.sid}) — 다음 평가부터 바로 적용됩니다</div>`;
      setTimeout(() => { closeDrawer(); onSaved?.(); }, 600);
    } catch (err) {
      msg.innerHTML = errorBox(err);
      btn.disabled = false;
    }
  }

  async function remove() {
    const ok = await confirmModal({
      title: '규칙 삭제',
      message: `'${rule.name}' 규칙을 삭제할까요?\n되돌리려면 다시 만들어야 합니다. (끄기만 하려면 '규칙 사용'을 끄세요)`,
      danger: true,
      confirmText: '삭제',
    });
    if (!ok) return;
    try {
      await api.send('DELETE', `/api/alerts/rules/${encodeURIComponent(rule.name)}`);
      closeDrawer();
      onSaved?.();
      toast(`'${rule.name}' 규칙이 삭제되었습니다.`, { type: 'success' });
    } catch (err) {
      body.querySelector('[data-msg]').innerHTML = errorBox(err);
      toast(err.message, { type: 'error' });
    }
  }

  render();
}
