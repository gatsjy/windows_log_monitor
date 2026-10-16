// 검색 문장 입력 칸 (B-01, ADR-033) — 이벤트 검색·실시간 화면의 필터 막대와 알림 규칙 편집기가 쓴다.
// 입력 중에는 네트워크 없이 그 자리에서 해석해 '해석:' 한 줄 또는 틀린 곳(⚠ n번째 글자 …)을 보여 주고,
// Enter·포커스를 잃을 때 확정(onCommit)한다. 틀린 문장은 확정하지 않는다 (이전 결과 유지).
// 해석 규칙은 querylang.js(서버 querylang.py 와 같은 알고리즘), 여기는 화면만.
import { CATEGORY_LABELS, LEVELS } from './levels.js';
import { KEYS, LEVEL_NAMES, QueryError, cpToUtf16, formatValue, parseTerms, tokenAt } from './querylang.js';
import { html } from './util.js';

export const KEY_LABELS = {
  host: 'PC', channel: '채널', provider: '공급자', source: '소스', category: '분류', user: '사용자', ip: '출발지 IP',
  level: '수준', event_id: '이벤트 ID', msg: '메시지', f: '원본 필드',
};

const EXAMPLES = [
  ['event_id:4625 -user:svc_backup', '로그온 실패 중 백업 계정 제외'],
  ['host:WEB-01,WEB-02 level:오류,심각', 'PC 두 대의 오류·심각'],
  ['"잘못된 암호" -ip:10.0.0.5', '구절 포함, 이 IP 제외'],
  ['msg:timeout,refused', '둘 중 하나라도 포함 (예전의 a|b)'],
  ['f.EventData.LogonType:10', '원본 필드 값'],
];

const quote = (v) => `"${v}"`;

/** term 하나 → 우리말 */
function describeTerm(t) {
  const label = t.key === 'f' ? `원본 ${t.path.join('.')}` : KEY_LABELS[t.key];
  if (t.key === 'msg') {
    const words = t.values.map(quote).join(' 또는 ');
    return t.neg ? `메시지에 ${words} 없음` : `메시지에 ${words} 포함`;
  }
  const show = (v) => (t.key === 'level' ? LEVEL_NAMES[v] : t.key === 'category' ? (CATEGORY_LABELS[v] ?? v) : String(v));
  const values = t.values.map(show).join(' 또는 ');
  return t.neg ? `${label} ${values} 제외` : `${label} ${values}`;
}

/** 문장(term 목록) → '이벤트 ID 4625 · 사용자 svc_backup 제외 · …' */
export function describe(terms) {
  return terms.length ? terms.map(describeTerm).join(' · ') : '조건 없음';
}

/** 겹치지 않는 포함 조건(host:A host:B)이 있으면 그 키 */
export function contradiction(terms) {
  const seen = new Map();
  for (const t of terms) {
    if (t.neg || t.key === 'msg' || t.key === 'f') continue;
    const prev = seen.get(t.key);
    const next = prev ? prev.filter((v) => t.values.includes(v)) : [...t.values];
    if (!next.length) return t.key;
    seen.set(t.key, next);
  }
  return null;
}

/** 막지는 않는 안내 (느릴 수 있는 문장 등). [{text, fix?: {label, apply(text) → text}}] */
export function lint(terms, { since } = {}) {
  const out = [];
  const conflict = contradiction(terms);
  if (conflict) out.push({ text: `조건이 서로 겹치지 않아 결과가 없습니다 (${KEY_LABELS[conflict]})` });
  const msgs = terms.filter((t) => t.key === 'msg' && !t.neg);
  const indexed = terms.some((t) => !t.neg && t.key !== 'msg' && t.key !== 'f');
  if (msgs.length && !indexed && !msgs.some((t) => t.values.every((v) => Array.from(v).length >= 3))) {
    out.push({ text: '2글자 이하 단어는 색인을 못 써서 긴 기간에서는 느립니다. "다시 부팅" 처럼 따옴표로 묶어 보세요.', fix: mergeShortWords(terms) });
  }
  if (terms.length && terms.every((t) => t.neg) && ['7d', '30d', '90d'].includes(since)) {
    out.push({ text: '제외 조건만으로 긴 기간을 세면 느릴 수 있습니다. 포함 조건(PC·이벤트 ID 등)을 함께 쓰면 빨라집니다.' });
  }
  return out;
}

// 이웃한 맨 단어(값 하나짜리 메시지 포함 조건)를 구절 하나로 — 뜻이 바뀐다(붙어 있는 문구만 찾음)
function mergeShortWords(terms) {
  const runs = [];
  let run = [];
  for (const t of terms) {
    if (t.key === 'msg' && !t.neg && t.values.length === 1) run.push(t);
    else { if (run.length > 1) runs.push(run); run = []; }
  }
  if (run.length > 1) runs.push(run);
  if (!runs.length) return null;
  const target = runs[0];
  return {
    label: '구절로 합치기 (붙어 있는 문구만 찾게 바뀝니다)',
    apply(text) {
      const cps = Array.from(text);
      const [start] = target[0].span;
      const end = target[target.length - 1].span[1];
      return cps.slice(0, start).join('') + formatValue(target.map((t) => t.values[0]).join(' '), 'word') + cps.slice(end).join('');
    },
  };
}

// 오류 위치가 든 토큰(따옴표 안의 띄어쓰기는 토큰 안으로 본다) 범위 [ts, te)
function tokenSpan(cps, at) {
  const isWs = (c) => /\s/.test(c);
  // 처음부터 읽어 오며 따옴표 안·밖을 따진다 — 토큰 경계는 따옴표 밖의 띄어쓰기
  let ts = 0;
  let inQuote = false;
  for (let i = 0; i < Math.min(at, cps.length); i += 1) {
    if (QUOTE_CHARS.includes(cps[i])) inQuote = !inQuote;
    else if (!inQuote && isWs(cps[i])) ts = i + 1;
  }
  let te = Math.max(at, ts);
  for (; te < cps.length; te += 1) {
    if (QUOTE_CHARS.includes(cps[te])) inQuote = !inQuote;
    else if (!inQuote && isWs(cps[te])) break;
  }
  return [ts, te];
}
const QUOTE_CHARS = ['"', '“', '”'];

// 오류마다 빠른 고침 단추. 고친 문장이 다시 틀리면(같은 자리 또는 그 앞에서) 내놓지 않는다
export function quickFixes(err) {
  const fixes = [];
  const cps = Array.from(err.text);
  const splice = (start, end, insert) => cps.slice(0, start).join('') + insert + cps.slice(end).join('');
  const [ts, te] = tokenSpan(cps, err.start);
  const neg = cps[ts] === '-' && ts + 1 < te;
  const from = neg ? ts + 1 : ts;
  const token = cps.slice(from, te).join('');
  const suggest = err.params?.suggest;
  if (suggest && suggest !== 'f.경로' && ['unknown_key', 'bad_category'].includes(err.code)) {
    fixes.push({ label: `'${suggest}' 로 고치기`, apply: () => splice(err.start, err.end, suggest) });
  }
  if (err.code === 'single_quote') {
    // 이 자리에서 시작하는 '…' 한 쌍만 큰따옴표 구절로 (안의 따옴표는 두 번 쓰기)
    const close = cps.indexOf("'", err.start + 1);
    if (close > err.start) {
      const inner = cps.slice(err.start + 1, close).join('');
      const quoted = `"${Array.from(inner).map((c) => (QUOTE_CHARS.includes(c) ? c + c : c)).join('')}"`;
      fixes.push({ label: '큰따옴표로 바꾸기', apply: () => splice(err.start, close + 1, quoted) });
    }
  }
  if (['unknown_key', 'missing_key', 'wildcard', 'paren', 'reserved_word', 'single_quote', 'operator', 'time_key'].includes(err.code) && token) {
    const phrase = formatValue(token, 'word');
    fixes.push({ label: '따옴표로 감싸기 (글자 그대로 찾기)', apply: () => splice(from, te, phrase.startsWith('"') ? phrase : `"${phrase}"`) });
  }
  if (err.code === 'pipe' && token.includes('|')) {
    const colon = token.indexOf(':');
    const key = colon > 0 ? token.slice(0, colon).toLowerCase() : '';
    if (key && (KEYS.includes(key) || key.startsWith('f.'))) {
      // host:A|B → host:A,B (그 키 안의 '또는')
      fixes.push({ label: `${token.replaceAll('|', ',')} 로 바꾸기`, apply: () => splice(from, te, token.replaceAll('|', ',')) });
    } else {
      const parts = token.split('|').filter(Boolean);
      if (parts.length > 1) fixes.push({ label: `msg:${parts.join(',')} 로 바꾸기`, apply: () => splice(from, te, `msg:${parts.map((p) => formatValue(p)).join(',')}`) });
    }
  }
  if (err.code === 'space_after_colon') fixes.push({ label: '띄어쓰기 지우기', apply: () => splice(err.start + 1, err.end, '') });
  return fixes.filter((f) => {
    try { parseTerms(f.apply()); return true; } catch (next) { return next instanceof QueryError && next.start > err.start; }
  });
}

function marked(text, start, end) {
  const cps = Array.from(text);
  const before = cps.slice(0, start).join('');
  const bad = cps.slice(start, end).join('');
  const after = cps.slice(end).join('');
  return html`<code class="qb-src">${before}<mark class="qb-mark">${bad || '▏'}</mark>${after}</code>`;
}

function helpCard() {
  return html`<div class="qb-help-body">
    <p><b>띄어쓰기</b> = 그리고 · <b>쉼표</b> = 또는 (<code>host:A,B</code>) · 앞의 <b><code>-</code></b> = 제외 (<code>-user:svc</code>) ·
      <b><code>"…"</code></b> = 구절. 따옴표 안의 <code>"</code> 는 <code>""</code> 로 두 번 씁니다. 키 이름이 아닌데 <code>:</code> 가 든 말(<code>Error:</code>)은 따옴표로 감싸세요.</p>
    <div class="qb-keys">${Object.entries(KEY_LABELS).map(([k, l]) => html`<button type="button" class="chip" data-insert="${k === 'f' ? 'f.' : `${k}:`}">${l} <code>${k === 'f' ? 'f.경로' : k}</code></button>`)}</div>
    <div class="qb-examples">${EXAMPLES.map(([q, d]) => html`<button type="button" class="qb-example" data-example="${q}"><code>${q}</code><span class="muted">${d}</span></button>`)}</div>
    <ul class="muted">
      <li>제외해도 그 값이 없는 로그(예: 사용자가 없는 로그)는 남습니다.</li>
      <li>PC·사용자·IP 는 대소문자를 구분하고, 메시지는 구분하지 않습니다. 와일드카드(*)·괄호는 아직 없습니다.</li>
      <li>제외 조건만 쓴 긴 기간 검색은 느릴 수 있습니다.</li>
      <li>공유 링크를 받은 사람의 조회 범위가 더 좁으면 그 안의 결과만 보입니다. '링크 복사'는 지금 구간으로 고정합니다.</li>
    </ul>
  </div>`;
}

/**
 * @param {HTMLElement} el
 * @param {{value?: string, onCommit: (text: string) => void, onAnalyze?: (terms|null) => void, since?: () => string,
 *          suggestions?: () => Record<string, string[]>, fieldBudget?: () => number, placeholder?: string, label?: string,
 *          slashShortcut?: boolean, staleNote?: boolean}} opt   staleNote: 틀린 동안 '이전 결과' 안내 (검색 화면만)
 */
// 입력 칸(<input>)은 줄바꿈을 말없이 지운다 → 미리 띄어쓰기로 (문장에서 줄바꿈은 띄어쓰기와 같은 뜻)
const oneLine = (text) => String(text ?? '').replace(/\r\n?|\n/g, ' ');

export function queryBox(el, opt) {
  let committed = oneLine(opt.value);
  let terms = null;
  let error = null;
  let acItems = [];
  let acIndex = -1;
  let acRange = null;
  let timer = null;

  el.innerHTML = html`<div class="qb">
    <div class="qb-row">
      <input class="input grow qb-input" type="search" spellcheck="false" autocomplete="off" enterkeyhint="search"
        role="combobox" aria-autocomplete="list" aria-expanded="false" aria-label="${opt.label ?? '검색 문장'}"
        placeholder="${opt.placeholder ?? '예) event_id:4625 -user:svc_backup level:오류,심각 "잘못된 암호"'}">
      <button type="button" class="btn ghost sm qb-help-btn" aria-expanded="false" title="검색 문장 도움말">?</button>
    </div>
    <ul class="qb-ac" role="listbox" hidden></ul>
    <div class="qb-line" aria-live="polite"></div>
    <div class="qb-help" hidden>${helpCard()}</div>
  </div>`;
  const input = el.querySelector('.qb-input');
  const line = el.querySelector('.qb-line');
  const ac = el.querySelector('.qb-ac');
  const help = el.querySelector('.qb-help');
  const helpBtn = el.querySelector('.qb-help-btn');
  input.value = committed;

  function analyze() {
    const text = input.value;
    try {
      terms = parseTerms(text, { fieldBudget: opt.fieldBudget?.() ?? 10 });
      error = null;
    } catch (err) {
      if (!(err instanceof QueryError)) throw err;
      terms = null;
      error = err;
    }
    render();
    opt.onAnalyze?.(terms, text);
  }

  let lastRendered = '';
  function render(stale = false) {
    input.setAttribute('aria-invalid', String(Boolean(error)));
    // 같은 내용이면 다시 그리지 않는다 — 단추를 누르는 순간 입력 칸이 포커스를 잃어(change) 다시 그리면 클릭이 사라진다
    // committed 는 '이전 결과' 안내에만 쓰이므로 그때만 비교한다 (Enter 뒤 첫 blur 에 다시 그려 클릭을 잃지 않게)
    const staleShown = Boolean(error) && opt.staleNote !== false && input.value !== committed;
    const signature = JSON.stringify([input.value, staleShown, stale, opt.since?.() ?? '', error?.code, error?.start, error?.display]);
    if (signature === lastRendered) return;
    lastRendered = signature;
    if (error) {
      const fixes = quickFixes(error);
      line.className = 'qb-line qb-error';
      line.innerHTML = html`<div>⚠ ${error.display}</div>${marked(error.text, error.start, error.end)}
        ${fixes.length ? html`<div class="qb-fixes">${fixes.map((f, i) => html`<button type="button" class="btn sm" data-fix="${i}">${f.label}</button>`)}</div>` : ''}
        ${opt.staleNote !== false && input.value !== committed ? html`<div class="muted">문장에 오류가 있어 이전 결과를 보여 줍니다.</div>` : ''}`;
      line.querySelectorAll('[data-fix]').forEach((b) => b.addEventListener('click', () => {
        set(fixes[Number(b.dataset.fix)].apply(), { commit: true });
        input.focus();
      }));
      return;
    }
    const lints = lint(terms, { since: opt.since?.() });
    line.className = `qb-line${stale ? ' qb-stale' : ''}`;
    line.innerHTML = html`<div class="muted">해석: ${describe(terms)}</div>
      ${lints.map((l, i) => html`<div class="qb-lint">${l.text}${l.fix ? html` <button type="button" class="btn ghost sm" data-lint="${i}">${l.fix.label}</button>` : ''}</div>`)}`;
    line.querySelectorAll('[data-lint]').forEach((b) => b.addEventListener('click', () => {
      set(lints[Number(b.dataset.lint)].fix.apply(input.value), { commit: true });
    }));
  }

  function commit() {
    closeAc();
    if (error) {
      // 틀린 곳을 선택해 바로 고칠 수 있게
      input.setSelectionRange(cpToUtf16(input.value, error.start), cpToUtf16(input.value, error.end));
      return;
    }
    if (input.value === committed) return;
    committed = input.value;
    opt.onCommit(committed);
  }

  /** 밖(드롭다운·수준 칩·상세 패널)에서 문장을 바꿈 */
  function set(text, { commit: doCommit = false } = {}) {
    input.value = oneLine(text);
    analyze();
    if (doCommit) commit();
    else if (!error) committed = text;
  }

  // ------------------------------------------------------------ 자동완성 (이미 받아 둔 목록만, 입력마다 서버를 부르지 않음)
  function caretCp() { return Array.from(input.value.slice(0, input.selectionStart ?? input.value.length)).length; }

  function candidates(tok) {
    const lower = tok.prefix.toLowerCase();
    const match = (v, extra = '') => !lower || v.toLowerCase().includes(lower) || extra.toLowerCase().includes(lower);
    if (tok.kind === 'key') {
      if (!tok.prefix) return [];
      return [...KEYS, 'f'].filter((k) => match(k, KEY_LABELS[k]))
        .map((k) => ({ insert: k === 'f' ? 'f.' : `${k}:`, label: k === 'f' ? 'f.경로' : `${k}:`, hint: KEY_LABELS[k], key: true }));
    }
    const lists = {
      level: Object.entries(LEVELS).map(([, m]) => [m.label, m.en]),
      category: Object.entries(CATEGORY_LABELS),
      ...Object.fromEntries(Object.entries(opt.suggestions?.() ?? {}).map(([k, vals]) => [k, vals.map((v) => [v, ''])])),
    };
    const chosen = new Set(tok.chosen ?? []);
    return (lists[tok.key] ?? []).filter(([v, extra]) => !chosen.has(v) && match(v, extra)).slice(0, 30)
      .map(([v, extra]) => ({ insert: formatValue(v), label: v, hint: extra }));
  }

  function openAc() {
    const tok = tokenAt(input.value, caretCp());
    acItems = candidates(tok);
    acRange = [tok.start, caretCp()];
    if (!acItems.length || document.activeElement !== input) { closeAc(); return; }
    acIndex = -1;
    ac.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    ac.innerHTML = html`${acItems.map((it, i) => html`<li role="option" id="qb-ac-${i}" data-i="${i}"><code>${it.label}</code> <span class="muted">${it.hint}</span></li>`)}`;
  }

  function closeAc() {
    ac.hidden = true;
    acItems = [];
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
  }

  function choose(i) {
    const it = acItems[i];
    if (!it) return;
    const cps = Array.from(input.value);
    const [s] = acRange;
    // 커서 뒤 같은 토큰의 나머지(값 입력 중이던 글자)는 바꿀 값으로 덮는다
    let e = acRange[1];
    while (e < cps.length && !/[\s,]/.test(cps[e])) e += 1;
    const next = cps.slice(0, s).join('') + it.insert + cps.slice(e).join('');
    input.value = next;
    const caret = cpToUtf16(next, s + Array.from(it.insert).length);
    input.setSelectionRange(caret, caret);
    analyze();
    if (it.key) openAc(); else closeAc();
  }

  function moveAc(delta) {
    if (!acItems.length) return;
    acIndex = (acIndex + delta + acItems.length) % acItems.length;
    ac.querySelectorAll('li').forEach((li, i) => li.classList.toggle('on', i === acIndex));
    input.setAttribute('aria-activedescendant', `qb-ac-${acIndex}`);
  }

  input.addEventListener('input', (e) => {
    clearTimeout(timer);
    timer = setTimeout(analyze, 150);
    if (!e.isComposing) openAc();
  });
  input.addEventListener('compositionend', () => openAc());
  input.addEventListener('keydown', (e) => {
    if (e.isComposing || e.keyCode === 229) return;    // 한글 조합 중 Enter 는 글자 확정
    if (!ac.hidden && acItems.length) {
      if (e.key === 'ArrowDown') { e.preventDefault(); moveAc(1); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); moveAc(-1); return; }
      if ((e.key === 'Enter' || e.key === 'Tab') && acIndex >= 0) { e.preventDefault(); choose(acIndex); return; }
      // Esc 를 여기서 끝낸다 — 상세 패널(규칙 편집기)이 Esc 로 통째로 닫히지 않게
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeAc(); return; }
    }
    if (e.key === 'Enter') { e.preventDefault(); clearTimeout(timer); analyze(); commit(); }
    if (e.key === 'Escape' && input.value !== committed) { e.preventDefault(); e.stopPropagation(); set(committed); }
  });
  input.addEventListener('change', () => { clearTimeout(timer); analyze(); if (!error) commit(); });
  input.addEventListener('blur', () => setTimeout(closeAc, 150));
  ac.addEventListener('mousedown', (e) => {
    const li = e.target.closest('li[data-i]');
    if (li) { e.preventDefault(); choose(Number(li.dataset.i)); }
  });
  helpBtn.addEventListener('click', () => {
    help.hidden = !help.hidden;
    helpBtn.setAttribute('aria-expanded', String(!help.hidden));
  });
  help.addEventListener('click', (e) => {
    const ins = e.target.closest('[data-insert]');
    const ex = e.target.closest('[data-example]');
    if (ins) {
      const v = input.value;
      const at = input.selectionStart ?? v.length;
      const pre = v.slice(0, at);
      const add = (pre && !/\s$/.test(pre) ? ' ' : '') + ins.dataset.insert;
      input.value = pre + add + v.slice(at);
      input.focus();
      input.setSelectionRange(at + add.length, at + add.length);
      analyze();
    }
    if (ex) set(ex.dataset.example, { commit: true });
  });
  // 다른 입력 칸에 있지 않을 때 '/' 를 누르면 문장 칸으로 (검색 화면의 흔한 단축키)
  const onSlash = (e) => {
    if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t instanceof HTMLElement && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))) return;
    if (!el.isConnected) return;
    e.preventDefault();
    input.focus();
  };
  if (opt.slashShortcut) document.addEventListener('keydown', onSlash);

  analyze();
  return {
    input,
    get value() { return input.value; },
    get committed() { return committed; },
    get terms() { return terms; },
    set,
    /** 서버가 400 + query_error 로 거절했을 때 (파서 불일치 대비 — 보통은 화면에서 먼저 막힌다) */
    showServerError(qe, text) {
      error = new QueryError(qe.code, qe.start, qe.end, text ?? input.value, {});
      error.message = qe.message;
      error.display = `검색 문장 ${qe.start + 1}번째 글자: ${qe.message}`;
      lastRendered = '';
      render();
    },
    /** 기간이 바뀌면 린트(긴 기간 제외 경고)를 다시 */
    refresh() { lastRendered = ''; render(); },
    destroy() { document.removeEventListener('keydown', onSlash); clearTimeout(timer); },
  };
}
