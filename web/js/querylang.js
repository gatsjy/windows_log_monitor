// 검색 문장(B-01, ADR-033): event_id:4625 ip:10.0.0.5 -user:svc_backup level:오류,심각 "잘못된 암호"
// server/app/querylang.py · server/app/filters.py(matches) 와 **한 줄씩 같은 알고리즘**이다. 규칙을 바꾸면 두 언어와
// 케이스 표(server/tests/querylang_cases.json)를 함께 고친다. 시험: node --test 'server/tests/js/*.test.mjs'
// 상수·오류 문구는 아래 @sync 블록 하나 — pytest(test_querylang_sync.py)가 Python 의 SYNC 와 같은지 본다.
// import 도 DOM 도 쓰지 않는다 (Node 에서 그대로 import 해 시험).
// 위치(start, end)는 코드 포인트 기준 — 화면에서 입력 칸에 표시할 때만 cpToUtf16 으로 바꾼다.

const SYNC = /* @sync:begin */ {
  "ws": [
    " ",
    "\t",
    "\n",
    "\r",
    " ",
    "　"
  ],
  "quotes": [
    "\"",
    "“",
    "”"
  ],
  "reserved": {
    "*": "wildcard",
    "|": "pipe",
    "(": "paren",
    ")": "paren"
  },
  "reserved_words": [
    "AND",
    "OR",
    "NOT",
    "&&"
  ],
  "keys": [
    "host",
    "channel",
    "provider",
    "source",
    "category",
    "user",
    "ip",
    "level",
    "event_id",
    "msg"
  ],
  "time_keys": [
    "since",
    "until"
  ],
  "levels": {
    "1": [
      "심각",
      "critical"
    ],
    "2": [
      "오류",
      "error"
    ],
    "3": [
      "경고",
      "warning"
    ],
    "4": [
      "정보",
      "info",
      "information"
    ],
    "5": [
      "상세",
      "verbose"
    ]
  },
  "categories": [
    "security",
    "system",
    "application",
    "powershell",
    "defender",
    "rdp",
    "sysmon",
    "windows",
    "iis",
    "mssql",
    "linux",
    "syslog",
    "file"
  ],
  "category_hints": {
    "보안": "security",
    "시스템": "system",
    "응용": "application",
    "응용 프로그램": "application",
    "app": "application",
    "파워셸": "powershell",
    "백신": "defender",
    "원격": "rdp",
    "원격 데스크톱": "rdp",
    "기타": "windows",
    "웹": "iis",
    "웹 서버": "iis",
    "web": "iis",
    "db": "mssql",
    "sql": "mssql",
    "리눅스": "linux",
    "장비": "syslog",
    "파일": "file"
  },
  "key_hints": {
    "q": "msg",
    "message": "msg",
    "text": "msg",
    "메시지": "msg",
    "내용": "msg",
    "username": "user",
    "account": "user",
    "사용자": "user",
    "계정": "user",
    "src_ip": "ip",
    "srcip": "ip",
    "source_ip": "ip",
    "ipaddress": "ip",
    "출발지": "ip",
    "아이피": "ip",
    "eventid": "event_id",
    "event": "event_id",
    "id": "event_id",
    "eid": "event_id",
    "이벤트": "event_id",
    "computer": "host",
    "pc": "host",
    "hostname": "host",
    "호스트": "host",
    "컴퓨터": "host",
    "cat": "category",
    "분류": "category",
    "lvl": "level",
    "severity": "level",
    "수준": "level",
    "레벨": "level",
    "채널": "channel",
    "공급자": "provider",
    "소스": "source",
    "f": "f.경로",
    "field": "f.경로",
    "fields": "f.경로",
    "raw": "f.경로",
    "원본": "f.경로"
  },
  "limits": {
    "max_len": 500,
    "max_terms": 30,
    "max_values": 50,
    "max_value_len": 200,
    "max_fields": 10,
    "max_msg": 20,
    "max_segments": 16,
    "max_segment_len": 100,
    "max_event_id": 2147483647
  },
  "errors": {
    "too_long": "검색 문장은 {max}자까지 쓸 수 있습니다.",
    "control_char": "보이지 않는 제어 문자가 들어 있습니다. 지우고 다시 입력하세요.",
    "unterminated_quote": "따옴표가 닫히지 않았습니다. 끝에 \" 를 붙이세요.",
    "junk_after_quote": "닫는 따옴표 뒤에는 띄어쓰기나 쉼표가 와야 합니다.",
    "quote_in_word": "단어 중간에 따옴표가 있습니다. 전체를 따옴표로 감싸고, 안의 \" 는 \"\" 로 두 번 쓰세요.",
    "empty_quoted": "따옴표 안이 비어 있습니다.",
    "lone_minus": "'-' 뒤에 제외할 조건이나 단어를 붙여 쓰세요. 예) -user:svc_backup",
    "double_minus": "'-' 는 한 번만 씁니다. '-' 로 시작하는 글자를 찾으려면 따옴표로 감싸세요. 예) \"--force\"",
    "wildcard": "와일드카드(*)는 지원하지 않습니다(정확히 일치만). 글자 * 를 찾으려면 따옴표로 감싸세요.",
    "pipe": "'|' 는 쓸 수 없습니다. 여러 값 중 하나는 쉼표로 씁니다. 예) msg:timeout,refused · host:A,B",
    "paren": "괄호 묶음은 지원하지 않습니다. 글자 그대로 찾으려면 따옴표로 감싸세요.",
    "reserved_word": "'{word}' 는 쓸 수 없습니다. 띄어 쓰면 '그리고', 쉼표는 '또는'(host:A,B), 앞의 - 는 '제외'(-host:A)입니다. 글자 그대로 찾으려면 \"{word}\".",
    "operator": "비교·부정 기호 '{ch}' 는 쓸 수 없습니다. 제외는 -host:A 처럼 앞에 - 를 붙입니다.",
    "single_quote": "작은따옴표 대신 큰따옴표(\")로 감싸세요.",
    "missing_key": "':' 앞에 조건 이름이 없습니다. 글자 그대로 찾으려면 따옴표로 감싸세요.",
    "unknown_key": "알 수 없는 조건 '{key}' 입니다.{hint} 글자 그대로 찾으려면 따옴표로 감싸세요.",
    "hint_suggest": " '{suggest}' 를 찾으셨나요?",
    "time_key": "기간은 문장에 쓰지 않고 위의 기간 선택으로 정합니다.",
    "bad_path": "원본 필드 경로가 잘못되었습니다. 점으로 이어 씁니다. 예) f.EventData.LogonType",
    "bad_index": "배열 위치는 0, 1, 2 처럼 앞자리 0·부호 없이 씁니다.",
    "path_too_long": "원본 필드 경로가 너무 깁니다 (최대 {segments}단계, 단계마다 {segment}자).",
    "empty_value": "'{key}:' 뒤에 값이 없습니다.",
    "space_after_colon": "':' 뒤에 띄어쓰기가 있습니다. {key}:값 처럼 붙여 쓰세요.",
    "empty_item": "쉼표 앞뒤에 값이 없습니다.",
    "bad_level": "'{value}' 는 수준이 아닙니다. 심각·오류·경고·정보·상세 또는 1~5 중에서 씁니다.",
    "bad_int": "이벤트 ID '{value}' 는 0 이상의 정수여야 합니다. 여러 개는 4625,4740 처럼 씁니다.",
    "int_range": "이벤트 ID '{value}' 가 너무 큽니다 (최대 2147483647).",
    "bad_category": "'{value}' 는 분류 이름이 아닙니다.{hint} 쓸 수 있는 값: {list}",
    "cidr": "IP 대역(/) 검색은 지원하지 않습니다. 주소를 쉼표로 나열하세요.",
    "value_too_long": "값은 {max}자까지 쓸 수 있습니다.",
    "too_many_terms": "조건은 {max}개까지 쓸 수 있습니다.",
    "too_many_values": "한 조건의 값은 {max}개까지 쓸 수 있습니다.",
    "too_many_fields": "원본 필드(f.) 조건은 URL 의 f. 조건과 합쳐 {max}개까지 쓸 수 있습니다.",
    "too_many_msg": "메시지 단어·구절은 {max}개까지 쓸 수 있습니다."
  }
} /* @sync:end */;

const WS = new Set(SYNC.ws);
const QUOTES = new Set(SYNC.quotes);
const RESERVED = SYNC.reserved;
const RESERVED_WORDS = new Set(SYNC.reserved_words);
export const KEYS = SYNC.keys;
export const LIMITS = SYNC.limits;
export const LEVEL_NAMES = Object.fromEntries(Object.entries(SYNC.levels).map(([k, v]) => [Number(k), v[0]]));
export const CATEGORIES = SYNC.categories;
const LEVEL_OF = new Map(Object.entries(SYNC.levels).flatMap(([k, names]) => [k, ...names].map((n) => [n, Number(k)])));
const IDENT = /^[A-Za-z_가-힣][A-Za-z0-9_.가-힣-]*$/;
const INDEX_LIKE = /^[+-]?[0-9]+$/;
const INDEX = /^(0|[1-9][0-9]*)$/;
const DIGITS = /^[0-9]+$/;
const MAX_FIELD_FILTERS = 10;
// 문장 키 → 이벤트(API 응답·SSE) 필드 이름
const EVENT_FIELD = { user: 'username', ip: 'src_ip' };
const INCLUDE_FIELD = {
  host: 'hosts', channel: 'channels', provider: 'providers', source: 'sources', category: 'categories',
  user: 'users', ip: 'ips', level: 'levels', event_id: 'event_ids',
};

const isControl = (ch) => { const o = ch.codePointAt(0); return (o < 0x20 && !'\t\n\r'.includes(ch)) || o === 0x7f; };
const isReserved = (ch) => Object.prototype.hasOwnProperty.call(RESERVED, ch);
const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/** A-Z 만 소문자로 (toLowerCase 는 'İ' 같은 글자를 바꿔 Python 과 어긋난다) */
export const asciiLower = (text) => text.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** 메시지 대소문자 무시 비교용 — PostgreSQL ILIKE 와 맞춘다 (querylang.fold 참고) */
export const fold = (text) => text.replaceAll('İ', 'i').replaceAll('Σ', 'σ').toLowerCase();

export function renderError(code, params) {
  return SYNC.errors[code].replace(/\{([a-z_]+)\}/g, (_, name) => String(params[name] ?? ''));
}

export class QueryError extends Error {
  constructor(code, start, end, text, params = {}) {
    const message = renderError(code, params);
    const snip = Array.from(text).slice(start, end).slice(0, 20).join('');
    const where = `검색 문장 ${start + 1}번째 글자`;
    super(snip ? `${where} '${snip}': ${message}` : `${where}: ${message}`);
    Object.assign(this, { name: 'QueryError', code, start, end, text, params, message: message });
    this.display = snip ? `${where} '${snip}': ${message}` : `${where}: ${message}`;
  }

  asDict() { return { code: this.code, start: this.start, end: this.end, message: this.message }; }
}

export function termJson(t) {
  const out = { key: t.key, neg: t.neg, values: [...t.values], span: [...t.span] };
  if (t.key === 'f') out.path = [...t.path];
  return out;
}

function levenshtein(a, b) {
  const x = Array.from(a);
  const y = Array.from(b);
  let prev = Array.from({ length: y.length + 1 }, (_, i) => i);
  x.forEach((ca, i) => {
    const cur = [i + 1];
    y.forEach((cb, j) => cur.push(Math.min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (ca !== cb ? 1 : 0))));
    prev = cur;
  });
  return prev[prev.length - 1];
}

/** 오타 안내: 힌트 표 먼저, 그다음 3자 이상이면 편집 거리 2 이하 (동점이면 목록 순서) */
function suggest(name, hints, choices) {
  const low = asciiLower(name);
  if (hasOwn(hints, low)) return hints[low];
  if (low.includes('.')) {
    const dot = name.indexOf('.');
    const head = name.slice(0, dot);
    const rest = name.slice(dot + 1);
    const found = hasOwn(hints, asciiLower(head)) ? hints[asciiLower(head)] : '';
    if (found === 'f.경로') return `f.${rest}`;
    if (found) return found;
  }
  if (Array.from(low).length >= 3) {
    let best = '';
    let bestD = 3;
    for (const choice of choices) {
      const d = levenshtein(low, choice);
      if (d < bestD) { best = choice; bestD = d; }
    }
    return best;
  }
  return '';
}

const hint = (s) => (s ? renderError('hint_suggest', { suggest: s }) : '');

class Scanner {
  constructor(text, fieldBudget) {
    this.text = text;
    this.t = Array.from(text);
    this.n = this.t.length;
    this.fieldBudget = fieldBudget;
    this.nMsg = 0;
  }

  err(code, start, end, params = {}) { return new QueryError(code, start, end, this.text, params); }

  slice(a, b) { return this.t.slice(a, b).join(''); }

  countMsg(start, end) {
    this.nMsg += 1;
    if (this.nMsg > LIMITS.max_msg) throw this.err('too_many_msg', start, end, { max: LIMITS.max_msg });
  }

  reserved(i) { return this.err(RESERVED[this.t[i]], i, i + 1); }

  parse() {
    const { t, n } = this;
    if (n > LIMITS.max_len) throw this.err('too_long', LIMITS.max_len, n, { max: LIMITS.max_len });
    for (let i = 0; i < n; i += 1) if (isControl(t[i])) throw this.err('control_char', i, i + 1);
    const terms = [];
    let nFields = 0;
    let i = 0;
    for (;;) {
      while (i < n && WS.has(t[i])) i += 1;
      if (i === n) break;
      const start = i;
      let neg = false;
      if (t[i] === '-') {
        if (i + 1 === n || WS.has(t[i + 1])) throw this.err('lone_minus', i, i + 1);
        if (t[i + 1] === '-') throw this.err('double_minus', i, i + 2);
        neg = true;
        i += 1;
      }
      let term;
      if (QUOTES.has(t[i])) {
        let value;
        [value, i] = this.readQuoted(i);
        if (i < n && !WS.has(t[i])) throw this.err('junk_after_quote', i, i + 1);
        term = { key: 'msg', values: [value], neg, path: [], span: [start, i] };
        this.countMsg(start, i);
      } else {
        [term, i] = this.readBareTerm(i, start, neg);
      }
      if (term.key === 'f') {
        nFields += 1;
        if (nFields > this.fieldBudget) throw this.err('too_many_fields', ...term.span, { max: LIMITS.max_fields });
      }
      if (terms.length === LIMITS.max_terms) throw this.err('too_many_terms', ...term.span, { max: LIMITS.max_terms });
      terms.push(term);
    }
    return terms;
  }

  readBareTerm(i, start, neg) {
    const { t, n } = this;
    if (t[i] === '!') throw this.err('operator', i, i + 1, { ch: '!' });
    if (t[i] === "'") throw this.err('single_quote', i, i + 1);
    let j = i;
    while (j < n && !WS.has(t[j]) && !QUOTES.has(t[j]) && t[j] !== ':') {
      if (isReserved(t[j])) throw this.reserved(j);
      j += 1;
    }
    if (j < n && QUOTES.has(t[j])) throw this.err('quote_in_word', j, j + 1);
    if (j === n || WS.has(t[j])) {                          // ':' 없는 단어 = 메시지 부분일치
      const word = this.slice(i, j);
      if (RESERVED_WORDS.has(word)) throw this.err('reserved_word', i, j, { word });
      this.countMsg(start, j);
      return [{ key: 'msg', values: [word], neg, path: [], span: [start, j] }, j];
    }
    const head = this.slice(i, j);                          // t[j] === ':'
    if (head === '') throw this.err('missing_key', j, j + 1);
    const low = asciiLower(head);
    if (KEYS.includes(low)) return this.readValues(low, [], head, j, start, neg);
    if (low.startsWith('f.')) {
      const path = this.parsePath(Array.from(head).slice(2).join(''), i + 2, [i, j]);
      return this.readValues('f', path, head, j, start, neg);
    }
    if (SYNC.time_keys.includes(low)) throw this.err('time_key', i, j);
    const nxt = j + 1 < n ? t[j + 1] : '';
    if (IDENT.test(head) && ![':', '\\', '/'].includes(nxt)) {
      const suggested = suggest(head, SYNC.key_hints, KEYS);   // suggest: 화면의 '고치기' 단추용 (문구에는 hint)
      throw this.err('unknown_key', i, j, { key: head, hint: hint(suggested), suggest: suggested });
    }
    let k = j;                                              // ':' 가 든 메시지 단어 (C:\x, http://x, 12:30, fe80::1)
    while (k < n && !WS.has(t[k])) {
      if (QUOTES.has(t[k])) throw this.err('quote_in_word', k, k + 1);
      if (isReserved(t[k])) throw this.reserved(k);
      k += 1;
    }
    this.countMsg(start, k);
    return [{ key: 'msg', values: [this.slice(i, k)], neg, path: [], span: [start, k] }, k];
  }

  parsePath(s, off, keySpan) {
    const segs = s.split('.');
    if (s === '' || segs.includes('') || s.includes(',')) throw this.err('bad_path', ...keySpan);
    if (segs.length > LIMITS.max_segments || segs.some((seg) => Array.from(seg).length > LIMITS.max_segment_len)) {
      throw this.err('path_too_long', ...keySpan, { segments: LIMITS.max_segments, segment: LIMITS.max_segment_len });
    }
    let pos = off;
    for (const seg of segs) {
      const len = Array.from(seg).length;
      if (INDEX_LIKE.test(seg) && !INDEX.test(seg)) throw this.err('bad_index', pos, pos + len);
      pos += len + 1;
    }
    return segs;
  }

  readValues(key, path, head, j, start, neg) {
    const { t, n } = this;
    let k = j + 1;
    if (k === n) throw this.err('empty_value', j, j + 1, { key: head });
    if (WS.has(t[k])) {
      let m = k;
      while (m < n && WS.has(t[m])) m += 1;
      if (m === n) throw this.err('empty_value', j, j + 1, { key: head });
      throw this.err('space_after_colon', j, m, { key: head });
    }
    const values = [];
    for (;;) {
      let value;
      let e;
      let s0;
      let s1;
      if (QUOTES.has(t[k])) {
        [value, e] = this.readQuoted(k);
        s0 = k; s1 = e;
        if (e < n && !WS.has(t[e]) && t[e] !== ',') throw this.err('junk_after_quote', e, e + 1);
      } else if (t[k] === ',') {
        throw this.err('empty_item', k, k + 1);
      } else {
        e = k;
        while (e < n && !WS.has(t[e]) && t[e] !== ',') {
          if (QUOTES.has(t[e])) throw this.err('quote_in_word', e, e + 1);
          if (isReserved(t[e])) throw this.reserved(e);
          e += 1;
        }
        value = this.slice(k, e);
        s0 = k; s1 = e;
        if ('<>=!'.includes(t[k])) throw this.err('operator', k, k + 1, { ch: t[k] });
        if (t[k] === "'") throw this.err('single_quote', k, k + 1);
      }
      if (Array.from(value).length > LIMITS.max_value_len) throw this.err('value_too_long', s0, s1, { max: LIMITS.max_value_len });
      const typed = this.validate(key, value, s0, s1);
      if (!values.includes(typed)) {
        if (values.length === LIMITS.max_values) throw this.err('too_many_values', s0, s1, { max: LIMITS.max_values });
        values.push(typed);
      }
      if (key === 'msg') this.countMsg(s0, s1);
      k = e;
      if (k < n && t[k] === ',') {
        if (k + 1 === n || WS.has(t[k + 1])) throw this.err('empty_item', k, k + 1);
        k += 1;
        continue;
      }
      break;
    }
    return [{ key, values, neg, path, span: [start, k] }, k];
  }

  readQuoted(p) {
    const { t, n } = this;
    let k = p + 1;
    const buf = [];
    for (;;) {
      if (k === n) throw this.err('unterminated_quote', p, n);
      const c = t[k];
      if (QUOTES.has(c)) {
        if (k + 1 < n && QUOTES.has(t[k + 1])) { buf.push(c); k += 2; continue; }   // "" → " (스마트 따옴표도 같은 규칙)
        k += 1;
        break;
      }
      buf.push(c);
      k += 1;
    }
    if (buf.every((c) => WS.has(c))) throw this.err('empty_quoted', p, k);
    return [buf.join(''), k];
  }

  validate(key, value, s0, s1) {
    if (key === 'ip' && value.includes('/')) throw this.err('cidr', s0, s1);
    if (key === 'category') {
      const low = asciiLower(value);
      if (CATEGORIES.includes(low)) return low;
      const suggested = suggest(value, SYNC.category_hints, CATEGORIES);
      throw this.err('bad_category', s0, s1, { value, hint: hint(suggested), suggest: suggested, list: CATEGORIES.join(', ') });
    }
    if (key === 'level') {
      const level = LEVEL_OF.get(asciiLower(value));
      if (level === undefined) throw this.err('bad_level', s0, s1, { value });
      return level;
    }
    if (key === 'event_id') {
      if (!DIGITS.test(value)) throw this.err('bad_int', s0, s1, { value });
      const digits = value.replace(/^0+/, '') || '0';
      if (digits.length > 10 || Number(digits) > LIMITS.max_event_id) throw this.err('int_range', s0, s1, { value });
      return Number(digits);
    }
    return value;
  }
}

/** 문장 → term 목록 {key, values, neg, path, span}. 틀리면 QueryError(처음 하나) */
export function parseTerms(text, { fieldBudget = LIMITS.max_fields } = {}) {
  return new Scanner(String(text ?? ''), fieldBudget).parse();
}

// ------------------------------------------------------------------ 정규형

function needsQuote(value, kind) {
  const cps = Array.from(value);
  if (!cps.length || cps.some((c) => WS.has(c) || QUOTES.has(c) || isReserved(c) || isControl(c))) return true;
  if ("!'".includes(cps[0])) return true;
  if (kind === 'word') return cps[0] === '-' || value.includes(':') || RESERVED_WORDS.has(value);
  return '<>='.includes(cps[0]) || value.includes(',');
}

/** 값 하나 → 문장 표기. kind = 'word'(메시지 단어) | 'value'(키:값의 값) */
export function formatValue(value, kind = 'value') {
  const text = String(value);
  if (!needsQuote(text, kind)) return text;
  return `"${Array.from(text).map((c) => (QUOTES.has(c) ? c + c : c)).join('')}"`;
}

export function formatTerm(term) {
  const sign = term.neg ? '-' : '';
  if (term.key === 'msg' && term.values.length === 1) return sign + formatValue(term.values[0], 'word');
  const values = term.key === 'level' ? term.values.map((v) => LEVEL_NAMES[v]) : term.values.map((v) => formatValue(v));
  const key = term.key === 'f' ? `f.${term.path.join('.')}` : term.key;
  return `${sign}${key}:${values.join(',')}`;
}

export const formatQuery = (terms) => terms.map(formatTerm).join(' ');

// ------------------------------------------------------------------ 원본 JSON

function rawJson(v) {
  if (v === null || v === undefined) return 'null';
  if (Array.isArray(v)) return `[${v.map(rawJson).join(', ')}]`;
  if (typeof v === 'object') return `{${Object.entries(v).map(([k, x]) => `${JSON.stringify(k)}: ${rawJson(x)}`).join(', ')}}`;
  return JSON.stringify(v);
}

/** PostgreSQL `raw #>> path` 와 같은 문자열 표현 (배열·객체는 ', ' · ': ' 구분자) */
export function rawText(v) {
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  return rawJson(v);
}

/** 원본 JSON 경로 값 (없으면 undefined). 배열은 ASCII 숫자 위치만 */
export function walkRaw(value, path) {
  let cur = value;
  for (const part of path) {
    if (cur !== null && typeof cur === 'object' && !Array.isArray(cur)) cur = hasOwn(cur, part) ? cur[part] : undefined;
    else if (Array.isArray(cur) && DIGITS.test(part) && Number(part) < cur.length) cur = cur[Number(part)];
    else return undefined;
  }
  return cur;
}

// ------------------------------------------------------------------ 필터 (server/app/filters.py EventFilter)

const LIST_PARAMS = ['host', 'channel', 'provider', 'source', 'category', 'user', 'ip'];
const pyStrip = (s) => s.trim();
const splitList = (v) => String(v).split(',').map(pyStrip).filter(Boolean);

function emptyFilter() {
  return {
    hosts: [], channels: [], providers: [], sources: [], categories: [], users: [], ips: [], levels: [], event_ids: [],
    qTerms: [], fields: [], excludes: new Map(), msgAll: [], msgNot: [], fieldAny: [], never: false,
  };
}

/** 문장의 term 들을 AND 로 더한 새 필터 (filters.EventFilter.merged 와 같은 규칙) */
export function mergeTerms(filter, terms) {
  const f = { ...filter, excludes: new Map([...filter.excludes].map(([k, v]) => [k, [...v]])) };
  for (const term of terms) {
    const values = [...term.values];
    if (term.neg) {
      if (term.key === 'msg') { f.msgNot = [...f.msgNot, ...values.filter((v) => !f.msgNot.includes(v))]; continue; }
      const key = term.key === 'f' ? `f.${term.path.join('.')}` : term.key;
      const bucket = f.excludes.get(key) ?? [];
      values.forEach((v) => { if (!bucket.includes(v)) bucket.push(v); });
      f.excludes.set(key, bucket);
    } else if (term.key === 'msg') {
      f.msgAll = [...f.msgAll, values];
    } else if (term.key === 'f') {
      if (values.length === 1) f.fields = [...f.fields, [[...term.path], values[0]]];
      else f.fieldAny = [...f.fieldAny, [[...term.path], values]];
    } else {
      const name = INCLUDE_FIELD[term.key];
      if (f[name].length) {
        const narrowed = f[name].filter((v) => values.includes(v));
        f.never = f.never || !narrowed.length;
        f[name] = narrowed;
      } else {
        f[name] = values;
      }
    }
  }
  return f;
}

function parseIntParam(v) {
  return /^[+-]?[0-9]+$/.test(v) ? Number(v) : NaN;
}

/** 조건 객체({host, level, q, 'f.경로', query, …}) → 필터. 서버가 400 을 낼 조건이면 null (EventFilter.from_params) */
export function buildFilter(params) {
  let f = emptyFilter();
  const fieldFilters = [];
  for (const [key, value] of Object.entries(params ?? {})) {
    if (key.startsWith('f.') && key.length > 2) {
      const path = key.slice(2).split('.').filter(Boolean);
      if (path.length) fieldFilters.push([path, String(value ?? '')]);
    }
  }
  if (fieldFilters.length > MAX_FIELD_FILTERS) return null;
  for (const key of LIST_PARAMS) {
    if (params[key] != null && params[key] !== '') f[INCLUDE_FIELD[key]] = splitList(params[key]);
  }
  for (const key of ['level', 'event_id']) {
    if (params[key] == null || params[key] === '') continue;
    const ints = splitList(params[key]).map(parseIntParam);
    if (ints.some(Number.isNaN)) return null;
    f[INCLUDE_FIELD[key]] = ints;
  }
  const q = Array.from(pyStrip(String(params.q ?? ''))).slice(0, 200).join('');
  f.qTerms = q.split('|').map(pyStrip).filter(Boolean);
  f.fields = fieldFilters;
  const text = params.query == null ? '' : String(params.query);
  if (text.trim()) f = mergeTerms(f, parseTerms(text, { fieldBudget: MAX_FIELD_FILTERS - fieldFilters.length }));
  return f;
}

function eventValue(ev, key) {
  const v = ev[EVENT_FIELD[key] ?? key];
  return v === undefined ? null : v;
}

const foldCache = new WeakMap();
function foldedMessage(ev) {
  let m = foldCache.get(ev);
  if (m === undefined) { m = fold(ev.message ?? ''); foldCache.set(ev, m); }
  return m;
}

/** 필터 → (이벤트) => 맞는가. filters.EventFilter.matches 와 같은 순서·같은 NULL 규칙 (시간 조건은 보지 않음) */
export function compileFilter(f) {
  if (!f) return () => false;
  if (f.never) return () => false;
  const cols = Object.entries(INCLUDE_FIELD).filter(([, name]) => f[name].length);
  const q = f.qTerms.map(fold);
  const msgAll = f.msgAll.map((g) => g.map(fold));
  const msgNot = f.msgNot.map(fold);
  const excludes = [...f.excludes];
  return (ev) => {
    for (const [key, name] of cols) {
      const v = eventValue(ev, key);
      if (v === null || !f[name].includes(v)) return false;
    }
    const message = foldedMessage(ev);
    if (q.length && !q.some((t) => message.includes(t))) return false;
    for (const group of msgAll) if (!group.some((v) => message.includes(v))) return false;
    for (const [path, expected] of f.fields) {
      const cur = walkRaw(ev.raw, path);
      if (cur == null || rawText(cur) !== expected) return false;
    }
    for (const [path, values] of f.fieldAny) {
      const cur = walkRaw(ev.raw, path);
      if (cur == null || !values.includes(rawText(cur))) return false;
    }
    for (const [key, values] of excludes) {
      if (key.startsWith('f.')) {
        const cur = walkRaw(ev.raw, key.slice(2).split('.'));
        if (cur != null && values.includes(rawText(cur))) return false;
      } else {
        const v = eventValue(ev, key);
        if (v !== null && values.includes(v)) return false;   // 값이 없으면 남김 = SQL 의 IS NOT TRUE
      }
    }
    return !msgNot.some((v) => message.includes(v));
  };
}

/** 조건 객체 → 술어. 문장이 틀렸거나 서버가 거절할 조건이면 늘 false (위젯의 서버 조회가 오류를 보여 준다) */
export function compileQuery(params) {
  try {
    return compileFilter(buildFilter(params));
  } catch (err) {
    if (err instanceof QueryError) return () => false;
    throw err;
  }
}

// ------------------------------------------------------------------ 옛 링크 파라미터 → 문장 (화면에 들어올 때)

const FOLD_KEYS = ['host', 'channel', 'provider', 'source', 'category', 'user', 'ip', 'level', 'event_id'];
const sameList = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const unique = (list) => list.filter((v, i) => list.indexOf(v) === i);

function onlyTerm(text) {
  try {
    const terms = parseTerms(text);
    return terms.length === 1 ? terms[0] : null;
  } catch { return null; }
}

/**
 * 옛 파라미터(host=…&level=1,2&q=a|b&f.X=1)를 문장 하나로 접는다. 뜻이 똑같이 옮겨지는 것만 접고(다시 읽어 확인),
 * 아니면 rest 에 옛 파라미터로 남긴다 (서버도 그대로 처리). 기간(since·until)은 늘 rest.
 * @returns {{query: string, rest: object}}
 */
export function foldParams(params) {
  const parts = [];
  const rest = {};
  const existing = params.query == null ? '' : String(params.query).trim();
  if (existing) parts.push(existing);
  for (const key of FOLD_KEYS) {
    const raw = params[key];
    if (raw == null || raw === '') continue;
    const values = splitList(raw);
    const typed = key === 'level' || key === 'event_id' ? values.map(parseIntParam) : values;
    const term = typed.some((v) => Number.isNaN(v)) ? null
      : onlyTerm(`${key}:${values.map((v) => formatValue(v)).join(',')}`);
    if (term && term.key === key && !term.neg && sameList(term.values, unique(typed))) parts.push(formatTerm(term));
    else rest[key] = raw;
  }
  for (const [key, value] of Object.entries(params)) {
    if (!(key.startsWith('f.') && key.length > 2)) continue;
    const path = key.slice(2).split('.').filter(Boolean);
    if (!path.length) { rest[key] = value; continue; }
    const text = String(value ?? '');
    const term = onlyTerm(`f.${path.join('.')}:${formatValue(text)}`);
    if (term && term.key === 'f' && !term.neg && sameList(term.path, path) && sameList(term.values, [text])) {
      parts.push(formatTerm(term));
    } else {
      rest[key] = value;
    }
  }
  if (params.q != null && params.q !== '') {
    const q = Array.from(pyStrip(String(params.q))).slice(0, 200).join('');
    const terms = q.split('|').map(pyStrip).filter(Boolean);
    if (terms.length) {
      const text = terms.length === 1 ? formatValue(terms[0], 'word') : `msg:${terms.map((v) => formatValue(v)).join(',')}`;
      const term = onlyTerm(text);
      if (term && term.key === 'msg' && !term.neg && sameList(term.values, unique(terms))) parts.push(formatTerm(term));
      else rest.q = params.q;
    }
  }
  for (const [key, value] of Object.entries(params)) {
    if (key === 'query' || FOLD_KEYS.includes(key) || key === 'q' || (key.startsWith('f.') && key.length > 2)) continue;
    rest[key] = value;
  }
  const query = parts.join(' ');
  const leftFields = Object.keys(rest).filter((k) => k.startsWith('f.') && k.length > 2).length;
  try {
    parseTerms(query, { fieldBudget: MAX_FIELD_FILTERS - leftFields });
  } catch {
    // 합친 문장이 한도를 넘거나 원래 문장이 틀렸으면 접지 않는다 (서버가 원래대로 판단·오류)
    const untouched = { ...params };
    delete untouched.query;
    return { query: params.query == null ? '' : String(params.query), rest: untouched };
  }
  return { query, rest };
}

// ------------------------------------------------------------------ 컨트롤 → 문장 (사용자 표기·순서·따옴표 보존)

function pieces(text) {
  const cps = Array.from(text);
  return parseTerms(text).map((t) => ({ term: t, text: cps.slice(t.span[0], t.span[1]).join('') }));
}

/** 드롭다운: 그 키의 포함 조건을 value 하나로 (value 가 비면 '전체' = 포함 조건만 지움). 제외에서 그 값은 뺀다 */
export function setKey(text, key, value) {
  const out = [];
  let at = -1;
  for (const p of pieces(text)) {
    if (p.term.key === key && !p.term.neg) {
      if (at < 0) at = out.length;
      continue;
    }
    if (p.term.key === key && p.term.neg && value !== '') {
      const left = p.term.values.filter((v) => v !== value);
      if (!left.length) continue;
      if (left.length !== p.term.values.length) { out.push(formatTerm({ ...p.term, values: left })); continue; }
    }
    out.push(p.text);
  }
  if (value !== '') {
    const term = formatTerm({ key, values: [value], neg: false, path: [] });
    if (at < 0) out.push(term); else out.splice(at, 0, term);
  }
  return out.join(' ');
}

/** 수준 칩: 수준 조건 전부를 levels(포함) 하나로. 비었거나 5개 모두면 수준 조건 없음 */
export function setLevels(text, levels) {
  const set = [...new Set(levels.map(Number))].sort((a, b) => a - b);
  const out = [];
  let at = -1;
  for (const p of pieces(text)) {
    if (p.term.key === 'level') { if (at < 0) at = out.length; continue; }
    out.push(p.text);
  }
  if (set.length && set.length < 5) {
    const term = formatTerm({ key: 'level', values: set, neg: false, path: [] });
    if (at < 0) out.push(term); else out.splice(at, 0, term);
  }
  return out.join(' ');
}

const sameTerm = (a, b) => a.key === b.key && Boolean(a.neg) === Boolean(b.neg)
  && sameList(a.path ?? [], b.path ?? []) && sameList(a.values, b.values);

/** 상세 패널의 '좁히기·제외': 같은 조건이 이미 있으면 그대로, 아니면 끝에 붙인다 */
export function addTerm(text, term) {
  const t = { neg: false, path: [], ...term };
  if (parseTerms(text).some((x) => sameTerm(x, t))) return text;
  const head = text.trimEnd();
  return head ? `${head} ${formatTerm(t)}` : formatTerm(t);
}

// ------------------------------------------------------------------ 위치 (입력 칸은 UTF-16)

export const cpToUtf16 = (text, cp) => Array.from(text).slice(0, cp).join('').length;
export const utf16ToCp = (text, unit) => Array.from(text.slice(0, unit)).length;

/**
 * 자동완성용: 커서(코드 포인트)가 있는 토큰. {start, end, kind: 'key'|'value', key, prefix}
 * kind 'value' 면 key 는 소문자 키, prefix 는 마지막 쉼표 뒤 입력 중인 값(따옴표 뺌)
 */
export function tokenAt(text, caret) {
  const cps = Array.from(text);
  let start = caret;
  while (start > 0 && !WS.has(cps[start - 1])) start -= 1;
  let end = caret;
  while (end < cps.length && !WS.has(cps[end])) end += 1;
  let from = start;
  if (cps[from] === '-') from += 1;
  const before = cps.slice(from, caret).join('');
  const colon = before.indexOf(':');
  if (colon < 0 || QUOTES.has(cps[from])) return { start: from, end, kind: 'key', key: '', prefix: before };
  const key = asciiLower(before.slice(0, colon));
  const valuePart = before.slice(colon + 1);
  const lastComma = valuePart.lastIndexOf(',');
  const prefix = valuePart.slice(lastComma + 1).replace(/^["“”]/, '');
  const valueStart = from + Array.from(before.slice(0, colon + 1 + lastComma + 1)).length;
  return { start: valueStart, end, kind: 'value', key, prefix, chosen: valuePart.slice(0, Math.max(lastComma, 0)).split(',').filter(Boolean) };
}
