// 교차 퍼징: 같은 무작위 문장 3,000개를 web/js/querylang.js 와 server/app/querylang.py(+filters.matches)에 넣어
// 파싱 결과(term·오류 코드·위치·문구)와 고정 이벤트 매칭 결과가 똑같은지 본다. python3(3.11+)이 없으면 건너뜀.
//   node --test 'server/tests/js/*.test.mjs'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { QueryError, compileQuery, parseTerms, termJson } from '../../../web/js/querylang.js';

const CASES = JSON.parse(readFileSync(new URL('../querylang_cases.json', import.meta.url), 'utf8'));
const PYRUN = fileURLToPath(new URL('./pyrun.py', import.meta.url));

function python() {
  const r = spawnSync('python3', ['-I', '-c', 'import sys; print(sys.version_info >= (3, 11))'], { encoding: 'utf8' });
  return r.status === 0 && r.stdout.trim() === 'True';
}

// 고정 seed 의 xorshift32 — 같은 문장이 늘 같은 순서로 나온다 (실패를 다시 볼 수 있게)
function rng(seed) {
  let x = seed >>> 0;
  const next = () => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 4294967296; };
  return { next, pick: (list) => list[Math.floor(next() * list.length)], int: (a, b) => a + Math.floor(next() * (b - a + 1)) };
}

const KEYS = ['host', 'Host', 'HOST', 'channel', 'provider', 'source', 'category', 'user', 'ip', 'level', 'event_id', 'msg',
  'f.EventID', 'F.Arr', 'f.Flag', 'f.StringInserts.5', 'f.EventData.LogonType', 'f.N', 'f.a..b', 'f.', 'f.x.01', 'f.x.-1',
  'hots', 'q', 'since', '사용자', 'Error', 'C', 'http', '12', 'fe80', 'lvl', 'field.EventData.X', 'cat'];
const VALUES = ['WEB-01', 'DC-01', 'DC-02', '"PC 01"', 'svc_backup', 'Svc_Backup', 'root', '10.0.0.5', 'fe80::1', '10.0.0.0/24',
  '오류', '심각', '경고', '1', '2', '7', 'err', 'Error', 'INFO', 'security', 'Security', 'iis', '보안', 'secrity', '4625', '04625',
  '99999999999', '+5', 'abc', 'true', '"[""x"", ""y""]"', 'user77', 'sshd', 'nginx', '-x', 'a:b', '>3', "'x'", '""', '"a,b"',
  '“PC 01”', 'x*', 'a|b', '😀', '١٢', 'Security'];
const WORDS = ['timeout', 'Timeout', 'REFUSED', '잘못된', '"잘못된 암호"', '“잘못된 암호”', '"say ""hi"""', 'C:\\Windows\\System32',
  'http://intra/login', '12:30:01', 'fe80::1', 'AND', 'OR', 'not', 'or', '*', '|', '(x)', "'x'", '!x', '--x', '-', '😀',
  'İstanbul', 'istanbul', 'ΟΔΟΣ', 'οδοσ', 'οδος', '50%_off', '50%off', '\\\\srv\\share', '1,024', '"a""b"', '"unterminated',
  '""', 'x"y', '"a"b', 'TimeoutException:', 'Error:', ':x', '다시', '부팅', '"다시 부팅"', 'Failed', 'password', 'w3wp.exe',
  'System.TimeoutException', 'svc_backup', '\u0001', 'ok\u007f', 'İ', 'Σ'];
const SEPS = [' ', ' ', ' ', '  ', '\u3000', '\t', '\u00a0', '\n', ''];

function sentence(r) {
  const parts = [];
  for (let i = r.int(1, 6); i > 0; i -= 1) {
    const roll = r.next();
    const neg = r.next() < 0.3 ? '-' : '';
    if (roll < 0.45) parts.push(neg + r.pick(WORDS));
    else {
      const values = Array.from({ length: r.int(1, 3) }, () => r.pick(VALUES));
      const glue = r.next() < 0.05 ? ', ' : r.next() < 0.03 ? ',,' : ',';
      parts.push(`${neg}${r.pick(KEYS)}${r.next() < 0.04 ? ': ' : ':'}${values.join(glue)}`);
    }
    parts.push(r.pick(SEPS));
  }
  return parts.join('');
}

function jsResult(text) {
  try {
    const terms = parseTerms(text).map(termJson);
    return { terms, ids: CASES.fixtures.filter(compileQuery({ query: text })).map((f) => f.id) };
  } catch (err) {
    if (err instanceof QueryError) return { error: err.asDict() };
    throw err;
  }
}

test('교차 퍼징: JS 와 Python 이 3,000 문장에서 같은 결과', { skip: !python() && 'python3 3.11+ 없음' }, () => {
  const r = rng(20261016);
  const texts = Array.from({ length: 3000 }, () => sentence(r));
  const out = spawnSync('python3', ['-I', PYRUN], { input: texts.map((t) => JSON.stringify(t)).join('\n') + '\n', encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024 });
  assert.equal(out.status, 0, out.stderr);
  const lines = out.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(lines.length, texts.length);
  let errors = 0;
  texts.forEach((text, i) => {
    const js = jsResult(text);
    if (js.error) errors += 1;
    assert.deepEqual(js, lines[i], `문장 ${i}: ${JSON.stringify(text)}`);
  });
  // 정상·오류가 고루 섞였는지 (한쪽만 시험하면 의미가 없다)
  assert.ok(errors > 300 && errors < 2700, `오류 ${errors}/3000`);
});
