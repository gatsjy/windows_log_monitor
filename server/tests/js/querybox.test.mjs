// 검색 문장 입력 칸의 순수 함수 시험 — 빠른 고침·해석 문구·린트 (DOM 없이)
//   node --test 'server/tests/js/*.test.mjs'
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { contradiction, describe, lint, quickFixes } from '../../../web/js/querybox.js';
import { QueryError, parseTerms } from '../../../web/js/querylang.js';

function errorOf(text) {
  try { parseTerms(text); } catch (err) { if (err instanceof QueryError) return err; throw err; }
  throw new Error(`오류가 아님: ${text}`);
}

const applied = (text) => Object.fromEntries(quickFixes(errorOf(text)).map((f) => [f.label, f.apply()]));

test('빠른 고침은 고친 문장이 맞거나 오류가 뒤로 물러날 때만 내놓는다', () => {
  assert.deepEqual(applied('event_id:4625 hots:WEB-01'), {
    "'host' 로 고치기": 'event_id:4625 host:WEB-01',
    '따옴표로 감싸기 (글자 그대로 찾기)': 'event_id:4625 "hots:WEB-01"',
  });
  // 키 값 안의 | 는 그 키의 '또는'으로 (메시지 검색으로 바꾸지 않는다)
  assert.deepEqual(applied('host:WEB-01|WEB-02'), { 'host:WEB-01,WEB-02 로 바꾸기': 'host:WEB-01,WEB-02' });
  assert.deepEqual(applied('timeout|refused'), { 'msg:timeout,refused 로 바꾸기': 'msg:timeout,refused' });
  // 스마트 따옴표가 든 토큰도 맞게 감싼다 (두 번 쓰기)
  assert.equal(applied('Error:“x”')['따옴표로 감싸기 (글자 그대로 찾기)'], '"Error:““x””"');
  // 작은따옴표: 그 자리의 한 쌍만, 안의 큰따옴표는 두 번
  assert.equal(applied(`"it's" 'abc'`)['큰따옴표로 바꾸기'], `"it's" "abc"`);
  assert.equal(applied(`user:'say "hi"'`)['큰따옴표로 바꾸기'], 'user:"say ""hi"""');
  // 따옴표 안의 띄어쓰기는 토큰 안 — 구절을 반으로 자르지 않는다
  assert.equal(applied('제목:"디스크 부족"')['따옴표로 감싸기 (글자 그대로 찾기)'], '"제목:""디스크 부족"""');
  // 'f.경로' 힌트에는 고치기 단추를 내지 않는다 (경로를 모름)
  assert.equal(Object.keys(applied('raw:10')).some((l) => l.includes("'f.")), false);
  assert.deepEqual(applied('host: WEB-01'), { '띄어쓰기 지우기': 'host:WEB-01' });
  for (const text of ['event_id:4625 hots:WEB-01', 'host:WEB-01|WEB-02', 'Error:“x”', `"it's" 'abc'`, 'a OR b', 'x*', 'since:1h']) {
    for (const fix of quickFixes(errorOf(text))) {
      const err = (() => { try { parseTerms(fix.apply()); return null; } catch (e) { return e; } })();
      assert.ok(!err || err.start > errorOf(text).start, `${text} → ${fix.label} → ${fix.apply()}`);
    }
  }
});

test('해석 문구와 린트', () => {
  assert.equal(describe(parseTerms('event_id:4625 -user:svc,guest level:오류,심각 "잘못된 암호" category:security')),
    '이벤트 ID 4625 · 사용자 svc 또는 guest 제외 · 수준 오류 또는 심각 · 메시지에 "잘못된 암호" 포함 · 분류 보안');
  assert.equal(describe([]), '조건 없음');
  assert.equal(contradiction(parseTerms('host:A,B host:B')), null);
  assert.equal(contradiction(parseTerms('host:A host:B')), 'host');
  const texts = (terms, opt) => lint(terms, opt).map((l) => l.text.split(' ').slice(0, 3).join(' '));
  assert.deepEqual(texts(parseTerms('다시 부팅')), ['2글자 이하 단어는']);
  assert.equal(lint(parseTerms('다시 부팅'))[0].fix.apply('다시 부팅'), '"다시 부팅"');
  assert.deepEqual(texts(parseTerms('다시 host:A')), []);   // 색인을 쓰는 다른 조건이 있으면 괜찮다
  assert.deepEqual(texts(parseTerms('-host:A'), { since: '30d' }), ['제외 조건만으로 긴']);
  assert.deepEqual(texts(parseTerms('-host:A'), { since: '24h' }), []);
});
