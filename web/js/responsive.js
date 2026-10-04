// 좁은 화면 보정 — 화면 코드를 고치지 않고, 그려진 결과에 표시만 덧붙인다.
//  1) 표: 각 칸에 머리글 이름(data-label)을 달아 둔다 → CSS 가 모바일에서 '항목: 값' 카드로 쌓는다.
//     이벤트 표(.ev-table)는 전용 카드 배치, 쿼리 결과처럼 원본 격자가 필요한 표는 .no-stack.
//  2) 카드 격자: 한 줄(합계 12칸)에 놓인 카드끼리 묶어 태블릿·모바일에서 쓸 칸 수를 정한다.
//     태블릿(<1000px): 반 폭 이하 카드는 2개씩, 홀수로 남는 마지막 카드는 전체 폭.
//     모바일(<600px): 숫자 카드(3칸 이하)만 2개씩, 나머지는 전체 폭.

function spanOf(card) {
  const m = /span\s+(\d+)/.exec(card.style.gridColumn || card.getAttribute('style') || '');
  return m ? Number(m[1]) : 12;
}

function pairUp(cards, want, cls) {
  // want(card) → 6 이면 반 폭 후보. 연속된 반 폭 후보 묶음에서 홀수로 남는 마지막은 전체 폭
  let run = [];
  const flush = () => {
    run.forEach((c, i) => c.classList.add(`${cls}-${run.length % 2 && i === run.length - 1 ? 12 : 6}`));
    run = [];
  };
  cards.forEach((c) => {
    if (want(c) === 6) run.push(c);
    else { flush(); c.classList.add(`${cls}-12`); }
  });
  flush();
}

function layoutGrid(grid) {
  const cards = [...grid.children].filter((c) => c.classList.contains('card'));
  if (!cards.length) return;
  cards.forEach((c) => c.classList.remove('m-6', 'm-12', 's-6', 's-12'));
  // 한 줄 단위로 나눈다 (합계가 12 를 넘으면 다음 줄)
  const rows = [];
  let row = [];
  let sum = 0;
  cards.forEach((c) => {
    const span = spanOf(c);
    if (sum + span > 12 && row.length) { rows.push(row); row = []; sum = 0; }
    row.push(c);
    sum += span;
  });
  if (row.length) rows.push(row);
  rows.forEach((r) => {
    pairUp(r, (c) => (spanOf(c) <= 6 ? 6 : 12), 'm');
    pairUp(r, (c) => (spanOf(c) <= 3 ? 6 : 12), 's');
  });
}

function labelTable(table) {
  if (table.closest('.query-result') || table.classList.contains('no-stack')) return;
  const heads = [...table.querySelectorAll('thead th')].map((th) => th.textContent.trim());
  if (!heads.length) return;
  if (!table.classList.contains('ev-table')) table.classList.add('stack');
  table.querySelectorAll('tbody tr').forEach((tr) => {
    if (tr.dataset.labeled) return;
    tr.dataset.labeled = '1';
    [...tr.children].forEach((td, i) => {
      if (heads[i] && !td.dataset.label) td.dataset.label = heads[i];
      // 카드로 쌓을 때 긴 값(메시지·규칙 조건 등)은 한 줄 전체를 쓴다
      td.classList.toggle('wide', td.textContent.trim().length > 22 || !!td.querySelector('.dlv, .btn, .type-tag'));
    });
  });
}

function scan(node) {
  if (!(node instanceof Element)) return;
  if (node.matches('.grid')) layoutGrid(node);
  if (node.parentElement?.matches('.grid')) layoutGrid(node.parentElement); // 이미 있는 격자에 카드가 들어온 경우
  node.querySelectorAll('.grid').forEach(layoutGrid);
  const tables = node.matches('table.table') ? [node] : node.querySelectorAll('table.table');
  tables.forEach(labelTable);
  const owner = node.closest('table.table');
  if (owner) labelTable(owner); // 실시간 화면처럼 행만 추가되는 경우
}

/** root 아래에 새로 그려지는 표·카드 격자를 계속 보정한다 */
export function enhance(root) {
  if (!root) return;
  scan(root);
  new MutationObserver((records) => {
    for (const r of records) r.addedNodes.forEach(scan);
  }).observe(root, { childList: true, subtree: true });
}
