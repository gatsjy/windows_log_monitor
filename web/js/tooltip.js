// 화면 전체에서 하나만 쓰는 툴팁.
let el;

function node() {
  el ??= document.getElementById('tooltip');
  return el;
}

export function show(content, x, y) {
  const t = node();
  t.innerHTML = String(content);
  t.hidden = false;
  const pad = 14;
  const { width, height } = t.getBoundingClientRect();
  let left = x + pad;
  let top = y + pad;
  if (left + width > window.innerWidth - 8) left = x - width - pad;
  if (top + height > window.innerHeight - 8) top = y - height - pad;
  t.style.left = `${Math.max(8, left)}px`;
  t.style.top = `${Math.max(8, top)}px`;
}

export function hide() {
  node().hidden = true;
}
