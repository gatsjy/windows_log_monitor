// 의존성 없는 SVG 차트. 규칙: 얇은 막대(최대 24px), 위쪽만 둥근 4px 끝, 막대 사이 2px 여백,
// 흐린 1px 격자선, 마우스를 올리면 툴팁. 색은 CSS 변수(var(--...))로만 받는다.
import { esc, fmtCompact, fmtNum, html, fmtTime, raw } from './util.js';
import * as tooltip from './tooltip.js';
import { categoryLabel, levelColor, levelLabel, sourceLabel } from './levels.js';

const GAP = 2;

// ---------------------------------------------------------------- 색/라벨
const CHANNEL_COLORS = {
  System: 'var(--s1)',
  Application: 'var(--s2)',
  Security: 'var(--s3)',
  Setup: 'var(--s4)',
  'Microsoft-Windows-PowerShell/Operational': 'var(--s5)',
  ForwardedEvents: 'var(--s6)',
  'Microsoft-Windows-Sysmon/Operational': 'var(--s7)',
};

// 분류마다 고정 색 (8가지 범주색 안에서. 나머지 분류는 남은 색 → 기타)
const CATEGORY_COLORS = {
  security: 'var(--s1)', system: 'var(--s2)', application: 'var(--s3)', iis: 'var(--s4)',
  mssql: 'var(--s5)', powershell: 'var(--s7)', syslog: 'var(--s6)', rdp: 'var(--s8)',
};

/** 그룹 값마다 고정 색. 순위가 아니라 값(이름)에 색이 붙도록 해서 필터를 바꿔도 색이 유지된다. */
export function seriesColors(group, keys) {
  const map = {};
  if (group === 'level') {
    keys.forEach((k) => { map[k] = levelColor(Number(k)); });
    return map;
  }
  const used = new Set();
  if (group === 'category') {
    keys.forEach((k) => { if (CATEGORY_COLORS[k]) { map[k] = CATEGORY_COLORS[k]; used.add(CATEGORY_COLORS[k]); } });
  }
  if (group === 'channel') {
    keys.forEach((k) => { if (CHANNEL_COLORS[k]) { map[k] = CHANNEL_COLORS[k]; used.add(CHANNEL_COLORS[k]); } });
  }
  const free = [1, 2, 3, 4, 5, 6, 7, 8].map((i) => `var(--s${i})`).filter((c) => !used.has(c));
  [...keys].sort().forEach((k) => {
    if (map[k]) return;
    map[k] = k === '__other__' ? 'var(--s-other)' : free.shift() || 'var(--s-other)';
  });
  return map;
}

export function seriesLabel(group, key) {
  if (key === '__other__') return '기타';
  if (key === '' || key == null) return '(없음)';
  if (group === 'level') return levelLabel(Number(key));
  if (group === 'source') return sourceLabel(key);
  if (group === 'category') return categoryLabel(key);
  return key;
}

// ------------------------------------------------------------- 크기 감지
export function observeWidth(el, cb) {
  el._ro?.disconnect();
  let last = 0;
  const ro = new ResizeObserver(([entry]) => {
    const w = Math.floor(entry.contentRect.width);
    if (w > 0 && w !== last) { last = w; cb(w); }
  });
  ro.observe(el);
  el._ro = ro;
}

function niceScale(max, ticks = 4) {
  const raw = Math.max(max, 1) / ticks;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const norm = raw / mag;
  const nice = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10;
  const step = Math.max(1, nice * mag);
  return { step, top: Math.ceil(Math.max(max, 1) / step) * step };
}

function roundTopPath(x, y, w, h, r) {
  r = Math.max(0, Math.min(r, w / 2, h));
  return `<path d="M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z"`;
}

function tickLabel(date, intervalSec, spanSec) {
  const d = new Date(date);
  const p = (n) => String(n).padStart(2, '0');
  if (intervalSec >= 86400) return `${d.getMonth() + 1}/${d.getDate()}`;
  if (spanSec > 36 * 3600) return `${d.getMonth() + 1}/${d.getDate()} ${p(d.getHours())}:${p(d.getMinutes())}`;
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

// ------------------------------------------------------------- 누적 막대
/**
 * 시간대별 누적 막대.
 * @param {HTMLElement} el
 * @param {{buckets:string[], intervalSec:number, series:{key,label,color,values:number[]}[],
 *          height?:number, onSelect?:(range:{since:string,until:string})=>void}} opt
 *   series 순서 = 아래에서 위로 쌓는 순서
 */
export function columnChart(el, opt) {
  const { buckets, intervalSec, series, height = 200, onSelect } = opt;
  if (!buckets.length || !series.some((s) => s.values.some((v) => v > 0))) {
    el._ro?.disconnect();
    el.innerHTML = '<div class="empty">이 기간에 데이터가 없습니다</div>';
    return;
  }
  el.classList.add('chart-wrap');
  const spanSec = buckets.length * intervalSec;

  observeWidth(el, (width) => {
    const M = { top: 10, right: 4, bottom: 24, left: 42 };
    const pw = width - M.left - M.right;
    const ph = height - M.top - M.bottom;
    const n = buckets.length;
    const totals = buckets.map((_, i) => series.reduce((a, s) => a + (s.values[i] || 0), 0));
    const { step, top } = niceScale(Math.max(...totals));
    const y = (v) => M.top + ph - (v / top) * ph;
    const band = pw / n;
    const barW = Math.max(1, Math.min(24, band - GAP));

    let s = '';
    for (let v = 0; v <= top + 1e-9; v += step) {
      const yy = Math.round(y(v)) + 0.5;
      s += `<line class="${v === 0 ? 'base-line' : 'grid-line'}" x1="${M.left}" x2="${width - M.right}" y1="${yy}" y2="${yy}"/>`;
      s += `<text class="tick" x="${M.left - 8}" y="${yy}" text-anchor="end" dominant-baseline="middle">${fmtCompact(v)}</text>`;
    }
    s += `<rect class="hover-band" x="0" y="${M.top}" width="${band}" height="${ph}" visibility="hidden"/>`;

    buckets.forEach((_, i) => {
      const x = M.left + i * band + (band - barW) / 2;
      const visible = series.filter((se) => (se.values[i] || 0) > 0);
      let base = y(0);
      visible.forEach((se, j) => {
        const h = (se.values[i] / top) * ph;
        const segTop = base - h;
        const bottom = base - (j > 0 ? GAP : 0);
        const segH = bottom - segTop;
        if (segH >= 0.5) {
          s += j === visible.length - 1
            ? `${roundTopPath(x, segTop, barW, segH, 4)} fill="${se.color}"/>`
            : `<rect x="${x}" y="${segTop}" width="${barW}" height="${segH}" fill="${se.color}"/>`;
        }
        base = segTop;
      });
    });

    const maxLabels = Math.max(2, Math.floor(pw / 90));
    const every = Math.ceil(n / maxLabels);
    for (let i = 0; i < n; i += every) {
      s += `<text class="tick" x="${M.left + i * band + band / 2}" y="${height - 6}" text-anchor="middle">${esc(tickLabel(buckets[i], intervalSec, spanSec))}</text>`;
    }
    buckets.forEach((_, i) => {
      s += `<rect class="hit" data-i="${i}" x="${M.left + i * band}" y="${M.top}" width="${band}" height="${ph}"/>`;
    });

    el.innerHTML = `<svg class="chart" width="${width}" height="${height}" role="img">${s}</svg>`;
    const svg = el.firstElementChild;
    const hoverBand = svg.querySelector('.hover-band');

    svg.addEventListener('mousemove', (ev) => {
      const i = ev.target.dataset?.i;
      if (i === undefined) return;
      hoverBand.setAttribute('x', M.left + i * band);
      hoverBand.setAttribute('visibility', 'visible');
      const start = new Date(buckets[i]);
      const end = new Date(start.getTime() + intervalSec * 1000);
      const rows = [...series].reverse().filter((se) => se.values[i] > 0);
      tooltip.show(html`
        <div class="tt-title">${fmtTime(start, { seconds: false })} – ${fmtTime(end, { seconds: false, date: false })}</div>
        ${rows.map((se) => html`<div class="tt-row"><span class="sw" style="background:${se.color}"></span>${se.label}<span class="v">${fmtNum(se.values[i])}</span></div>`)}
        <div class="tt-row tt-total">합계<span class="v">${fmtNum(totals[i])}</span></div>
        ${onSelect ? html`<div class="muted" style="margin-top:4px">클릭하면 이 구간만 검색</div>` : ''}
      `, ev.clientX, ev.clientY);
    });
    svg.addEventListener('mouseleave', () => { hoverBand.setAttribute('visibility', 'hidden'); tooltip.hide(); });
    if (onSelect) {
      svg.addEventListener('click', (ev) => {
        const i = ev.target.dataset?.i;
        if (i === undefined) return;
        tooltip.hide();
        const start = new Date(buckets[i]);
        onSelect({ since: start.toISOString(), until: new Date(start.getTime() + intervalSec * 1000).toISOString() });
      });
    }
  });
}

/** 범례: 2개 이상 계열일 때만. items = [{label, color, total}] */
export function legend(items) {
  if (items.length < 2) return '';
  return html`<div class="legend">${items.map((it) => html`
    <span class="legend-item"><span class="sw" style="background:${it.color}"></span>${it.label}
      ${it.total != null ? html`<span class="v">${fmtCompact(it.total)}</span>` : ''}</span>`)}</div>`;
}

// ------------------------------------------------------------ 가로 막대 목록
/**
 * @param {{label, sub?, value:number, color?:string, title?:string}[]} rows
 * @param {(row, index) => void} onClick
 */
export function barList(el, rows, onClick) {
  if (!rows.length) {
    el.innerHTML = '<div class="empty">데이터가 없습니다</div>';
    return;
  }
  const max = Math.max(...rows.map((r) => r.value), 1);
  el.innerHTML = html`<div class="barlist">${rows.map((r, i) => html`
    <button class="bl-row" data-i="${i}" title="${r.title ?? ''}">
      <span class="bl-label">${r.label}${r.sub ? html`<span class="sub">${r.sub}</span>` : ''}</span>
      <span class="bl-track"><span class="bl-bar" style="width:${(r.value / max) * 100}%;background:${r.color || 'var(--s1)'}"></span></span>
      <span class="bl-value">${fmtNum(r.value)}</span>
    </button>`)}</div>`;
  if (onClick) {
    el.querySelectorAll('.bl-row').forEach((btn) => {
      btn.addEventListener('click', () => onClick(rows[Number(btn.dataset.i)], Number(btn.dataset.i)));
    });
  }
}

// --------------------------------------------------------------- 스파크라인
export function sparkline(values, color = 'var(--s1)') {
  if (!values?.length) return '';
  const max = Math.max(...values, 1);
  const n = values.length;
  const pts = values.map((v, i) => [n === 1 ? 50 : (i / (n - 1)) * 100, 30 - (v / max) * 27 - 1.5]);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`).join('');
  const area = `${line}L100,30L0,30Z`;
  return raw(`<svg viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true">
    <path d="${area}" fill="${color}" opacity="0.10"/>
    <path d="${line}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/>
  </svg>`);
}
