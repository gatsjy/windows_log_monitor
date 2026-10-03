// 수집 PC: 로그를 보내는 모든 PC/서버/장비의 수신 상태 + 에이전트 설치 안내.
import * as api from '../api.js';
import { sourceLabel, statusBadge } from '../levels.js';
import { errorBox, fmtCompact, fmtDuration, fmtNum, fmtRelative, fmtTime, html, navigate, replaceParams } from '../util.js';

export async function mount(root, params) {
  let since = params.since || '24h';
  let timer;

  root.innerHTML = html`
    <div class="page-head">
      <div><h1 class="page-title">수집 PC</h1>
        <p class="page-sub">로그를 보내는 PC·서버·장비 목록입니다. 마지막 수신 시각으로 상태를 판단합니다.</p></div>
      <div class="toolbar">
        <div class="seg" data-seg>${[['24h', '24시간'], ['7d', '7일'], ['30d', '30일']].map(([v, l]) =>
          html`<button data-v="${v}" class="${v === since ? 'on' : ''}">${l}</button>`)}</div>
      </div>
    </div>
    <div class="grid" data-summary style="margin-bottom:14px"></div>
    <section class="card" style="margin-bottom:14px"><div class="card-body flush" data-table><div class="skeleton"></div></div></section>
    <section class="card"><div class="card-head"><h2 class="card-title">에이전트 설치 안내</h2></div>
      <div class="card-body" data-guide></div></section>`;

  root.querySelectorAll('[data-seg] button').forEach((b) => b.addEventListener('click', () => {
    since = b.dataset.v;
    root.querySelectorAll('[data-seg] button').forEach((x) => x.classList.toggle('on', x === b));
    replaceParams('agents', { since });
    load();
  }));

  const server = location.hostname === 'localhost' ? '<서버IP>' : location.hostname;
  const port = location.port || (location.protocol === 'https:' ? '443' : '80');
  root.querySelector('[data-guide]').innerHTML = html`
    <ol class="ref-list" style="padding-left:20px">
      <li><b>Windows</b> — Fluent Bit(Apache 2.0) Windows 설치 파일을 설치한 뒤, 저장소의 <code>agent/windows</code> 폴더를 PC 에 복사하고 관리자 PowerShell 에서:
        <pre class="message-box" style="margin:6px 0 10px">powershell -ExecutionPolicy Bypass -File .\\install.ps1 -ServerHost ${server} -ServerPort ${port} -ApiKey &lt;수집 API 키&gt;</pre></li>
      <li><b>Linux</b> — Fluent Bit 패키지 설치 후 <code>agent/linux/install.sh ${server} ${port} &lt;수집 API 키&gt;</code> (journald + /var/log)</li>
      <li><b>네트워크 장비 syslog</b> — 서버에서 <code>docker compose --profile syslog up -d</code> 후, 장비의 syslog 대상을 <code>${server}:514</code> (UDP/TCP) 로 지정</li>
    </ol>
    <p class="muted" style="font-size:12.5px;margin:8px 0 0">자세한 내용은 <code>agent/windows/README.md</code>, <code>agent/linux/README.md</code> 참고. API 키는 서버 <code>.env</code> 의 <code>WLM_INGEST_API_KEYS</code>.</p>`;

  async function load() {
    try {
      const { items, thresholds } = await api.get('/api/agents', { since });
      const count = (s) => items.filter((a) => a.status === s).length;
      root.querySelector('[data-summary]').innerHTML = html`${[
        ['전체', items.length, ''], ['온라인', count('online'), statusBadge('online')],
        ['지연', count('stale'), statusBadge('stale')], ['오프라인', count('offline'), statusBadge('offline')],
      ].map(([label, n, badge]) => html`<section class="card" style="grid-column: span 3"><div class="card-body">
        <div class="stat"><div class="stat-meta">${badge || label}</div><div class="stat-value">${fmtNum(n)}<small>대</small></div></div>
      </div></section>`)}`;

      const table = root.querySelector('[data-table]');
      if (!items.length) {
        table.innerHTML = '<div class="empty">아직 로그를 보낸 PC 가 없습니다. 아래 설치 안내를 참고하세요.</div>';
        return;
      }
      table.innerHTML = html`<div class="table-wrap"><table class="table">
        <thead><tr><th>상태</th><th>PC</th><th>소스</th><th>IP</th><th>마지막 수신</th><th>하트비트</th>
          <th class="r">이벤트</th><th class="r">오류</th><th class="r">경고</th><th class="r">누적</th><th>최초 등록</th><th>설정 버전</th></tr></thead>
        <tbody>${items.map((a) => html`<tr class="clickable" data-host="${a.host}">
          <td>${statusBadge(a.status)}</td>
          <td class="nowrap"><b>${a.host}</b></td>
          <td class="nowrap ink-2">${a.sources.map(sourceLabel).join(', ') || '–'}</td>
          <td class="nowrap num ink-2">${a.last_ip || '–'}</td>
          <td class="nowrap" title="${fmtTime(a.last_seen)}">${fmtRelative(a.last_seen)}</td>
          <td class="nowrap ink-2">${a.last_heartbeat_at ? fmtRelative(a.last_heartbeat_at) : '–'}</td>
          <td class="r num">${fmtCompact(a.events)}</td>
          <td class="r num">${fmtNum(a.errors)}</td>
          <td class="r num">${fmtNum(a.warnings)}</td>
          <td class="r num muted">${fmtCompact(a.events_total)}</td>
          <td class="nowrap muted">${fmtTime(a.first_seen, { seconds: false })}</td>
          <td class="nowrap muted">${a.meta?.config_version ?? '–'}</td>
        </tr>`)}</tbody></table></div>
        <p class="muted" style="font-size:12px;padding:0 16px">온라인: ${fmtDuration(thresholds.online_sec)} 이내 수신 · 지연: ${fmtDuration(thresholds.stale_sec)} 이내 · 그 이후 오프라인. 행을 누르면 해당 PC 의 이벤트를 검색합니다.</p>`;
      table.querySelectorAll('[data-host]').forEach((tr) =>
        tr.addEventListener('click', () => navigate('events', { since, host: tr.dataset.host })));
    } catch (err) {
      const table = root.querySelector('[data-table]');
      if (table) table.innerHTML = errorBox(err); // 화면을 떠난 뒤 끝난 요청이면 무시
    }
  }

  await load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 15000);
  return () => clearInterval(timer);
}
