// 로그 수준(level) / PC 상태 표시. 색만으로 구분하지 않도록 항상 아이콘 + 글자를 함께 쓴다.
import { html, raw } from './util.js';

export const LEVELS = {
  1: { key: 'critical', label: '심각', en: 'Critical' },
  2: { key: 'error', label: '오류', en: 'Error' },
  3: { key: 'warning', label: '경고', en: 'Warning' },
  4: { key: 'info', label: '정보', en: 'Information' },
  5: { key: 'verbose', label: '상세', en: 'Verbose' },
};

export const levelColor = (level) => `var(--lvl-${LEVELS[level] ? level : 4})`;
export const levelLabel = (level) => LEVELS[level]?.label ?? String(level);

// 16x16 아이콘. 모양이 수준마다 달라서 색약/흑백 인쇄에서도 구분된다.
const ICONS = {
  1: '<path d="M5.3 1h5.4L15 5.3v5.4L10.7 15H5.3L1 10.7V5.3z" fill="var(--lvl-1)"/><path d="M8 4.3v4.6M8 11.3v.4" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/>',
  2: '<circle cx="8" cy="8" r="7" fill="var(--lvl-2)"/><path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8" stroke="#fff" stroke-width="1.7" stroke-linecap="round"/>',
  3: '<path d="M8 1.2l7 12.6H1z" fill="var(--lvl-3)" stroke="var(--lvl-3)" stroke-width="1.2" stroke-linejoin="round"/><path d="M8 5.8v3.6M8 11.5v.3" stroke="#3a2a00" stroke-width="1.7" stroke-linecap="round"/>',
  4: '<circle cx="8" cy="8" r="7" fill="var(--lvl-4)"/><path d="M8 7.2v4.3M8 4.6v.3" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/>',
  5: '<circle cx="8" cy="8" r="4" fill="var(--lvl-5)"/>',
};

export function levelIcon(level) {
  return raw(`<svg viewBox="0 0 16 16" aria-hidden="true">${ICONS[level] || ICONS[4]}</svg>`);
}

export function levelBadge(level) {
  return html`<span class="lvl" title="${LEVELS[level]?.en ?? ''}">${levelIcon(level)}<span>${levelLabel(level)}</span></span>`;
}

export const STATUS = {
  online: '온라인',
  stale: '지연',
  offline: '오프라인',
};

export function statusBadge(status) {
  return html`<span class="status ${status}"><span class="dot"></span>${STATUS[status] ?? status}</span>`;
}

export const SOURCE_LABELS = {
  winevtlog: 'Windows 이벤트',
  iis: 'IIS 접속 로그',
  mssql: 'SQL Server ERRORLOG',
  syslog: 'syslog',
  journald: 'journald',
  file: '파일',
};

// 로그 분류 (server/app/normalizers/categories.py 와 같은 값)
export const CATEGORY_LABELS = {
  security: '보안',
  system: '시스템',
  application: '응용 프로그램',
  powershell: 'PowerShell',
  defender: '백신 (Defender)',
  rdp: '원격 데스크톱',
  sysmon: 'Sysmon',
  windows: '기타 Windows',
  iis: '웹 서버 (IIS)',
  mssql: 'DB (MSSQL)',
  linux: 'Linux',
  syslog: 'syslog 장비',
  file: '파일 로그',
};
export const categoryLabel = (c) => CATEGORY_LABELS[c] ?? c ?? '–';
export const sourceLabel = (s) => SOURCE_LABELS[s] ?? s;

// 알림 심각도 → 로그 수준 아이콘을 그대로 쓴다
export const SEVERITIES = {
  critical: { level: 1, label: '심각' },
  error: { level: 2, label: '오류' },
  warning: { level: 3, label: '경고' },
  info: { level: 4, label: '정보' },
};

export function severityBadge(severity) {
  const s = SEVERITIES[severity] ?? SEVERITIES.info;
  return html`<span class="lvl">${levelIcon(s.level)}<span>${s.label}</span></span>`;
}
