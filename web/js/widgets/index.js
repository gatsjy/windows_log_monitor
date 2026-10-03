// 위젯 레지스트리. 새 위젯 = 파일 하나 추가 + 여기에 한 줄 등록 (+ 서버 dashboards.py 의 WIDGET_TYPES).
// 위젯 모양: { label, flush?, async render(bodyElement, widgetConfig, ctx), live?(body, cfg, ctx, events) }
//   render: API 로 조회해서 그린다 (처음 + 대시보드 동기화 주기마다). 상태는 body._live 에 둔다
//   live:   (선택) 실시간 스트림으로 들어온 새 이벤트 중 cfg.query 에 맞는 것만 받아 제자리 갱신
//   ctx.query(cfg) → 대시보드 기간 + cfg.query 를 합친 API 파라미터
//   ctx.drill(params) → 이벤트 검색 화면으로 이동
//   ctx.resync(body) → 이 위젯만 다시 조회 (live 로 맞출 수 없는 변화가 생겼을 때)
import alerts from './alerts.js';
import events from './events.js';
import hosts from './hosts.js';
import stat from './stat.js';
import text from './text.js';
import timeseries from './timeseries.js';
import top from './top.js';

export const WIDGETS = { stat, timeseries, top, events, hosts, text, alerts };
