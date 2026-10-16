"""정기 점검 보고서 (BACKLOG B-05, ADR-032) — ISMS 2.9.5 로그 정기 점검.

config     일정·받는 곳 (환경설정 app_settings 'report')
builder    기간의 로그·알림·수집 PC·보관·백업 상태를 모아 보고서 내용(payload)을 만든다
render     메일 HTML·평문, 메신저 공지(요약 + 링크)
scheduler  정한 시각에 만들고 저장하고 보낸다 (알림 엔진처럼 앱 안의 작업 + advisory lock)
"""
