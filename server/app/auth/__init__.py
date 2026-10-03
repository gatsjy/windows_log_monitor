"""인증 (Phase 2): 로그인·세션·역할·계정 잠금·비밀번호 정책.

  passwords.py  scrypt 해시, 비밀번호 정책, 임시 비밀번호 생성
  service.py    로그인/로그아웃/세션 확인/비밀번호 변경/사용자 관리 (모두 audit_log 기록)
  deps.py       FastAPI 의존성 (require_user / require_admin / CSRF)
"""
