# 보안 정책

## 취약점 신고

보안 취약점은 **공개 이슈로 올리지 말고** GitHub 의 [비공개 취약점 신고](https://github.com/gatsjy/windows_log_monitor/security/advisories/new)로 알려 주세요.

- 재현 방법, 영향 범위, 버전(`/healthz` 의 `version`)을 적어 주시면 빨리 확인할 수 있습니다.
- 확인 후 수정 버전과 함께 [CHANGELOG.md](CHANGELOG.md) 에 공개합니다.

## 지원 버전

| 버전 | 보안 수정 |
|---|---|
| 0.4.x | 지원 |
| 0.3.x 이하 | 0.4 로 업그레이드 권장 |

## 운영 전 보안 점검 (요약)

자세한 통제 항목은 [docs/ISMS.md](docs/ISMS.md) 에 있습니다.

- [ ] `.env` 를 만들고 `POSTGRES_PASSWORD`, `WLM_INGEST_API_KEYS`, `WLM_SECRET_KEY` 를 무작위 값으로 바꿨다 (폐쇄망 `install.sh` 는 자동 생성)
- [ ] `.env` 에 `KEY=    # 설명` 처럼 빈 값 뒤 주석이 없다 (compose 가 설명문을 값으로 읽음)
- [ ] 개발용 `docker-compose.override.yml` 없이 기동했다 (`docker compose -f docker-compose.yml ...`)
- [ ] 첫 로그인 후 `admin` 비밀번호를 바꾸고, 담당자별 개인 계정을 만들었다
- [ ] HTTPS 리버스 프록시 뒤에 두고 `WLM_COOKIE_SECURE=true`, 에이전트 `tls: on` (계획: [BACKLOG](docs/BACKLOG.md) B-06)
- [ ] 웹·수집 포트(8080)는 사내 대역에서만 접근 가능하다. DB 포트는 열지 않았다
- [ ] 운영에서 API 문서(`/docs`)를 숨겼다 (`WLM_API_DOCS=false`)
- [ ] `.env`(암호화 키), DB 백업, `archive/` 를 서로 다른 곳에 보관한다

## 설계상 보안 특성

- 비밀번호는 scrypt 해시, 세션 토큰은 SHA-256 만 저장합니다. 쿠키는 HttpOnly·SameSite=Strict 이고, 상태를 바꾸는 요청에는 CSRF 헤더가 필요합니다.
- 화면에서 입력한 SMTP·Oracle 비밀번호, 웹훅 주소·토큰은 `WLM_SECRET_KEY` 로 암호화해 저장하고, API 응답으로 내보내지 않습니다.
- 감사 로그(`audit_log`)는 DB 트리거로 수정·삭제를 막습니다.
- 컨테이너는 root 가 아닌 사용자(uid 10001)로 실행합니다.
- 저장소의 비밀번호·키 값(`dev-ingest-key`, `wlm-dev-password`, `dev-only-secret-key-…`, 테스트 값)은 **개발·테스트 전용 기본값**입니다. 운영에 쓰지 마세요.
