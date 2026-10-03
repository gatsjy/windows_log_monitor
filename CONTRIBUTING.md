# 기여 안내

이슈와 풀 리퀘스트를 환영합니다. 시작 전에 [AGENTS.md](AGENTS.md)(개발 규칙)와 [docs/PROJECT.md](docs/PROJECT.md)(명세)를 읽어 주세요.
무엇을 만들지 고민된다면 [docs/BACKLOG.md](docs/BACKLOG.md) 의 P1 항목부터 봅니다.

## 개발 환경

```bash
docker compose up -d --build        # 코드·UI 가 컨테이너에 연결되어 저장하면 바로 반영
python3 tools/simulate.py           # 테스트 데이터
```

## 꼭 지킬 규칙 (요약)

1. **오픈소스 의존성만** 씁니다(MIT, BSD, Apache 2.0, PostgreSQL, LGPL, MPL). SSPL·Elastic License·BSL 은 안 됩니다.
2. **원본 보존:** 에이전트가 보낸 레코드는 `events.raw` 에 그대로 둡니다. 해석한 값은 컬럼이나 `raw.<소스>.*` 로 덧붙입니다.
3. **마이그레이션은 추가만:** `server/migrations/` 의 기존 파일은 고치지 않고 새 번호 파일을 만듭니다.
4. **이벤트 SQL 은 `server/app/repository.py` 에만** 둡니다.
5. **UI 는 빌드 없이:** 프레임워크·npm·CDN 을 쓰지 않습니다. 폐쇄망에서 그대로 동작해야 합니다.
6. **비밀값은 평문 저장·응답 금지.** 보안·감사 관련 변경은 `docs/ISMS.md` 도 갱신합니다.
7. UI 문구는 한국어, 코드 식별자는 영어입니다. PowerShell 스크립트는 영어만 씁니다.

## 풀 리퀘스트 전에

```bash
docker compose exec api python -m pytest                   # 테스트
docker compose exec api ruff check --no-cache app tests    # 린트
```

- 관련 화면을 브라우저에서 직접 열어 확인하고, 콘솔 오류가 없는지 봅니다.
- 동작이 바뀌면 `docs/PROJECT.md`, 설계 결정은 `docs/DECISIONS.md`, 사용자에게 보이는 변경은 `CHANGELOG.md` 의 다음 버전 절에 적습니다.
- 성능에 영향이 있으면 `tools/bench/bench.py --skip-seed` 로 전후를 재고 `docs/PERFORMANCE.md` 에 기록합니다.
- 컨테이너 이미지·포트·볼륨이 바뀌면 `deploy/airgap/` 스크립트와 `docs/AIRGAP.md` 를 확인합니다.

## 라이선스

기여한 코드는 이 프로젝트의 [MIT 라이선스](LICENSE) 로 배포됩니다.
