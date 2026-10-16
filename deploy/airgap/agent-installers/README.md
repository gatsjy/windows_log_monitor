# 에이전트 설치 파일 (반입 묶음에 함께 넣을 파일)

여기에 넣은 파일은 `make-bundle.sh` 가 반입 묶음의 `agent-installers/` 로 복사합니다. 설치 파일은 저장소에 올리지 않습니다(.gitignore).

예외로 `*.sha256`(설치 파일의 SHA-256 고정값)은 저장소에 둡니다. `make-bundle.sh` 와 CI 윈도 작업이 내려받은 zip 을 이 값으로 확인합니다. `FLUENTBIT_VERSION` 을 올리면 새 `.sha256` 을 확인해 함께 커밋합니다.

| 넣을 파일 | 받는 곳 |
|---|---|
| Fluent Bit Windows 64bit 설치 파일 (`fluent-bit-4.0.x-win64.exe` 또는 `.zip`) | docs.fluentbit.io → Installation → Windows |
| Linux 서버용 Fluent Bit 패키지 (`.rpm` / `.deb`, 배포판·버전별) | packages.fluentbit.io |

절차: [docs/AIRGAP.md](../../../docs/AIRGAP.md) §5
