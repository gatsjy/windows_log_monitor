#!/usr/bin/env bash
# CI(B-08, ADR-037): 에이전트의 SQL Server ERRORLOG 묶음(multiline)을 실제 Fluent Bit 으로 돌려 본다.
#   python3 tools/ci/render_agent_configs.py agent-render
#   tools/ci/test_fluentbit_mssql.sh agent-render/windows.yaml           # 비교
#   tools/ci/test_fluentbit_mssql.sh agent-render/windows.yaml --update  # 기대값 다시 만들기 (Fluent Bit 버전을 올릴 때)
# 채운 윈도 설정에서 multiline 정의와 MSSQL tail 만 꺼내(render_agent_configs.py --derive-mssql) 리눅스 이미지로 돌린다
# (winevtlog 는 윈도 빌드에만 있다). 윈도 빌드는 CI 의 윈도 작업이 같은 기대값으로 따로 본다.
#   (a) 고정 ERRORLOG(UTF-16LE·CRLF)를 처음부터 읽힌 레코드의 log 가 server/tests/fixtures/mssql/fb-ml.jsonl 과 같다.
#       multiline 을 뺀 0.3.0 방식은 fb-plain.jsonl — 서버 시험(test_agent_sync.py)이 두 방식의 집계가 같은지 본다.
#   (b) 서버가 꺼진 채로, 묶던 중에 에이전트를 멈췄다가 다시 띄워도 모든 레코드가 정확히 한 번, 줄이 다 붙은 채로 나온다.
#       storage.type 이 memory 면 여기서 실패한다(멈출 때 보내지 못한 것과 묶던 것을 잃는다 — 그래서 filesystem 필수).
# 필요: docker, python3 (표준 라이브러리만)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
RENDERED=${1:?채운 windows.yaml 경로}
UPDATE=${2:-}
IMAGE=${FLUENTBIT_IMAGE:-fluent/fluent-bit:4.0}
FIX="$REPO/server/tests/fixtures/mssql"
WORK=$(mktemp -d)
NAME=wlm-fb-mssql-$$
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

derive() {  # 이름 [--plain]   → fb.yaml(파일 출력)·fb-down.yaml(닿지 않는 서버)
  mkdir -p "$WORK/$1/logs" "$WORK/$1/state" "$WORK/$1/out"
  cp "$FIX/ERRORLOG.utf16" "$WORK/$1/logs/ERRORLOG"
  for out in "" --down; do
    python3 "$REPO/tools/ci/render_agent_configs.py" --derive-mssql "$RENDERED" "$WORK/$1/fb${out:+-down}.yaml" \
      --path /data/logs/ERRORLOG --state /data/state --out /data/out/records.jsonl ${2:+"$2"} $out
  done
}
start() {  # 이름 [설정 파일 이름]
  docker run -d --name "$NAME" --user "$(id -u):$(id -g)" -v "$WORK/$1:/data" "$IMAGE" \
    /fluent-bit/bin/fluent-bit -c "/data/${2:-fb.yaml}" >/dev/null
}
stop() { docker stop -t 15 "$NAME" >/dev/null; docker logs "$NAME" 2>&1 | grep -iE "error|warn" >&2 || true; docker rm "$NAME" >/dev/null; }
# 출력 줄 수가 5초 동안 그대로면 다 읽은 것 (multiline flush_timeout 2초 + flush 1초보다 길게)
settle() {  # 이름
  local file="$WORK/$1/out/records.jsonl" last=-1 same=0 n
  for _ in $(seq 1 60); do
    n=0; [ -f "$file" ] && n=$(wc -l < "$file" | tr -d ' ')
    if [ "$n" = "$last" ] && [ "$n" -gt 0 ]; then same=$((same + 1)); else same=0; fi
    [ "$same" -ge 5 ] && return 0
    last=$n; sleep 1
  done
  fail "$1: 출력이 멈추지 않거나 비어 있습니다 ($file)${2:+ — $2}"
}
logs_only() { python3 -c '
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    if line.strip():
        print(json.dumps({"log": json.loads(line)["log"]}, ensure_ascii=False))
' "$1"; }

# (a) 처음부터 읽기: multiline(0.4.0) · 줄마다(0.3.0)
for variant in ml plain; do
  if [ "$variant" = plain ]; then derive plain --plain; else derive ml; fi
  start "$variant"; settle "$variant"; stop
  logs_only "$WORK/$variant/out/records.jsonl" > "$WORK/$variant.jsonl"
  if [ "$UPDATE" = "--update" ]; then
    cp "$WORK/$variant.jsonl" "$FIX/fb-$variant.jsonl"
    echo "갱신: $FIX/fb-$variant.jsonl ($(wc -l < "$WORK/$variant.jsonl" | tr -d ' ')건)"
  else
    diff -u "$FIX/fb-$variant.jsonl" "$WORK/$variant.jsonl" >&2 || fail "fb-$variant.jsonl 과 다릅니다 (Fluent Bit 동작이 바뀌었으면 --update 후 서버 시험)"
  fi
done
[ "$UPDATE" = "--update" ] && exit 0
[ "$(wc -l < "$WORK/ml.jsonl")" -lt "$(wc -l < "$WORK/plain.jsonl")" ] || fail "multiline 이 줄을 묶지 않았습니다"

# (b) 서버가 꺼진 채 묶던 중 정지 → 다시 기동(서버 켜짐): 모든 레코드와 덧붙인 묶음이 정확히 한 번, 줄이 다 붙은 채로
derive restart
start restart fb-down.yaml; sleep 4   # 처음부터 읽고, 보내지 못한 채 버퍼에 쌓인다
printf '2026-10-04 11:00:00.00 spid77      restart-check first line\r\n\trestart-check second line\r\n\trestart-check third line\r\n' \
  | python3 -c 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().decode().encode("utf-16-le"))' >> "$WORK/restart/logs/ERRORLOG"
sleep 1   # tail 이 읽게 (flush_timeout 2초 전에 멈춘다)
stop
[ ! -s "$WORK/restart/out/records.jsonl" ] || fail "서버가 꺼져 있는데 파일 출력이 생겼습니다 (시험 구성 오류)"
start restart; settle restart "멈출 때 보내지 못한 레코드를 잃었습니다 (storage.type 이 filesystem 인가)"; stop
python3 - "$WORK/restart/out/records.jsonl" "$FIX/fb-ml.jsonl" <<'EOF' || fail "멈췄다 다시 띄운 뒤의 레코드가 틀립니다"
import json, sys
logs = [json.loads(line)["log"] for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
want = [json.loads(line)["log"] for line in open(sys.argv[2], encoding="utf-8") if line.strip()]
hits = [log for log in logs if "restart-check first line" in log]
print(f"재기동 시험: 레코드 {len(logs)}건, 덧붙인 묶음 {len(hits)}건")
assert [log for log in logs if "restart-check" not in log] == want, "버퍼에 있던 레코드가 빠지거나 겹쳤습니다"
assert len(hits) == 1, hits
assert "restart-check second line" in hits[0] and "restart-check third line" in hits[0], hits[0]
assert not any("restart-check" in log and log is not hits[0] for log in logs), "이어지는 줄이 따로 나왔습니다"
EOF
echo "Fluent Bit MSSQL multiline 시험 통과 ($IMAGE)"
