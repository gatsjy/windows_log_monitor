#!/bin/sh
# Log Monitor DB 백업·복구 시험 (BACKLOG B-16, ADR-031) — postgres:17-alpine 컨테이너(compose 의 backup 서비스) 안에서 돈다.
#
#   daemon         매일 WLM_BACKUP_TIME 이 지나면 그날 백업 한 번, WLM_BACKUP_VERIFY_WEEKDAY 요일에는 이어서 복구 시험 (서비스 기본 명령)
#   backup         지금 백업 한 번
#   verify [파일]  백업 파일을 임시 DB 에 복원해 확인 (기본: 가장 최근). 실제 DB 는 건드리지 않는다
#   list           백업 목록
#   restore 파일 --yes [--no-safety-dump]
#                  운영 DB 를 이 백업으로 되돌린다 (장애 복구). 먼저 api 를 멈춘다: docker compose stop api
#                  연결된 세션이 있으면 거부하고, 지금 DB 를 before-restore-*.dump 로 남긴 뒤, 임시 DB 에 복원이 끝나면 이름을 바꿔 끼운다
#   selftest       시험용 DB 로 백업 → 복구 시험 → 손상 감지 → 보관 개수 → 복원을 스스로 시험 (실제 DB·백업 폴더는 건드리지 않음)
#
# 예)  docker compose exec backup backup.sh backup
#      docker compose exec backup backup.sh verify
#      docker compose run --rm backup selftest
#      docker compose stop api && docker compose run --rm backup restore wlm-20261016-023000.dump --yes && docker compose start api
#
# 결과는 DB 의 audit_log 에 남긴다 (backup.create / backup.verify / backup.failed / backup.restore)
#   → 화면 '환경설정 > 로그 보관' 과 '감사 로그'에서 확인 (ISMS 2.9.3 백업·복구 시험 증적).
# 접속 정보는 PGHOST·PGUSER·PGPASSWORD·PGDATABASE (compose 가 넣어 준다).
# .env(암호화 키)는 일부러 묶지 않는다 — 키는 DB 백업과 따로 보관해야 백업만 빼 가도 비밀값을 못 푼다(ISMS 2.7.2).
#
# busybox sh 로 돈다. 함수 안에서 set -e 가 기대대로 동작하지 않아(if 조건 안에서는 꺼짐) 실패는 직접 확인한다.

set -u
umask 077   # 백업에는 로그·계정 정보가 들어 있다 → 소유자만 읽게

BACKUP_DIR=${WLM_BACKUP_DIR:-/backups}
KEEP=${WLM_BACKUP_KEEP:-14}
AT=${WLM_BACKUP_TIME:-02:30}
VERIFY_DAY=${WLM_BACKUP_VERIFY_WEEKDAY:-7}   # date +%u: 1=월 … 7=일. 0 이면 자동 복구 시험을 하지 않는다
CONFIG_DIR=${WLM_BACKUP_CONFIG_DIR:-/config}
# db 볼륨(읽기 전용으로 붙임) — 복구 시험·복원은 DB 크기만큼 같은 디스크를 더 쓰므로 남은 공간을 먼저 본다
PGDATA_DIR=${WLM_BACKUP_PGDATA_DIR:-/pgdata}
SPACE_RESERVE_KB=${WLM_BACKUP_SPACE_RESERVE_KB:-1048576}   # 복원 뒤에도 남겨 둘 공간 (WAL·운영 DB 증가분). 기본 1GB
MAINT_DB=${WLM_BACKUP_MAINT_DB:-postgres}                  # 운영 DB 이름을 바꿔 끼울 때 접속할 DB
TABLES="events alerts alert_notes audit_log users agents"
# 외부 저장소 복제 (B-17, ADR-047): 백업·로그 보관 파일을 다른 디스크·NAS(호스트에서 마운트한 폴더)에 한 벌 더.
# 같은 서버 디스크에만 있으면 서버 장애·랜섬웨어 때 사고 증거와 함께 사라진다(ISMS 2.9.4, 고시 제8조③)
REPLICA=${WLM_REPLICA:-off}
REPLICA_DIR=${WLM_REPLICA_MOUNT:-/replica}
ARCHIVE_DIR=${WLM_ARCHIVE_MOUNT:-/archive}
RETENTION_DAYS=${WLM_RETENTION_DAYS:-365}                  # 보관 파일 만료 (api 와 같은 값)
REPLICA_BACKUP_DAYS=${WLM_REPLICA_BACKUP_DAYS:-35}         # 복제한 DB 백업을 남겨 둘 날 수

# 신호로 멈출 때 지울 것 (만들던 덤프, 복원하던 임시 DB). compose 가 init(tini)으로 자식 프로세스까지 멈춘 뒤 여기로 온다
CURRENT_PART=""
CURRENT_TEMP_DB=""

log() { echo "$(date '+%Y-%m-%d %H:%M:%S %Z') $*"; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# 셸 문자열 → JSON 문자열 안에 넣을 수 있게 (오류 문구용: 줄바꿈은 공백으로)
json_esc() { printf '%s' "$1" | tr '\n\r\t' '   ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

psql_q() { psql -X -q -At -v ON_ERROR_STOP=1 "$@"; }

# audit ACTION TARGET DETAIL_JSON — 값은 psql 변수(:'name')로 넘겨 SQL 로 해석되지 않게
audit() {
  printf '%s\n' "INSERT INTO audit_log (actor, action, target, detail) VALUES ('system', :'action', :'target', :'detail'::jsonb);" \
    | psql_q -d "$PGDATABASE" -v action="$1" -v target="$2" -v detail="$3" >/dev/null \
    || log "경고: 감사로그 기록 실패 ($1 $2)"
}

on_signal() {
  [ -n "$CURRENT_PART" ] && rm -f "$CURRENT_PART"
  [ -n "$CURRENT_TEMP_DB" ] && dropdb --if-exists "$CURRENT_TEMP_DB" >/dev/null 2>&1
  log "중단됨 — 만들던 파일·임시 DB 를 정리했습니다"
  exit 143
}
trap on_signal INT TERM

# 보관 개수는 1 이상의 정수만. 0 을 '무제한'으로 알고 넣으면 방금 만든 백업까지 지워지므로 아예 받지 않는다
check_settings() {
  case $KEEP in ''|*[!0-9]*) log "WLM_BACKUP_KEEP 은 1 이상의 정수입니다: '$KEEP'"; return 2 ;; esac
  [ "$KEEP" -ge 1 ] || { log "WLM_BACKUP_KEEP 은 1 이상이어야 합니다 (0 이면 방금 만든 백업까지 지워집니다)"; return 2; }
  case $AT in [01][0-9]:[0-5][0-9]|2[0-3]:[0-5][0-9]) ;; *) log "WLM_BACKUP_TIME 형식은 HH:MM 입니다: $AT"; return 2 ;; esac
  case $VERIFY_DAY in [0-7]) ;; *) log "WLM_BACKUP_VERIFY_WEEKDAY 는 0(안 함)~7 입니다: $VERIFY_DAY"; return 2 ;; esac
  return 0
}

# 주요 테이블 행 수를 JSON 한 줄로 내는 SQL (그 DB 에 있는 테이블만). 테이블 이름은 위 TABLES 고정값
counts_sql() {
  have=$(psql_q -d "$1" -c "SELECT coalesce(string_agg(t, ' '), '') FROM unnest(string_to_array('$TABLES', ' ')) t WHERE to_regclass(t) IS NOT NULL") || return 1
  q=""
  for t in $have; do q="$q${q:+, }'$t', (SELECT count(*) FROM $t)"; done
  echo "SELECT json_build_object($q)::jsonb::text;"
}

# 행 수 JSON (실패하면 1 — 빠진 테이블을 조용히 넘기지 않는다)
counts_of() { q=$(counts_sql "$1") && psql_q -d "$1" -c "$q"; }

migration_of() { psql_q -d "$1" -c "SELECT coalesce(max(version), '') FROM schema_migrations"; }

newest_dump() { ls -1t "$BACKUP_DIR"/wlm-*.dump 2>/dev/null | head -n 1; }

# psql 은 -c 로 준 명령에서 :'변수' 를 바꾸지 않는다 → 변수를 쓰는 SQL 은 표준 입력으로 넘긴다
maint_sql() { _q=$1; shift; printf '%s\n' "$_q" | psql_q -d "$MAINT_DB" "$@"; }

db_exists() { [ "$(maint_sql "SELECT 1 FROM pg_database WHERE datname = :'d';" -v d="$1" 2>/dev/null)" = 1 ]; }

allow_connections() { maint_sql "ALTER DATABASE :\"d\" ALLOW_CONNECTIONS $2;" -v d="$1" >/dev/null; }

db_size_kb() { psql_q -d "$1" -c "SELECT pg_database_size(current_database()) / 1024"; }

# 다른 세션 수 (api·화면·다른 작업). 이 스크립트 자신의 연결은 빼고 센다
other_sessions() { maint_sql "SELECT count(*) FROM pg_stat_activity WHERE datname = :'d' AND pid <> pg_backend_pid();" -v d="$1"; }

# DB 디스크에 KB 만큼 + 여유분이 남아 있는가. 실패하면 사유를 SPACE_REASON 에 남긴다.
# db 볼륨이 안 붙어 있으면(직접 만든 compose 등) 확인할 수 없으니 경고만 남기고 넘어간다
space_ok() {
  SPACE_REASON=""
  [ -d "$PGDATA_DIR" ] || { log "경고: $PGDATA_DIR 가 없어 DB 디스크의 남은 공간을 확인하지 못했습니다"; return 0; }
  free=$(df -k -P "$PGDATA_DIR" 2>/dev/null | awk 'NR == 2 {print $4}')
  case $free in ''|*[!0-9]*) log "경고: DB 디스크의 남은 공간을 읽지 못했습니다"; return 0 ;; esac
  need=$(( $1 + SPACE_RESERVE_KB ))
  [ "$free" -ge "$need" ] && return 0
  SPACE_REASON="DB 디스크 공간 부족: 필요 약 $(( need / 1024 ))MB (DB 크기 + 여유 $(( SPACE_RESERVE_KB / 1024 ))MB), 남은 공간 $(( free / 1024 ))MB"
  return 1
}

# 임시 DB 지우기. 잠깐 연결이 끊긴 경우를 위해 몇 번 다시 시도한다 (남으면 DB 크기만큼 디스크를 계속 차지)
drop_temp_db() {
  for _ in 1 2 3; do
    dropdb --if-exists "$1" >/dev/null 2>&1 && { CURRENT_TEMP_DB=""; return 0; }
    sleep 5
  done
  log "경고: 임시 DB '$1' 를 지우지 못했습니다 — 디스크를 차지하니 직접 지우세요: docker compose exec backup dropdb $1"
  return 1
}

# ------------------------------------------------------------------ 백업
backup_fail() {  # 이름 단계 오류
  [ -n "$CURRENT_PART" ] && rm -f "$CURRENT_PART"
  CURRENT_PART=""
  log "백업 실패 ($2): $3"
  audit backup.failed "$1" "{\"stage\": \"$2\", \"error\": \"$(json_esc "$3")\", \"started_at\": \"$started\"}"
  return 1
}

do_backup() {
  mkdir -p "$BACKUP_DIR" || { log "백업 폴더를 만들 수 없음: $BACKUP_DIR"; return 1; }
  stamp=$(date +%Y%m%d-%H%M%S)
  base="$BACKUP_DIR/wlm-$stamp"
  name="wlm-$stamp.dump"
  started=$(now_utc)
  t0=$(date +%s)
  q=$(counts_sql "$PGDATABASE") || { backup_fail "$name" connect "DB 에 접속할 수 없습니다 ($PGHOST/$PGDATABASE)"; return 1; }
  log "백업 시작: $name (DB $PGDATABASE)"

  # 행 수·마이그레이션 버전을 pg_dump 와 같은 스냅숏에서 센다 — 복구 시험이 '백업에 든 행 수와 정확히 같은가'를 볼 수 있게.
  # (따로 세면 그 사이 매시간 정리 작업이 지운 행 때문에 맞지 않는다.) 스냅숏을 내보낸 트랜잭션이 열려 있는 동안 \! 로 pg_dump 를 돌린다
  CURRENT_PART="$base.dump.part"
  work=$(mktemp -d)
  WLM_DUMP_PART="$CURRENT_PART" WLM_DUMP_ERR="$work/err" WLM_DUMP_RC="$work/rc"
  export WLM_DUMP_PART WLM_DUMP_ERR WLM_DUMP_RC
  psql_q -d "$PGDATABASE" >"$work/out" 2>"$work/psql" <<SQL
BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY;
SELECT pg_export_snapshot() AS snap \gset
\setenv WLM_SNAPSHOT :snap
SELECT coalesce(max(version), '') FROM schema_migrations;
$q
\! pg_dump --snapshot="\$WLM_SNAPSHOT" -Fc -Z 6 -f "\$WLM_DUMP_PART" "\$PGDATABASE" 2>"\$WLM_DUMP_ERR"; echo \$? > "\$WLM_DUMP_RC"
COMMIT;
SQL
  psql_rc=$?
  dump_rc=$(cat "$work/rc" 2>/dev/null)
  version=$(sed -n 1p "$work/out")
  counts=$(sed -n 2p "$work/out")
  dump_err=$(cat "$work/err" "$work/psql" 2>/dev/null)
  rm -rf "$work"
  if [ "$psql_rc" != 0 ] || [ "$dump_rc" != 0 ] || [ -z "$counts" ]; then
    backup_fail "$name" dump "${dump_err:-pg_dump 종료 코드 ${dump_rc:-없음}}"; return 1
  fi
  mv "$CURRENT_PART" "$base.dump" || { backup_fail "$name" dump "덤프 파일 이름을 바꿀 수 없음"; return 1; }
  CURRENT_PART=""
  sha=$(sha256sum "$base.dump" | cut -d' ' -f1)
  echo "$sha  $name" > "$base.dump.sha256"
  bytes=$(stat -c %s "$base.dump")
  # 대시보드·알림 규칙 (화면에서 고친 설정) 도 같은 시각으로 묶어 둔다 — 작다
  config_file=""
  if [ -d "$CONFIG_DIR" ] && tar -czf "$base.config.tar.gz" -C "$CONFIG_DIR" . 2>/dev/null; then
    config_file="wlm-$stamp.config.tar.gz"
  fi
  seconds=$(( $(date +%s) - t0 ))
  detail="{\"file\": \"$name\", \"bytes\": $bytes, \"sha256\": \"$sha\", \"started_at\": \"$started\", \"finished_at\": \"$(now_utc)\", \"seconds\": $seconds, \"migration\": \"$version\", \"counts\": $counts, \"config\": \"$config_file\", \"keep\": $KEEP}"
  echo "$detail" > "$base.json"
  prune "$name"
  audit backup.create "$name" "$detail"
  log "백업 완료: $name ($bytes 바이트, ${seconds}초) sha256=$sha"
  return 0
}

# 최근 KEEP 개만 남긴다. 방금 만든 파일($1)은 어떤 경우에도 지우지 않는다.
# 업그레이드 전 백업(before-*.dump, install.sh)·복원 전 사본(before-restore-*)은 건드리지 않는다.
# 중단된 백업이 남긴 *.part 는 하루가 지나면 지운다 (지금 다른 곳에서 만들고 있는 것일 수 있어 바로 지우지 않는다)
prune() {
  ls -1t "$BACKUP_DIR"/wlm-*.dump 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    [ "$(basename "$old")" = "${1:-}" ] && continue
    base=${old%.dump}
    rm -f "$old" "$old.sha256" "$base.json" "$base.config.tar.gz"
    log "오래된 백업 정리: $(basename "$old")"
  done
  find "$BACKUP_DIR" -maxdepth 1 -name '*.dump.part' -mmin +1440 2>/dev/null | while read -r part; do
    rm -f "$part"
    log "중단된 백업 조각 정리: $(basename "$part")"
  done
}

# ------------------------------------------------------------------ 복구 시험
# 실패: 감사로그에 ok=false + 이유를 남기고 1
verify_fail() {
  log "복구 시험 실패: $2"
  audit backup.verify "$1" "{\"file\": \"$1\", \"ok\": false, \"reason\": \"$(json_esc "$2")\", \"checked_at\": \"$(now_utc)\"}"
  return 1
}

do_verify() {
  file=${1:-$(newest_dump)}
  check_db="${PGDATABASE}_restore_check"
  # 시험할 백업이 없는 것도 실패로 남긴다 (보관 설정 실수로 백업이 지워진 경우 등을 화면에서 알 수 있게)
  [ -n "$file" ] || { verify_fail "(없음)" "복구 시험할 백업이 없습니다 ($BACKUP_DIR)"; return 1; }
  case $file in /*) ;; *) file="$BACKUP_DIR/$file" ;; esac
  name=$(basename "$file")
  t0=$(date +%s)
  [ -f "$file" ] || { verify_fail "$name" "파일이 없습니다: $file"; return 1; }
  log "복구 시험 시작: $name → 임시 DB $check_db"

  # 1) 해시: 만든 뒤 바뀌지 않았는가 (손상·변조)
  expected=$(cut -d' ' -f1 "$file.sha256" 2>/dev/null || true)
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  [ -n "$expected" ] || { verify_fail "$name" "해시 파일(.sha256)이 없습니다"; return 1; }
  [ "$expected" = "$actual" ] || { verify_fail "$name" "해시가 다릅니다 — 파일이 손상되었거나 바뀌었습니다"; return 1; }

  # 2) 백업 정보(.json): 있으면 반드시 읽을 수 있어야 한다 (업그레이드 전 백업 before-*.dump 에는 없다)
  manifest="${file%.dump}.json"
  expected_version=""
  if [ -f "$manifest" ]; then
    # JSON 은 psql 로 읽는다 (컨테이너에 jq 가 없다)
    if ! info=$(printf '%s\n' "SELECT coalesce((:'m'::json)->>'migration', '') || '|' || coalesce(json_typeof((:'m'::json)->'counts'), '없음');" \
        | psql_q -d "$PGDATABASE" -v m="$(cat "$manifest")" 2>&1); then
      verify_fail "$name" "백업 정보 파일(.json)을 읽을 수 없습니다: $info"; return 1
    fi
    [ "${info##*|}" = object ] || { verify_fail "$name" "백업 정보 파일(.json)에 행 수(counts)가 없습니다"; return 1; }
    expected_version=${info%|*}
  fi

  # 3) 남은 공간: 임시 DB 는 운영 DB 와 같은 디스크에 운영 DB 크기만큼 생긴다 → 모자라면 시험하지 않고 실패로 남긴다
  size_kb=$(db_size_kb "$PGDATABASE" 2>/dev/null) || size_kb=0
  space_ok "$size_kb" || { verify_fail "$name" "$SPACE_REASON — 공간을 늘리거나 시험 서버에서 복구 시험을 하세요"; return 1; }

  # 4) 임시 DB 에 실제로 복원
  drop_temp_db "$check_db" || { verify_fail "$name" "이전 임시 DB 를 지울 수 없습니다: $check_db"; return 1; }
  if ! err=$(createdb "$check_db" 2>&1); then verify_fail "$name" "임시 DB 를 만들 수 없음: $err"; return 1; fi
  CURRENT_TEMP_DB=$check_db
  if ! err=$(pg_restore --no-owner --no-privileges --exit-on-error -d "$check_db" "$file" 2>&1); then
    drop_temp_db "$check_db"
    verify_fail "$name" "복원 실패: $err"
    return 1
  fi

  # 5) 복원된 내용: 마이그레이션 버전과 주요 테이블 행 수가 백업에 담긴 것(같은 스냅숏에서 센 값)과 정확히 같은가
  if ! restored=$(counts_of "$check_db" 2>&1) || ! version=$(migration_of "$check_db" 2>&1); then
    drop_temp_db "$check_db"
    verify_fail "$name" "복원한 DB 를 읽을 수 없습니다: ${restored:-}${version:-}"; return 1
  fi
  drop_temp_db "$check_db"
  diff=""
  if [ -f "$manifest" ]; then
    if [ "$version" != "$expected_version" ]; then
      verify_fail "$name" "마이그레이션 버전이 다릅니다: 복원 $version, 백업 때 $expected_version"; return 1
    fi
    # 빠진 테이블은 '없음'으로 (NULL 이 섞여 조용히 통과하지 않게)
    if ! diff=$(printf '%s\n' "SELECT coalesce(string_agg(p.key || ' ' || coalesce(q.value, '없음') || '/' || p.value, ', '), '')
        FROM json_each_text((:'m'::json)->'counts') p LEFT JOIN json_each_text(:'r'::json) q USING (key)
        WHERE q.value IS DISTINCT FROM p.value;" \
        | psql_q -d "$PGDATABASE" -v m="$(cat "$manifest")" -v r="$restored" 2>&1); then
      verify_fail "$name" "행 수를 비교할 수 없습니다: $diff"; return 1
    fi
  fi
  seconds=$(( $(date +%s) - t0 ))
  if [ -n "$diff" ]; then
    verify_fail "$name" "행 수가 백업 때와 다릅니다 (복원/백업): $diff"; return 1
  fi
  audit backup.verify "$name" "{\"file\": \"$name\", \"ok\": true, \"sha256\": \"$actual\", \"migration\": \"$version\", \"counts\": $restored, \"seconds\": $seconds, \"manifest\": $([ -f "$manifest" ] && echo true || echo false), \"checked_at\": \"$(now_utc)\"}"
  log "복구 시험 성공: $name (${seconds}초) 행 수 $restored"
  return 0
}

# ------------------------------------------------------------------ 복원 (장애 복구)
# 운영 DB 를 백업 내용으로 바꾼다. 되돌리기 어려우므로:
#   --yes 가 있어야 하고, 해시가 맞는 파일만 쓰고, 운영 DB 에 연결된 세션(api 등)이 있으면 거부한다.
#   지금 DB 를 before-restore-*.dump 로 먼저 남기고(잘못 고른 파일이어도 되돌릴 수 있게),
#   임시 DB 에 복원이 끝난 다음에만 이름을 바꿔 끼운다(복원이 실패해도 운영 DB 는 그대로).
do_restore() {
  file=${1:-}
  [ -n "$file" ] || { echo "복원할 백업 파일을 지정하세요 (backup.sh list)" >&2; return 2; }
  [ "${2:-}" = "--yes" ] || { echo "운영 DB '$PGDATABASE' 를 $file 내용으로 바꿉니다. 맞으면 끝에 --yes 를 붙이세요 (먼저 docker compose stop api)" >&2; return 2; }
  safety_dump=1
  case ${3:-} in '') ;; --no-safety-dump) safety_dump=0 ;; *) echo "알 수 없는 옵션: $3" >&2; return 2 ;; esac
  case $file in /*) ;; *) file="$BACKUP_DIR/$file" ;; esac
  name=$(basename "$file")
  restoring="${PGDATABASE}_restoring"
  [ -f "$file" ] || { log "파일이 없습니다: $file"; return 1; }
  expected=$(cut -d' ' -f1 "$file.sha256" 2>/dev/null || true)
  [ -n "$expected" ] && [ "$expected" = "$(sha256sum "$file" | cut -d' ' -f1)" ] \
    || { log "해시가 맞지 않아 복원하지 않습니다 (파일 손상·변조 또는 .sha256 없음): $name"; return 1; }

  exists=0
  db_exists "$PGDATABASE" && exists=1
  if [ "$exists" = 1 ]; then
    n=$(other_sessions "$PGDATABASE") || { log "DB 에 접속할 수 없습니다"; return 1; }
    [ "$n" = 0 ] || { log "운영 DB '$PGDATABASE' 에 연결된 세션이 ${n}개 있어 복원하지 않습니다 — 먼저 docker compose stop api (알림·보고서 작업도 api 안에서 돈다)"; return 1; }
    size_kb=$(db_size_kb "$PGDATABASE") || size_kb=0
    space_ok "$size_kb" || { log "복원하지 않습니다: $SPACE_REASON"; return 1; }
  fi

  # 1) 지금 DB 의 안전 사본
  safety_name=""
  if [ "$exists" = 1 ] && [ "$safety_dump" = 1 ]; then
    safety_name="before-restore-$(date +%Y%m%d-%H%M%S).dump"
    CURRENT_PART="$BACKUP_DIR/$safety_name.part"
    log "복원 전 지금 DB 를 남깁니다: $safety_name"
    if ! err=$(pg_dump -Fc -Z 6 -f "$CURRENT_PART" "$PGDATABASE" 2>&1); then
      rm -f "$CURRENT_PART"; CURRENT_PART=""
      log "지금 DB 를 남기지 못해 복원하지 않습니다: $err (DB 가 망가져 덤프가 안 되면 --no-safety-dump)"; return 1
    fi
    mv "$CURRENT_PART" "$BACKUP_DIR/$safety_name"; CURRENT_PART=""
    (cd "$BACKUP_DIR" && sha256sum "$safety_name" > "$safety_name.sha256")
  fi

  # 2) 임시 DB 에 복원
  log "복원 시작: $name → 임시 DB $restoring"
  drop_temp_db "$restoring" || return 1
  createdb "$restoring" || { log "임시 DB 를 만들 수 없습니다: $restoring"; return 1; }
  CURRENT_TEMP_DB=$restoring
  if ! err=$(pg_restore --no-owner --exit-on-error -d "$restoring" "$file" 2>&1); then
    drop_temp_db "$restoring"
    log "복원 실패 — 운영 DB 는 바뀌지 않았습니다: $err"
    return 1
  fi

  # 3) 바꿔 끼우기: 운영 DB 연결을 막고, 그 사이 다시 붙은 세션이 없을 때만 이름을 바꾼다
  if [ "$exists" = 1 ]; then
    replaced="${PGDATABASE}_replaced"
    allow_connections "$PGDATABASE" false || { drop_temp_db "$restoring"; return 1; }
    n=$(other_sessions "$PGDATABASE")
    if [ "$n" != 0 ]; then
      allow_connections "$PGDATABASE" true
      drop_temp_db "$restoring"
      log "복원하는 동안 운영 DB 에 세션 ${n}개가 다시 연결되어 바꿔 끼우지 않았습니다 — api 를 멈추고 다시 하세요"; return 1
    fi
    drop_temp_db "$replaced" || return 1
    if ! maint_sql 'ALTER DATABASE :"d" RENAME TO :"old"; ALTER DATABASE :"new" RENAME TO :"d";' \
        -v d="$PGDATABASE" -v old="$replaced" -v new="$restoring" -1 >/dev/null; then
      allow_connections "$PGDATABASE" true
      drop_temp_db "$restoring"
      log "DB 이름을 바꾸지 못했습니다 — 운영 DB 는 바뀌지 않았습니다"; return 1
    fi
    CURRENT_TEMP_DB=""
    drop_temp_db "$replaced"
  else
    maint_sql 'ALTER DATABASE :"new" RENAME TO :"d";' -v d="$PGDATABASE" -v new="$restoring" >/dev/null || return 1
    CURRENT_TEMP_DB=""
  fi
  # 복원한 DB 에 복원 사실을 남긴다 (백업 시점 이후의 감사로그는 이 복원으로 운영 DB 에서 빠지므로, 그 공백을 알 수 있게.
  # 빠진 기록은 안전 사본에 남아 있다)
  audit backup.restore "$name" "{\"file\": \"$name\", \"restored_at\": \"$(now_utc)\", \"safety_dump\": \"$safety_name\", \"counts\": $(counts_of "$PGDATABASE" 2>/dev/null || echo null)}"
  log "복원 완료: $name${safety_name:+ (이전 DB: backups/$safety_name)} — 이제 docker compose start api"
  return 0
}

do_list() {
  ls -1t "$BACKUP_DIR"/wlm-*.dump "$BACKUP_DIR"/before-*.dump 2>/dev/null | while read -r f; do
    echo "$(basename "$f")  $(stat -c %s "$f") 바이트  $(date -r "$f" '+%Y-%m-%d %H:%M')"
  done
}

# ------------------------------------------------------------------ 상주
# 오늘 할 차례인가: 시각(HHMM)이 지났고 오늘 아직 안 했으면. 정확히 그 1분에만 돌면 긴 복구 시험이 다음 날 시각을 넘기거나
# 서머타임으로 그 시각이 없는 날 하루를 건너뛴다. 마지막으로 돈 날짜는 파일에 남겨 컨테이너가 다시 떠도 같은 날 두 번 돌지 않는다
is_due() { [ "$1" -ge "$(echo "$AT" | tr -d :)" ] && [ "$2" != "$3" ]; }

daemon() {
  check_settings || exit 2
  state="$BACKUP_DIR/.last-run"
  mkdir -p "$BACKUP_DIR"
  last=$(cat "$state" 2>/dev/null || true)
  # 지난번에 중간에 멈췄다면 남은 것 정리 (임시 DB 는 DB 크기만큼 디스크를 차지한다)
  rm -f "$BACKUP_DIR"/*.dump.part
  dropdb --if-exists "${PGDATABASE}_restore_check" >/dev/null 2>&1
  log "백업 대기: 매일 $AT 이후 한 번 (마지막 ${last:-없음}), 최근 ${KEEP}개 보관, 복구 시험 요일 $VERIFY_DAY (1=월 … 7=일, 0=안 함), 폴더 $BACKUP_DIR, 외부 복제 $REPLICA"
  while true; do
    today=$(date +%Y-%m-%d)
    if is_due "$(date +%H%M)" "$today" "$last"; then
      dow=$(date +%u)   # 백업이 자정을 넘겨도 시작한 날의 요일로 복구 시험 여부를 정한다
      last=$today
      echo "$today" > "$state" || log "경고: $state 에 기록하지 못했습니다 (컨테이너가 다시 뜨면 오늘 백업을 한 번 더 할 수 있음)"
      if do_backup && [ "$dow" = "$VERIFY_DAY" ]; then
        do_verify || true
      fi
      # 백업이 실패해도 보관 파일 복제는 한다 (B-17)
      if [ "$REPLICA" = on ]; then do_replicate || true; fi
    fi
    sleep 20
  done
}

# ------------------------------------------------------------------ 외부 저장소 복제
# 새 파일만 복사하고 해시로 확인한다. 이미 있는 것은 덮어쓰지 않는다 — 원본이 랜섬웨어로 암호화돼도 복제본은 그대로 남게.
# 지우는 것은 보관기간이 지난 보관 파일과 REPLICA_BACKUP_DAYS 가 지난 백업뿐이다. 원본에서 사라졌는데 만료가 아닌 것은 지우지 않고 센다.
replicate_dir() {  # 원본 폴더, 복제 폴더, 파일 무늬...
  _src=$1; _dst=$2; shift 2
  mkdir -p "$_dst" || { R_FAILED=$((R_FAILED + 1)); return 1; }
  for _pat in "$@"; do
    for _f in "$_src"/$_pat; do
      [ -f "$_f" ] || continue
      _name=$(basename "$_f")
      # 만료된 보관 파일은 복제하지 않는다 (곧 원본도 지워진다 — 복사했다가 바로 지우는 일을 매일 되풀이하지 않게)
      if [ "$_dst" = "$REPLICA_DIR/archive" ] && archive_expired "$_name"; then continue; fi
      if [ -e "$_dst/$_name" ]; then
        [ "$(stat -c %s "$_f")" = "$(stat -c %s "$_dst/$_name")" ] || R_DIFFERENT=$((R_DIFFERENT + 1))
        continue
      fi
      if cp -p "$_f" "$_dst/.$_name.part" \
         && [ "$(sha256sum < "$_f" | cut -d' ' -f1)" = "$(sha256sum < "$_dst/.$_name.part" | cut -d' ' -f1)" ] \
         && mv "$_dst/.$_name.part" "$_dst/$_name"; then
        R_COPIED=$((R_COPIED + 1))
      else
        rm -f "$_dst/.$_name.part"
        R_FAILED=$((R_FAILED + 1))
        log "복제 실패: $_name"
      fi
    done
  done
}

archive_expired() {  # events_YYYY_MM.* 의 달이 끝난 지 보관기간이 지났나 (api 의 만료 판단과 같게)
  # busybox date 는 '+1 month'·'-N days' 를 모른다 → 다음 달 1일을 직접 만들고 초로 뺀다
  _y=$(basename "$1" | sed -n 's/^events_\([0-9]\{4\}\)_[0-9]\{2\}\..*/\1/p')
  _m=$(basename "$1" | sed -n 's/^events_[0-9]\{4\}_\([0-9]\{2\}\)\..*/\1/p')
  [ -n "$_y" ] && [ -n "$_m" ] || return 1
  _m=$((1${_m} - 100 + 1))   # 앞의 0 때문에 8진수로 읽히지 않게
  if [ "$_m" -gt 12 ]; then _y=$((_y + 1)); _m=1; fi
  _end=$(date -d "$(printf '%04d-%02d-01' "$_y" "$_m")" +%s 2>/dev/null) || return 1
  [ "$_end" -lt $(( $(date +%s) - RETENTION_DAYS * 86400 )) ]
}

do_replicate() {
  started=$(now_utc)
  R_COPIED=0; R_FAILED=0; R_DIFFERENT=0; R_DELETED=0; R_MISSING=0; R_KEPT=0
  probe="$REPLICA_DIR/.wlm-write-test"
  if ! { [ -d "$REPLICA_DIR" ] && : > "$probe" && rm -f "$probe"; }; then
    log "복제 실패: $REPLICA_DIR 에 쓸 수 없습니다 (NAS 마운트·권한 확인)"
    audit backup.replicate "$REPLICA_DIR" "{\"ok\": false, \"error\": \"복제 폴더에 쓸 수 없습니다\", \"started_at\": \"$started\"}"
    return 1
  fi
  replicate_dir "$BACKUP_DIR" "$REPLICA_DIR/backups" '*.dump' '*.dump.sha256' 'wlm-*.json' '*.config.tar.gz'
  replicate_dir "$ARCHIVE_DIR" "$REPLICA_DIR/archive" 'events_*.jsonl.gz' 'events_*.meta.json'
  for _f in "$REPLICA_DIR"/archive/events_*; do
    [ -f "$_f" ] || continue
    if archive_expired "$_f"; then
      # 만료 — 원본도 지워졌다. 객체 잠금(WORM)이면 지우지 못한다: 남긴 채 센다 (잠금 기간 = 보관기간으로 두면 맞는다)
      if rm -f "$_f" 2>/dev/null && [ ! -e "$_f" ]; then R_DELETED=$((R_DELETED + 1)); else R_KEPT=$((R_KEPT + 1)); fi
    elif [ ! -e "$ARCHIVE_DIR/$(basename "$_f")" ]; then
      R_MISSING=$((R_MISSING + 1))   # 원본이 만료 전에 사라졌다 — 사고일 수 있다. 복제본은 지우지 않는다
    fi
  done
  for _f in $(find "$REPLICA_DIR/backups" -maxdepth 1 -type f -name 'wlm-*' -mtime +"$REPLICA_BACKUP_DAYS" 2>/dev/null); do
    if rm -f "$_f" 2>/dev/null && [ ! -e "$_f" ]; then R_DELETED=$((R_DELETED + 1)); else R_KEPT=$((R_KEPT + 1)); fi
  done
  files=$(find "$REPLICA_DIR/backups" "$REPLICA_DIR/archive" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | wc -l | tr -d ' ')
  ok=$([ "$R_FAILED" = 0 ] && echo true || echo false)
  log "복제: 새로 $R_COPIED, 실패 $R_FAILED, 크기 다름 $R_DIFFERENT, 만료 삭제 $R_DELETED, 원본 없음 $R_MISSING, 복제본 $files 개"
  audit backup.replicate "$REPLICA_DIR" "{\"ok\": $ok, \"copied\": $R_COPIED, \"failed\": $R_FAILED, \"different\": $R_DIFFERENT, \"deleted\": $R_DELETED, \"kept\": $R_KEPT, \"missing_locally\": $R_MISSING, \"files\": $files, \"started_at\": \"$started\"}"
  [ "$R_FAILED" = 0 ]
}

# ------------------------------------------------------------------ 자체 시험
selftest() {
  real_db=$PGDATABASE
  PGDATABASE=wlm_backup_selftest
  BACKUP_DIR=$(mktemp -d)
  KEEP=2
  CONFIG_DIR=$(mktemp -d)
  echo '{"name": "selftest"}' > "$CONFIG_DIR/dashboard.json"
  failed=0
  check() { if [ "$1" = "$2" ]; then log "  통과: $3"; else log "  실패: $3 (기대 $2, 실제 $1)"; failed=1; fi; }
  sql() { psql_q -d "$PGDATABASE" -c "$1"; }

  for d in "$PGDATABASE" "${PGDATABASE}_restore_check" "${PGDATABASE}_restoring" "${PGDATABASE}_replaced"; do
    dropdb --if-exists "$d" >/dev/null 2>&1
  done
  createdb "$PGDATABASE" || { log "시험용 DB 를 만들 수 없음"; exit 1; }
  psql_q -d "$PGDATABASE" >/dev/null <<'SQL'
CREATE TABLE schema_migrations (version TEXT PRIMARY KEY);
INSERT INTO schema_migrations VALUES ('001_init'), ('010_selftest');
CREATE TABLE audit_log (id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT now(), actor TEXT, actor_ip TEXT,
                        action TEXT, target TEXT, detail JSONB);
CREATE TABLE events (id BIGSERIAL, received_at TIMESTAMPTZ NOT NULL DEFAULT now(), message TEXT) PARTITION BY RANGE (received_at);
CREATE TABLE events_all PARTITION OF events FOR VALUES FROM ('2000-01-01') TO ('2100-01-01');
INSERT INTO events (message) SELECT '시험 이벤트 ' || g FROM generate_series(1, 500) g;
CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT);
INSERT INTO users (username) VALUES ('admin'), ('kim');
SQL

  log "시험 0: 설정 검사·일정"
  (KEEP=0; check_settings >/dev/null); check "$?" 2 "WLM_BACKUP_KEEP=0 은 거부 (방금 만든 백업까지 지워지므로)"
  (KEEP=abc; check_settings >/dev/null); check "$?" 2 "숫자가 아닌 보관 개수는 거부"
  (AT=24:00; check_settings >/dev/null); check "$?" 2 "없는 시각은 거부"
  check_settings >/dev/null; check "$?" 0 "올바른 설정"
  (AT=02:30; is_due 0300 2026-03-29 2026-03-28); check "$?" 0 "시각을 넘겨 확인해도 그날 한 번 (서머타임으로 02:30 이 없는 날)"
  (AT=02:30; is_due 0229 2026-03-29 2026-03-28); check "$?" 1 "시각 전에는 하지 않음"
  (AT=02:30; is_due 2359 2026-03-29 2026-03-29); check "$?" 1 "같은 날 두 번 하지 않음"

  log "시험 1: 백업 → 복구 시험 (행 수는 덤프와 같은 스냅숏)"
  do_backup; check "$?" 0 "백업"
  first=$(newest_dump)
  manifest="${first%.dump}.json"
  check "$(grep -c '"events": 500' "$manifest")" 1 "백업 정보에 행 수"
  check "$(ls "$BACKUP_DIR"/*.config.tar.gz 2>/dev/null | wc -l | tr -d ' ')" 1 "설정 묶음"
  check "$(stat -c %a "$first")" 600 "백업 파일은 소유자만 읽기"
  do_verify; check "$?" 0 "정상 백업의 복구 시험"
  check "$(sql "SELECT count(*) FROM pg_database WHERE datname = '${PGDATABASE}_restore_check'")" 0 "임시 DB 를 지움"

  log "시험 2: 손상된 파일은 복구 시험에서 걸린다"
  cp "$first" "$BACKUP_DIR/broken.dump.tmp"
  printf 'x' >> "$first"
  do_verify "$first"; check "$?" 1 "끝에 1바이트 덧붙인 파일 (해시)"
  mv "$BACKUP_DIR/broken.dump.tmp" "$first"
  cp "$first.sha256" "$BACKUP_DIR/sha.tmp"
  rm -f "$first.sha256"
  do_verify "$first"; check "$?" 1 "해시 파일이 없는 백업"
  # 해시는 맞지만 내용이 잘린 파일 (만들 때부터 깨진 백업) → 복원 단계에서 걸려야 한다
  cp "$first" "$BACKUP_DIR/whole.tmp"
  head -c 4000 "$BACKUP_DIR/whole.tmp" > "$first"
  echo "$(sha256sum "$first" | cut -d' ' -f1)  $(basename "$first")" > "$first.sha256"
  do_verify "$first"; check "$?" 1 "반쯤 잘린 덤프 (복원 실패)"
  mv "$BACKUP_DIR/whole.tmp" "$first"
  mv "$BACKUP_DIR/sha.tmp" "$first.sha256"
  # 행 수가 백업 때와 다르면 (덤프가 일부만 담긴 경우) 걸려야 한다 — 많아도 적어도
  cp "$manifest" "$BACKUP_DIR/manifest.tmp"
  sed 's/"events": 500/"events": 999999/' "$BACKUP_DIR/manifest.tmp" > "$manifest"
  do_verify "$first"; check "$?" 1 "행 수가 백업 때보다 적음"
  sed 's/"events": 500/"events": 7/' "$BACKUP_DIR/manifest.tmp" > "$manifest"
  do_verify "$first"; check "$?" 1 "행 수가 백업 때와 다름 (많음)"
  # 복원본에 아예 없는 테이블 (NULL 이 섞여도 통과하지 않아야 한다)
  sed 's/"events": 500/"events": 500, "ghost": 3/' "$BACKUP_DIR/manifest.tmp" > "$manifest"
  do_verify "$first"; check "$?" 1 "복원본에 없는 테이블"
  echo 'not json' > "$manifest"
  do_verify "$first"; check "$?" 1 "읽을 수 없는 백업 정보 파일"
  echo '{"migration": "010_selftest"}' > "$manifest"
  do_verify "$first"; check "$?" 1 "행 수가 빠진 백업 정보 파일"
  mv "$BACKUP_DIR/manifest.tmp" "$manifest"
  do_verify "$first"; check "$?" 0 "원래대로 되돌린 백업은 다시 통과"
  # DB 디스크가 모자라면 복원하지 않고 실패로 남긴다
  (SPACE_RESERVE_KB=999999999999; do_verify "$first" >/dev/null); check "$?" 1 "디스크 공간이 모자라면 시험하지 않음"
  check "$(sql "SELECT count(*) FROM pg_database WHERE datname = '${PGDATABASE}_restore_check'")" 0 "공간 부족 때 임시 DB 를 만들지 않음"

  log "시험 3: 보관 개수 ($KEEP 개)"
  # 업그레이드 전 백업은 실제로는 이후 매일 백업보다 오래되었다 → 가장 오래된 시각으로 두고 정리해도 남는지 본다
  touch "$BACKUP_DIR/before-0.6.0-x.dump"; touch -d '2000-01-01 00:00:00' "$BACKUP_DIR/before-0.6.0-x.dump"
  touch "$BACKUP_DIR/wlm-19990101-000000.dump.part"; touch -d '2000-01-01 00:00:00' "$BACKUP_DIR/wlm-19990101-000000.dump.part"
  touch "$BACKUP_DIR/wlm-fresh.dump.part"
  sleep 1; do_backup >/dev/null; sleep 1; do_backup >/dev/null; sleep 1; do_backup >/dev/null
  check "$(ls "$BACKUP_DIR"/wlm-*.dump | wc -l | tr -d ' ')" "$KEEP" "최근 ${KEEP}개만 남음"
  check "$(ls "$BACKUP_DIR"/before-*.dump | wc -l | tr -d ' ')" 1 "업그레이드 전 백업은 지우지 않음"
  check "$(ls "$BACKUP_DIR"/*.part | wc -l | tr -d ' ')" 1 "하루 지난 .part 만 정리 (만드는 중일 수 있는 것은 둔다)"
  rm -f "$BACKUP_DIR"/*.part
  # 방금 만든 백업은 파일 시각이 꼬여도(다른 파일이 더 새로워 보여도) 지우지 않는다
  (KEEP=1; touch -d '2099-01-01 00:00:00' "$BACKUP_DIR"/wlm-*.dump; sleep 1; do_backup >/dev/null)
  just=$(ls "$BACKUP_DIR"/wlm-*.dump | sort | tail -n 1)
  check "$(ls "$BACKUP_DIR"/wlm-*.dump | wc -l | tr -d ' ')|$(sql "SELECT target FROM audit_log WHERE action = 'backup.create' ORDER BY id DESC LIMIT 1")" \
    "2|$(basename "$just")" "방금 만든 백업은 정리하지 않음"
  (BACKUP_DIR=$(mktemp -d); do_verify >/dev/null); check "$?" 1 "백업이 하나도 없으면 실패로 기록"

  log "시험 4: 감사로그"
  check "$(sql "SELECT count(*) FROM audit_log WHERE action = 'backup.create'")" 5 "backup.create 5건"
  check "$(sql "SELECT count(*) FROM audit_log WHERE action = 'backup.verify' AND (detail->>'ok')::bool")" 2 "복구 시험 성공 2건"
  check "$(sql "SELECT count(*) FROM audit_log WHERE action = 'backup.verify' AND NOT (detail->>'ok')::bool")" 10 "복구 시험 실패 10건 (사유 기록)"
  check "$(sql "SELECT count(*) FROM audit_log WHERE action = 'backup.verify' AND detail->>'reason' LIKE '%공간 부족%'")" 1 "공간 부족 사유"

  log "시험 5: 복원 (장애 복구)"
  target=$(newest_dump)
  do_restore "$target" >/dev/null 2>&1; check "$?" 2 "--yes 없이는 복원하지 않음"
  sql "DELETE FROM users WHERE username = 'kim'" >/dev/null
  # 연결된 세션(api 등)이 있으면 거부
  psql_q -d "$PGDATABASE" -c "SELECT pg_sleep(4)" >/dev/null 2>&1 &
  sleeper=$!
  sleep 1
  do_restore "$target" --yes >/dev/null; check "$?" 1 "운영 DB 에 연결된 세션이 있으면 거부"
  check "$(ls "$BACKUP_DIR"/before-restore-* 2>/dev/null | wc -l | tr -d ' ')" 0 "거부는 아무것도 하기 전에 (안전 사본도 만들지 않음)"
  wait "$sleeper"
  check "$(sql "SELECT count(*) FROM users")" 1 "거부했을 때 운영 DB 는 그대로"
  # 해시는 맞지만 깨진 파일 → 임시 DB 에서 실패하고 운영 DB 는 그대로
  head -c 4000 "$target" > "$BACKUP_DIR/wlm-broken.dump"
  (cd "$BACKUP_DIR" && sha256sum wlm-broken.dump > wlm-broken.dump.sha256)
  do_restore "$BACKUP_DIR/wlm-broken.dump" --yes >/dev/null; check "$?" 1 "깨진 백업은 복원 실패"
  check "$(sql "SELECT count(*) FROM users")" 1 "복원이 실패해도 운영 DB 는 그대로"
  rm -f "$BACKUP_DIR"/wlm-broken.dump*
  do_restore "$target" --yes; check "$?" 0 "백업으로 되돌림"
  check "$(sql "SELECT count(*) FROM users")" 2 "지운 행이 돌아옴"
  check "$(sql "SELECT count(*) FROM audit_log WHERE action = 'backup.restore'")" 1 "복원 기록"
  safety=$(ls "$BACKUP_DIR"/before-restore-*.dump 2>/dev/null | head -n 1)
  check "$([ -n "$safety" ] && cd "$BACKUP_DIR" && sha256sum -c "$(basename "$safety").sha256" >/dev/null 2>&1 && echo ok)" ok "복원 전 DB 의 안전 사본 (해시 포함)"
  check "$(sql "SELECT count(*) FROM pg_database WHERE datname LIKE '${PGDATABASE}\_%'")" 0 "임시·교체 DB 가 남지 않음"
  check "$(sql "SELECT datallowconn FROM pg_database WHERE datname = '$PGDATABASE'")" t "복원한 DB 에 접속 가능"

  log "시험 6: 외부 저장소 복제 (B-17)"
  REPLICA_DIR=$(mktemp -d); ARCHIVE_DIR=$(mktemp -d); RETENTION_DAYS=365
  old=events_$(( $(date +%Y) - 3 ))_08; new=$(date +events_%Y_%m)
  for a in "$old" "$new"; do echo "$a" > "$ARCHIVE_DIR/$a.jsonl.gz"; echo '{}' > "$ARCHIVE_DIR/$a.meta.json"; done
  do_replicate >/dev/null; check "$?" 0 "복제"
  check "$(ls "$REPLICA_DIR"/archive | wc -l | tr -d ' ')|$(ls "$REPLICA_DIR"/backups/*.dump | wc -l | tr -d ' ')" \
    "2|$(ls "$BACKUP_DIR"/*.dump | wc -l | tr -d ' ')" "만료 안 된 보관 파일·백업이 복제됨 (만료된 것은 복제 뒤 지움)"
  check "$([ -e "$REPLICA_DIR/archive/$old.jsonl.gz" ] && echo y || echo n)" n "만료된 보관 파일은 복제하지 않음"
  # 예전에 복제해 둔 것이 만료되면 복제본에서도 지운다
  cp "$ARCHIVE_DIR/$old.jsonl.gz" "$ARCHIVE_DIR/$old.meta.json" "$REPLICA_DIR/archive/"
  do_replicate >/dev/null
  check "$([ -e "$REPLICA_DIR/archive/$old.jsonl.gz" ] && echo y || echo n)" n "만료된 복제본은 지움"
  check "$(sql "SELECT detail->>'deleted' FROM audit_log WHERE action = 'backup.replicate' ORDER BY id DESC LIMIT 1")" 2 "만료 삭제 2개 (본문·메타)"
  check "$(archive_expired "events_$(date +%Y_%m).jsonl.gz" && echo y || echo n)|$(archive_expired "events_$(( $(date +%Y) - 1 ))_12.jsonl.gz" && echo y || echo n)" \
    "n|n" "이번 달·작년 12월은 만료 아님 (보관 365일)"
  (RETENTION_DAYS=30; check "$(archive_expired "events_$(( $(date +%Y) - 1 ))_12.jsonl.gz" && echo y || echo n)" y "보관 30일이면 작년 12월은 만료")
  check "$(cd "$REPLICA_DIR/archive" && sha256sum < "$new.jsonl.gz" | cut -d' ' -f1)" "$(sha256sum < "$ARCHIVE_DIR/$new.jsonl.gz" | cut -d' ' -f1)" "해시가 같은 복제본"
  do_replicate >/dev/null
  check "$(sql "SELECT detail->>'copied' FROM audit_log WHERE action = 'backup.replicate' ORDER BY id DESC LIMIT 1")" 0 "두 번째는 새 파일만 (없음)"
  echo 'ENCRYPTED BY RANSOMWARE' > "$ARCHIVE_DIR/$new.jsonl.gz"
  do_replicate >/dev/null
  check "$(cat "$REPLICA_DIR/archive/$new.jsonl.gz")" "$new" "원본이 바뀌어도 복제본은 덮어쓰지 않음"
  check "$(sql "SELECT detail->>'different' FROM audit_log WHERE action = 'backup.replicate' ORDER BY id DESC LIMIT 1")" 1 "크기가 달라진 원본을 셈"
  rm -f "$ARCHIVE_DIR/$new.jsonl.gz"
  do_replicate >/dev/null
  check "$([ -e "$REPLICA_DIR/archive/$new.jsonl.gz" ] && echo y || echo n)" y "만료 전에 원본이 사라져도 복제본은 지우지 않음"
  check "$(sql "SELECT detail->>'missing_locally' FROM audit_log WHERE action = 'backup.replicate' ORDER BY id DESC LIMIT 1")" 1 "사라진 원본을 셈"
  touch -d '2000-01-01 00:00:00' "$REPLICA_DIR/backups/wlm-20000101-000000.dump" "$REPLICA_DIR/backups/before-restore-old.dump"
  do_replicate >/dev/null
  check "$(ls "$REPLICA_DIR"/backups/wlm-20000101-000000.dump 2>/dev/null | wc -l | tr -d ' ')|$(ls "$REPLICA_DIR"/backups/before-restore-old.dump | wc -l | tr -d ' ')" \
    "0|1" "오래된 복제 백업은 지우고 복원 전 안전 사본은 남김"
  (REPLICA_DIR=/proc/no-such-dir; do_replicate >/dev/null 2>&1); check "$?" 1 "복제 폴더에 쓸 수 없으면 실패로 기록"
  check "$(sql "SELECT count(*) FROM audit_log WHERE action = 'backup.replicate' AND NOT (detail->>'ok')::bool")" 1 "실패 기록"
  rm -rf "$REPLICA_DIR" "$ARCHIVE_DIR"

  dropdb --if-exists "$PGDATABASE" >/dev/null 2>&1
  rm -rf "$BACKUP_DIR" "$CONFIG_DIR"
  PGDATABASE=$real_db
  if [ "$failed" = 0 ]; then log "자체 시험 통과"; exit 0; fi
  log "자체 시험 실패"; exit 1
}

cmd=${1:-daemon}
[ $# -gt 0 ] && shift
case $cmd in
  daemon) daemon ;;
  backup) check_settings || exit 2; do_backup; exit $? ;;
  verify) do_verify "${1:-}"; exit $? ;;
  list) do_list ;;
  restore) do_restore "${1:-}" "${2:-}" "${3:-}"; exit $? ;;
  replicate) do_replicate; exit $? ;;
  selftest) selftest ;;
  *) echo "사용법: backup.sh [daemon|backup|verify [파일]|list|restore 파일 --yes [--no-safety-dump]|replicate|selftest]" >&2; exit 2 ;;
esac
