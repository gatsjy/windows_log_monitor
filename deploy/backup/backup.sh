#!/bin/sh
# Log Monitor DB 백업·복구 시험 (BACKLOG B-16, ADR-031) — postgres:17-alpine 컨테이너(compose 의 backup 서비스) 안에서 돈다.
#
#   daemon         매일 WLM_BACKUP_TIME 에 백업, WLM_BACKUP_VERIFY_WEEKDAY 요일에는 이어서 복구 시험 (서비스 기본 명령)
#   backup         지금 백업 한 번
#   verify [파일]  백업 파일을 임시 DB 에 복원해 확인 (기본: 가장 최근). 실제 DB 는 건드리지 않는다
#   list           백업 목록
#   restore 파일 --yes   운영 DB 를 이 백업으로 되돌린다 (장애 복구). 먼저 api 를 멈춘다: docker compose stop api
#   selftest       시험용 DB 로 백업 → 복구 시험 → 손상 감지 → 보관 개수 정리를 스스로 시험 (실제 DB·백업 폴더는 건드리지 않음)
#
# 예)  docker compose exec backup backup.sh backup
#      docker compose exec backup backup.sh verify
#      docker compose run --rm backup selftest
#      docker compose stop api && docker compose run --rm backup restore wlm-20261016-023000.dump --yes && docker compose start api
#
# 결과는 DB 의 audit_log 에 남긴다 (backup.create / backup.verify / backup.failed)
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
TABLES="events alerts alert_notes audit_log users agents"

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

# 주요 테이블 행 수 → {"events": 12, ...} (없는 테이블은 뺀다)
counts_json() {
  out=""
  for t in $TABLES; do
    n=$(psql_q -d "$1" -c "SELECT count(*) FROM $t" 2>/dev/null) || continue
    out="$out${out:+, }\"$t\": $n"
  done
  echo "{$out}"
}

migration_of() { psql_q -d "$1" -c "SELECT max(version) FROM schema_migrations" 2>/dev/null || true; }

newest_dump() { ls -1t "$BACKUP_DIR"/wlm-*.dump 2>/dev/null | head -n 1; }

# ------------------------------------------------------------------ 백업
do_backup() {
  mkdir -p "$BACKUP_DIR" || { log "백업 폴더를 만들 수 없음: $BACKUP_DIR"; return 1; }
  stamp=$(date +%Y%m%d-%H%M%S)
  base="$BACKUP_DIR/wlm-$stamp"
  name="wlm-$stamp.dump"
  started=$(now_utc)
  t0=$(date +%s)
  # 백업 직전 행 수 — 복구 시험 때 '이만큼은 있어야 한다'의 기준 (덤프 중에 들어온 행은 더 많을 수 있다)
  counts=$(counts_json "$PGDATABASE")
  version=$(migration_of "$PGDATABASE")
  log "백업 시작: $name (DB $PGDATABASE, 마이그레이션 $version)"

  if ! err=$(pg_dump -Fc -Z 6 -f "$base.dump.part" "$PGDATABASE" 2>&1); then
    rm -f "$base.dump.part"
    log "백업 실패: $err"
    audit backup.failed "$name" "{\"stage\": \"dump\", \"error\": \"$(json_esc "$err")\", \"started_at\": \"$started\"}"
    return 1
  fi
  mv "$base.dump.part" "$base.dump"
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
  prune
  audit backup.create "$name" "$detail"
  log "백업 완료: $name ($bytes 바이트, ${seconds}초) sha256=$sha"
  return 0
}

# 최근 KEEP 개만 남긴다. 업그레이드 전 백업(before-*.dump, install.sh)은 건드리지 않는다
prune() {
  ls -1t "$BACKUP_DIR"/wlm-*.dump 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    base=${old%.dump}
    rm -f "$old" "$old.sha256" "$base.json" "$base.config.tar.gz"
    log "오래된 백업 정리: $(basename "$old")"
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
  [ -n "$file" ] || { log "복구 시험할 백업이 없습니다 ($BACKUP_DIR)"; return 1; }
  case $file in /*) ;; *) file="$BACKUP_DIR/$file" ;; esac
  name=$(basename "$file")
  check_db="${PGDATABASE}_restore_check"
  t0=$(date +%s)
  [ -f "$file" ] || { verify_fail "$name" "파일이 없습니다: $file"; return 1; }
  log "복구 시험 시작: $name → 임시 DB $check_db"

  # 1) 해시: 만든 뒤 바뀌지 않았는가 (손상·변조)
  expected=$(cut -d' ' -f1 "$file.sha256" 2>/dev/null || true)
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  [ -n "$expected" ] || { verify_fail "$name" "해시 파일(.sha256)이 없습니다"; return 1; }
  [ "$expected" = "$actual" ] || { verify_fail "$name" "해시가 다릅니다 — 파일이 손상되었거나 바뀌었습니다"; return 1; }

  # 2) 임시 DB 에 실제로 복원
  dropdb --if-exists "$check_db" >/dev/null 2>&1
  if ! err=$(createdb "$check_db" 2>&1); then verify_fail "$name" "임시 DB 를 만들 수 없음: $err"; return 1; fi
  if ! err=$(pg_restore --no-owner --no-privileges --exit-on-error -d "$check_db" "$file" 2>&1); then
    dropdb --if-exists "$check_db" >/dev/null 2>&1
    verify_fail "$name" "복원 실패: $err"
    return 1
  fi

  # 3) 복원된 내용: 마이그레이션 버전이 같고, 주요 테이블 행 수가 백업 직전보다 적지 않은가
  restored=$(counts_json "$check_db")
  version=$(migration_of "$check_db")
  dropdb --if-exists "$check_db" >/dev/null 2>&1
  manifest="${file%.dump}.json"
  expected_version=""
  short=""
  if [ -f "$manifest" ]; then
    # JSON 비교는 psql 로 (컨테이너에 jq 가 없다)
    expected_version=$(printf '%s\n' "SELECT (:'m'::json)->>'migration';" | psql_q -d "$PGDATABASE" -v m="$(cat "$manifest")")
    short=$(printf '%s\n' "SELECT string_agg(p.key || ' ' || q.value || '/' || p.value, ', ')
        FROM json_each_text((:'m'::json)->'counts') p LEFT JOIN json_each_text(:'r'::json) q USING (key)
        WHERE q.value IS NULL OR q.value::bigint < p.value::bigint;" \
      | psql_q -d "$PGDATABASE" -v m="$(cat "$manifest")" -v r="$restored")
  fi
  seconds=$(( $(date +%s) - t0 ))
  if [ -n "$expected_version" ] && [ "$version" != "$expected_version" ]; then
    verify_fail "$name" "마이그레이션 버전이 다릅니다: 복원 $version, 백업 때 $expected_version"; return 1
  fi
  if [ -n "$short" ]; then
    verify_fail "$name" "행 수가 백업 직전보다 적습니다 (복원/백업 직전): $short"; return 1
  fi
  audit backup.verify "$name" "{\"file\": \"$name\", \"ok\": true, \"sha256\": \"$actual\", \"migration\": \"$version\", \"counts\": $restored, \"seconds\": $seconds, \"manifest\": $([ -f "$manifest" ] && echo true || echo false), \"checked_at\": \"$(now_utc)\"}"
  log "복구 시험 성공: $name (${seconds}초) 행 수 $restored"
  return 0
}

# ------------------------------------------------------------------ 복원 (장애 복구)
# 운영 DB 를 지우고 백업으로 다시 만든다. 되돌릴 수 없으므로 --yes 가 있어야 하고, 해시가 맞는 파일만 쓴다
do_restore() {
  file=${1:-}
  [ -n "$file" ] || { echo "복원할 백업 파일을 지정하세요 (backup.sh list)" >&2; return 2; }
  [ "${2:-}" = "--yes" ] || { echo "운영 DB '$PGDATABASE' 를 지우고 $file 로 되돌립니다. 맞으면 끝에 --yes 를 붙이세요 (먼저 docker compose stop api)" >&2; return 2; }
  case $file in /*) ;; *) file="$BACKUP_DIR/$file" ;; esac
  name=$(basename "$file")
  [ -f "$file" ] || { log "파일이 없습니다: $file"; return 1; }
  expected=$(cut -d' ' -f1 "$file.sha256" 2>/dev/null || true)
  [ -n "$expected" ] && [ "$expected" = "$(sha256sum "$file" | cut -d' ' -f1)" ] \
    || { log "해시가 맞지 않아 복원하지 않습니다 (파일 손상·변조 또는 .sha256 없음): $name"; return 1; }
  log "복원 시작: $name → $PGDATABASE (기존 내용은 지워집니다)"
  dropdb --force --if-exists "$PGDATABASE" || { log "기존 DB 를 지울 수 없습니다 (연결 중인 api 를 멈췄는지 확인)"; return 1; }
  createdb "$PGDATABASE" || return 1
  if ! err=$(pg_restore --no-owner --exit-on-error -d "$PGDATABASE" "$file" 2>&1); then
    log "복원 실패: $err"
    return 1
  fi
  # 복원한 DB 에 복원 사실을 남긴다 (백업 시점 이후의 감사로그는 이 복원으로 사라지므로, 그 공백을 알 수 있게)
  audit backup.restore "$name" "{\"file\": \"$name\", \"restored_at\": \"$(now_utc)\", \"counts\": $(counts_json "$PGDATABASE")}"
  log "복원 완료: $name — 이제 docker compose start api"
  return 0
}

do_list() {
  ls -1t "$BACKUP_DIR"/wlm-*.dump 2>/dev/null | while read -r f; do
    echo "$(basename "$f")  $(stat -c %s "$f") 바이트  $(date -r "$f" '+%Y-%m-%d %H:%M')"
  done
}

# ------------------------------------------------------------------ 상주
daemon() {
  case $AT in [0-2][0-9]:[0-5][0-9]) ;; *) log "WLM_BACKUP_TIME 형식은 HH:MM 입니다: $AT"; exit 2 ;; esac
  log "백업 대기: 매일 $AT, 최근 ${KEEP}개 보관, 복구 시험 요일 $VERIFY_DAY (1=월 … 7=일, 0=안 함), 폴더 $BACKUP_DIR"
  last=""
  while true; do
    today=$(date +%Y-%m-%d)
    # 분 단위로 맞춘다. 같은 날 두 번 돌지 않게 날짜를 기억 (컨테이너가 재시작되면 그날 시각이 지났으면 다음 날)
    if [ "$(date +%H:%M)" = "$AT" ] && [ "$last" != "$today" ]; then
      last=$today
      if do_backup && [ "$(date +%u)" = "$VERIFY_DAY" ]; then
        do_verify || true
      fi
    fi
    sleep 20
  done
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

  dropdb --if-exists "$PGDATABASE" >/dev/null 2>&1
  dropdb --if-exists "${PGDATABASE}_restore_check" >/dev/null 2>&1
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

  log "시험 1: 백업 → 복구 시험"
  do_backup; check "$?" 0 "백업"
  first=$(newest_dump)
  check "$(ls "$BACKUP_DIR"/*.config.tar.gz 2>/dev/null | wc -l | tr -d ' ')" 1 "설정 묶음"
  do_verify; check "$?" 0 "정상 백업의 복구 시험"

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
  # 백업 직전보다 행이 적게 복원되면 (덤프가 일부만 담긴 경우) 걸려야 한다
  manifest="${first%.dump}.json"
  cp "$manifest" "$BACKUP_DIR/manifest.tmp"
  sed 's/"events": 500/"events": 999999/' "$BACKUP_DIR/manifest.tmp" > "$manifest"
  do_verify "$first"; check "$?" 1 "행 수가 백업 직전보다 적음"
  mv "$BACKUP_DIR/manifest.tmp" "$manifest"
  do_verify "$first"; check "$?" 0 "원래대로 되돌린 백업은 다시 통과"

  log "시험 3: 보관 개수 ($KEEP 개)"
  sleep 1; do_backup >/dev/null; sleep 1; do_backup >/dev/null; sleep 1; do_backup >/dev/null
  check "$(ls "$BACKUP_DIR"/wlm-*.dump | wc -l | tr -d ' ')" "$KEEP" "최근 ${KEEP}개만 남음"
  touch "$BACKUP_DIR/before-0.6.0-x.dump"; prune
  check "$(ls "$BACKUP_DIR"/before-*.dump | wc -l | tr -d ' ')" 1 "업그레이드 전 백업은 지우지 않음"

  log "시험 4: 감사로그"
  check "$(psql_q -d "$PGDATABASE" -c "SELECT count(*) FROM audit_log WHERE action = 'backup.create'")" 4 "backup.create 4건"
  check "$(psql_q -d "$PGDATABASE" -c "SELECT count(*) FROM audit_log WHERE action = 'backup.verify' AND (detail->>'ok')::bool")" 2 "복구 시험 성공 2건"
  check "$(psql_q -d "$PGDATABASE" -c "SELECT count(*) FROM audit_log WHERE action = 'backup.verify' AND NOT (detail->>'ok')::bool")" 4 "복구 시험 실패 4건 (사유 기록)"

  log "시험 5: 복원 (장애 복구)"
  do_restore "$(newest_dump)" >/dev/null 2>&1; check "$?" 2 "--yes 없이는 복원하지 않음"
  psql_q -d "$PGDATABASE" -c "DELETE FROM users WHERE username = 'kim'" >/dev/null
  do_restore "$(newest_dump)" --yes; check "$?" 0 "백업으로 되돌림"
  check "$(psql_q -d "$PGDATABASE" -c "SELECT count(*) FROM users")" 2 "지운 행이 돌아옴"
  check "$(psql_q -d "$PGDATABASE" -c "SELECT count(*) FROM audit_log WHERE action = 'backup.restore'")" 1 "복원 기록"


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
  backup) do_backup; exit $? ;;
  verify) do_verify "${1:-}"; exit $? ;;
  list) do_list ;;
  restore) do_restore "${1:-}" "${2:-}"; exit $? ;;
  selftest) selftest ;;
  *) echo "사용법: backup.sh [daemon|backup|verify [파일]|list|restore 파일 --yes|selftest]" >&2; exit 2 ;;
esac
