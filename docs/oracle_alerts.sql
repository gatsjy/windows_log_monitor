-- Log Monitor → 사내 Oracle 알림 테이블 (config/alerts.yaml 의 type: oracle 기본 INSERT 대상)
-- 다른 구조의 기존 테이블을 쓰려면 alerts.yaml 의 notifier 에 sql: 로 INSERT 문을 직접 지정한다.
-- 시각 컬럼은 UTC 기준 TIMESTAMP.

CREATE TABLE LOGMON_ALERTS (
    ALERT_ID        NUMBER(19)      NOT NULL,   -- Log Monitor 알림 번호 (재전송 시 중복 방지 키)
    RULE_NAME       VARCHAR2(200)   NOT NULL,
    SEVERITY        VARCHAR2(20)    NOT NULL,   -- critical / error / warning / info
    HOST            VARCHAR2(255),              -- 발생 PC (규칙의 group_by 값)
    EVENT_COUNT     NUMBER(19),
    WINDOW_SEC      NUMBER(10),
    FIRST_EVENT_AT  TIMESTAMP,
    LAST_EVENT_AT   TIMESTAMP,
    FIRED_AT        TIMESTAMP       NOT NULL,
    TITLE           VARCHAR2(500),
    MESSAGE         VARCHAR2(4000),             -- 사람이 읽는 본문 (메일 본문과 같음)
    LINK            VARCHAR2(1000),             -- Log Monitor 검색 화면 주소
    DETAIL_JSON     CLOB,                       -- 알림 전체 데이터 (최근 이벤트 샘플 포함)
    CREATED_AT      TIMESTAMP DEFAULT SYSTIMESTAMP,
    CONSTRAINT LOGMON_ALERTS_PK PRIMARY KEY (ALERT_ID)
);

CREATE INDEX LOGMON_ALERTS_FIRED_IX ON LOGMON_ALERTS (FIRED_AT);

-- 해소 통지 (B-35 2단계): SQL 에 :event_action 을 쓰면 자동 해결된 알림의 해소(event_action = 'resolve')도 보낸다.
--   위 기본 INSERT 는 :event_action 이 없어 해소를 받지 않는다 (ALERT_ID 가 기본 키라 같은 번호를 다시 넣으면 ORA-00001 —
--   재전송 중복으로 보고 성공 처리하므로 해소가 아무 흔적 없이 '보냄'이 된다).
--   받으려면 예) 열을 더하고 기본 키를 (ALERT_ID, EVENT_ACTION) 으로 바꾼 뒤 SQL 에 :dedup_key, :event_action 을 넣는다:
--   ALTER TABLE LOGMON_ALERTS ADD (DEDUP_KEY VARCHAR2(32), EVENT_ACTION VARCHAR2(10) DEFAULT 'trigger' NOT NULL);
--   ALTER TABLE LOGMON_ALERTS DROP CONSTRAINT LOGMON_ALERTS_PK;
--   ALTER TABLE LOGMON_ALERTS ADD CONSTRAINT LOGMON_ALERTS_PK PRIMARY KEY (ALERT_ID, EVENT_ACTION);
--   DEDUP_KEY 는 같은 규칙·대상이면 같다 — 사고관리 쪽에서 trigger 로 연 건을 resolve 로 닫는 키.

-- 전용 계정 권한 예시 (INSERT 만):
-- CREATE USER LOGMON IDENTIFIED BY "..." ;
-- GRANT CREATE SESSION TO LOGMON;
-- GRANT INSERT ON 스키마.LOGMON_ALERTS TO LOGMON;   -- 다른 스키마 테이블이면 table: 스키마.LOGMON_ALERTS

-- 생존 신호 (B-34, 선택): 외부 연동의 '생존 신호 SQL' 에 아래 MERGE 를 넣으면 1분마다 한 행을 갱신한다.
--   서버 전체가 멈추면 AT 가 멈춘다 — 병원 DB 감시(예: AT 가 5분보다 오래되면 경보)가 Log Monitor 의 정지를 잡는다.
--   바인드: :at (UTC TIMESTAMP), :status (ok·warn·down = 알림 기능 상태), :version, :problems (문제 수)
CREATE TABLE LOGMON_HEARTBEAT (
    ID        NUMBER(1)     NOT NULL,
    AT        TIMESTAMP     NOT NULL,
    STATUS    VARCHAR2(10)  NOT NULL,
    VERSION   VARCHAR2(20),
    PROBLEMS  NUMBER(5),
    CONSTRAINT LOGMON_HEARTBEAT_PK PRIMARY KEY (ID)
);
-- MERGE INTO LOGMON_HEARTBEAT h USING dual ON (h.ID = 1)
--   WHEN MATCHED THEN UPDATE SET h.AT = :at, h.STATUS = :status, h.VERSION = :version, h.PROBLEMS = :problems
--   WHEN NOT MATCHED THEN INSERT (ID, AT, STATUS, VERSION, PROBLEMS) VALUES (1, :at, :status, :version, :problems)

