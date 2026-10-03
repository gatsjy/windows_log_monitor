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

-- 전용 계정 권한 예시 (INSERT 만):
-- CREATE USER LOGMON IDENTIFIED BY "..." ;
-- GRANT CREATE SESSION TO LOGMON;
-- GRANT INSERT ON 스키마.LOGMON_ALERTS TO LOGMON;   -- 다른 스키마 테이블이면 table: 스키마.LOGMON_ALERTS
