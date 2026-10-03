// 사람이 읽기 쉬운 설명 사전. 필드 탐색 / 이벤트 상세 화면에서 쓴다.
// 자주 보는 이벤트 ID 나 사내 전용 로그 필드가 있으면 여기에 추가하면 된다.

/** 원본 필드 설명. 키 = `${source}:${path}` 또는 path */
export const FIELD_DOCS = {
  // Windows 이벤트 로그 (Fluent Bit winevtlog)
  'winevtlog:ProviderName': '이벤트를 기록한 구성요소(공급자) 이름',
  'winevtlog:ProviderGuid': '공급자 GUID',
  'winevtlog:Qualifiers': '이벤트 ID 상위 비트 (구형 공급자에서 사용)',
  'winevtlog:EventID': '이벤트 종류 번호. 같은 번호라도 공급자마다 의미가 다를 수 있음',
  'winevtlog:Version': '이벤트 정의 버전',
  'winevtlog:Level': '수준 — 1 심각, 2 오류, 3 경고, 4 정보, 5 상세 (0 은 정보로 처리)',
  'winevtlog:Task': '작업 범주 번호 (보안 로그: 12544 = 로그온 등)',
  'winevtlog:Opcode': '작업 코드',
  'winevtlog:Keywords': '분류 비트마스크. 보안 로그 감사 성공 0x8020…, 감사 실패 0x8010…',
  'winevtlog:TimeCreated': '이벤트 발생 시각 (PC 의 로컬 시간대 포함)',
  'winevtlog:EventRecordID': '채널 안에서의 레코드 일련번호 (누락 확인에 사용)',
  'winevtlog:ActivityID': '연관 작업 추적 ID',
  'winevtlog:RelatedActivityID': '상위 작업 추적 ID',
  'winevtlog:ProcessID': '이벤트를 기록한 프로세스 ID',
  'winevtlog:ThreadID': '이벤트를 기록한 스레드 ID',
  'winevtlog:Channel': '로그 채널 (System / Application / Security / …/Operational)',
  'winevtlog:Computer': 'PC 의 전체 이름(FQDN)',
  'winevtlog:UserID': '이벤트와 관련된 사용자 SID',
  'winevtlog:Message': 'Windows 가 사람이 읽을 수 있게 만든 메시지',
  'winevtlog:StringInserts': '메시지에 끼워 넣는 값 목록 (사용자명, IP 등). 순서는 이벤트 ID 마다 다름',
  // syslog
  'syslog:pri': 'PRI 값 = facility × 8 + severity',
  'syslog:time': '장비가 보낸 원래 시각 문자열',
  'syslog:host': '장비가 보낸 호스트명',
  'syslog:ident': '프로그램 이름 (sshd, nginx …)',
  'syslog:pid': '프로세스 ID',
  'syslog:message': '로그 본문',
  'syslog:source_ip': '로그를 보낸 장비의 IP (수신기가 추가)',
  'syslog:raw_message': '파싱 전 원문',
  // Windows EventData (에이전트 event_data_as_map) — 자주 보는 필드
  'winevtlog:EventData.TargetUserName': '대상 계정 (로그온한/실패한/변경된 계정)',
  'winevtlog:EventData.SubjectUserName': '행위자 계정 (작업을 한 계정)',
  'winevtlog:EventData.IpAddress': '접속해 온 IP (원본 네트워크 주소)',
  'winevtlog:EventData.LogonType': '로그온 유형 — 2 대화형, 3 네트워크, 4 배치, 5 서비스, 7 잠금 해제, 10 원격 데스크톱, 11 캐시',
  'winevtlog:EventData.Status': '실패 코드 (0xc000006d 잘못된 이름/암호, 0xc0000234 잠긴 계정 …)',
  'winevtlog:EventData.SubStatus': '세부 실패 코드 (0xc000006a 잘못된 암호, 0xc0000064 없는 사용자 …)',
  'winevtlog:EventData.ServiceName': '서비스 이름 (7045 서비스 설치)',
  'winevtlog:EventData.ImagePath': '서비스 실행 파일 경로',
  'winevtlog:EventData.ScriptBlockText': 'PowerShell 이 실행한 스크립트 본문 (4104)',
  'winevtlog:EventData.TargetSid': '대상 SID (S-1-5-32-544 = Administrators 그룹)',
  // IIS (서버가 해석해 raw.iis 에 추가)
  'iis:log': 'IIS 가 쓴 원래 한 줄 (W3C 형식)',
  'iis:iis.status': 'HTTP 상태 코드',
  'iis:iis.uri_stem': '요청 경로',
  'iis:iis.uri_query': '쿼리 문자열',
  'iis:iis.client_ip': '접속한 클라이언트 IP',
  'iis:iis.username': '인증된 사용자 (없으면 비어 있음)',
  'iis:iis.time_taken': '처리 시간 (ms)',
  'iis:iis.user_agent': '브라우저/프로그램 (User-Agent)',
  'iis:iis.win32_status': 'Windows 오류 코드 (0 = 정상)',
  // SQL Server ERRORLOG (raw.mssql)
  'mssql:log': 'ERRORLOG 원래 한 줄',
  'mssql:mssql.process': '기록한 프로세스 (Logon, spid51, Backup …)',
  'mssql:mssql.error': 'SQL Server 오류 번호',
  'mssql:mssql.severity': '심각도 (20 이상 치명적, 17~19 리소스·하드웨어, 11~16 사용자 오류)',
  'mssql:mssql.client': '로그인 시도한 클라이언트 IP',
  // 공통 (에이전트가 붙이는 필드)
  agent_host: '에이전트가 붙인 PC 이름 — 화면의 "PC" 기준값',
  log_source: '수집 입력 종류 (서버의 정규화기 선택에 사용)',
  log_channel: '파일 로그의 채널 이름 (에이전트 설정에서 지정)',
  date: '에이전트(Fluent Bit)가 레코드를 만든 시각 (UTC)',
  file: '로그 파일 경로',
};

export function fieldDoc(source, path) {
  return FIELD_DOCS[`${source}:${path}`] ?? FIELD_DOCS[path] ?? '';
}

/** 자주 보는 Windows 이벤트 ID (일반적인 의미) */
export const EVENT_DOCS = {
  4624: '로그온 성공',
  4625: '로그온 실패',
  4634: '로그오프',
  4647: '사용자 로그오프 시작',
  4648: '명시적 자격 증명으로 로그온',
  4672: '특수 권한 할당 (관리자급 로그온)',
  4688: '새 프로세스 생성',
  4697: '서비스 설치 (보안 로그)',
  4719: '감사 정책 변경',
  4720: '사용자 계정 생성',
  4722: '사용자 계정 활성화',
  4723: '암호 변경 시도',
  4724: '암호 재설정 시도',
  4725: '사용자 계정 비활성화',
  4726: '사용자 계정 삭제',
  4728: '전역 보안 그룹에 구성원 추가',
  4732: '로컬 보안 그룹에 구성원 추가',
  4740: '사용자 계정 잠금',
  4756: '유니버설 보안 그룹에 구성원 추가',
  4767: '사용자 계정 잠금 해제',
  4771: 'Kerberos 사전 인증 실패',
  4776: '자격 증명 확인 (NTLM)',
  1102: '보안 감사 로그 삭제됨',
  104: '이벤트 로그 삭제됨',
  41: '비정상 재부팅 (Kernel-Power)',
  51: '디스크 페이징 오류',
  129: '저장소 컨트롤러 재설정',
  153: '디스크 IO 재시도',
  1000: '응용 프로그램 오류 (충돌)',
  1001: 'Windows 오류 보고',
  1002: '응용 프로그램 응답 없음',
  1026: '.NET 런타임 오류',
  1074: '종료/재시작 요청',
  4104: 'PowerShell 스크립트 블록 실행',
  6005: '이벤트 로그 서비스 시작 (부팅)',
  6006: '이벤트 로그 서비스 중지 (종료)',
  6008: '예기치 않은 종료',
  7031: '서비스 비정상 종료 (복구 동작 수행)',
  7034: '서비스 예기치 않게 종료',
  7036: '서비스 상태 변경',
  7040: '서비스 시작 유형 변경',
  7045: '새 서비스 설치',
  10016: 'DCOM 권한 설정 오류',
  16384: '소프트웨어 보호 서비스 예약',
  21: '원격 데스크톱 세션 로그온 성공',
  24: '원격 데스크톱 세션 연결 끊김',
  1116: 'Defender 악성 코드 탐지',
  1117: 'Defender 악성 코드 조치',
  4698: '예약 작업 생성',
  4769: 'Kerberos 서비스 티켓 요청',
  // SQL Server (응용 프로그램 로그·ERRORLOG)
  18456: 'SQL Server 로그인 실패',
  18453: 'SQL Server 로그인 성공',
  18264: 'SQL Server 백업 완료',
  3041: 'SQL Server 백업 실패',
  9002: 'SQL Server 트랜잭션 로그 가득 참',
  823: 'SQL Server 디스크 I/O 오류',
  824: 'SQL Server 페이지 손상(체크섬)',
  825: 'SQL Server 읽기 재시도',
  701: 'SQL Server 메모리 부족',
  17137: 'SQL Server 데이터베이스 시작',
};

// IIS 는 event_id 에 HTTP 상태 코드가 들어간다
export const HTTP_STATUS = {
  200: 'OK', 201: '생성됨', 204: '내용 없음', 301: '영구 이동', 302: '임시 이동', 304: '변경 없음',
  400: '잘못된 요청', 401: '인증 필요', 403: '거부됨', 404: '페이지 없음', 405: '허용 안 되는 메서드', 429: '요청 과다',
  500: '서버 오류', 502: '게이트웨이 오류', 503: '서비스 불가', 504: '게이트웨이 시간 초과',
};

/** 이벤트 ID 설명. IIS 는 HTTP 상태 설명 */
export const eventDoc = (id, source) => {
  if (id == null) return '';
  if (source === 'iis') return HTTP_STATUS[id] ? `HTTP ${HTTP_STATUS[id]}` : 'HTTP 상태';
  return EVENT_DOCS[id] ?? '';
};
