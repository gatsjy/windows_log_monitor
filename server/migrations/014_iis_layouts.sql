-- B-08 (ADR-037): IIS '#Fields:' 머리줄 = 파일별 열 순서.
-- 에이전트 tail 은 db 위치에서 이어 읽어 재시작 뒤에도 머리줄을 다시 보내지 않는다 → 서버가 기억해야 하는데,
-- 프로세스 메모리에만 두면 서버를 다시 시작한 뒤 사용자 지정 열 순서를 기본 순서로 잘못 읽었다.
CREATE TABLE IF NOT EXISTS iis_layouts (
    host    TEXT        NOT NULL,              -- agent_host (normalizers.base.pick_host)
    file    TEXT        NOT NULL,              -- 에이전트가 붙인 file(path_key) 값 그대로
    dir     TEXT        NOT NULL,              -- file 의 폴더(…\W3SVC<n>) — 새 파일의 머리줄을 못 받았을 때 같은 폴더의 최신 열 순서를 쓴다
    fields  TEXT        NOT NULL,              -- '#Fields:' 뒤 이름들 (공백 하나로)
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, file)
);
CREATE INDEX IF NOT EXISTS iis_layouts_dir_idx ON iis_layouts (host, dir, seen_at DESC);
