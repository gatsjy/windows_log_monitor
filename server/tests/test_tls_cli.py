"""인증서 명령 tls-init / tls-renew / tls-status (B-06, ADR-036). DB 없이 돈다."""

from __future__ import annotations

import stat
import sys

import pytest

from app import cli, tlsutil


def _cli(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["app.cli", *args])
    try:
        cli.main()
        code = 0
    except SystemExit as exc:
        code = exc.code
    return code, capsys.readouterr().out


def test_init_renew_status(tmp_path, monkeypatch, capsys):
    out, ca_dir = tmp_path / "tls", tmp_path / "tls-ca"
    code, text = _cli(monkeypatch, capsys, "tls-init", "--out", str(out), "--ca-dir", str(ca_dir),
                      "--name", "logmon.corp.local", "--ip", "10.0.0.10")
    assert code == 0 and "logmon.corp.local" in text and "오프라인" in text and "[오류]" not in text
    mode = lambda p: stat.S_IMODE(p.stat().st_mode)
    assert mode(ca_dir / "ca.key") == 0o600 and mode(out / "server.key") == 0o600 and mode(out / "ca.crt") == 0o644
    assert not (out / "ca.key").exists()   # CA 개인키는 api 가 읽는 폴더에 두지 않는다
    leaf, ca_in_chain = tlsutil.load_certs(str(out / "server.crt"))
    assert ca_in_chain == tlsutil.load_certs(str(out / "ca.crt"))[0]
    assert not list(out.glob(".*"))   # 임시 파일이 남지 않음

    # 두 번째 init 은 CA 를 덮지 않는다
    code, _ = _cli(monkeypatch, capsys, "tls-init", "--out", str(out), "--ca-dir", str(ca_dir), "--name", "x.local")
    assert "이미 CA 가 있습니다" in str(code)
    # CA 개인키를 오프라인으로 옮긴 뒤(tls-ca/ 없음) 다시 init 해도 배포된 CA 를 덮지 않는다
    code, _ = _cli(monkeypatch, capsys, "tls-init", "--out", str(out), "--ca-dir", str(tmp_path / "moved-away"),
                   "--name", "logmon.corp.local")
    assert "이미 배포된 CA" in str(code) and not (tmp_path / "moved-away" / "ca.key").exists()
    # CA 키를 tls/ 에 두려 하면 거부
    code, _ = _cli(monkeypatch, capsys, "tls-init", "--out", str(out), "--ca-dir", str(out), "--name", "x.local")
    assert "다른 곳" in str(code)

    # 갱신: 이름 유지 + 추가, 같은 CA, 새 키
    old_key = (out / "server.key").read_bytes()
    code, text = _cli(monkeypatch, capsys, "tls-renew", "--dir", str(out), "--ca-dir", str(ca_dir),
                      "--name", "web.logmon.corp.local")
    assert code == 0 and "재배포 없음" in text
    leaf2 = tlsutil.load_certs(str(out / "server.crt"))[0]
    assert tlsutil.san_names(leaf2) == (["logmon.corp.local", "web.logmon.corp.local"], ["10.0.0.10"])
    assert leaf2.serial_number != leaf.serial_number and (out / "server.key").read_bytes() != old_key
    # 이름 제한 밖은 거부 (새 CA 필요)
    code, _ = _cli(monkeypatch, capsys, "tls-renew", "--dir", str(out), "--ca-dir", str(ca_dir), "--name", "other.local")
    assert "이름 제한 밖" in str(code)

    # 상태: 정상이면 0
    code, text = _cli(monkeypatch, capsys, "tls-status", "--dir", str(out))
    assert code == 0 and "D-" in text and "서버 인증서와 이어짐" in text


def test_renew_refuses_other_ca(tmp_path, monkeypatch, capsys):
    out = tmp_path / "tls"
    _cli(monkeypatch, capsys, "tls-init", "--out", str(out), "--ca-dir", str(tmp_path / "a"), "--name", "a.local")
    _cli(monkeypatch, capsys, "tls-init", "--out", str(tmp_path / "other"), "--ca-dir", str(tmp_path / "b"),
         "--name", "a.local")
    code, _ = _cli(monkeypatch, capsys, "tls-renew", "--dir", str(out), "--ca-dir", str(tmp_path / "b"))
    assert "다른 CA" in str(code)
    # 상태가 '다른 CA' 면 종료 코드 1
    (out / "ca.crt").write_bytes((tmp_path / "b" / "ca.crt").read_bytes())
    code, text = _cli(monkeypatch, capsys, "tls-status", "--dir", str(out))
    assert code == 1 and "[오류]" in text


@pytest.mark.parametrize("args", [["--name", "10.0.0.1"], ["--name", "*.corp.local"], []])
def test_init_rejects_bad_names(tmp_path, monkeypatch, capsys, args):
    code, _ = _cli(monkeypatch, capsys, "tls-init", "--out", str(tmp_path / "t"), "--ca-dir", str(tmp_path / "c"), *args)
    assert str(code).startswith("오류:") and not (tmp_path / "c" / "ca.key").exists()
