"""
tests/test_network_service.py
=============================
Umfassende Unittests für ui.network_service (NetworkService und RemoteFileService).
"""

from __future__ import annotations

import ftplib
import io
import stat
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from security.exceptions import InsecureFTPError
from ui.network_service import NetworkService, RemoteFileService


class TestNetworkServiceParams:
    """Tests für Parameternormalisierung und Profilparsing."""

    def test_parse_connection_params_defaults(self) -> None:
        profile = {
            "host": "https://ftp.myshop.com/",
            "username": "admin",
            "password": "secret",
        }
        params = NetworkService.parse_connection_params(profile)
        assert params["protocol"] == "FTP"
        assert params["host"] == "ftp.myshop.com"
        assert params["port"] == 21
        assert params["username"] == "admin"
        assert params["password"] == "secret"
        assert params["remote_path"] == ""
        assert params["timeout"] == 25
        assert params["allow_insecure_ftp"] is False

    def test_parse_connection_params_sftp_and_insecure_flag(self) -> None:
        profile = {
            "protocol": "SFTP",
            "host": "ssh.myshop.com",
            "port": "2222",
            "username": "sshuser",
            "password": "sshpassword",
            "remote_path": "/var/www/html",
            "timeout": "40",
            "allow_insecure_ftp": True,
        }
        params = NetworkService.parse_connection_params(profile)
        assert params["protocol"] == "SFTP"
        assert params["host"] == "ssh.myshop.com"
        assert params["port"] == 2222
        assert params["remote_path"] == "/var/www/html"
        assert params["timeout"] == 40
        assert params["allow_insecure_ftp"] is True


class TestNetworkServiceCreateConnection:
    """Tests für den Verbindungsaufbau und die TLS-Absicherung."""

    @patch("ftplib.FTP_TLS")
    def test_create_connection_ftp_tls_success(self, mock_ftp_tls_class: MagicMock) -> None:
        mock_ftp = MagicMock()
        mock_ftp.nlst.return_value = ["system", "GXEngine", "index.php"]
        mock_ftp_tls_class.return_value = mock_ftp

        logs: list[tuple[str, str]] = []
        progress: list[str] = []

        profile = {
            "protocol": "FTP",
            "host": "localhost",
            "port": 21,
            "username": "user",
            "password": "pwd",
            "remote_path": "/shop",
        }

        conn, files = NetworkService.create_remote_connection(
            profile,
            log_callback=lambda m, s: logs.append((m, s)),
            progress_callback=progress.append,
        )

        assert conn == mock_ftp
        assert files == ["system", "GXEngine", "index.php"]
        mock_ftp.connect.assert_called_once_with("localhost", 21, timeout=25)
        mock_ftp.auth.assert_called_once()
        mock_ftp.login.assert_called_once_with("user", "pwd")
        mock_ftp.prot_p.assert_called_once()
        mock_ftp.cwd.assert_called_once_with("/shop")
        assert any("Explizites TLS aktiviert (FTPS)" in m[0] for m in logs)

    @patch("ftplib.FTP_TLS", side_effect=Exception("TLS Handshake Timeout"))
    @patch("ftplib.FTP")
    def test_create_connection_ftp_tls_fails_insecure_blocked_by_default(
        self, mock_ftp_class: MagicMock, mock_ftp_tls_class: MagicMock
    ) -> None:
        profile = {
            "protocol": "FTP",
            "host": "insecure.shop.de",
            "port": 21,
            "username": "user",
            "password": "pwd",
            "allow_insecure_ftp": False,
        }

        logs: list[tuple[str, str]] = []
        conn, files = NetworkService.create_remote_connection(
            profile,
            log_callback=lambda m, s: logs.append((m, s)),
        )

        assert conn is None
        assert files == []
        # ftplib.FTP darf NICHT aufgerufen worden sein!
        mock_ftp_class.assert_not_called()
        assert any("standardmäßig verworfen" in m[0] for m in logs if m[1] == "error")

    @patch("ftplib.FTP_TLS", side_effect=Exception("Server supports plain FTP only"))
    @patch("ftplib.FTP")
    def test_create_connection_ftp_tls_fails_insecure_allowed_explicitly(
        self, mock_ftp_class: MagicMock, mock_ftp_tls_class: MagicMock
    ) -> None:
        mock_ftp = MagicMock()
        mock_ftp.nlst.return_value = ["index.php"]
        mock_ftp_class.return_value = mock_ftp

        profile = {
            "protocol": "FTP",
            "host": "legacy.shop.de",
            "port": 21,
            "username": "legacyuser",
            "password": "legacypwd",
            "allow_insecure_ftp": True,
        }

        logs: list[tuple[str, str]] = []
        conn, files = NetworkService.create_remote_connection(
            profile,
            log_callback=lambda m, s: logs.append((m, s)),
        )

        assert conn == mock_ftp
        assert files == ["index.php"]
        mock_ftp_class.assert_called_once()
        mock_ftp.connect.assert_called_once_with("legacy.shop.de", 21, timeout=25)
        mock_ftp.login.assert_called_once_with("legacyuser", "legacypwd")
        assert any("WARNUNG: FTPS fehlgeschlagen" in m[0] for m in logs if m[1] == "warn")

    @patch("ui.network_service.paramiko")
    def test_create_connection_sftp_success(self, mock_paramiko: MagicMock) -> None:
        mock_ssh = MagicMock()
        mock_sftp = MagicMock()
        mock_sftp.listdir.return_value = ["system", "templates"]
        mock_ssh.open_sftp.return_value = mock_sftp
        mock_paramiko.SSHClient.return_value = mock_ssh
        mock_paramiko.AutoAddPolicy = MagicMock()

        profile = {
            "protocol": "SFTP",
            "host": "sftp.shop.de",
            "port": 22,
            "username": "sftpuser",
            "password": "pwd",
            "remote_path": "/var/www/gambio",
        }

        conn, files = NetworkService.create_remote_connection(profile)
        assert conn == mock_sftp
        assert files == ["system", "templates"]
        mock_ssh.connect.assert_called_once_with("sftp.shop.de", 22, "sftpuser", "pwd", timeout=10)
        mock_sftp.chdir.assert_called_once_with("/var/www/gambio")

    @patch("ui.network_service.paramiko", None)
    def test_create_connection_sftp_missing_paramiko(self) -> None:
        profile = {"protocol": "SFTP", "host": "sftp.shop.de", "username": "user", "password": "pwd"}
        logs: list[tuple[str, str]] = []
        conn, files = NetworkService.create_remote_connection(profile, log_callback=lambda m, s: logs.append((m, s)))
        assert conn is None
        assert files == []
        assert any("paramiko fehlt" in m[0] or "nicht installiert" in m[0] for m in logs)

    def test_create_connection_unsupported_protocol(self) -> None:
        profile = {"protocol": "GOPHER", "host": "gopher.shop.de"}
        conn, files = NetworkService.create_remote_connection(profile)
        assert conn is None
        assert files == []


class TestNetworkServiceTestConnection:
    """Tests für test_connection."""

    def test_test_connection_https_skips(self) -> None:
        res = NetworkService.test_connection({"protocol": "HTTPS", "host": "myshop.de", "username": "u"})
        assert res["success"] is False
        assert "HTTPS wird übersprungen" in res["error"]

    def test_test_connection_missing_host_or_user(self) -> None:
        res = NetworkService.test_connection({"protocol": "FTP", "host": "", "username": ""})
        assert res["success"] is False
        assert "Bitte Host und Benutzername ausfüllen" in res["error"]

    @patch("ftplib.FTP_TLS")
    def test_test_connection_ftp_success_with_version(self, mock_ftp_tls_class: MagicMock) -> None:
        mock_ftp = MagicMock()
        mock_ftp.nlst.return_value = ["system", "GXEngine", "templates"]

        def fake_retrbinary(cmd: str, callback: Any) -> None:
            if "main.conf.php" in cmd:
                content = b"<?php define('foo', 'bar'); $conf = ['PROJECT_VERSION' => 'v4.9.2.0'];"
                callback(content)

        mock_ftp.retrbinary.side_effect = fake_retrbinary
        mock_ftp_tls_class.return_value = mock_ftp

        res = NetworkService.test_connection(
            {
                "protocol": "FTP",
                "host": "myshop.de",
                "username": "user",
                "password": "pwd",
                "remote_path": "/html",
            }
        )

        assert res["success"] is True
        assert res["shop_detected"] is True
        assert res["version"] == "v4.9.2.0"
        assert res["tls_used"] is True
        assert res["insecure_fallback"] is False
        mock_ftp.quit.assert_called_once()

    @patch("ftplib.FTP_TLS", side_effect=Exception("No FTPS support"))
    @patch("ftplib.FTP")
    def test_test_connection_ftp_tls_fails_blocked_without_permission(
        self, mock_ftp_class: MagicMock, mock_ftp_tls_class: MagicMock
    ) -> None:
        res = NetworkService.test_connection(
            {
                "protocol": "FTP",
                "host": "myshop.de",
                "username": "user",
                "password": "pwd",
                "allow_insecure_ftp": False,
            }
        )
        assert res["success"] is False
        assert "standardmäßig deaktiviert" in res["error"]
        mock_ftp_class.assert_not_called()

    @patch("ftplib.FTP_TLS", side_effect=Exception("No FTPS support"))
    @patch("ftplib.FTP")
    def test_test_connection_ftp_tls_fails_allowed_with_permission(
        self, mock_ftp_class: MagicMock, mock_ftp_tls_class: MagicMock
    ) -> None:
        mock_ftp = MagicMock()
        mock_ftp.nlst.return_value = ["system", "templates"]
        mock_ftp_class.return_value = mock_ftp

        res = NetworkService.test_connection(
            {
                "protocol": "FTP",
                "host": "myshop.de",
                "username": "user",
                "password": "pwd",
                "allow_insecure_ftp": True,
            }
        )
        assert res["success"] is True
        assert res["insecure_fallback"] is True
        assert res["tls_used"] is False
        mock_ftp_class.assert_called_once()


class TestNetworkServiceClose:
    """Tests für das sichere Schließen von Verbindungen."""

    def test_close_connection_ftp(self) -> None:
        mock_ftp = MagicMock(spec=ftplib.FTP)
        NetworkService.close_connection(mock_ftp)
        mock_ftp.quit.assert_called_once()

    def test_close_connection_ftp_quit_error_calls_close(self) -> None:
        mock_ftp = MagicMock(spec=ftplib.FTP)
        mock_ftp.quit.side_effect = Exception("Broken pipe")
        NetworkService.close_connection(mock_ftp)
        mock_ftp.close.assert_called_once()

    def test_close_connection_sftp_tuple(self) -> None:
        mock_ssh = MagicMock()
        mock_sftp = MagicMock()
        NetworkService.close_connection((mock_ssh, mock_sftp))
        mock_sftp.close.assert_called_once()
        mock_ssh.close.assert_called_once()

    def test_close_connection_none_does_not_raise(self) -> None:
        NetworkService.close_connection(None)


class TestRemoteFileService:
    """Tests für rekursive Remote-Dateioperationen."""

    def test_delete_remote_item_file(self) -> None:
        mock_conn = MagicMock(spec=ftplib.FTP)
        success, item_type = RemoteFileService.delete_remote_item(mock_conn, "test.php")
        assert success is True
        assert item_type == "Datei"
        mock_conn.delete.assert_called_once_with("test.php")

    def test_delete_remote_item_folder(self) -> None:
        mock_conn = MagicMock(spec=ftplib.FTP)
        mock_conn.nlst.return_value = []
        success, item_type = RemoteFileService.delete_remote_item(mock_conn, "old_dir")
        assert success is True
        assert item_type == "Ordner"
        mock_conn.rmd.assert_called_once_with("old_dir")

    def test_clean_remote_cache_ftp(self) -> None:
        mock_conn = MagicMock(spec=ftplib.FTP)
        mock_conn.nlst.return_value = [
            "cache/.htaccess",
            "cache/index.html",
            "cache/query_123.tmp",
            "cache/session_abc.tmp",
        ]
        deleted = RemoteFileService.clean_remote_cache(mock_conn, cache_dir="cache")
        assert deleted == 2
        mock_conn.delete.assert_has_calls([call("cache/query_123.tmp"), call("cache/session_abc.tmp")], any_order=True)

    def test_scan_bak_files_ftp(self) -> None:
        mock_conn = MagicMock(spec=ftplib.FTP)
        mock_conn.mlsd.return_value = [
            ("index.php", {"type": "file"}),
            ("configure.php.bak", {"type": "file"}),
            ("images", {"type": "dir"}),  # should be skipped
        ]
        found = RemoteFileService.scan_bak_files(mock_conn)
        assert found == ["configure.php.bak"]
