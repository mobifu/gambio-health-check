"""
tests/test_build.py
===================
Unit-Tests für die Build- und Hilfsfunktionen in build.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import build


class TestVersionManagement:
    """Tests für die Versionierungslogik."""

    def test_get_current_version_success(self, tmp_path: Path):
        test_file = tmp_path / "app.py"
        test_file.write_text('SOFTWARE_VERSION = "2.4.1"\n', encoding="utf-8")
        assert build.get_current_version(test_file) == "2.4.1"

    def test_get_current_version_file_not_found(self, tmp_path: Path):
        missing_file = tmp_path / "does_not_exist.py"
        assert build.get_current_version(missing_file) == "1.0.0"

    def test_get_current_version_no_match(self, tmp_path: Path):
        test_file = tmp_path / "app.py"
        test_file.write_text("print('hello')\n", encoding="utf-8")
        assert build.get_current_version(test_file) == "1.0.0"

    def test_update_app_utils_existing_version(self, tmp_path: Path):
        test_file = tmp_path / "app.py"
        test_file.write_text('SOFTWARE_VERSION = "1.0.0"\nprint("run")\n', encoding="utf-8")
        success = build.update_app_utils("1.1.0", test_file)
        assert success is True
        assert 'SOFTWARE_VERSION = "1.1.0"' in test_file.read_text(encoding="utf-8")

    def test_update_app_utils_missing_version_adds_it(self, tmp_path: Path):
        test_file = tmp_path / "app.py"
        test_file.write_text('print("no version")\n', encoding="utf-8")
        success = build.update_app_utils("1.0.5", test_file)
        assert success is True
        content = test_file.read_text(encoding="utf-8")
        assert 'SOFTWARE_VERSION = "1.0.5"' in content

    def test_update_app_utils_non_existent_file(self, tmp_path: Path):
        missing_file = tmp_path / "missing.py"
        assert build.update_app_utils("1.0.0", missing_file) is False

    def test_update_readme_success(self, tmp_path: Path):
        readme = tmp_path / "README.md"
        readme.write_text("# Gambio Health Check v1.0.0\nInfo text\n", encoding="utf-8")
        success = build.update_readme("1.0.0", "1.0.1", readme)
        assert success is True
        assert "v1.0.1" in readme.read_text(encoding="utf-8")

    def test_update_readme_missing_file(self, tmp_path: Path):
        missing_readme = tmp_path / "README.md"
        assert build.update_readme("1.0.0", "1.0.1", missing_readme) is False


class TestFileHashingAndSnapshots:
    """Tests für SHA-256 Hashing und Snapshot-Verwaltung."""

    def test_calculate_file_hash(self, tmp_path: Path):
        sample_file = tmp_path / "sample.txt"
        sample_file.write_text("Hello World", encoding="utf-8")
        file_hash = build.calculate_file_hash(sample_file)
        assert file_hash is not None
        assert len(file_hash) == 64

    def test_calculate_file_hash_missing(self, tmp_path: Path):
        missing = tmp_path / "missing.bin"
        assert build.calculate_file_hash(missing) is None

    def test_snapshot_save_and_load(self, tmp_path: Path):
        snap_file = tmp_path / ".snapshot.json"
        data = {"app.py": "abc123hash", "ui/dialogs.py": "def456hash"}
        assert build.save_snapshot(data, snap_file) is True

        loaded = build.load_previous_snapshot(snap_file)
        assert loaded == data

    def test_load_previous_snapshot_missing_file(self, tmp_path: Path):
        snap_file = tmp_path / "missing.json"
        assert build.load_previous_snapshot(snap_file) == {}

    def test_get_current_snapshot(self, tmp_path: Path):
        (tmp_path / "test.py").write_text("code = 1", encoding="utf-8")
        sub = tmp_path / "ui"
        sub.mkdir()
        (sub / "view.py").write_text("view = True", encoding="utf-8")

        snapshot = build.get_current_snapshot(tmp_path)
        assert "test.py" in snapshot
        assert "ui/view.py" in snapshot


class TestBuildUtilities:
    """Tests für Dateisuch- und Bereinigungsroutinen."""

    def test_find_all_python_files(self, tmp_path: Path):
        (tmp_path / "root.py").write_text("#", encoding="utf-8")
        src = tmp_path / "src"
        src.mkdir()
        (src / "module.py").write_text("#", encoding="utf-8")
        venv = tmp_path / "venv"
        venv.mkdir()
        (venv / "ignore.py").write_text("#", encoding="utf-8")

        found = build.find_all_python_files(tmp_path)
        found_names = [Path(p).name for p in found]
        assert "root.py" in found_names
        assert "module.py" in found_names
        assert "ignore.py" not in found_names

    def test_create_pyinstaller_command_flags(self, tmp_path: Path):
        cmd = build.create_pyinstaller_command(
            main_script="app.py",
            app_name="TestApp",
            is_windowed=True,
            dist_dir=tmp_path / "dist",
            work_dir=tmp_path / "work",
        )
        assert "--name" in cmd
        assert "TestApp" in cmd
        assert "--windowed" in cmd
        assert "--clean" in cmd

        cmd_console = build.create_pyinstaller_command(
            main_script="app.py",
            app_name="TestApp",
            is_windowed=False,
            dist_dir=tmp_path / "dist",
            work_dir=tmp_path / "work",
        )
        assert "--console" in cmd_console

    def test_cleanup_build_files(self, tmp_path: Path):
        temp_dir = tmp_path / "build_temp_123456"
        temp_dir.mkdir()
        dist_dir = tmp_path / "dist_123456"
        dist_dir.mkdir()
        c_file = tmp_path / "test.c"
        c_file.write_text("// C", encoding="utf-8")

        build.cleanup_build_files(base_dir=tmp_path)

        assert not temp_dir.exists()
        assert not dist_dir.exists()
        assert not c_file.exists()

    def test_final_cleanup(self, tmp_path: Path):
        spec_file = tmp_path / "HealthCheckModul.spec"
        spec_file.write_text("# spec", encoding="utf-8")

        build.final_cleanup("HealthCheckModul", base_dir=tmp_path)
        assert not spec_file.exists()


class TestPackaging:
    """Tests für Packaging und Release-Generierung."""

    def test_create_final_package(self, tmp_path: Path, monkeypatch):
        dist_dir = tmp_path / "dist"
        app_dir = dist_dir / "HealthCheckModul"
        app_dir.mkdir(parents=True)
        (app_dir / "HealthCheckModul.exe").write_text("binary", encoding="utf-8")

        monkeypatch.setattr(build, "BASE_DIR", tmp_path)
        # Verhindern von subprocess explorer
        monkeypatch.setattr(build.platform, "system", lambda: "Linux")

        zip_result = build.create_final_package(dist_dir, "1.5.0")
        assert zip_result is not None
        assert zip_result.exists()
        assert zip_result.suffix == ".zip"
        assert "HealthCheckModul-v1.5.0" in zip_result.name

    def test_create_final_package_source_missing(self, tmp_path: Path):
        missing_dist = tmp_path / "non_existent"
        result = build.create_final_package(missing_dist, "1.0.0")
        assert result is None


class TestVersionCheckCLI:
    """Tests für perform_version_check und CLI Arguments."""

    def test_perform_version_check_non_interactive(self, tmp_path: Path, monkeypatch):
        app_file = tmp_path / "app.py"
        app_file.write_text('SOFTWARE_VERSION = "1.2.3"\n', encoding="utf-8")
        monkeypatch.setattr(build, "APP_UTILS_FILE", app_file)
        monkeypatch.setattr(build, "SNAPSHOT_FILE", tmp_path / ".snap.json")

        ver = build.perform_version_check(interactive=False, base_dir=tmp_path)
        assert ver == "1.2.3"

    def test_perform_version_check_explicit_version(self, tmp_path: Path, monkeypatch):
        app_file = tmp_path / "app.py"
        app_file.write_text('SOFTWARE_VERSION = "1.0.0"\n', encoding="utf-8")
        readme = tmp_path / "README.md"
        readme.write_text("Version: 1.0.0\n", encoding="utf-8")

        monkeypatch.setattr(build, "APP_UTILS_FILE", app_file)
        monkeypatch.setattr(build, "README_FILE", readme)
        monkeypatch.setattr(build, "SNAPSHOT_FILE", tmp_path / ".snap.json")

        ver = build.perform_version_check(
            interactive=False,
            explicit_version="2.0.0",
            base_dir=tmp_path,
        )
        assert ver == "2.0.0"
        assert 'SOFTWARE_VERSION = "2.0.0"' in app_file.read_text(encoding="utf-8")

    def test_parse_arguments(self):
        with patch.object(
            build.sys,
            "argv",
            ["build.py", "--skip-quality-gate", "--non-interactive", "--bump-version", "3.0.0"],
        ):
            args = build.parse_arguments()
            assert args.skip_quality_gate is True
            assert args.non_interactive is True
            assert args.bump_version == "3.0.0"
            assert args.clean_only is False
