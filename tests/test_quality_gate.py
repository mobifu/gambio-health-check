"""
tests/test_quality_gate.py
==========================
Unit-Tests für die Quality-Gate-Phasen in build.py.

Testet:
- _run_check: Erfolg (Exit 0) und Abbruch (Exit != 0)
- phase1_dependency_audit: Aufruf korrekt
- phase2_static_security_analysis: Aufruf korrekt (bandit-Parameter)
- phase3_unit_tests: Aufruf korrekt (pytest tests/)
- run_quality_gate: Gesamtablauf, Abbruch bei erster fehlgeschlagener Phase
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Hilfsfunktion: Importiert build.py als Modul, ohne __main__ auszuführen.
# Wir müssen setuptools & Cython mocken, damit der Import auch ohne
# installierte Pakete funktioniert.
# ---------------------------------------------------------------------------


def _import_build() -> types.ModuleType:
    """Importiert build.py sicher mit gemockten Abhängigkeiten."""
    # Fake-Module für optionale Build-Deps bereitstellen
    for name in ("setuptools", "Cython"):
        if name not in sys.modules:
            fake = types.ModuleType(name)
            if name == "setuptools":

                class _DummyExtension:
                    def __init__(self, name: str, sources: list[str], *args: Any, **kwargs: Any) -> None:
                        self.name = name
                        self.sources = sources

                def _dummy_setup(**kw: Any) -> None:
                    pass

                setattr(fake, "Extension", _DummyExtension)
                setattr(fake, "setup", _dummy_setup)
            sys.modules[name] = fake

    build_path = Path(__file__).parent.parent / "build.py"
    spec = importlib.util.spec_from_file_location("build", build_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Konnte ModuleSpec für {build_path} nicht laden.")

    module = importlib.util.module_from_spec(spec)
    # __name__ != "__main__"  ➜ if-Block wird NICHT ausgeführt
    spec.loader.exec_module(module)
    return module


build = _import_build()


# ---------------------------------------------------------------------------
# Tests für _run_check
# ---------------------------------------------------------------------------


class TestRunCheck:
    """Testet die interne Hilfsfunktion _run_check."""

    def test_success_does_not_exit(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Bei Exit-Code 0 darf sys.exit NICHT aufgerufen werden."""
        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            build._run_check("TestLabel", ["echo", "ok"])

        mock_run.assert_called_once_with(["echo", "ok"])

    def test_failure_calls_sys_exit_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        """_run_check muss sys.exit(1) aufrufen, wenn der Exit-Code != 0 ist."""
        fake_result = MagicMock()
        fake_result.returncode = 1

        with patch("subprocess.run", return_value=fake_result), pytest.raises(SystemExit) as exc_info:
            build._run_check("Label", ["cmd"])

        assert exc_info.value.code == 1

    def test_failure_message_contains_label(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Im Fehlerfall muss das Label in der Ausgabe enthalten sein."""
        fake_result = MagicMock()
        fake_result.returncode = 1

        with patch("subprocess.run", return_value=fake_result), pytest.raises(SystemExit):
            build._run_check("MeinLabel", ["cmd"])

        captured = capsys.readouterr()
        assert "MeinLabel" in captured.out

    def test_failure_message_contains_exit_code(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Im Fehlerfall muss der Exit-Code in der Ausgabe enthalten sein."""
        fake_result = MagicMock()
        fake_result.returncode = 42

        with patch("subprocess.run", return_value=fake_result), pytest.raises(SystemExit):
            build._run_check("Label", ["cmd"])

        captured = capsys.readouterr()
        assert "42" in captured.out


# ---------------------------------------------------------------------------
# Tests für die einzelnen Phasen
# ---------------------------------------------------------------------------


class TestPhase1DependencyAudit:
    """Phase 1: pip-audit"""

    def test_calls_pip_audit_module(self, capsys: pytest.CaptureFixture[str]) -> None:
        """pip-audit muss über sys.executable -m pip_audit aufgerufen werden."""
        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            build.phase1_dependency_audit()

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == sys.executable
        assert "-m" in cmd
        assert "pip_audit" in cmd

    def test_exits_on_vulnerability_found(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Bei gefundenen Schwachstellen (Exit != 0) muss der Build abbrechen."""
        fake_result = MagicMock()
        fake_result.returncode = 1

        with patch("subprocess.run", return_value=fake_result), pytest.raises(SystemExit) as exc_info:
            build.phase1_dependency_audit()

        assert exc_info.value.code == 1


class TestPhase2StaticAnalysis:
    """Phase 2: bandit"""

    def test_calls_bandit_with_correct_flags(self, capsys: pytest.CaptureFixture[str]) -> None:
        """bandit muss mit -r . -lll -iii und --skip aufgerufen werden."""
        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            build.phase2_static_security_analysis()

        cmd = mock_run.call_args[0][0]
        assert "bandit" in cmd
        assert "-r" in cmd
        assert "-lll" in cmd
        assert "-iii" in cmd
        assert "--skip" in cmd
        assert "B402,B321,B501" in cmd

    def test_excludes_venv_and_tests(self, capsys: pytest.CaptureFixture[str]) -> None:
        """venv und tests müssen aus dem bandit-Scan ausgeschlossen werden."""
        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            build.phase2_static_security_analysis()

        cmd = mock_run.call_args[0][0]
        exclude_index = cmd.index("--exclude")
        exclude_value = cmd[exclude_index + 1]
        assert "venv" in exclude_value
        assert "tests" in exclude_value

    def test_exits_on_critical_finding(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Bei kritischem bandit-Fund muss der Build abbrechen."""
        fake_result = MagicMock()
        fake_result.returncode = 1

        with patch("subprocess.run", return_value=fake_result), pytest.raises(SystemExit) as exc_info:
            build.phase2_static_security_analysis()

        assert exc_info.value.code == 1


class TestPhase3UnitTests:
    """Phase 3: pytest"""

    def test_calls_pytest_on_tests_folder(self, capsys: pytest.CaptureFixture[str]) -> None:
        """pytest muss auf den Ordner tests/ angewendet werden."""
        fake_result = MagicMock()
        fake_result.returncode = 0

        with patch("subprocess.run", return_value=fake_result) as mock_run:
            build.phase3_unit_tests()

        cmd = mock_run.call_args[0][0]
        assert "pytest" in cmd
        assert "tests/" in cmd

    def test_exits_on_test_failure(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Bei fehlgeschlagenem Test muss der Build abbrechen."""
        fake_result = MagicMock()
        fake_result.returncode = 1

        with patch("subprocess.run", return_value=fake_result), pytest.raises(SystemExit) as exc_info:
            build.phase3_unit_tests()

        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Tests für run_quality_gate (Gesamtablauf)
# ---------------------------------------------------------------------------


class TestRunQualityGate:
    """Testet den gesamten Gate-Ablauf."""

    def test_all_phases_called_in_order_on_success(self) -> None:
        """Bei Erfolg müssen alle Phasen aufgerufen werden."""
        call_order: list[str] = []

        def fake_phase0() -> None:
            call_order.append("phase0")

        def fake_phase1() -> None:
            call_order.append("phase1")

        def fake_phase2() -> None:
            call_order.append("phase2")

        def fake_phase3() -> None:
            call_order.append("phase3")

        with (
            patch.object(build, "phase0_pre_commit_hooks", fake_phase0),
            patch.object(build, "phase1_dependency_audit", fake_phase1),
            patch.object(build, "phase2_static_security_analysis", fake_phase2),
            patch.object(build, "phase3_unit_tests", fake_phase3),
        ):
            build.run_quality_gate()

        assert call_order == ["phase0", "phase1", "phase2", "phase3"]

    def test_aborts_after_phase1_failure(self) -> None:
        """Schlägt Phase 1 fehl, dürfen Phase 2 und 3 NICHT ausgeführt werden."""
        call_order: list[str] = []

        def fake_phase0() -> None:
            call_order.append("phase0")

        def fail_phase1() -> None:
            call_order.append("phase1")
            sys.exit(1)

        def fake_phase2() -> None:
            call_order.append("phase2")

        def fake_phase3() -> None:
            call_order.append("phase3")

        with (
            patch.object(build, "phase0_pre_commit_hooks", fake_phase0),
            patch.object(build, "phase1_dependency_audit", fail_phase1),
            patch.object(build, "phase2_static_security_analysis", fake_phase2),
            patch.object(build, "phase3_unit_tests", fake_phase3),
            pytest.raises(SystemExit) as exc_info,
        ):
            build.run_quality_gate()

        assert exc_info.value.code == 1
        assert "phase2" not in call_order
        assert "phase3" not in call_order

    def test_aborts_after_phase2_failure(self) -> None:
        """Schlägt Phase 2 fehl, darf Phase 3 NICHT ausgeführt werden."""
        call_order: list[str] = []

        def fake_phase0() -> None:
            call_order.append("phase0")

        def fake_phase1() -> None:
            call_order.append("phase1")

        def fail_phase2() -> None:
            call_order.append("phase2")
            sys.exit(1)

        def fake_phase3() -> None:
            call_order.append("phase3")

        with (
            patch.object(build, "phase0_pre_commit_hooks", fake_phase0),
            patch.object(build, "phase1_dependency_audit", fake_phase1),
            patch.object(build, "phase2_static_security_analysis", fail_phase2),
            patch.object(build, "phase3_unit_tests", fake_phase3),
            pytest.raises(SystemExit) as exc_info,
        ):
            build.run_quality_gate()

        assert exc_info.value.code == 1
        assert "phase3" not in call_order

    def test_success_prints_all_green_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Bei Erfolg muss eine 'ALLE PHASEN BESTANDEN'-Meldung erscheinen."""
        with (
            patch.object(build, "phase0_pre_commit_hooks"),
            patch.object(build, "phase1_dependency_audit"),
            patch.object(build, "phase2_static_security_analysis"),
            patch.object(build, "phase3_unit_tests"),
        ):
            build.run_quality_gate()

        captured = capsys.readouterr()
        assert "ALLE PHASEN BESTANDEN" in captured.out
