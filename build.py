"""
build.py
========
Build-Automatisierung für das Gambio Health-Check-Modul.

Ablauf:
1. Quality Gate (Phasen 0 bis 3): Pre-Commit, pip-audit, bandit, pytest.
2. Optionaler Versions-Check & Update (app.py, README.md, Snapshot).
3. Bereinigung alter Build-Artefakte.
4. Cython-Kompilierung von Python-Modulen.
5. PyInstaller-Packaging für Desktop-Distribution.
6. Erstellung eines Release-ZIP-Pakets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# =============================================================================
# Logging-Konfiguration
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("build")

# =============================================================================
# Pfade & Konstanten
# =============================================================================
BASE_DIR = Path(__file__).resolve().parent
SOURCE_DIR = BASE_DIR

TIMESTAMP = datetime.now(tz=timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
BUILD_TEMP = BASE_DIR / f"build_temp_{TIMESTAMP}"
DIST_DIR = BASE_DIR / f"dist_{TIMESTAMP}"

APP_UTILS_FILE = BASE_DIR / "app.py"
README_FILE = BASE_DIR / "README.md"
HANDBUCH_FILE = BASE_DIR / "USER_MANUAL.md"
SNAPSHOT_FILE = BASE_DIR / ".file_snapshot.json"
PHP_COMPAT_FILE = BASE_DIR / "config" / "php_compat.json"

QG_SEPARATOR = "=" * 70

EXCLUDED_DIR_NAMES = {
    "venv",
    ".git",
    "__pycache__",
    "build",
    "dist",
    "tests",
    ".pytest_cache",
    ".ruff_cache",
}


# =============================================================================
# QUALITY GATE – Phasen 0 bis 3
# =============================================================================
def _run_check(label: str, command: list[str]) -> None:
    """Führt einen externen Prüfbefehl aus und bricht bei Fehler sofort ab."""
    print(f"\n{QG_SEPARATOR}")
    print(f"  QUALITY GATE | {label}")
    print(f"  Befehl : {' '.join(command)}")
    print(QG_SEPARATOR)

    try:
        result = subprocess.run(command)  # noqa: PLW1510
    except OSError as err:
        logger.error("Befehl konnte nicht gestartet werden: %s (%s)", command, err)
        sys.exit(1)

    if result.returncode != 0:
        print(f"\n{'!' * 70}")
        print(f"  [FEHLGESCHLAGEN] {label}")
        print(f"  Exit-Code: {result.returncode}")
        print("  Der Build wird ABGEBROCHEN. Behebe die obigen Probleme und")
        print("  starte den Build erneut.")
        print(f"{'!' * 70}\n")
        sys.exit(1)

    print(f"  [{label}] [OK]")


def phase0_pre_commit_hooks() -> None:
    """Phase 0: Pre-Commit Hooks via pre-commit."""
    _run_check(
        label="Phase 0/3 – Pre-Commit Hooks (pre-commit run --all-files)",
        command=[sys.executable, "-m", "pre_commit", "run", "--all-files"],
    )


def phase1_dependency_audit() -> None:
    """Phase 1: Dependency Audit via pip-audit."""
    _run_check(
        label="Phase 1/3 – Dependency Audit (pip-audit)",
        command=[sys.executable, "-m", "pip_audit"],
    )


def phase2_static_security_analysis() -> None:
    """Phase 2: Statische Code-Analyse via bandit."""
    _run_check(
        label="Phase 2/3 – Statische Code-Analyse (bandit)",
        command=[
            sys.executable,
            "-m",
            "bandit",
            "-r",
            ".",
            "-lll",
            "-iii",
            "--exclude",
            "./venv,./tests,./.git,./build_temp_*,./dist_*",
            "--skip",
            "B402,B321,B501",
        ],
    )


def phase3_unit_tests() -> None:
    """Phase 3: Unit-Tests via pytest."""
    _run_check(
        label="Phase 3/3 – Unit-Tests (pytest)",
        command=[sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
    )


def run_quality_gate() -> None:
    """Führt alle Quality-Gate-Phasen sequentiell aus."""
    print(f"\n{'#' * 70}")
    print("#  QUALITY GATE GESTARTET")
    print("#  Alle Phasen müssen 'OK' sein, damit der Build fortgesetzt wird.")
    print(f"#{'#' * 69}\n")

    phase0_pre_commit_hooks()
    phase1_dependency_audit()
    phase2_static_security_analysis()
    phase3_unit_tests()

    print(f"\n{QG_SEPARATOR}")
    print("  QUALITY GATE | ✓ ALLE PHASEN BESTANDEN – Build wird gestartet.")
    print(f"{QG_SEPARATOR}\n")


# =============================================================================
# Versionierung & File Hashing
# =============================================================================
def get_current_version(app_file: Path | str = APP_UTILS_FILE) -> str:
    """Liest die aktuelle Version aus der angegebenen App-Datei aus (Standard: 1.0.0)."""
    target = Path(app_file).resolve()
    if not target.is_file():
        return "1.0.0"

    try:
        content = target.read_text(encoding="utf-8")
        match = re.search(r'SOFTWARE_VERSION\s*=\s*"([^"]+)"', content)
        if match:
            return match.group(1)
    except OSError as err:
        logger.warning("Version konnte nicht aus %s gelesen werden: %s", target, err)

    return "1.0.0"


def update_app_utils(new_version: str, app_file: Path | str = APP_UTILS_FILE) -> bool:
    """Aktualisiert SOFTWARE_VERSION in app.py."""
    target = Path(app_file).resolve()
    if not target.is_file():
        logger.error("Datei %s existiert nicht.", target)
        return False

    try:
        content = target.read_text(encoding="utf-8")
        if "SOFTWARE_VERSION" in content:
            new_content = re.sub(
                r'SOFTWARE_VERSION\s*=\s*"[^"]+"',
                f'SOFTWARE_VERSION = "{new_version}"',
                content,
            )
        else:
            new_content = f'SOFTWARE_VERSION = "{new_version}"\n' + content

        target.write_text(new_content, encoding="utf-8")
        print(f"Version in {target.name} aktualisiert: {new_version}")
        return True
    except OSError as err:
        logger.error("Fehler beim Aktualisieren von %s: %s", target, err)
        return False


def update_readme(old_version: str, new_version: str, readme_file: Path | str = README_FILE) -> bool:
    """Aktualisiert die Versionsangabe in der README-Datei."""
    target = Path(readme_file).resolve()
    if not target.is_file():
        return False

    try:
        content = target.read_text(encoding="utf-8")
        if old_version in content:
            new_content = content.replace(old_version, new_version, 1)
            target.write_text(new_content, encoding="utf-8")
            print(f"Version in {target.name} aktualisiert.")
            return True
    except OSError as err:
        logger.warning("Fehler beim Aktualisieren von %s: %s", target, err)
    return False


def calculate_file_hash(filepath: Path | str) -> str | None:
    """Berechnet den SHA-256-Hash einer Datei in speichereffizienten Chunks."""
    target = Path(filepath).resolve()
    if not target.is_file():
        return None

    hasher = hashlib.sha256()
    try:
        with target.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as err:
        logger.warning("Hash-Berechnung fehlgeschlagen für %s: %s", target, err)
        return None


def get_current_snapshot(base_dir: Path | str = BASE_DIR) -> dict[str, str]:
    """Erstellt einen Hash-Snapshot aller relevanten Projekt-Python-Dateien."""
    base = Path(base_dir).resolve()
    snapshot: dict[str, str] = {}
    patterns = ["*.py", "ui/*.py", "security/*.py", "config/*.py"]

    for pattern in patterns:
        for p in base.glob(pattern):
            if not p.is_file():
                continue
            # Build-Skripte und Caches ausschließen
            if p.name in ("build.py",) or any(part in EXCLUDED_DIR_NAMES for part in p.parts):
                continue
            try:
                rel_path = p.relative_to(base).as_posix()
                file_hash = calculate_file_hash(p)
                if file_hash:
                    snapshot[rel_path] = file_hash
            except ValueError:
                continue

    return snapshot


def load_previous_snapshot(snapshot_file: Path | str = SNAPSHOT_FILE) -> dict[str, str]:
    """Lädt den vorherigen Snapshot aus der JSON-Datei."""
    target = Path(snapshot_file).resolve()
    if target.is_file():
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as err:
            logger.warning("Snapshot-Datei %s beschädigt: %s", target, err)
    return {}


def save_snapshot(snapshot: dict[str, str], snapshot_file: Path | str = SNAPSHOT_FILE) -> bool:
    """Speichert den Snapshot in der angegebenen Datei."""
    target = Path(snapshot_file).resolve()
    try:
        target.write_text(json.dumps(snapshot, indent=4), encoding="utf-8")
        return True
    except OSError as err:
        logger.error("Fehler beim Speichern des Snapshots nach %s: %s", target, err)
        return False


def perform_version_check(
    interactive: bool = True,
    explicit_version: str | None = None,
    base_dir: Path | str = BASE_DIR,
) -> str:
    """Prüft auf Code-Änderungen und führt bei Bedarf ein Versionsupdate durch."""
    print("\n--- Prüfung auf Code-Änderungen ---")
    current_version = get_current_version(APP_UTILS_FILE)

    if explicit_version:
        update_app_utils(explicit_version, APP_UTILS_FILE)
        update_readme(current_version, explicit_version, README_FILE)
        save_snapshot(get_current_snapshot(base_dir))
        return explicit_version

    prev_snapshot = load_previous_snapshot(SNAPSHOT_FILE)
    curr_snapshot = get_current_snapshot(base_dir)

    detected_changes = False
    for filename, current_hash in curr_snapshot.items():
        if filename not in prev_snapshot or prev_snapshot[filename] != current_hash:
            detected_changes = True
            break

    suggested = "1.0.1"
    try:
        parts = [int(p) for p in current_version.split(".")]
        if len(parts) == 3:
            suggested = f"{parts[0]}.{parts[1]}.{parts[2] + 1}"
    except ValueError:
        pass

    if not detected_changes:
        print("Keine Änderungen erkannt.")
        if not interactive:
            return current_version
        ans = input(f"Aktuelle Version ist {current_version}. Trotzdem erhöhen? (j/n): ").strip().lower()
        if ans != "j":
            return current_version

    if not interactive:
        # Im automatisierten Modus Version beibehalten, falls nicht explizit gesetzt
        return current_version

    new_ver = input(f"Neue Version eingeben [{suggested}]: ").strip() or suggested
    ans = input(f"Version {current_version} -> {new_ver} aktualisieren? (j/n): ").strip().lower()
    if ans == "j":
        update_app_utils(new_ver, APP_UTILS_FILE)
        update_readme(current_version, new_ver, README_FILE)
        save_snapshot(curr_snapshot, SNAPSHOT_FILE)
        print("Version aktualisiert. Build wird fortgesetzt...\n")
        return new_ver

    return current_version


# =============================================================================
# Build & Kompilierungs-Routinen
# =============================================================================
def find_all_python_files(directory: Path | str = SOURCE_DIR) -> list[str]:
    """Sucht rekursiv alle kompilierbaren Python-Dateien unter Ausschluss von Temp- und Testordnern."""
    base = Path(directory).resolve()
    excluded_dirs = EXCLUDED_DIR_NAMES.union({BUILD_TEMP.name, DIST_DIR.name})

    python_files: list[str] = []
    for file_path in base.rglob("*.py"):
        rel_parts = file_path.relative_to(base).parts[:-1]
        if any(part in excluded_dirs or part.startswith(("build_temp_", "dist_")) for part in rel_parts):
            continue
        python_files.append(str(file_path))

    return sorted(python_files)


def create_cython_extensions(python_files: list[str | Path]) -> list[Any]:
    """Erstellt Cython-Extension-Objekte für die übergebenen Python-Dateien."""
    try:
        from setuptools import Extension
    except ImportError as err:
        logger.error("setuptools fehlt für Cython-Extensions: %s", err)
        raise

    extensions: list[Any] = []
    base = BASE_DIR

    for py_file in python_files:
        path = Path(py_file).resolve()
        try:
            rel_path = path.relative_to(base)
        except ValueError:
            rel_path = path

        module_parts = list(rel_path.parent.parts) + [rel_path.stem]
        module_name = ".".join(p for p in module_parts if p and p != ".")
        extensions.append(Extension(module_name, [str(path)]))

    return extensions


def kill_process_if_running(process_name: str) -> None:
    """Beendet unter Windows blockierende laufende Prozesse vor dem Build."""
    if platform.system() != "Windows":
        return

    process_name_os = f"{process_name}.exe" if not process_name.endswith(".exe") else process_name
    command = ["taskkill", "/F", "/IM", process_name_os]

    logger.info("Prüfe, ob '%s' noch läuft und beende es bei Bedarf...", process_name_os)
    try:
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    except OSError as err:
        logger.debug("Fehler beim Beenden von %s: %s", process_name_os, err)


def cleanup_build_files(base_dir: Path | str = BASE_DIR) -> None:
    """Bereinigt alte temporäre Build- und Dist-Verzeichnisse sowie Kompilate."""
    base = Path(base_dir).resolve()
    logger.info("Suche nach alten Build-Verzeichnissen...")

    # Verzeichnisse löschen
    for item in base.iterdir():
        if item.is_dir() and (item.name.startswith(("build_temp_", "dist_")) or item.name == "build"):
            shutil.rmtree(item, ignore_errors=True)

    # Veraltete Kompilate (.c, .pyd, .so) löschen
    compiled_exts = {".c", ".pyd", ".so"}
    for p in base.rglob("*"):
        if p.is_file() and p.suffix in compiled_exts:
            rel_parts = p.relative_to(base).parts[:-1]
            if any(part in EXCLUDED_DIR_NAMES or part.startswith(("build_temp_", "dist_")) for part in rel_parts):
                continue
            try:
                p.unlink(missing_ok=True)
            except OSError as err:
                logger.debug("Konnte Datei %s nicht entfernen: %s", p, err)


def final_cleanup(app_name: str, base_dir: Path | str = BASE_DIR) -> None:
    """Bereinigt temporäre Build-Verzeichnisse und Spezifikationsdateien nach dem Build."""
    base = Path(base_dir).resolve()
    logger.info("Starte finales Aufräumen für '%s'...", app_name)

    if BUILD_TEMP.exists():
        shutil.rmtree(BUILD_TEMP, ignore_errors=True)

    build_dir = base / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)

    spec_file = base / f"{app_name}.spec"
    if spec_file.exists():
        try:
            spec_file.unlink()
        except OSError as err:
            logger.debug("Spezifikationsdatei %s konnte nicht gelöscht werden: %s", spec_file, err)

    compiled_ext = ".pyd" if platform.system() == "Windows" else ".so"
    compiled_exts = {".c", compiled_ext}
    for p in base.rglob("*"):
        if p.is_file() and p.suffix in compiled_exts:
            rel_parts = p.relative_to(base).parts[:-1]
            if any(part in EXCLUDED_DIR_NAMES or part.startswith(("build_temp_", "dist_")) for part in rel_parts):
                continue
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass


def create_pyinstaller_command(
    main_script: str,
    app_name: str,
    is_windowed: bool,
    dist_dir: Path | str,
    work_dir: Path | str = BUILD_TEMP,
) -> list[str]:
    """Baut den plattformunabhängigen PyInstaller-Aufrufbefehl zusammen."""
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        app_name,
        "--clean",
        "--log-level",
        "INFO",
        str(main_script),
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        "--exclude-module",
        "profiles",
        "--exclude-module",
        "tests",
    ]

    path_sep = ";" if platform.system() == "Windows" else ":"

    if HANDBUCH_FILE.is_file():
        command.extend(["--add-data", f"{HANDBUCH_FILE}{path_sep}."])

    if PHP_COMPAT_FILE.is_file():
        command.extend(["--add-data", f"{PHP_COMPAT_FILE}{path_sep}config"])

    if is_windowed:
        command.append("--windowed")
    else:
        command.append("--console")

    return command


def run_build_process(
    build_targets: list[dict[str, Any]],
    dist_dir: Path | str = DIST_DIR,
    work_dir: Path | str = BUILD_TEMP,
) -> None:
    """Führt den gesamten Build inkl. Cython-Kompilierung und PyInstaller-Packaging durch."""
    try:
        from setuptools import setup
    except ImportError:
        logger.error("setuptools fehlt. Bitte mit 'pip install setuptools' installieren.")
        sys.exit(1)

    target_dist = Path(dist_dir).resolve()
    target_work = Path(work_dir).resolve()

    try:
        for target in build_targets:
            kill_process_if_running(target["app_name"])

        cleanup_build_files()

        target_work.mkdir(parents=True, exist_ok=True)
        target_dist.mkdir(parents=True, exist_ok=True)

        python_files = find_all_python_files(SOURCE_DIR)

        script_name = Path(__file__).name
        excluded_from_cython = {script_name, "app.py", "pytest.ini"}

        filtered_files: list[str] = []
        for f in python_files:
            p = Path(f)
            fname = p.name
            # app.py und UI-Dateien vom Cython-Compile ausschließen um Probleme mit PySide6 zu vermeiden
            if fname in excluded_from_cython or "ui" in p.parts:
                logger.info("Überspringe Cython-Kompilierung für: %s", f)
                continue
            filtered_files.append(f)

        if filtered_files:
            logger.info("Erstelle Cython-Erweiterungen für %d Dateien...", len(filtered_files))
            extensions = create_cython_extensions(filtered_files)

            logger.info("Starte Cython-Kompilierung...")
            setup(
                name="health_check_modules",
                ext_modules=extensions,
                script_args=["build_ext", "--inplace"],
                zip_safe=False,
            )

        for target in build_targets:
            main_script = target["main_script"]
            app_name = target["app_name"]
            is_windowed = target.get("windowed", True)

            logger.info("--- Starte PyInstaller für '%s' ---", app_name)
            pyinstaller_command = create_pyinstaller_command(
                main_script=main_script,
                app_name=app_name,
                is_windowed=is_windowed,
                dist_dir=target_dist,
                work_dir=target_work,
            )
            subprocess.check_call(pyinstaller_command)

        for target in build_targets:
            final_cleanup(target["app_name"])

        logger.info("Build abgeschlossen! Ausführbare Dateien befinden sich in '%s'.", target_dist)

    except Exception:
        logger.exception("Build fehlgeschlagen.")
        sys.exit(1)


def create_final_package(dist_dir: Path | str, version: str) -> Path | None:
    """Erstellt das finale Release-Verzeichnis und ein komprimiertes ZIP-Archiv."""
    dist_path = Path(dist_dir).resolve()
    package_name = f"HealthCheckModul-v{version}"
    target_path = BASE_DIR / package_name
    source_path = dist_path / "HealthCheckModul"

    if not source_path.exists():
        logger.warning("Source-Pfad %s existiert nicht, ZIP wird nicht erstellt.", source_path)
        return None

    logger.info("Erstelle finales Release-Paket: %s", target_path)

    if target_path.exists():
        shutil.rmtree(target_path, ignore_errors=True)

    try:
        shutil.copytree(source_path, target_path)
        if HANDBUCH_FILE.is_file():
            shutil.copy2(HANDBUCH_FILE, target_path)

        zip_filename_str = shutil.make_archive(
            str(target_path),
            "zip",
            root_dir=str(target_path.parent),
            base_dir=target_path.name,
        )
        zip_path = Path(zip_filename_str)
        logger.info("ZIP-Archiv erfolgreich erstellt: %s", zip_path)

        if platform.system() == "Windows":
            try:
                subprocess.run(["explorer", f"/select,{zip_path}"], check=False)
            except OSError as err:
                logger.debug("Explorer konnte nicht geöffnet werden: %s", err)

        return zip_path

    except OSError as e:
        logger.error("Fehler beim Erstellen des Release-Ordners: %s", e)
        return None


# =============================================================================
# CLI & Hauptprogramm
# =============================================================================
def parse_arguments() -> argparse.Namespace:
    """Parsed die CLI-Optionen für den Build."""
    parser = argparse.ArgumentParser(description="Gambio Health Check Modul - Automatisierter Build & Release-Packer")
    parser.add_argument(
        "--skip-quality-gate",
        action="store_true",
        help="Überspringt das Quality Gate (nur für lokale Tests/Debugging).",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Deaktiviert interaktive Benutzereingaben für Versionsabfragen.",
    )
    parser.add_argument(
        "--bump-version",
        type=str,
        default=None,
        help="Setzt eine explizite Versionsnummer und aktualisiert app.py & README.md.",
    )
    parser.add_argument(
        "--clean-only",
        action="store_true",
        help="Bereinigt nur temporäre Build-Verzeichnisse und beendet das Skript.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    if args.clean_only:
        cleanup_build_files()
        print("Bereinigung abgeschlossen.")
        return

    # 1. Quality Gate
    if not args.skip_quality_gate:
        run_quality_gate()
    else:
        logger.warning("Quality Gate wurde via --skip-quality-gate übersprungen!")

    # 2. Versionierungs-Check
    current_version = perform_version_check(
        interactive=not args.non_interactive,
        explicit_version=args.bump_version,
    )

    # 3. Build-Targets & Durchführung
    targets_to_build = [
        {"main_script": "app.py", "app_name": "HealthCheckModul", "windowed": True},
    ]

    run_build_process(targets_to_build, dist_dir=DIST_DIR, work_dir=BUILD_TEMP)

    # 4. Finales Packaging
    if current_version:
        create_final_package(DIST_DIR, current_version)


if __name__ == "__main__":
    main()
