import os
import shutil
import subprocess
import sys

# =============================================================================
# QUALITY GATE – Sicherheits- & Qualitätsprüfungen
# Alle drei Phasen müssen erfolgreich durchlaufen, bevor der Build startet.
# =============================================================================

QG_SEPARATOR = "=" * 70


def _run_check(label: str, command: list[str]) -> None:
    """Führt einen externen Prüfbefehl aus und bricht bei Fehler sofort ab."""
    print(f"\n{QG_SEPARATOR}")
    print(f"  QUALITY GATE | {label}")
    print(f"  Befehl : {' '.join(command)}")
    print(QG_SEPARATOR)

    result = subprocess.run(command)

    if result.returncode != 0:
        print(f"\n{'!' * 70}")
        print(f"  [FEHLGESCHLAGEN] {label}")
        print(f"  Exit-Code: {result.returncode}")
        print("  Der Build wird ABGEBROCHEN. Behebe die obigen Probleme und")
        print("  starte den Build erneut.")
        print(f"{'!' * 70}\n")
        sys.exit(1)

    print(f"  [{label}] [OK]")


def phase1_dependency_audit() -> None:
    """Phase 1: Dependency Audit via pip-audit.

    Prüft alle installierten Pakete auf bekannte CVEs.
    Schlägt fehl, wenn verwundbare Abhängigkeiten gefunden werden.
    """
    _run_check(
        label="Phase 1/3 – Dependency Audit (pip-audit)",
        command=[sys.executable, "-m", "pip_audit"],
    )


def phase2_static_security_analysis() -> None:
    """Phase 2: Statische Code-Analyse via bandit.

    Nur kritische Sicherheitsprobleme (Severity HIGH + Confidence HIGH)
    blockieren den Build. Parameter -lll bedeutet: Level HIGH Severity,
    -iii bedeutet: Level HIGH Confidence.
    """
    _run_check(
        label="Phase 2/3 – Statische Code-Analyse (bandit)",
        # -r .        : rekursiv ab Stammverzeichnis
        # -lll        : nur HIGH-Severity-Funde melden
        # -iii        : nur HIGH-Confidence-Funde als Fehler werten
        # --exclude   : Build-Artefakte, venv und Tests ausschließen
        # --skip      : Ticket-GAMBIO-402: B402, B321 (FTP Fallback für alte Shops)
        #             : Ticket-GAMBIO-501: B501 (Self-Signed SSL bei defekten Shop-Certs)
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


def phase0_pre_commit_hooks() -> None:
    """Phase 0: Pre-Commit Hooks via pre-commit.

    Führt alle konfigurierten Pre-Commit-Hooks (Formatierung, Ruff, Bandit, Pytest) aus.
    """
    _run_check(
        label="Phase 0/3 – Pre-Commit Hooks (pre-commit run --all-files)",
        command=[sys.executable, "-m", "pre_commit", "run", "--all-files"],
    )


def phase3_unit_tests() -> None:
    """Phase 3: Unit-Tests via pytest.

    Führt die gesamte Test-Suite aus (inkl. Krypto/Verschlüsselungs-Tests).
    Ein einzelner fehlgeschlagener Test blockiert den Build.
    """
    _run_check(
        label="Phase 3/3 – Unit-Tests (pytest)",
        command=[sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
    )


def run_quality_gate() -> None:
    """Führt alle Quality-Gate-Phasen sequentiell aus.

    Wird eine Phase nicht bestanden, endet das Skript sofort mit Exit-Code 1.
    Erst nach bestandenem Gate darf der eigentliche Build starten.
    """
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


try:
    from setuptools import Extension, setup
except ImportError:
    print("\nKRITISCHER FEHLER: Das Python-Modul 'setuptools' fehlt.")
    print("Bitte installieren Sie es mit: pip install setuptools\n")
    sys.exit(1)

try:
    import Cython
except ImportError:
    print("\nKRITISCHER FEHLER: Das Python-Modul 'Cython' fehlt.")
    print("Bitte installieren Sie es mit: pip install Cython\n")
    sys.exit(1)

import logging
import platform
import time
from datetime import datetime
import re
import json
import hashlib
import glob

# Konfiguration
SOURCE_DIR = "."  # Stammverzeichnis des Python-Codes

# NEU: Dynamische Verzeichnisnamen mit Zeitstempel
TIMESTAMP = datetime.now().strftime("%Y%m%d-%H%M%S")
BUILD_TEMP = f"build_temp_{TIMESTAMP}"
DIST_DIR = f"dist_{TIMESTAMP}"

# --- Versionierung & Changelog Konfiguration ---
APP_UTILS_FILE = "app.py"  # Im Health-Check Projekt nehmen wir app.py
README_FILE = "README.md"
CHANGELOG_FILE = "CHANGELOG.md"
HANDBUCH_FILE = "USER_MANUAL.md"
UNRELEASED_FILE = "UNRELEASED.md"
SNAPSHOT_FILE = ".file_snapshot.json"

# Dateinamen auf das neue Projekt anpassen
FILE_MAPPING = {
    "app.py": "Anwendungs-Startpunkt",
    "ui/main_window.py": "Hauptfenster GUI",
    "ui/dialogs.py": "Dialoge GUI",
    "security/master_password.py": "Master-Passwort Logik",
    "config/config_manager.py": "Konfigurations-Logik",
    "logging_config.py": "Logging Konfiguration",
}


# --- Versionierungs-Funktionen ---
def get_current_version():
    """Liest die aktuelle Version aus app.py. Wenn nicht gefunden, gibt es 1.0.0 zurück."""
    if not os.path.exists(APP_UTILS_FILE):
        return "1.0.0"
    with open(APP_UTILS_FILE, "r", encoding="utf-8") as f:
        content = f.read()
        match = re.search(r'SOFTWARE_VERSION\s*=\s*"([^"]+)"', content)
        if match:
            return match.group(1)
    return "1.0.0"


def update_app_utils(new_version):
    with open(APP_UTILS_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    if "SOFTWARE_VERSION" in content:
        new_content = re.sub(
            r'SOFTWARE_VERSION\s*=\s*"[^"]+"',
            f'SOFTWARE_VERSION = "{new_version}"',
            content,
        )
    else:
        new_content = f'SOFTWARE_VERSION = "{new_version}"\n' + content
    with open(APP_UTILS_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"Version in {APP_UTILS_FILE} aktualisiert.")


def update_readme(old_version, new_version):
    if not os.path.exists(README_FILE):
        return
    with open(README_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    if old_version in content:
        new_content = content.replace(old_version, new_version, 1)
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"Version in {README_FILE} aktualisiert.")


def calculate_file_hash(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None


def get_current_snapshot():
    snapshot = {}
    for pattern in ["*.py", "ui/*.py", "security/*.py", "config/*.py"]:
        for filepath in glob.glob(pattern):
            normalized_path = filepath.replace("\\", "/")
            if normalized_path == os.path.basename(__file__):
                continue  # Build-Skript ausschließen
            snapshot[normalized_path] = calculate_file_hash(filepath)
    return snapshot


def load_previous_snapshot():
    if os.path.exists(SNAPSHOT_FILE):
        with open(SNAPSHOT_FILE, "r") as f:
            return json.load(f)
    return {}


def save_snapshot(snapshot):
    with open(SNAPSHOT_FILE, "w") as f:
        json.dump(snapshot, f, indent=4)


def perform_version_check():
    """Führt die Prüfung auf Änderungen durch und fragt nach Update."""
    print("\n--- Prüfung auf Code-Änderungen ---")
    current_version = get_current_version()

    prev_snapshot = load_previous_snapshot()
    curr_snapshot = get_current_snapshot()
    detected_changes = False

    for filename, current_hash in curr_snapshot.items():
        if filename not in prev_snapshot or prev_snapshot[filename] != current_hash:
            detected_changes = True
            break

    if not detected_changes:
        print("Keine Änderungen erkannt.")
        if input(f"Aktuelle Version ist {current_version}. Trotzdem erhöhen? (j/n): ").lower() != "j":
            return

    try:
        parts = [int(p) for p in current_version.split(".")]
        suggested = f"{parts[0]}.{parts[1]}.{parts[2] + 1}" if len(parts) == 3 else "1.0.1"
    except ValueError:
        suggested = "1.0.1"

    new_ver = input(f"Neue Version eingeben [{suggested}]: ").strip() or suggested
    if new_ver and input(f"Version {current_version} -> {new_ver} aktualisieren? (j/n): ").lower() == "j":
        update_app_utils(new_ver)
        update_readme(current_version, new_ver)
        save_snapshot(curr_snapshot)
        print("Version aktualisiert. Build wird fortgesetzt...\n")


# Logging konfigurieren
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def find_all_python_files(directory):
    python_files = []
    excluded_dirs = {BUILD_TEMP, DIST_DIR, "venv", ".git", "__pycache__", "tests"}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))
    return python_files


def create_cython_extensions(python_files):
    extensions = []
    for py_file in python_files:
        normalized_path = os.path.normpath(py_file)
        if normalized_path.startswith("." + os.sep):
            normalized_path = normalized_path[2:]
        module_name = os.path.splitext(normalized_path)[0].replace(os.sep, ".")
        extensions.append(Extension(module_name, [py_file]))
    return extensions


def kill_process_if_running(process_name):
    system = platform.system()
    if system == "Windows":
        process_name_os = f"{process_name}.exe"
        command = ["taskkill", "/F", "/IM", process_name_os]
    else:
        return

    logging.info(f"Prüfe, ob '{process_name_os}' noch läuft und beende es bei Bedarf...")
    try:
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    except Exception:
        pass


def cleanup_build_files():
    logging.info("Suche nach alten Build-Verzeichnissen...")
    for item in os.listdir(SOURCE_DIR):
        if os.path.isdir(item) and (item.startswith("build_temp_") or item.startswith("dist_")):
            shutil.rmtree(item, ignore_errors=True)

    if os.path.exists("build"):
        shutil.rmtree("build", ignore_errors=True)

    excluded_cleanup_dirs = {
        "venv",
        ".git",
        "__pycache__",
        "build",
        BUILD_TEMP,
        DIST_DIR,
    }
    for root, dirs, files in os.walk(SOURCE_DIR):
        dirs[:] = [d for d in dirs if d not in excluded_cleanup_dirs]
        for file in files:
            if file.endswith((".c", ".pyd", ".so")):
                try:
                    os.remove(os.path.join(root, file))
                except Exception:
                    pass


def create_pyinstaller_command(main_script, app_name, is_windowed, dist_dir):
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        app_name,
        "--clean",
        "--log-level",
        "INFO",
        main_script,
        "--distpath",
        dist_dir,
        "--workpath",
        BUILD_TEMP,
        "--exclude-module",
        "profiles",
        "--exclude-module",
        "tests",
    ]

    if os.path.exists(HANDBUCH_FILE):
        command.extend(["--add-data", f"{HANDBUCH_FILE};."])

    php_compat_path = os.path.join("config", "php_compat.json")
    if os.path.exists(php_compat_path):
        command.extend(["--add-data", f"{php_compat_path};config"])

    if is_windowed:
        command.append("--windowed")
    else:
        command.append("--console")

    return command


def final_cleanup(app_name):
    logging.info("Starte finales Aufräumen...")
    if os.path.exists(BUILD_TEMP):
        shutil.rmtree(BUILD_TEMP, ignore_errors=True)
    if os.path.exists("build"):
        shutil.rmtree("build", ignore_errors=True)

    spec_file = f"{app_name}.spec"
    if os.path.exists(spec_file):
        os.remove(spec_file)

    excluded_cleanup_dirs = {
        BUILD_TEMP,
        DIST_DIR,
        "venv",
        ".git",
        "__pycache__",
        "build",
    }
    for root, dirs, files in os.walk(SOURCE_DIR):
        dirs[:] = [d for d in dirs if d not in excluded_cleanup_dirs]
        compiled_ext = ".pyd" if platform.system() == "Windows" else ".so"
        for file in files:
            if file.endswith((".c", compiled_ext)):
                try:
                    os.remove(os.path.join(root, file))
                except Exception:
                    pass


def run_build_process(build_targets):
    try:
        for target in build_targets:
            kill_process_if_running(target["app_name"])

        cleanup_build_files()

        dist_dir = DIST_DIR
        os.makedirs(BUILD_TEMP, exist_ok=True)
        os.makedirs(dist_dir, exist_ok=True)

        python_files = find_all_python_files(SOURCE_DIR)

        script_name = os.path.basename(__file__)
        # app.py darf nicht cythonisiert werden, da es der Entry Point ist
        excluded_from_cython = {script_name, "app.py", "pytest.ini"}

        filtered_files = []
        for f in python_files:
            fname = os.path.basename(f)
            # GUI/UI oft nicht cythonisieren um Bugs zu vermeiden,
            # aber hier im Health-Check Projekt versuchen wir alles bis auf app.py
            if fname in excluded_from_cython or "ui\\" in f or "ui/" in f:
                logging.info(f"Überspringe Cython-Kompilierung für: {f}")
                continue
            filtered_files.append(f)

        python_files = filtered_files

        if python_files:
            logging.info("Erstelle Cython-Erweiterungen...")
            extensions = create_cython_extensions(python_files)

            logging.info("Starte Cython-Kompilierung...")
            setup(
                name="health_check_modules",
                ext_modules=extensions,
                script_args=["build_ext", "--inplace"],
                zip_safe=False,
            )

        for target in build_targets:
            main_script = target["main_script"]
            app_name = target["app_name"]
            is_windowed = target["windowed"]

            logging.info(f"--- Starte PyInstaller für '{app_name}' ---")
            pyinstaller_command = create_pyinstaller_command(main_script, app_name, is_windowed, dist_dir)
            subprocess.check_call(pyinstaller_command)

        for target in build_targets:
            final_cleanup(target["app_name"])

        logging.info(f"Build abgeschlossen! Ausführbare Dateien befinden sich in '{dist_dir}'.")

    except Exception as e:
        logging.error(f"Build fehlgeschlagen: {e}")


def create_final_package(dist_dir, version):
    package_name = f"HealthCheckModul-v{version}"
    target_path = os.path.abspath(package_name)
    source_path = os.path.join(dist_dir, "HealthCheckModul")

    if not os.path.exists(source_path):
        return

    logging.info(f"Erstelle finales Release-Paket: {target_path}")

    if os.path.exists(target_path):
        shutil.rmtree(target_path, ignore_errors=True)

    try:
        shutil.copytree(source_path, target_path)
        if os.path.exists(HANDBUCH_FILE):
            shutil.copy2(HANDBUCH_FILE, target_path)

        zip_filename = shutil.make_archive(
            target_path,
            "zip",
            root_dir=os.path.dirname(target_path),
            base_dir=os.path.basename(target_path),
        )
        logging.info(f"ZIP-Archiv erfolgreich erstellt: {zip_filename}")

        if platform.system() == "Windows":
            subprocess.run(["explorer", "/select,", zip_filename])

    except OSError as e:
        logging.error(f"Fehler beim Erstellen des Release-Ordners: {e}")


if __name__ == "__main__":
    # --- Quality Gate -----------------------------------------------------------
    # Prüft Abhängigkeiten, Code-Sicherheit und Unit-Tests BEVOR der Build startet.
    # Schlägt eine Phase fehl, wird sofort mit Exit-Code 1 abgebrochen.
    run_quality_gate()

    # --- Cython-Abhängigkeiten sicherstellen ------------------------------------
    try:
        import cython  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "cython", "setuptools"])

    # --- Versions-Check & Build -------------------------------------------------
    perform_version_check()
    current_version = get_current_version()

    targets_to_build = [
        {"main_script": "app.py", "app_name": "HealthCheckModul", "windowed": True},
    ]

    run_build_process(targets_to_build)

    if current_version:
        create_final_package(DIST_DIR, current_version)
