# Gambio Health Check

Ein leistungsstarkes, lokal ausgeführtes Desktop-Werkzeug zur Überprüfung der Systemintegrität und Update-Vorbereitung für Gambio-Shopsysteme.

## 1. Projektübersicht

Der **Gambio Health Check** unterstützt Shopbetreiber, Agenturen und Entwickler dabei, Gambio-Installationen proaktiv zu überwachen und reibungslose Update-Prozesse zu gewährleisten.

Im Gegensatz zu Cloud-basierten Lösungen arbeitet dieses Tool vollständig **lokal**. Sensible Zugangsdaten werden ausschließlich verschlüsselt auf Ihrem System gespeichert und niemals an externe Server übertragen.

### Hauptzweck
*   **Prävention:** Erkennung von Inkonsistenzen in der Dateistruktur oder Datenbank vor dem Auftreten von Fehlern.
*   **Update-Sicherheit:** Analyse der Systemvoraussetzungen und Kompatibilitäten für anstehende Gambio-Updates.
*   **Datenschutz:** Sichere Verwaltung von Server-Profilen und Passwörtern.

## 2. Features

*   **Health-Check:** Modulare Prüfung von Dateiberechtigungen, Server-Konfigurationen, PHP/MySQL-Versionen und Datenbank-Integrität.
*   **Datei-Integritätsprüfung (Baseline Hashing):** Erstellt rekursiv Hashes aller Shop-Dateien, um unbefugte Änderungen (z.B. Malware) zu erkennen. Folgende Ausnahmen werden beim Hashing automatisch ignoriert:
    * *Verzeichnisse:* `images`, `cache`, `logs`, `export`, `import`, `backups`, `uploads`, `node_modules`, `.git`
    * *Dateitypen:* `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.svg`
    * *Individuelle Ausnahmen:* Über die Einstellungen können benutzerdefinierte Dateien und Ordner/Pfade vom Scan ausgeschlossen werden.
*   **Performance-Optimiert:** Auch bei sehr großen Shops mit 50.000+ Dateien bleibt das Programm durch optimierte I/O-Zugriffe und reduzierte UI-Updates beim Baseline-Erstellen und Hash-Check voll reaktionsfähig.
*   **Update-Analyse:** Tiefenprüfung der Kompatibilität für bereitstehende Updates (PHP, MySQL, Shop-Version) inkl. Prüfung auf Vollständigkeit.
*   **Plugin-Kompatibilitäts-Scan:** Analysiert das `/GXModules`-Verzeichnis über einen Abstract Syntax Tree (AST) Scanner auf Drittanbieter-Module mit veraltetem Code (z. B. alte PHP 4-Konstruktoren, entfernte PHP 8-Funktionen). Core-Module können ausgeklammert werden. Falls `phply` nicht installiert oder nicht korrekt initialisiert ist, wechselt der Scanner automatisch in den robusten Regex-Fallback-Modus.
    > **Wichtig:** Ein Fund bedeutet nicht zwingend einen fatalen Fehler. Es kann sich um ungenutzten (toten) Code handeln. Durch den AST-basierten Scan werden False Positives (z. B. Methoden mit identischem Namen wie veraltete Funktionen) jedoch bereits weitestgehend eliminiert. Falls eine Datei jedoch Syntaxfehler enthält und nicht analysiert werden kann, wird auf einen Text-Scan zurückgegriffen.
*   **Backup-Datei Scanner:** Asynchrone Suche nach potenziell unsicheren `.bak`-Dateien auf dem Server, um alte Code-Stände oder Konfigurationen aufzuspüren und sicher zu entfernen.
*   **Logfile Scanner & Cleanup:** Analysiert Logfiles auf kritische Fehler (z.B. "ERROR", "FATAL") mit Exportfunktion für den Gambio-Support und bereinigt alte Logfiles automatisch nach konfigurierbarem Alter.
*   **Altlasten-Bereinigung:** Intelligente Analyse und sicheres Löschen verwaister Dateien **und Ordner** aus alten Update-Paketen. Der Check erkennt jetzt zuverlässig sowohl Dateien mit Extension als auch Ordner ohne Extension in `to_delete.php` und prüft deren Existenz über FTP/SFTP (mit NLST-Fallback für Ordner).
    > **Sicherheitsmechanismus (Backup-Zwang):** Um versehentliche Datenverluste zu vermeiden, müssen Anwender über eine Checkbox explizit bestätigen, dass ein aktuelles Backup (Dateien und Datenbank) angefertigt wurde, bevor Löschfunktionen freigeschaltet werden.
*   **Whitelist-System:** Konfigurierbare Liste für Dateien, die niemals automatisch gelöscht werden dürfen (z.B. `paypal3.php`).
*   **Verschlüsselte Konfiguration & Profil-Verwaltung:** Speicherung von Shop-Profilen in einer gesicherten AES-verschlüsselten Datei. Die getroffene Profil-Auswahl bleibt auch bei Neustarts der Anwendung und Seitenwechseln (z. B. zur Konfiguration) dauerhaft erhalten.
*   **Moderne GUI:** Benutzerfreundliche Oberfläche basierend auf **PySide6**.
*   **Security-Logging:** Intelligenter `SensitiveFilter`, der verhindert, dass Passwörter oder Tokens in Log-Dateien auftauchen.
*   **Plugin-Architektur:** Einfache Erweiterbarkeit für individuelle Prüfroutinen.

## 3. Sicherheit

Sicherheit steht bei diesem Tool an erster Stelle:
*   **Schlüsselableitung:** Verwendung von **PBKDF2-HMAC-SHA256** mit 600.000 Iterationen zur Erzeugung kryptographischer Schlüssel aus dem Masterpasswort.
*   **Verschlüsselung:** Einsatz von **Fernet (AES-128 im CBC-Modus mit HMAC-Authentifizierung)** für die Daten-Verschlüsselung.
*   **Brute-Force-Schutz:** Exponentielle Zeitverzögerung bei falschen Passworteingaben.
*   **Kein Klartext:** Passwörter werden niemals im Klartext auf der Festplatte gespeichert oder geloggt.
*   **Session-Lock:** Automatischer Schutzmechanismus, der den Zugriff nach Inaktivität sperrt.

## 4. Installation

### Voraussetzungen
*   **Python 3.10** oder höher.
*   **pip** (Python Package Installer).

### Abhängigkeiten installieren
Klonen Sie das Repository und installieren Sie die benötigten Bibliotheken:

```bash
pip install -r requirements.txt
```

### Anwendung starten
Starten Sie das Tool über die Hauptdatei im `ui`-Verzeichnis:

```bash
python ui/app.py
```

*Hinweis für Linux-Nutzer:* Stellen Sie sicher, dass Sie über die entsprechenden Berechtigungen für den Zugriff auf lokale Konfigurationsdateien verfügen.

## 5. Projektstruktur

```text
Health-Check-Modul/
├── config/
│   └── config_manager.py     # Logik für verschlüsseltes Speichern/Laden
├── security/
│   ├── crypto.py             # Kryptographische Operationen
│   ├── exceptions.py         # Sicherheitsspezifische Fehlermeldungen
│   └── master_password.py    # Masterpasswort- & Session-Management
├── ui/
│   ├── app.py                # Einstiegspunkt der Anwendung
│   ├── dialogs.py            # GUI-Dialoge (Login, Shop-Profile)
│   └── main_window.py        # Hauptfenster & Navigation
├── tests/                    # Automatisierte Tests (pytest)
├── logging_config.py         # Logging-Setup mit Sensitive-Filter
└── README.md
```

## 6. Screenshots (Platzhalter)

*   **Login-Dialog:** [Hier Screenshot einfügen: Abfrage Masterpasswort]
*   **Hauptfenster:** [Hier Screenshot einfügen: Übersicht Health-Checks]
*   **Konfigurationsseite:** [Hier Screenshot einfügen: Verwaltung Shop-Profile]

## 7. Entwicklung

# Gambio Health Check

Ein leistungsstarkes, lokal ausgeführtes Desktop-Werkzeug zur Überprüfung der Systemintegrität und Update-Vorbereitung für Gambio-Shopsysteme.

## 1. Projektübersicht

Der **Gambio Health Check** unterstützt Shopbetreiber, Agenturen und Entwickler dabei, Gambio-Installationen proaktiv zu überwachen und reibungslose Update-Prozesse zu gewährleisten.

Im Gegensatz zu Cloud-basierten Lösungen arbeitet dieses Tool vollständig **lokal**. Sensible Zugangsdaten werden ausschließlich verschlüsselt auf Ihrem System gespeichert und niemals an externe Server übertragen.

### Hauptzweck
*   **Prävention:** Erkennung von Inkonsistenzen in der Dateistruktur oder Datenbank vor dem Auftreten von Fehlern.
*   **Update-Sicherheit:** Analyse der Systemvoraussetzungen und Kompatibilitäten für anstehende Gambio-Updates.
*   **Datenschutz:** Sichere Verwaltung von Server-Profilen und Passwörtern.

## 2. Features

*   **Health-Check:** Modulare Prüfung von Dateiberechtigungen, Server-Konfigurationen, PHP/MySQL-Versionen und Datenbank-Integrität.
*   **Datei-Integritätsprüfung (Baseline Hashing):** Erstellt rekursiv Hashes aller Shop-Dateien, um unbefugte Änderungen (z.B. Malware) zu erkennen. Folgende Ausnahmen werden beim Hashing automatisch ignoriert:
    * *Verzeichnisse:* `images`, `cache`, `logs`, `export`, `import`, `backups`, `uploads`, `node_modules`, `.git`
    * *Dateitypen:* `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.svg`
    * *Individuelle Ausnahmen:* Über die Einstellungen können benutzerdefinierte Dateien und Ordner/Pfade vom Scan ausgeschlossen werden.
*   **Performance-Optimiert:** Auch bei sehr großen Shops mit 50.000+ Dateien bleibt das Programm durch optimierte I/O-Zugriffe und reduzierte UI-Updates beim Baseline-Erstellen und Hash-Check voll reaktionsfähig.
*   **Update-Analyse:** Tiefenprüfung der Kompatibilität für bereitstehende Updates (PHP, MySQL, Shop-Version) inkl. Prüfung auf Vollständigkeit.
*   **Plugin-Kompatibilitäts-Scan:** Analysiert das `/GXModules`-Verzeichnis über einen Abstract Syntax Tree (AST) Scanner auf Drittanbieter-Module mit veraltetem Code (z. B. alte PHP 4-Konstruktoren, entfernte PHP 8-Funktionen). Core-Module können ausgeklammert werden. Falls `phply` nicht installiert oder nicht korrekt initialisiert ist, wechselt der Scanner automatisch in den robusten Regex-Fallback-Modus.
    > **Wichtig:** Ein Fund bedeutet nicht zwingend einen fatalen Fehler. Es kann sich um ungenutzten (toten) Code handeln. Durch den AST-basierten Scan werden False Positives (z. B. Methoden mit identischem Namen wie veraltete Funktionen) jedoch bereits weitestgehend eliminiert. Falls eine Datei jedoch Syntaxfehler enthält und nicht analysiert werden kann, wird auf einen Text-Scan zurückgegriffen.
*   **Backup-Datei Scanner:** Asynchrone Suche nach potenziell unsicheren `.bak`-Dateien auf dem Server, um alte Code-Stände oder Konfigurationen aufzuspüren und sicher zu entfernen.
*   **Logfile Scanner & Cleanup:** Analysiert Logfiles auf kritische Fehler (z.B. "ERROR", "FATAL") mit Exportfunktion für den Gambio-Support und bereinigt alte Logfiles automatisch nach konfigurierbarem Alter.
*   **Altlasten-Bereinigung:** Intelligente Analyse und sicheres Löschen verwaister Dateien **und Ordner** aus alten Update-Paketen. Der Check erkennt jetzt zuverlässig sowohl Dateien mit Extension als auch Ordner ohne Extension in `to_delete.php` und prüft deren Existenz über FTP/SFTP (mit NLST-Fallback für Ordner).
    > **Sicherheitsmechanismus (Backup-Zwang):** Um versehentliche Datenverluste zu vermeiden, müssen Anwender über eine Checkbox explizit bestätigen, dass ein aktuelles Backup (Dateien und Datenbank) angefertigt wurde, bevor Löschfunktionen freigeschaltet werden.
*   **Whitelist-System:** Konfigurierbare Liste für Dateien, die niemals automatisch gelöscht werden dürfen (z.B. `paypal3.php`).
*   **Verschlüsselte Konfiguration & Profil-Verwaltung:** Speicherung von Shop-Profilen in einer gesicherten AES-verschlüsselten Datei. Die getroffene Profil-Auswahl bleibt auch bei Neustarts der Anwendung und Seitenwechseln (z. B. zur Konfiguration) dauerhaft erhalten.
*   **Moderne GUI:** Benutzerfreundliche Oberfläche basierend auf **PySide6**.
*   **Security-Logging:** Intelligenter `SensitiveFilter`, der verhindert, dass Passwörter oder Tokens in Log-Dateien auftauchen.
*   **Plugin-Architektur:** Einfache Erweiterbarkeit für individuelle Prüfroutinen.

## 3. Sicherheit

Sicherheit steht bei diesem Tool an erster Stelle:
*   **Schlüsselableitung:** Verwendung von **PBKDF2-HMAC-SHA256** mit 600.000 Iterationen zur Erzeugung kryptographischer Schlüssel aus dem Masterpasswort.
*   **Verschlüsselung:** Einsatz von **Fernet (AES-128 im CBC-Modus mit HMAC-Authentifizierung)** für die Daten-Verschlüsselung.
*   **Brute-Force-Schutz:** Exponentielle Zeitverzögerung bei falschen Passworteingaben.
*   **Kein Klartext:** Passwörter werden niemals im Klartext auf der Festplatte gespeichert oder geloggt.
*   **Session-Lock:** Automatischer Schutzmechanismus, der den Zugriff nach Inaktivität sperrt.

## 4. Installation

### Voraussetzungen
*   **Python 3.10** oder höher.
*   **pip** (Python Package Installer).

### Abhängigkeiten installieren
Klonen Sie das Repository und installieren Sie die benötigten Bibliotheken:

```bash
pip install -r requirements.txt
```

### Anwendung starten
Starten Sie das Tool über die Hauptdatei im `ui`-Verzeichnis:

```bash
python ui/app.py
```

*Hinweis für Linux-Nutzer:* Stellen Sie sicher, dass Sie über die entsprechenden Berechtigungen für den Zugriff auf lokale Konfigurationsdateien verfügen.

## 5. Projektstruktur

```text
Health-Check-Modul/
├── config/
│   └── config_manager.py     # Logik für verschlüsseltes Speichern/Laden
├── security/
│   ├── crypto.py             # Kryptographische Operationen
│   ├── exceptions.py         # Sicherheitsspezifische Fehlermeldungen
│   └── master_password.py    # Masterpasswort- & Session-Management
├── ui/
│   ├── app.py                # Einstiegspunkt der Anwendung
│   ├── dialogs.py            # GUI-Dialoge (Login, Shop-Profile)
│   └── main_window.py        # Hauptfenster & Navigation
├── tests/                    # Automatisierte Tests (pytest)
├── logging_config.py         # Logging-Setup mit Sensitive-Filter
└── README.md
```

## 6. Screenshots (Platzhalter)

*   **Login-Dialog:** [Hier Screenshot einfügen: Abfrage Masterpasswort]
*   **Hauptfenster:** [Hier Screenshot einfügen: Übersicht Health-Checks]
*   **Konfigurationsseite:** [Hier Screenshot einfügen: Verwaltung Shop-Profile]

## 7. Entwicklung

### Neue Checks hinzufügen
Die Architektur erlaubt das einfache Hinzufügen neuer Prüfungen. Erstellen Sie dazu ein neues Modul innerhalb der Logik-Ebene und binden Sie es in die `HealthCheckPage` ein.

### Tests ausführen
Das Projekt nutzt `pytest` für die Qualitätssicherung.

```bash
# Alle Tests
pytest tests/ -v --tb=short

# Nur Quality-Gate-Tests
pytest tests/test_quality_gate.py -v
```

### Pre-Commit-Hooks & Code-Qualität

Um automatische Prüfungen bei jedem Git Commit durchzuführen:

```bash
# Pre-Commit Hooks im Git Repository aktivieren
pre-commit install

# Manuelle Ausführung auf allen Dateien
pre-commit run --all-files
```

Folgende automatische Prüfungen sind aktiv:
* **Standard-Checks:** Trailing Whitespace, End-of-File, YAML-Syntax, Large Files, Python-AST-Syntax, Case-Conflicts, Merge-Conflicts, Debug-Statements (z. B. `breakpoint()`), Private Key Detection.
* **Ruff:** Statische Code-Analyse & Formatierung (`ruff` mit `--fix` und `ruff-format`).
* **Bandit:** Sicherheitsanalyse.
* **Pytest:** Automatischer Lauf aller Unit-Tests.

### Build-Prozess & Quality Gate

Der Build-Prozess startet über `build.py` und durchläuft vor jeder Kompilierung
vier sequentielle Sicherheits- und Qualitätsphasen:

| Phase | Tool | Zweck | Abbruchkriterium |
|-------|------|-------|------------------|
| 0 | `pre-commit` | Code-Stil (Ruff), Security (Bandit), Pytest | Formatierungs- / Lint- / Test-Fehler |
| 1 | `pip-audit` | CVE-Scan aller Abhängigkeiten | verwundbare Pakete gefunden |
| 2 | `bandit -lll -iii` | Statische Code-Analyse | HIGH-Severity + HIGH-Confidence Fund |
| 3 | `pytest tests/` | Unit-Test-Suite | mind. 1 fehlgeschlagener Test |

Schlägt eine Phase fehl, wird der Build **sofort** mit Exit-Code 1 abgebrochen.
Erst wenn alle Phasen `✓ OK` melden, startet Cython + PyInstaller.

```bash
# Build starten (inkl. Quality Gate)
python build.py
```

> **Hinweis:** `pre-commit`, `ruff`, `pip-audit` und `bandit` müssen in der Virtualenv vorhanden sein:
> ```bash
> pip install -r requirements.txt
> ```

### Entwickler-Richtlinien
*   Achten Sie darauf, sensible Daten niemals direkt in Log-Befehle zu schreiben.
*   Verwenden Sie für UI-Erweiterungen ausschließlich die definierten Styles in der `main_window.py`.
*   Neue Sicherheitsregeln in `bandit` → `--skip`-Ausnahmen nur mit Begründung und Ticket-Referenz.

## 8. Lizenz

Dieses Projekt wird unter der **MIT-Lizenz** veröffentlicht.

*Empfehlung:* Die MIT-Lizenz ist ideal für dieses Tool, da sie eine breite Nutzung und Weiterentwicklung ermöglicht, während die Haftung für die lokale Ausführung ausgeschlossen bleibt.

---
*Entwickelt für die Gambio-Community.*
