---
name: Security Audit
command: /audit
description: Führt einen Sicherheits-Audit auf Schwachstellen, Krypto-Hygiene und Testabdeckung durch
arguments:
  - name: target_path
    description: Optionaler Pfad (Datei oder Ordner). Wenn leer, wird das Projekt automatisch analysiert.
    required: false
    default: "auto"
---
# Workflow: Sicherheits-Audit & Coverage-Check

### 1. Scope-Ermittlung
Prüfe den Parameter `target_path`:
- **Falls ein Pfad angegeben wurde (nicht "auto"):** Nutze ausschließlich diesen Pfad als Scope (`<TARGET_SCOPE>`).
- **Falls "auto":** Finde eigenständig alle relevanten Produktivcode-Dateien und -Ordner:
  * Priorisiere Ordner wie `core/`, `src/`, `gui_modules/`, `licensing_module/` sowie Skripte im Root.
  * Schließe STRIKT aus: `.venv/`, `venv/`, `env/`, `build/`, `dist/`, `.git/`, `tests/`, `__pycache__/`, `*.c`, `*.so`, `*.pyd`.
  * Definiere diese Auswahl als deinen Arbeits-Scope (`<TARGET_SCOPE>`).

---

### 2. Statische Sicherheits-Analyse (Bandit)
Führe Bandit mit strengen Ausschlusskriterien im Terminal aus:
`bandit -r <TARGET_SCOPE> -x .venv,venv,tests,build,dist -ll -ii`

---

### 3. Kryptographie- & Code-Hygiene (Agent-Inspektion)
Untersuche den gefilterten `<TARGET_SCOPE>` gezielt auf:
- Moderne Ciphers (AES-256-GCM, ChaCha20-Poly1305 statt DES/ECB).
- Sichere KDF (Argon2id, PBKDF2 mit mind. 16-Byte-Salts).
- Sichere Nonce-Generierung via `secrets` / `os.urandom`.
- Vermeidung von Secret-Leaks in Logs und Exception-Messages.

---

### 4. Testabdeckungs-Check (Coverage)
Führe die Testabdeckung für den Ziel-Scope aus:
`pytest --cov=<TARGET_SCOPE> --cov-report=term-missing`

*Bewerte das Ergebnis:*
- Erreicht der geprüfte Bereich den definierten Mindestwert (z. B. 85%)?
- Gibt es sicherheitskritische Funktionen (Krypto, Auth, File-I/O), die in den Zeilen als „Missing“ aufgeführt sind?

---

### 5. Ergebnis-Report
Fasse das Ergebnis in drei klaren Abschnitten zusammen:
1. **Sicherheits-Befunde (SAST & Krypto):** Gefundene Schwachstellen inkl. Datei und Zeilennummer.
2. **Testabdeckung:** Aktueller Coverage-Prozentsatz und ungetestete Risikobereiche.
3. **Handlungsempfehlung:** Konkrete Schritte zur Behebung von Lücken oder zum Nachziehen fehlender Tests via `/test`.
