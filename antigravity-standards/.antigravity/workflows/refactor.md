# Command: /refactor [PFAD_ODER_DATEI]

## Modus-Erkennung:
- **Einzeldatei angegeben (z. B. `/refactor src/converter.py`):** Führe den 4-Phasen-Refactor direkt auf dieser Datei aus.
- **Ordner oder kein Pfad angegeben (z. B. `/refactor src/` oder `/refactor`):** Starte im **Projekt-Modus** (Schritt A vor Schritt B).

---

## Modus A: Projekt-Orchestrierung (bei Ordnern)
1. **Dependency Mapping:** Führe eine statische Analyse über alle `.py`-Dateien im Zielverzeichnis durch.
2. **Reihenfolge bestimmen:**
   - Starte mit Blattknoten (Utilities, reine Datenmodelle, Helper ohne interne Importe).
   - Fahre fort mit Kern-Businesslogik und I/O-Services.
   - Schließe mit Entrypoints (CLI, App-Klassen, Main-Modulen) ab.
3. **Execution Plan ausgeben:** Zeige dem Entwickler die ermittelte Reihenfolge als Checkliste und beginne mit Modul 1.
4. **Schleife:** Führe Modus B für jedes Modul sequenziell aus. Gehe erst zum nächsten Modul über, wenn die Tests grün sind.

---

## Modus B: 4-Phasen-Ausführung pro Modul

### 1. Phase: /audit
- Führe ein statisches Audit auf dem Zielmodul durch (Schwachstellen, Hardcoded Secrets, unsichere Deserialisierung/Subprocesses).
- Liste konkrete Smells und Angriffsflächen kurz stichpunktartig auf.

### 2. Phase: /test (Baseline sichern)
- Erstelle oder aktualisiere `pytest`-Tests für den Status Quo des Moduls.
- Isoliere I/O- und Netzwerkoperationen über Mocks.
- Sicherstellen, dass das bestehende Verhalten vollständig abgedeckt ist.

### 3. Phase: Strukturelles Refactoring
- Zerlege monolithische Funktionen (Single Responsibility).
- Führe typsichere Datenstrukturen (`@dataclass(frozen=True)` oder `pydantic.BaseModel`) ein.
- Wende Dependency Injection und `typing.Protocol` anstelle harter Kopplung an.
- Performance: Listenabfragen optimieren, Generatoren bei Streams nutzen, Ressourcen per `with`-Block schließen.
- **Verifikation:** Die Tests aus Phase 2 müssen weiterhin fehlerfrei durchlaufen.

### 4. Phase: /harden
- Vollständige Type-Hints ergänzen (`mypy --strict`-konform).
- Domänenspezifische Exceptions definieren und generische `except Exception:`-Klauseln ablösen.
- Code nach `ruff`-Regeln formatieren und bereinigen.

---

## Ausgabe-Regel:
Gib immer den vollständigen, lauffähigen Code des aktuellen Moduls und die zugehörigen Tests aus. Frage vor dem Wechsel zur nächsten Datei kurz nach Bestätigung.
