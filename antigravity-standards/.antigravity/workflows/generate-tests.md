---
name: Generate or Complete Tests
command: /test
description: Ermittelt ungetestete Zeilen und schreibt zwingend neue Pytest-Funktionen
arguments:
  - name: target_file
    description: Pfad zur Python-Datei
    required: true
---
# Workflow: Coverage-Lücken mit neuen Tests schließen

Ziel-Modul: `{{target_file}}`

### ⚠️ ABBRUCH-BEDINGUNG:
Es ist dir STRIKT UNTERSAGT, nach einem erfolgreichen `pytest`-Durchlauf aufzuhören, solange Zeilen ungetestet sind!
„X passed“ ist KEIN Erfolgsnachweis für diesen Task. Der Task gilt erst als erfüllt, wenn du NEUEN Code in die Testdatei geschrieben hast.

---

### MECHANISCHER 3-SCHRITTE-ABLAUF (Verbindlich abarbeiten):

#### SCHRITT 1: Fehlende Zeilen lokalisieren (Terminal)
Führe aus:
`pytest tests/ -k {{target_file}} --cov={{target_file}} --cov-report=term-missing`

Lies aus der Spalte **„Missing“** die ungetesteten Zeilennummern aus.
- Identifiziere in `{{target_file}}` mindestens 5 bis 10 Methoden, Funktionen oder Verzweigungen, die in diesen Zeilen liegen.

#### SCHRITT 2: Testdatei zwingend editieren (Tool-Aufruf)
Öffne `tests/test_<modulname>.py` (bzw. erstelle sie).
**Du MUSST JETZT konkreten Code in diese Datei schreiben.**
- Schreibe für die in Schritt 1 identifizierten Zeilen neue Testfunktionen (`def test_*`).
- Falls GUI-Code (Tkinter/CustomTkinter): Mocke Dialoge (`messagebox`, `filedialog`) und `root.mainloop` zwingend weg.
- Falls I/O oder REST: Mocke Netzwerk und Subprozesse.
- Nutze für temporäre Dateien die Pytest-Fixture `tmp_path`.
- **Wichtig:** Bestehende funktionierende Tests (die aktuellen 61) unangetastet lassen – hänge die neuen Tests hinten an!

#### SCHRITT 3: Verifizieren
Führe danach erneut aus:
`pytest -v tests/test_<modulname>.py --cov={{target_file}} --cov-report=term-missing`

- Alle Tests müssen grün sein.
- Die Anzahl der bestandenen Tests muss HÖHER sein als zu Beginn (z. B. 70 statt 61).
- Erst JETZT beendest du den Task und listest die Namen der neu hinzugefügten Testfunktionen auf.
