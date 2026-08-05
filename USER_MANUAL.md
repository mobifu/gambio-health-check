# Benutzerhandbuch: Gambio Health Check

Willkommen beim **Gambio Health Check**. Diese Software unterstützt Sie dabei, Ihre Gambio-Shop-Installation lokal zu überwachen, auf Fehler zu prüfen und Ihre Server-Zugangsdaten sicher zu verwalten.

---

## 1. Einleitung
### Zweck der Software
Das Modul dient der proaktiven Fehlervermeidung. Es führt Integritätsprüfungen durch und speichert sensible Zugangsdaten in einer lokal verschlüsselten Umgebung.

---

## 2. Login & Masterpasswort
### Masterpasswort-Dialog
Nach dem Start erscheint ein Anmeldefenster. Geben Sie hier Ihr Masterpasswort ein, um die Anwendung zu entsperren.

### Passwortregeln
Wählen Sie ein sicheres Passwort. Da die Verschlüsselung sehr rechenintensiv ist, schützt bereits ein moderat komplexes Passwort effektiv vor Offline-Angriffen.

### Brute-Force-Schutz
Um Ihre Daten vor automatisierten Erratungsversuchen zu schützen, verfügt die App über einen eingebauten Schutz, der bei Fehlversuchen künstliche Verzögerungen erzwingt und das System nach 10 Fehlversuchen vorübergehend sperrt.

### Session-Timeout
Aus Sicherheitsgründen wird Ihre Sitzung nach **10 Minuten Inaktivität** gesperrt.

---

## 3. Hauptfenster
### Sidebar
Auf der linken Seite finden Sie das Navigationsmenü:
*   **Health-Check:** Systemprüfung starten.
*   **Konfiguration:** Shop-Profile verwalten.
*   **Handbuch:** Dieses Benutzerhandbuch öffnen.

---

## 4. Durchführung der Prüfung
**Wichtig:** Bevor Sie eine Prüfung durchführen können, müssen Sie unter dem Reiter "Konfiguration" mindestens ein Shop-Profil anlegen.

Haben Sie ein Profil angelegt, wählen Sie dieses aus dem Dropdown-Menü aus.

> [!NOTE]
> **Profil-Persistenz:** Das Modul merkt sich Ihr zuletzt genutztes Shop-Profil. Wenn Sie zwischen der Health-Check-Ansicht und der Konfiguration wechseln oder das Programm komplett neu starten, bleibt Ihr ausgewähltes Profil automatisch erhalten.

Zusätzlich finden Sie eine Checkbox **"Gambio-Module (Core) bei Kompatibilitätsprüfung einschließen"**:
Standardmäßig werden beim Plugin-Scan die Core-Module von Gambio (`/GXModules/Gambio/`) übersprungen, um die Prüfung zu beschleunigen und Fehlalarme zu vermeiden. Aktivieren Sie die Checkbox, wenn Sie diese Dateien dennoch in den Scan einbeziehen möchten.

Klicken Sie abschließend auf **"Health-Check starten"**.

### Erklärung der Prüfungsergebnisse
Die Ergebnisse werden farblich gekennzeichnet:
*   **[✓] Grün (OK):** Alles in Ordnung.
*   **[!] Gelb (Warnung):** Ein potenzielles Problem wurde erkannt (z.B. PHP-Version neuer als offiziell getestet).
*   **[✗] Rot (Fehler):** Ein kritisches Problem wurde gefunden.

### Detail-Erläuterung der Module
*   **Verbindung & Struktur:** Prüft FTP/SFTP-Erreichbarkeit und Gambio-Ordnerstruktur.
*   **Server-Umgebung:** Ermittelt PHP-Version, Datenbank-Typ und Schreibrechte.
*   **Kompatibilitäts-Check:** Vergleicht Gambio-Version mit installierter PHP-Version.
*   **Plugin-Kompatibilitäts-Scan:** Analysiert Drittanbieter-Module (`/GXModules`) über einen Abstract Syntax Tree (AST) auf veralteten PHP-Code (z. B. PHP 4-Konstruktoren oder in PHP 8 entfernte Funktionen wie `each` oder `create_function`). Falls die AST-Bibliothek (`phply`) nicht korrekt initialisiert ist, wechselt der Scanner automatisch in den Regex-Fallback-Modus.

    > [!NOTE]
    > **Wichtiger Hinweis zu Kompatibilitäts-Warnungen:**
    > Wenn der Scanner inkompatiblen Code in einem Modul meldet, bedeutet das **nicht zwingend**, dass der Shop abstürzen wird.
    > 1. **Nicht ausgeführter Code:** Oft bringen externe Bibliotheken viel Code mit, von dem nur ein Bruchteil tatsächlich genutzt wird. Der betroffene Code wird möglicherweise nie aufgerufen.
    > 2. **False Positives (Fehlalarme) minimiert:** Da der Scanner nun den Code-Aufbau über einen AST (Abstract Syntax Tree) analysiert, anstatt nach simplen Textmustern zu suchen, sind Fehlalarme (wie etwa Namensgleichheiten mit veralteten PHP-Funktionen) deutlich reduziert. Falls eine Datei nicht geparst werden kann, gibt es als Fallback noch den alten textbasierten Scan, bei dem gelegentlich Fehlalarme auftreten können.
    >
    > Betrachten Sie diese Warnungen als **Hinweise** zur weiteren Prüfung, insbesondere vor einem Server-Update auf PHP 8.

*   **Altlasten-Analyse (Legacy Files):** Analysiert, welche Dateien und **Ordner** laut Gambio gelöscht werden sollten, aber noch existieren. Die Erkennung berücksichtigt sowohl Dateipfade mit Extension (z.B. `.php`) als auch reine Ordnerpfade ohne Extension aus den Gambio-Update-Paketen. Bei FTP-Verbindungen wird für Ordner automatisch ein NLST-Fallback genutzt, da der FTP-`SIZE`-Befehl bei Verzeichnissen nicht funktioniert.

---

## 5. Integritäts- & Hash-Check
### Was ist der Hash-Check?
Der Hash-Check ist eine fortgeschrittene Sicherheits- und Integritätsprüfung. Für jede Datei auf Ihrem Server wird ein einzigartiger digitaler Fingerabdruck (SHA-256 Hash) berechnet. Ändert sich ein Zeichen, ändert sich der Hash.

### Welche Dateien werden gescannt?
Grundsätzlich werden alle Dateien auf dem Server rekursiv gescannt und gehasht. Es gibt jedoch Ausnahmen, um die Performance zu verbessern und irrelevante Änderungen zu ignorieren:
* **Ausgeschlossene Verzeichnisse:** `images`, `cache`, `logs`, `export`, `import`, `backups`, `uploads`, `node_modules`, `.git`
* **Ausgeschlossene Dateitypen:** `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.svg`
* **Individuelle Ausnahmen:** Über die Einstellungen können Sie eigene Dateien oder Pfade (Whitelist) definieren, die vom Scan ausgeschlossen werden sollen.

### Warum sollten Sie den Hash-Check durchführen?
* **Schutz vor Malware:** Erkennt unautorisierte Änderungen durch Schadcode (Malware, Web-Shells) sofort.
* **Erkennung fehlerhafter Uploads:** Deckt beschädigte oder unvollständige Dateiübertragungen auf.
* **Sicherstellung der Integrität:** Überprüft, ob der Shop noch dem gespeicherten "sauberen" Zustand entspricht.

### Durchführung
1. **Baseline erzeugen:** Klicken Sie im Hauptmenü auf "Baseline erzeugen", wenn Ihr Shop in einem garantierten, sauberen Zustand ist.

   > [!IMPORTANT]
   > Eine Baseline-Erstellung ist nur dann sinnvoll, wenn sie **vor** einem möglichen Hackerangriff (in einem garantiert sauberen Zustand des Shops) durchgeführt wurde. Nach jedem Shop- oder Plugin-Update muss die Baseline neu erstellt werden, damit legitime Dateiänderungen nicht fälschlicherweise als Manipulationen gemeldet werden.

2. **Hash-Check starten:** Um den aktuellen Zustand mit der Baseline zu vergleichen, klicken Sie auf "Hash-Check starten".

### Erkennung von Abweichungen
Das Modul meldet folgende Abweichungen direkt in der Protokoll-Liste der Health-Check-Ergebnisse:
* **Neue Dateien (Warnung - Gelb):** Dateien, die seit der Erstellung der Baseline hinzugefügt wurden (`Unbekannte Datei gefunden: <Pfad>`). Diese werden zusätzlich auf Malware-Indikatoren geprüft.
* **Gelöschte/Fehlende Dateien (Fehler - Rot):** Dateien, die in der Baseline registriert waren, aber auf dem Server fehlen (`Datei fehlt: <Pfad>`).
* **Veränderte Dateien (Warnung - Gelb):** Dateien, deren SHA-256 Hash nicht mehr mit der Baseline übereinstimmt (`Datei verändert: <Pfad>`).

---

> [!IMPORTANT]
> **Sicherheitsmechanismus (Backup-Zwang) vor Löschaktionen**
> Um Datenverluste zu vermeiden, sind alle im Folgenden beschriebenen Lösch-Buttons standardmäßig deaktiviert. Sie müssen zunächst zwingend die Checkbox **"Ich bestätige, dass ich ein aktuelles Backup (Dateien & Datenbank) angefertigt habe."** in der Benutzeroberfläche ankreuzen, bevor das Löschen von Dateien freigeschaltet wird!

## 6. Backup-Dateien scannen und löschen
Um zu verhindern, dass alte Code-Stände oder sensible Konfigurationen auf dem Server verbleiben, können Sie gezielt nach `.bak`-Dateien suchen.
1. Klicken Sie auf **"Nach .bak Dateien scannen"** (oberhalb des Hash-Checks).
2. Der asynchrone Scan durchsucht rekursiv den Server (wichtige Systemordner wie `cache`, `images` werden aus Performance-Gründen übersprungen).
3. Wenn Dateien gefunden wurden, können Sie diese über den Button **"Gefundene .bak Dateien löschen"** dauerhaft vom Server entfernen (nur nach Bestätigung).

---

## 7. Altlasten löschen
Wenn Altlasten gefunden wurden, können Sie diese über den Button **"Gefundene Altlasten löschen"** dauerhaft entfernen (nur nach Bestätigung).

> [!NOTE]
> **Automatische Cache-Bereinigung nach dem Löschen:**
> Nach erfolgreicher Altlasten-Bereinigung leert die Software **vollautomatisch** den Gambio-System-Cache (Verzeichnis `/cache/`).
> Dabei greifen strikte Sicherheitsregeln:
> * **Dateischutz:** Die Dateien `.htaccess`, `index.html` und `index.php` werden im Cache-Ordner **nicht** gelöscht, um den Verzeichnisschutz aufrechtzuerhalten.
> * **Strukturschutz:** Alle Unterverzeichnisse innerhalb des Cache-Ordners bleiben unberührt. Es werden ausschließlich temporäre Cache-Dateien im Hauptverzeichnis gelöscht.

---

## 8. Logfiles analysieren und bereinigen
Das Modul bietet die Möglichkeit, alte Logdateien aus dem Verzeichnis `logfiles/` zu verwalten. Das regelmäßige Löschen von alten Logfiles ist sinnvoll, um Speicherplatz auf dem Server freizugeben und die Übersichtlichkeit zu wahren, wenn man Fehler in aktuellen Logs sucht.

1. **Logfiles scannen & Fehler exportieren:** Durchsucht alle Logdateien nach kritischen Fehlern (z.B. "ERROR", "FATAL", "Exception"). Werden Fehler gefunden, können Sie diese als Textdatei exportieren, um sie beispielsweise an den Gambio-Support weiterzuleiten.
2. **Alte Logfiles löschen:** Löscht alle Logdateien, die älter als das in der Konfiguration eingestellte Alter sind (Standard: 7 Tage). Die Dateien `.htaccess` und `index.html` sind davon ausgenommen und werden niemals gelöscht.

> [!TIP]
> **Hinweis zur Gambio-internen Funktion:** Gambio bietet im Admin-Bereich des Shops ebenfalls eine Möglichkeit, alte Logdateien nach einer bestimmten Zeitspanne automatisch löschen zu lassen. Die Bereinigungsfunktion in diesem Modul dient als zusätzliche Option, um Logs direkt im Zuge eines Health-Checks manuell aufzuräumen, falls die Automatik im Shop nicht aktiv oder falsch konfiguriert ist.

---

## 9. Konfiguration & Whitelist
Unter **"Konfiguration"** verwalten Sie Ihre Einstellungen:

### Shop-Profile anlegen
Um eine Verbindung zu Ihrem Shop aufzubauen, müssen Sie ein Profil erstellen. Füllen Sie dazu folgende Felder aus:
* **Profilname:** Ein frei wählbarer Name zur Erkennung (z.B. "Mein Hauptshop").
* **Host:** Die Server-Adresse, über die Ihr Shop erreichbar ist (z.B. `ftp.ihre-domain.de` oder eine IP-Adresse).
* **Port:** Für Standard-FTP in der Regel `21`, für das sichere SFTP meist `22`.
* **Protokoll:** Wählen Sie, ob die Verbindung per FTP oder SFTP aufgebaut werden soll.
* **Shop-Pfad:** Der Ordner-Pfad vom Startverzeichnis Ihres FTP-Benutzers bis in das Hauptverzeichnis des Shops (z.B. `/httpdocs` oder `/html/gambio`). Landen Sie mit Ihrem Benutzer direkt im Shop-Verzeichnis, können Sie oft `/` eintragen oder das Feld leer lassen.
* **Benutzername & Passwort:** Die Zugangsdaten für Ihren FTP- oder SFTP-Account.

Alle Daten werden lokal mit starker AES-128 Verschlüsselung gespeichert und sind ohne Ihr Masterpasswort nicht lesbar.

### Ignorierte Dateien & Ordner (Whitelist)
Geben Sie eine kommagetrennte Liste von Dateinamen, Ordnernamen oder Pfadteilen an, die bei Prüfungen ignoriert werden sollen (z. B. `paypal3.php` oder `mein_ordner`).

Folgende Verzeichnisse sind beim Hash Check **standardmäßig bereits ausgeschlossen**:
`images`, `cache`, `logs`, `export`, `import`, `backups`, `uploads`, `node_modules`, `.git`

Diese Liste gilt sowohl für die **Altlasten-Analyse** als auch für den **Integritäts- und Malware-Scan**.

### Maximales Alter der Logfiles
Legen Sie fest, nach wie vielen Tagen alte Dateien im `logfiles/` Ordner gelöscht werden sollen (Standard: 7 Tage). Diese Einstellung wird bei der Funktion "Alte Logfiles löschen" verwendet.

> [!TIP]
> **Keine Panik bei Malware-Warnungen (False Positives):**
> Das Modul sucht nach potenziell gefährlichen Begriffen (wie `eval`, `base64_decode` oder `system`) sowie extrem langen Zeichenketten. Diese Muster werden jedoch auch von absolut seriösen und notwendigen PHP-Bibliotheken (z. B. im `vendor`-Ordner, in Verschlüsselungsklassen wie `phpseclib` oder in Composer-Autoload-Dateien) für legitime Zwecke verwendet.
>
> Wenn eine Datei als „verdächtig“ gemeldet wird, prüfen Sie den Pfad. Liegt sie in einem Standard-Bibliotheksordner wie `vendor/` und wurde nicht kürzlich unerwartet verändert, handelt es sich meist um einen Fehlalarm (False Positive). Sie können den Dateinamen (z. B. `Malware_False_Positive.php` oder einfach Teile des Pfads wie `vendor/symfony/`) in diese Liste eintragen, um die Datei dauerhaft von künftigen Warnungen auszuschließen.


---

## 9. Sicherheitshinweise
Notieren Sie Ihr Masterpasswort niemals unverschlüsselt. Wenn Sie dieses Passwort vergessen, gibt es **keine Möglichkeit**, Ihre Profile wiederherzustellen.

---

## 10. Troubleshooting
*   **Passwort wird nicht akzeptiert:** Prüfen Sie die Feststelltaste. Ist die Konfiguration beschädigt, müssen Sie die Datei `config.dat` (falls lokal vorhanden) löschen und Profile neu anlegen.
*   **Verbindungsfehler:** Überprüfen Sie Host, Port und Anmeldedaten im jeweiligen Profil.

---

## 11. Haftungsausschluss (Disclaimer)
Dieses Tool wird „wie besehen“ (as is) und ohne jegliche ausdrückliche oder implizite Gewährleistung zur Verfügung gestellt. Die Nutzung der Software erfolgt auf eigene Verantwortung.

Der Entwickler übernimmt **keine Haftung** für eventuelle Schäden, Datenverluste, Serverausfälle oder sonstige Beeinträchtigungen, die durch die Nutzung, Fehlkonfiguration oder das Löschen von Dateien über dieses Programm entstehen. Vergewissern Sie sich vor dem Löschen von Dateien stets, dass diese tatsächlich nicht mehr benötigt werden, und erstellen Sie vorab Backups Ihres Gambio-Shops.

---

## 12. Entwicklerhinweise & Code-Qualität

Für Mitwirkende und Entwickler stehen folgende Werkzeuge zur Qualitätssicherung bereit:

### Pre-Commit Hooks
Aktivieren Sie automatische Prüfungen vor jedem Git-Commit:
```bash
pre-commit install
```
Beim Ausführen von `git commit` werden automatisch Dateiformatierung (`ruff`), Sicherheitsüberprüfungen (`bandit`) und Unit-Tests (`pytest`) durchgeführt.

### Qualitätsprüfung im Build-Prozess
Der Build-Skript `build.py` führt ein 4-phasiges Quality Gate aus (`Pre-Commit`, `pip-audit`, `bandit`, `pytest`), bevor das Programm kompiliert wird.
