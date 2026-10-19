import html
import json
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from PySide6.QtGui import QTextDocument
    from PySide6.QtPrintSupport import QPrinter

    PYSIDE_AVAILABLE = True
except ImportError:
    PYSIDE_AVAILABLE = False

logger = logging.getLogger(__name__)

# Maximales Limit für Einträge im Bericht zum Schutz vor Speicherüberlastung (DoS)
MAX_REPORT_ENTRIES = 10_000


def load_log_entries(
    log_source: str | Path,
    max_entries: int = MAX_REPORT_ENTRIES,
) -> tuple[Path | None, list[dict[str, Any]]]:
    """
    Liest Log-Einträge sicher aus einer Log-Datei oder dem neuesten Log eines Verzeichnisses.
    Begrenzt die Anzahl auf max_entries (Tail-Prinzip) und fängt fehlerhafte Zeilen ab.
    """
    source_path = Path(log_source).resolve()

    if source_path.is_file():
        log_file_path = source_path
    elif source_path.is_dir():
        latest_str = _get_latest_log_file(source_path)
        if not latest_str:
            logger.error(f"Keine Log-Datei in Verzeichnis {source_path} gefunden.")
            return None, []
        log_file_path = Path(latest_str).resolve()
    else:
        logger.error(f"Ungültige Log-Quelle (weder Datei noch Verzeichnis): {source_path}")
        return None, []

    entries_deque: deque[dict[str, Any]] = deque(maxlen=max_entries)
    try:
        # errors="replace" verhindert Abstürze bei ungültigen UTF-8-Sequenzen
        with open(log_file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    parsed = json.loads(clean_line)
                    if isinstance(parsed, dict):
                        entries_deque.append(parsed)
                    else:
                        logger.warning(
                            f"JSON-Zeile #{line_idx} in {log_file_path} ist kein Dictionary: {type(parsed).__name__}"
                        )
                except json.JSONDecodeError as decode_err:
                    logger.warning(f"Ungültige JSON-Zeile #{line_idx} in {log_file_path} übersprungen: {decode_err}")
    except OSError as e:
        logger.error(f"Fehler beim Lesen der Log-Datei {log_file_path}: {e}")
        return log_file_path, []

    return log_file_path, list(entries_deque)


def generate_html_report(
    profile_name: str,
    log_dir: str | Path,
    output_path: str | Path,
    max_entries: int = MAX_REPORT_ENTRIES,
) -> bool:
    """
    Liest die neueste Log-Datei für das Profil und generiert einen sicheren HTML-Bericht.
    """
    log_file, entries = load_log_entries(log_dir, max_entries=max_entries)
    if not log_file or not entries:
        logger.warning(f"Keine verwertbaren Log-Einträge für Profil '{profile_name}' gefunden.")
        return False

    html_content = _build_html(profile_name, entries)

    try:
        target_path = Path(output_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return True
    except OSError as e:
        logger.error(f"Fehler beim Schreiben des HTML-Berichts nach {output_path}: {e}")
        return False


def generate_pdf_report(
    profile_name: str,
    log_dir: str | Path,
    output_path: str | Path,
    max_entries: int = MAX_REPORT_ENTRIES,
) -> bool:
    """
    Liest die neueste Log-Datei, generiert HTML und exportiert es über QTextDocument als PDF.
    """
    if not PYSIDE_AVAILABLE:
        logger.error("PySide6.QtPrintSupport ist nicht verfügbar. PDF-Export nicht möglich.")
        return False

    log_file, entries = load_log_entries(log_dir, max_entries=max_entries)
    if not log_file or not entries:
        logger.warning(f"Keine verwertbaren Log-Einträge für PDF-Bericht ('{profile_name}') vorhanden.")
        return False

    html_content = _build_html(profile_name, entries)

    try:
        target_path = Path(output_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)

        doc = QTextDocument()
        doc.setHtml(html_content)

        printer = QPrinter()
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(str(target_path))

        doc.print_(printer)
        return True
    except (OSError, RuntimeError) as e:
        logger.error(f"Fehler beim Erstellen der PDF {output_path}: {e}")
        return False
    except Exception as e:  # noqa: BLE001
        logger.error(f"Unerwarteter Fehler beim Erstellen der PDF {output_path}: {e}")
        return False


def _get_latest_log_file(log_dir: str | Path) -> str:
    """Findet die aktuellste .log-Datei im angegebenen Verzeichnis (nach Modifikationszeit)."""
    try:
        dir_path = Path(log_dir).resolve()
        if not dir_path.exists() or not dir_path.is_dir():
            return ""
        files = [p for p in dir_path.glob("*.log") if p.is_file()]
        if not files:
            return ""
        # Bevorzuge st_mtime für zuverlässige Bestimmung der neuesten Logdatei
        latest = max(
            files,
            key=lambda f: f.stat().st_mtime,
        )
        return str(latest)
    except OSError as e:
        logger.warning(f"Fehler beim Suchen der neuesten Log-Datei in {log_dir}: {e}")
        return ""


def _determine_css_class(level: str, msg: str) -> str:
    """Ermittelt deterministisch die CSS-Klasse für das Logging-Level."""
    level_upper = level.upper()
    msg_upper = msg.upper()
    if any(k in level_upper for k in ("ERROR", "FATAL", "CRITICAL")):
        return "level-error"
    if "WARN" in level_upper:
        return "level-warn"
    if "OK" in level_upper or "ERFOLG" in msg_upper or "BEREIT" in msg_upper:
        return "level-ok"
    return "level-info"


def _build_html(profile_name: str, entries: list[dict[str, Any]]) -> str:
    """Erzeugt ein sicheres HTML5-Dokument mit Content-Security-Policy und XSS-Escaping."""
    safe_profile = html.escape(str(profile_name), quote=True)
    now_str = datetime.now(timezone.utc).astimezone().strftime("%d.%m.%Y %H:%M:%S")

    total_count = len(entries)
    error_count = sum(
        1 for e in entries if any(k in str(e.get("level", "")).upper() for k in ("ERROR", "FATAL", "CRITICAL"))
    )
    warn_count = sum(1 for e in entries if "WARN" in str(e.get("level", "")).upper())
    info_count = total_count - error_count - warn_count

    rows: list[str] = []
    for entry in entries:
        raw_level = str(entry.get("level", "INFO")).strip()
        raw_msg = str(entry.get("msg", ""))
        raw_time = str(entry.get("time", ""))

        safe_level = html.escape(raw_level, quote=True)
        safe_msg = html.escape(raw_msg, quote=True)
        safe_time = html.escape(raw_time, quote=True)

        css_class = _determine_css_class(raw_level, raw_msg)

        rows.append(
            f"""
                <tr>
                    <td class="col-time">{safe_time}</td>
                    <td class="col-status {css_class}">{safe_level}</td>
                    <td class="col-msg">{safe_msg}</td>
                </tr>"""
        )

    table_rows = "".join(rows)

    return f"""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src 'none'; img-src data:; base-uri 'none'; form-action 'none';">
    <title>Health-Check Bericht: {safe_profile}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 40px; color: #2c3e50; background: #fafbfc; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
        h1 {{ color: #1e293b; border-bottom: 2px solid #3b82f6; padding-bottom: 12px; margin-top: 0; }}
        .header-info {{ display: flex; gap: 30px; margin-bottom: 24px; font-size: 14px; color: #64748b; background: #f8fafc; padding: 12px 16px; border-radius: 6px; }}
        .stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ flex: 1; padding: 12px 16px; border-radius: 6px; border: 1px solid #e2e8f0; text-align: center; }}
        .stat-card strong {{ display: block; font-size: 20px; margin-bottom: 4px; }}
        .stat-errors strong {{ color: #dc2626; }}
        .stat-warnings strong {{ color: #d97706; }}
        .stat-infos strong {{ color: #2563eb; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; table-layout: fixed; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
        th {{ background-color: #f1f5f9; font-weight: 600; color: #334155; }}
        tr:hover {{ background-color: #f8fafc; }}
        .col-time {{ width: 170px; white-space: nowrap; }}
        .col-status {{ width: 90px; }}
        .col-msg {{ white-space: pre-wrap; word-break: break-word; }}
        .level-ok {{ color: #16a34a; font-weight: bold; }}
        .level-warn {{ color: #d97706; font-weight: bold; }}
        .level-error {{ color: #dc2626; font-weight: bold; }}
        .level-info {{ color: #2563eb; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Gambio Health-Check Bericht</h1>
        <div class="header-info">
            <div><strong>Shop-Profil:</strong> {safe_profile}</div>
            <div><strong>Datum:</strong> {now_str}</div>
            <div><strong>Einträge gesamt:</strong> {total_count}</div>
        </div>
        <div class="stats">
            <div class="stat-card stat-errors"><strong>{error_count}</strong>Fehler</div>
            <div class="stat-card stat-warnings"><strong>{warn_count}</strong>Warnungen</div>
            <div class="stat-card stat-infos"><strong>{info_count}</strong>Informationen</div>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 170px;">Zeit</th>
                    <th style="width: 90px;">Status</th>
                    <th>Nachricht</th>
                </tr>
            </thead>
            <tbody>{table_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
