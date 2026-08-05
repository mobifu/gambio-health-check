import os
import json
import logging
from datetime import datetime

try:
    from PySide6.QtGui import QTextDocument
    from PySide6.QtPrintSupport import QPrinter

    PYSIDE_AVAILABLE = True
except ImportError:
    PYSIDE_AVAILABLE = False

logger = logging.getLogger(__name__)


def generate_html_report(profile_name: str, log_dir: str, output_path: str) -> bool:
    """
    Liest die neueste Log-Datei für das Profil und generiert einen HTML-Bericht.
    """
    latest_log = _get_latest_log_file(log_dir)
    if not latest_log:
        logger.error(f"Keine Log-Datei in {log_dir} gefunden für den Bericht.")
        return False

    entries = []
    try:
        with open(latest_log, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass
    except Exception as e:
        logger.error(f"Fehler beim Lesen der Log-Datei {latest_log}: {e}")
        return False

    if not entries:
        logger.warning("Log-Datei ist leer.")
        return False

    html_content = _build_html(profile_name, entries)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Schreiben des HTML-Berichts nach {output_path}: {e}")
        return False


def generate_pdf_report(profile_name: str, log_dir: str, output_path: str) -> bool:
    """
    Liest die neueste Log-Datei, generiert HTML und exportiert es über QTextDocument als PDF.
    """
    if not PYSIDE_AVAILABLE:
        logger.error("PySide6.QtPrintSupport ist nicht verfügbar. PDF-Export nicht möglich.")
        return False

    latest_log = _get_latest_log_file(log_dir)
    if not latest_log:
        logger.error(f"Keine Log-Datei in {log_dir} gefunden für den PDF-Bericht.")
        return False

    entries = []
    try:
        with open(latest_log, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass
    except Exception as e:
        logger.error(f"Fehler beim Lesen der Log-Datei {latest_log}: {e}")
        return False

    if not entries:
        logger.warning("Log-Datei ist leer.")
        return False

    html_content = _build_html(profile_name, entries)

    try:
        doc = QTextDocument()
        doc.setHtml(html_content)

        printer = QPrinter()
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(output_path)

        doc.print_(printer)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen der PDF {output_path}: {e}")
        return False


def _get_latest_log_file(log_dir: str) -> str:
    try:
        if not os.path.exists(log_dir):
            return ""
        files = [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.endswith(".log")]
        return max(files, key=os.path.getctime) if files else ""
    except:
        return ""


def _build_html(profile_name: str, entries: list) -> str:
    # Style for the report
    html = f"""
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <title>Health-Check Bericht: {profile_name}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .header-info {{ margin-bottom: 30px; font-size: 14px; color: #7f8c8d; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; font-weight: bold; color: #2c3e50; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .level-ok {{ color: #27ae60; font-weight: bold; }}
            .level-warn {{ color: #f39c12; font-weight: bold; }}
            .level-error {{ color: #c0392b; font-weight: bold; }}
            .level-info {{ color: #2980b9; }}
        </style>
    </head>
    <body>
        <h1>Gambio Health-Check Bericht</h1>
        <div class="header-info">
            <p><strong>Shop-Profil:</strong> {profile_name}</p>
            <p><strong>Datum:</strong> {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</p>
        </div>
        <table>
            <thead>
                <tr>
                    <th style="width: 20%;">Zeit</th>
                    <th style="width: 15%;">Status</th>
                    <th>Nachricht</th>
                </tr>
            </thead>
            <tbody>
    """

    for entry in entries:
        level = entry.get("level", "INFO")
        msg = entry.get("msg", "")
        time_str = entry.get("time", "")

        css_class = "level-info"
        if "ERROR" in level:
            css_class = "level-error"
        elif "WARN" in level:
            css_class = "level-warn"
        elif "OK" in level or "ERFOLG" in msg.upper() or "BEREIT" in msg.upper():
            # Sometimes 'INFO' is used for successes. We can heuristic this or just rely on 'ERROR'/'WARN'
            pass

        html += f"""
                <tr>
                    <td>{time_str}</td>
                    <td class="{css_class}">{level}</td>
                    <td>{msg}</td>
                </tr>
        """

    html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    return html
