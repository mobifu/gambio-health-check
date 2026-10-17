"""
Zentrales Logging-Modul mit Sicherheitsfilter zur Maskierung sensibler Daten.
Verhindert das versehentliche Schreiben von Passwörtern, Tokens und API-Keys in Log-Dateien.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

# Vorkompilierte reguläre Ausdrücke zur Maskierung sensibler Parameter
_KEY_VALUE_PATTERN = re.compile(
    r'(pass|pwd|password|key|token|auth)=[^&\s"\']+',
    flags=re.IGNORECASE,
)

_JSON_PATTERN = re.compile(
    r'("?(?:pass|pwd|password|key|token|auth)"?\s*[:=]\s*)(["\']).*?\2',
    flags=re.IGNORECASE,
)

DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def sanitize_sensitive_data(text: str) -> str:
    """
    Anonymisiert sensible Informationen wie Passwörter, API-Keys und Tokens in Zeichenketten.
    Berücksichtigt URL-Parameter, Key-Value-Paare und JSON-Strukturen.

    :param text: Die zu überprüfende und zu bereinigende Zeichenkette.
    :return: Anonymisierte Zeichenkette mit maskierten Geheimnissen.
    """
    if not isinstance(text, str):
        text = str(text)

    # 1. Schutz für URL-Parameter und einfache Key-Value-Paare (z. B. pass=secret, auth=abc123)
    text = _KEY_VALUE_PATTERN.sub(r"\1=********", text)

    # 2. Schutz für JSON-ähnliche Strukturen (z. B. "password": "secret" oder 'token': 'xyz')
    text = _JSON_PATTERN.sub(r"\1\2********\2", text)

    return text


class SensitiveFilter(logging.Filter):
    """
    Ein Logging-Filter, der sensible Informationen wie Passwörter, Keys und Tokens anonymisiert.
    Berücksichtigt sowohl formatierte Log-Records als auch Parameter in `record.args`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filtert und maskiert sensible Daten in einem Log-Datensatz.

        :param record: Der zu filternde Log-Datensatz.
        :return: Immer True, damit der Datensatz geloggt wird (jedoch maskiert).
        """
        try:
            if record.args:
                formatted_msg = record.getMessage()
                record.msg = sanitize_sensitive_data(formatted_msg)
                record.args = ()
            else:
                record.msg = sanitize_sensitive_data(str(record.msg))
        except Exception:
            record.msg = sanitize_sensitive_data(str(record.msg))

        return True


def setup_logging(
    level: int = logging.INFO,
    log_format: Optional[str] = None,
) -> None:
    """
    Initialisiert die globale Logging-Konfiguration idempotent.
    Aktiviert den SensitiveFilter für alle Handler des Root-Loggers, um Secrets in Logs zu verhindern.

    :param level: Das globale Logging-Level (Standard: logging.INFO).
    :param log_format: Optionales Logging-Format (Standard: DEFAULT_LOG_FORMAT).
    """
    fmt = log_format or DEFAULT_LOG_FORMAT
    logging.basicConfig(level=level, format=fmt)

    # Filter zu allen Root-Handlern hinzufügen, falls noch nicht vorhanden
    for handler in logging.root.handlers:
        if not any(isinstance(f, SensitiveFilter) for f in handler.filters):
            handler.addFilter(SensitiveFilter())
