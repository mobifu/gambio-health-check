import logging
import re


class SensitiveFilter(logging.Filter):
    """
    Ein Logging-Filter, der sensible Informationen wie Passwörter, Keys und Tokens anonymisiert.
    Berücksichtigt sowohl URL-Parameter/Key-Value-Paare als auch JSON-Strukturen.
    """

    def filter(self, record):
        # Sicherstellen, dass die Nachricht ein String ist
        msg = str(record.msg)

        # 1. Schutz für URL-Parameter und einfache Key-Value-Paare (z.B. pass=secret, auth=abc123)
        # Erweitert um 'password' und robustere Erkennung
        msg = re.sub(
            r'(pass|pwd|password|key|token|auth)=[^&\s"\']+',
            r"\1=********",
            msg,
            flags=re.IGNORECASE,
        )

        # 2. Schutz für JSON-ähnliche Strukturen (z.B. "password": "secret" oder "token": "xyz")
        msg = re.sub(
            r'("?(?:pass|pwd|password|key|token|auth)"?\s*[:=]\s*)(["\']).*?\2',
            r"\1\2********\2",
            msg,
            flags=re.IGNORECASE,
        )

        record.msg = msg
        return True


def setup_logging():
    """
    Initialisiert die globale Logging-Konfiguration.
    Aktiviert den SensitiveFilter für alle Handler des Root-Loggers, um Secrets in Logs zu verhindern.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    for handler in logging.root.handlers:
        handler.addFilter(SensitiveFilter())
