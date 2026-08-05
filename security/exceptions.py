class SecurityError(Exception):
    """Basis-Klasse für alle sicherheitsrelevanten Fehler im Modul."""

    pass


class InvalidMasterPasswordError(SecurityError):
    """Wird geworfen, wenn das Master-Passwort falsch ist oder die verschlüsselte Datei manipuliert wurde."""

    pass


class TooManyFailedAttemptsError(SecurityError):
    """
    Wird geworfen, wenn zu viele Fehlversuche beim Master-Passwort auftreten
    und der Brute-Force-Schutz das System sperrt.
    """

    pass


class SessionExpiredError(SecurityError):
    """Wird geworfen, wenn die Session-Zeit durch Inaktivität überschritten wurde."""

    pass
