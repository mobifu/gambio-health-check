import os
import ftplib
import json
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from core.hash_engine import HashCheckEngine


@patch("core.hash_engine.hashlib.sha256")
def test_hash_engine_large_scale_performance(mock_sha256):
    """
    Simuliert einen Shop mit einer extrem großen Anzahl an Dateien (z.B. 50.000).
    Stellt sicher, dass HashCheckEngine.generate_baseline() ohne abzustürzen durchläuft
    und dass das UI-Progress-Signal nicht bei jeder Datei feuert (Performance-Optimierung).
    """
    # Setup mocks
    mock_conn = MagicMock(spec=ftplib.FTP)

    # Mocking _get_remote_files_recursive to return 50,000 dummy files directly
    # um die Rekursion des MLSD/LIST Mocks zu vereinfachen und nur die Hashing/Speicher-Schleife zu testen.
    NUM_FILES = 50000
    dummy_files = [f"dir/file_{i}.php" for i in range(NUM_FILES)]

    mock_worker = MagicMock()
    mock_worker._is_cancelled = False

    # Dummy Hash-Wert zurückgeben
    mock_hash = MagicMock()
    mock_hash.hexdigest.return_value = "dummyhash1234567890abcdef"
    mock_sha256.return_value = mock_hash

    # Engine initialisieren
    engine = HashCheckEngine(profile_name="PerformanceTestShop", conn=mock_conn, worker=mock_worker)

    # Speicherort auf ein temporäres Verzeichnis umbiegen
    tmp_dir = tempfile.mkdtemp()
    try:
        engine.hash_dir = tmp_dir
        engine.baseline_path = os.path.join(tmp_dir, "baseline.json")

        # _get_remote_files_recursive direkt patchen
        with patch.object(engine, "_get_remote_files_recursive", return_value=dummy_files):
            # generate_hash so patchen, dass es keinen echten FTP-Download macht
            with patch.object(
                engine,
                "generate_hash",
                return_value=("dummyhash1234567890abcdef", b"dummy content"),
            ):
                engine.generate_baseline()

        # Überprüfen, ob die Baseline geschrieben wurde
        assert os.path.exists(engine.baseline_path)

        # Überprüfen, ob sie die korrekte Anzahl an Einträgen hat
        with open(engine.baseline_path, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)
            assert len(baseline_data) == NUM_FILES
            assert baseline_data["dir/file_0.php"] == "dummyhash1234567890abcdef"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Überprüfen der UI-Optimierung (progress_signal sollte nicht für jede Datei aufgerufen werden)
    # Bei 50.000 Dateien und einem Intervall von 500 erwarten wir etwa 100 Aufrufe
    emit_calls = mock_worker.progress_signal.emit.call_count

    # +1 für "Suche Dateien auf dem Server..."
    assert emit_calls <= (NUM_FILES // 500) + 5
    assert emit_calls >= (NUM_FILES // 500)
