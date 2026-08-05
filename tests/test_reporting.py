import os
import json
import tempfile
from core.reporting import generate_html_report


def test_generate_html_report():
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_dir = os.path.join(tmp_dir, "logs")
        os.makedirs(log_dir)

        # Create dummy log file
        log_file = os.path.join(log_dir, "test.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "time": "2026-07-03 10:00:00",
                        "level": "INFO",
                        "msg": "Test start",
                    }
                )
                + "\n"
            )
            f.write(
                json.dumps(
                    {
                        "time": "2026-07-03 10:00:01",
                        "level": "WARN",
                        "msg": "Test warning",
                    }
                )
                + "\n"
            )

        output_html = os.path.join(tmp_dir, "report.html")

        result = generate_html_report("TestProfile", log_dir, output_html)

        assert result is True
        assert os.path.exists(output_html)

        with open(output_html, "r", encoding="utf-8") as f:
            content = f.read()

        assert "TestProfile" in content
        assert "Test start" in content
        assert "Test warning" in content
        assert "level-warn" in content
