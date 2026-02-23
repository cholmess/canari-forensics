from __future__ import annotations

import io
import json
import time
import unittest
from pathlib import Path

from canari_forensics.parsers.otel import OTELParser

FIXTURES = Path(__file__).parent / "fixtures"


class OTELParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = OTELParser()

    def test_parse_otlp_json_fixture(self) -> None:
        turns = list(self.parser.parse_file(FIXTURES / "otlp_sample.json"))

        self.assertEqual(len(turns), 3)
        self.assertEqual([t.role for t in turns], ["user", "assistant", "assistant"])
        self.assertEqual(turns[0].conversation_id, "0xtraceA")
        self.assertIn("sk_test_CANARI", turns[1].content)
        self.assertEqual(turns[2].metadata["span_id"], "0xspan2")
        self.assertEqual([t.turn_index for t in turns], [0, 1, 2])

    def test_parse_mlflow_native_fixture(self) -> None:
        turns = list(self.parser.parse_file(FIXTURES / "mlflow_trace_sample.json"))

        self.assertEqual(len(turns), 2)
        self.assertTrue(all(t.source_format == "mlflow" for t in turns))
        self.assertEqual(turns[0].conversation_id, "req-abc123")
        self.assertEqual(turns[0].role, "system")
        self.assertEqual(turns[1].role, "assistant")

    def test_parse_directory(self) -> None:
        turns = list(self.parser.parse_directory(FIXTURES))
        self.assertGreaterEqual(len(turns), 5)

    def test_parse_stream(self) -> None:
        payload = {
            "spans": [
                {
                    "trace_id": "trace-stream",
                    "span_id": "span-stream",
                    "start_time": "2026-02-22T14:29:00Z",
                    "events": [
                        {
                            "name": "gen_ai.assistant.message",
                            "timestamp": "2026-02-22T14:29:01Z",
                            "attributes": {"content": "streamed message"},
                        }
                    ],
                }
            ]
        }
        turns = list(self.parser.parse_stream(io.StringIO(json.dumps(payload))))
        self.assertEqual(len(turns), 1)
        self.assertEqual(turns[0].content, "streamed message")

    def test_performance_target_10k_turns_per_second(self) -> None:
        spans = []
        base = 1_708_698_540_000_000_000
        n_spans = 2_000
        for i in range(n_spans):
            spans.append(
                {
                    "trace_id": "perf-trace",
                    "span_id": f"span-{i}",
                    "start_time": base + i * 1_000,
                    "events": [
                        {
                            "name": "gen_ai.assistant.message",
                            "time_unix_nano": base + i * 1_000 + 1,
                            "attributes": {"content": f"message-{i}"},
                        },
                        {
                            "name": "gen_ai.assistant.message",
                            "time_unix_nano": base + i * 1_000 + 2,
                            "attributes": {"content": f"message-{i}-b"},
                        },
                    ],
                }
            )

        payload = {"spans": spans}
        started = time.perf_counter()
        turns = list(self.parser.parse_stream(io.StringIO(json.dumps(payload))))
        elapsed = time.perf_counter() - started
        throughput = len(turns) / elapsed if elapsed > 0 else float("inf")

        self.assertEqual(len(turns), n_spans * 2)
        self.assertGreaterEqual(
            throughput,
            10_000,
            f"Expected >=10k turns/s, got {throughput:.1f} turns/s",
        )


if __name__ == "__main__":
    unittest.main()
