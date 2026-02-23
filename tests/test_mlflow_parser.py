from __future__ import annotations

import unittest
from dataclasses import dataclass

from canari_forensics.parsers.mlflow_gateway import MLflowGatewayParser


@dataclass
class FakeEvent:
    name: str
    timestamp: str
    attributes: dict


@dataclass
class FakeSpan:
    span_id: str
    name: str
    start_time: str
    events: list[FakeEvent]


@dataclass
class FakeTraceData:
    spans: list[FakeSpan]


@dataclass
class FakeTrace:
    request_id: str
    data: FakeTraceData


class FakeMlflowClient:
    def __init__(self, traces):
        self._traces = traces

    def search_traces(self, experiment_ids, max_results):
        if experiment_ids != ["123"]:
            raise AssertionError("Unexpected experiment_ids")
        if max_results != 1000:
            raise AssertionError("Unexpected max_results")
        return self._traces


class MLflowParserTests(unittest.TestCase):
    def test_parse_mlflow_experiment_with_injected_client(self) -> None:
        trace = FakeTrace(
            request_id="req-1",
            data=FakeTraceData(
                spans=[
                    FakeSpan(
                        span_id="s1",
                        name="chat completions",
                        start_time="2026-02-22T14:29:00Z",
                        events=[
                            FakeEvent(
                                name="gen_ai.user.message",
                                timestamp="2026-02-22T14:29:01Z",
                                attributes={"content": "hello"},
                            ),
                            FakeEvent(
                                name="gen_ai.assistant.message",
                                timestamp="2026-02-22T14:29:02Z",
                                attributes={"content": "world"},
                            ),
                        ],
                    )
                ]
            ),
        )

        parser = MLflowGatewayParser()
        turns = list(
            parser.parse_mlflow_experiment(
                experiment_id="123",
                mlflow_client=FakeMlflowClient([trace]),
            )
        )

        self.assertEqual(len(turns), 2)
        self.assertEqual(turns[0].conversation_id, "req-1")
        self.assertEqual(turns[0].role, "user")
        self.assertEqual(turns[1].role, "assistant")
        self.assertEqual(turns[1].metadata["span_id"], "s1")
        self.assertTrue(all(t.source_format == "mlflow" for t in turns))


if __name__ == "__main__":
    unittest.main()
