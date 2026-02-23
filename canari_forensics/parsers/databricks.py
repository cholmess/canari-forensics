from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

from canari_forensics.models import ConversationTurn
from canari_forensics.parsers.otel import CONTENT_FIELDS, ROLE_MAP, OTELParser


class DatabricksAIGatewayParser(OTELParser):
    """OTEL parser with MLflow/Databricks trace retrieval helpers."""

    def parse_mlflow_experiment(
        self,
        experiment_id: str,
        tracking_uri: str = "databricks",
        max_results: int = 1000,
        mlflow_client: Any | None = None,
    ) -> Iterator[ConversationTurn]:
        """Query MLflow traces and yield normalized conversation turns."""
        client = mlflow_client
        if client is None:
            try:
                import mlflow  # type: ignore
            except ImportError as exc:
                raise RuntimeError(
                    "mlflow is required for Databricks source. Install mlflow or provide mlflow_client."
                ) from exc

            mlflow.set_tracking_uri(tracking_uri)
            client = mlflow.tracking.MlflowClient()

        traces = client.search_traces(experiment_ids=[experiment_id], max_results=max_results)
        for trace in traces:
            yield from self._parse_mlflow_trace_object(trace)

    def _parse_mlflow_trace_object(self, trace: Any) -> Iterator[ConversationTurn]:
        trace_id = self._extract_trace_id(trace)
        spans = self._extract_spans(trace)

        raw_turns: list[tuple[datetime, str, str, dict[str, Any]]] = []
        for span in spans:
            span_id = self._span_attr(span, "span_id", "spanId")
            span_name = self._span_attr(span, "name")
            span_start = self._parse_any_timestamp(
                self._span_attr(span, "start_time", "startTimeUnixNano", "start_time_unix_nano")
            ) or datetime.now(timezone.utc)

            events = self._span_attr(span, "events") or []
            for event in events:
                event_name = self._event_attr(event, "name")
                role = ROLE_MAP.get(str(event_name))
                if role is None:
                    continue

                attrs = self._event_attr(event, "attributes") or {}
                content = self._extract_content_from_any(attrs)
                if not content:
                    continue

                event_ts = self._parse_any_timestamp(
                    self._event_attr(event, "timestamp", "time_unix_nano", "timeUnixNano")
                ) or span_start

                raw_turns.append(
                    (
                        event_ts,
                        role,
                        content,
                        {
                            "span_id": str(span_id or ""),
                            "span_name": str(span_name or ""),
                            "event_name": str(event_name or ""),
                        },
                    )
                )

        raw_turns.sort(key=lambda t: t[0])
        for idx, (timestamp, role, content, metadata) in enumerate(raw_turns):
            yield ConversationTurn(
                conversation_id=trace_id,
                turn_index=idx,
                role=role,
                content=content,
                timestamp=timestamp,
                metadata=metadata,
                source_format="databricks",
            )

    def _extract_trace_id(self, trace: Any) -> str:
        candidates = [
            self._obj_attr(trace, "request_id", "requestId", "trace_id", "traceId"),
            self._obj_attr(self._obj_attr(trace, "info"), "request_id", "requestId", "trace_id", "traceId"),
            self._obj_attr(self._obj_attr(trace, "data"), "request_id", "requestId", "trace_id", "traceId"),
        ]
        for c in candidates:
            if c is not None and str(c).strip():
                return str(c)
        return "mlflow-trace"

    def _extract_spans(self, trace: Any) -> list[Any]:
        data_obj = self._obj_attr(trace, "data")
        spans = self._obj_attr(data_obj, "spans")
        if isinstance(spans, list):
            return spans

        trace_obj = self._obj_attr(trace, "trace")
        trace_data = self._obj_attr(trace_obj, "data")
        spans = self._obj_attr(trace_data, "spans")
        if isinstance(spans, list):
            return spans

        return []

    def _extract_content_from_any(self, attributes: Any) -> str:
        if isinstance(attributes, dict):
            return self._extract_content(attributes)

        if isinstance(attributes, list):
            normalized: dict[str, Any] = {}
            for item in attributes:
                if isinstance(item, dict) and "key" in item:
                    normalized[str(item["key"])] = item.get("value")
            for field in CONTENT_FIELDS:
                val = normalized.get(field)
                if val is None:
                    continue
                if isinstance(val, dict):
                    scalar = self._unwrap_otlp_value(val)
                else:
                    scalar = val
                if scalar is None:
                    continue
                text = str(scalar).strip()
                if text:
                    return text

        return ""

    def _obj_attr(self, obj: Any, *names: str) -> Any:
        if obj is None:
            return None
        for name in names:
            if isinstance(obj, dict) and name in obj:
                return obj[name]
            if hasattr(obj, name):
                return getattr(obj, name)
        return None

    def _span_attr(self, span: Any, *names: str) -> Any:
        return self._obj_attr(span, *names)

    def _event_attr(self, event: Any, *names: str) -> Any:
        return self._obj_attr(event, *names)
