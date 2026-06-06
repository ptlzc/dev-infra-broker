from __future__ import annotations

from unittest import TestCase
from unittest.mock import patch

from fastapi import HTTPException

from app.kubernetes_diagnostics_queries import _build_pod_logs_response, _list_events_payload
from app.kubernetes_diagnostics_resources import _pod_detail_response, _run_identity
from app.kubernetes_diagnostics_models import _event_summary, _pod_failure_summary


class FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text

    def json(self):
        raise ValueError("not json")


class KubernetesDiagnosticsTests(TestCase):
    def test_run_identity_extracts_common_keys(self) -> None:
        identity = _run_identity(
            {
                "labels": {
                    "dagster.io/run-id": "run-123",
                    "dagster.io/tag.env": "prod",
                },
                "annotations": {
                    "dagster.io/job-name": "my-job",
                    "dagster.io/code-location": "code-location-1",
                },
            }
        )

        self.assertEqual(identity["runId"], "run-123")
        self.assertEqual(identity["jobName"], "my-job")
        self.assertEqual(identity["codeLocation"], "code-location-1")
        self.assertEqual(identity["runTags"], {"dagster.io/tag.env": "prod"})

    def test_event_summary_redacts_sensitive_message(self) -> None:
        summary = _event_summary(
            {
                "metadata": {"name": "event-1"},
                "type": "Warning",
                "reason": "FailedMount",
                "message": "password=secret token=abc",
                "count": 1,
                "firstTimestamp": "2025-01-01T00:00:00Z",
                "lastTimestamp": "2025-01-01T00:01:00Z",
                "eventTime": "2025-01-01T00:00:30Z",
                "involvedObject": {"kind": "Pod", "name": "pod-1", "secret": "value"},
                "source": {"component": "kubelet", "host": "node-1"},
            }
        )

        self.assertIn("[REDACTED]", summary["message"])
        self.assertEqual(summary["involvedObject"]["secret"], "[REDACTED]")

    def test_event_listing_sorts_newest_first(self) -> None:
        payload = {
            "items": [
                {"metadata": {"name": "old"}, "lastTimestamp": "2025-01-01T00:00:01Z"},
                {"metadata": {"name": "new"}, "lastTimestamp": "2025-01-01T00:00:02Z"},
            ]
        }

        with patch("app.kubernetes_diagnostics_queries._kubernetes_json_request", return_value=payload) as mocked:
            events, selector = _list_events_payload(
                "ns-1",
                involved_object_kind="Pod",
                involved_object_name="pod-1",
                involved_object_uid="uid-1",
            )

        self.assertEqual(selector, "involvedObject.kind=Pod,involvedObject.name=pod-1,involvedObject.uid=uid-1")
        self.assertEqual([item["metadata"]["name"] for item in events], ["new", "old"])
        mocked.assert_called_once()

    def test_pod_logs_fallback_redacts_and_reports_backend_error(self) -> None:
        with patch("app.kubernetes_diagnostics_queries._kubernetes_request", return_value=FakeResponse(502, "password=secret")), patch(
            "app.kubernetes_diagnostics_queries._read_local_pod_logs",
            return_value="password=secret\nhello",
        ):
            response = _build_pod_logs_response(
                "ns-1",
                "pod-1",
                selection={"mode": "pod"},
                container=None,
                previous=False,
                tail_lines=200,
                since_seconds=None,
                limit_bytes=None,
                timestamps=False,
            )

        self.assertEqual(response.source, "local-node-log-file")
        self.assertTrue(response.redacted)
        self.assertIn("[REDACTED]", response.logs)
        self.assertEqual(response.backendError["statusCode"], 502)

    def test_previous_logs_missing_returns_reason(self) -> None:
        with patch("app.kubernetes_diagnostics_queries._kubernetes_request", return_value=FakeResponse(404, "previous unavailable")), patch(
            "app.kubernetes_diagnostics_queries._read_local_pod_logs",
            side_effect=FileNotFoundError,
        ):
            response = _build_pod_logs_response(
                "ns-1",
                "pod-1",
                selection={"mode": "pod"},
                container=None,
                previous=True,
                tail_lines=200,
                since_seconds=None,
                limit_bytes=None,
                timestamps=False,
            )

        self.assertEqual(response.logs, "")
        self.assertFalse(response.previousAvailable)
        self.assertIsNotNone(response.previousUnavailableReason)

    def test_pod_detail_includes_failure_summary_and_links(self) -> None:
        pod_payload = {
            "metadata": {
                "name": "pod-1",
                "namespace": "ns-1",
                "uid": "uid-1",
                "creationTimestamp": "2025-01-01T00:00:00Z",
                "labels": {"app": "demo"},
                "annotations": {"dagster.io/run-id": "run-1", "token": "secret"},
            },
            "spec": {
                "nodeName": "node-1",
                "containers": [
                    {
                        "name": "main",
                        "image": "busybox:latest",
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}},
                        "volumeMounts": [{"name": "v1", "mountPath": "/data"}],
                    }
                ],
            },
            "status": {
                "phase": "Running",
                "podIP": "10.0.0.1",
                "hostIP": "10.0.0.2",
                "startTime": "2025-01-01T00:00:10Z",
                "containerStatuses": [
                    {
                        "name": "main",
                        "ready": False,
                        "restartCount": 3,
                        "image": "busybox:latest",
                        "imageID": "docker://sha256:abc",
                        "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "boom"}},
                        "lastState": {"terminated": {"reason": "OOMKilled", "message": "memory"}},
                    }
                ],
                "conditions": [{"type": "Ready", "status": "False", "reason": "ContainersNotReady", "message": "not ready"}],
            },
        }
        events_payload = (
            [
                {
                    "metadata": {"name": "event-1"},
                    "type": "Warning",
                    "reason": "FailedMount",
                    "message": "secret=abc",
                    "count": 1,
                    "lastTimestamp": "2025-01-01T00:02:00Z",
                    "involvedObject": {"kind": "Pod", "name": "pod-1"},
                }
            ],
            "involvedObject.kind=Pod,involvedObject.name=pod-1,involvedObject.uid=uid-1",
        )

        with patch("app.kubernetes_diagnostics_resources._pod_payload", return_value=pod_payload), patch(
            "app.kubernetes_diagnostics_resources._list_events_payload",
            return_value=events_payload,
        ):
            response = _pod_detail_response("ns-1", "pod-1")

        self.assertEqual(response["diagnosticLinks"]["currentLogs"], "/v1/kubernetes/namespaces/ns-1/pods/pod-1/logs")
        self.assertEqual(response["failureSummary"]["lastTerminationReason"], "OOMKilled")
        self.assertNotIn("token", response["annotations"])
        self.assertEqual(response["failureSummary"]["recentEvents"][0]["reason"], "FailedMount")
