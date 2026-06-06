from __future__ import annotations

from unittest import TestCase

from app.capabilities import capabilities_payload


class CapabilitiesTests(TestCase):
    def test_capabilities_are_grouped_by_domain(self) -> None:
        payload = capabilities_payload()

        domains = {item["name"]: item for item in payload["domains"]}
        self.assertIn("platform-secret", domains)
        self.assertIn("core-observability", domains)
        self.assertIn("workload-intelligence", domains)
        self.assertIn("GET /v1/kubernetes/namespaces/<namespace>/jobs", domains["workload-intelligence"]["interfaces"])
        self.assertIn("GET /v1/argocd/applications/<name>", domains["core-observability"]["interfaces"])
