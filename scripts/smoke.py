from __future__ import annotations

import argparse
import sys

import httpx


def _request(client: httpx.Client, method: str, url: str) -> tuple[bool, str]:
    try:
        response = client.request(method, url, timeout=20.0)
    except httpx.HTTPError as exc:
        return False, f"request-failed: {exc}"
    if response.status_code in {401, 403}:
        return False, f"permission-failed: {response.status_code}"
    if response.status_code >= 400:
        return False, f"query-failed: {response.status_code}"
    return True, "ok"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--domain", choices=["core", "workload"], required=True)
    parser.add_argument("--namespace", default="quant")
    parser.add_argument("--name", default="dagster")
    parser.add_argument("--run-id", default="run-1")
    args = parser.parse_args()

    with httpx.Client() as client:
        if args.domain == "core":
            checks = [
                ("GET", f"{args.base_url}/healthz"),
                ("GET", f"{args.base_url}/v1/capabilities"),
                ("GET", f"{args.base_url}/v1/kubernetes/namespaces/{args.namespace}/pods"),
                ("GET", f"{args.base_url}/v1/kubernetes/namespaces/{args.namespace}/deployments/{args.name}"),
                ("GET", f"{args.base_url}/v1/argocd/applications/{args.name}"),
            ]
        else:
            checks = [
                ("GET", f"{args.base_url}/v1/kubernetes/namespaces/{args.namespace}/jobs"),
                ("GET", f"{args.base_url}/v1/kubernetes/namespaces/{args.namespace}/jobs/{args.name}"),
                ("GET", f"{args.base_url}/v1/kubernetes/namespaces/{args.namespace}/dagster/runs/{args.run_id}"),
            ]

        failed = False
        for method, url in checks:
            ok, state = _request(client, method, url)
            print(f"{method} {url} {state}")
            failed = failed or not ok
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
