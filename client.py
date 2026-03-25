"""Python client for safe-docker API.

API: /v1/projects/{project}/services/{service}/{action}
Auth: X-API-Key header
"""
from __future__ import annotations

from typing import Any

import requests


class SafeDockerClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        project: str,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.project = project
        self.headers = {"X-API-Key": api_key}
        self.timeout = timeout
        self.session = requests.Session()

    def _get(self, path: str, **kwargs: Any) -> Any:
        resp = self.session.get(
            f"{self.base_url}{path}",
            headers=self.headers,
            timeout=self.timeout,
            **kwargs,
        )
        resp.raise_for_status()
        return resp

    def _post(self, path: str) -> Any:
        resp = self.session.post(
            f"{self.base_url}{path}",
            headers=self.headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # --- Read-only ---

    def health(self) -> dict[str, Any]:
        """Health check (no auth required)."""
        resp = self.session.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def projects(self) -> list[dict[str, Any]]:
        """List all configured projects."""
        return self._get("/v1/projects").json()["projects"]

    def services(self, project: str | None = None) -> list[dict[str, Any]]:
        """List services in a project."""
        proj = project or self.project
        return self._get(f"/v1/projects/{proj}/services").json()["services"]

    def status(self, service: str, project: str | None = None) -> dict[str, Any]:
        """Status of a specific service."""
        proj = project or self.project
        return self._get(f"/v1/projects/{proj}/services/{service}/status").json()

    def logs(self, service: str, tail: int = 100, project: str | None = None) -> str:
        """Tail the last N lines of logs from a service."""
        proj = project or self.project
        resp = self._get(f"/v1/projects/{proj}/services/{service}/logs", params={"tail": tail})
        return resp.text

    # --- Container lifecycle (Docker SDK) ---

    def restart(self, service: str, project: str | None = None) -> dict[str, Any]:
        """Restart a specific service."""
        proj = project or self.project
        return self._post(f"/v1/projects/{proj}/services/{service}/restart")

    def start(self, service: str, project: str | None = None) -> dict[str, Any]:
        """Start a stopped service."""
        proj = project or self.project
        return self._post(f"/v1/projects/{proj}/services/{service}/start")

    def stop(self, service: str, project: str | None = None) -> dict[str, Any]:
        """Stop a running service."""
        proj = project or self.project
        return self._post(f"/v1/projects/{proj}/services/{service}/stop")

    # --- Compose operations ---

    def up(self, service: str, project: str | None = None) -> dict[str, Any]:
        """docker compose up -d <service>"""
        proj = project or self.project
        return self._post(f"/v1/projects/{proj}/services/{service}/up")

    def down(self, service: str, project: str | None = None) -> dict[str, Any]:
        """docker compose down <service>"""
        proj = project or self.project
        return self._post(f"/v1/projects/{proj}/services/{service}/down")

    # --- Dangerous operations (require dangerous: true in policy) ---

    def recreate(self, service: str, project: str | None = None) -> dict[str, Any]:
        """docker compose up -d --force-recreate <service>"""
        proj = project or self.project
        return self._post(f"/v1/projects/{proj}/services/{service}/recreate")

    def build(self, service: str, project: str | None = None) -> dict[str, Any]:
        """docker compose build <service>"""
        proj = project or self.project
        return self._post(f"/v1/projects/{proj}/services/{service}/build")
