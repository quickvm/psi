"""A stand-in Infisical: what Infisical's SDK, and PSI through it, asks of one.

It answers where the client's adapter hands a request to the network
(``psi.providers.infisical.api._deliver``), so the SDK's own requests, parsing, retries and
errors all run. Folders hold secrets by (project, environment, path); every request that
reached it is recorded with what it was sent with.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

import requests
from requests.structures import CaseInsensitiveDict

if TYPE_CHECKING:
    from collections.abc import Callable

type Folder = tuple[str, str, str]

LOGINS = ("universal-auth", "aws-auth", "gcp-auth", "azure-auth")


@dataclass(frozen=True)
class Sent:
    """A request that reached the stand-in."""

    method: str
    url: str
    headers: dict[str, str]
    body: Any
    kwargs: dict[str, Any]

    @property
    def path(self) -> str:
        return urlsplit(self.url).path

    @property
    def params(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlsplit(self.url).query).items()}


@dataclass
class FakeInfisical:
    """One instance with a universal-auth identity and an identity for cloud logins."""

    client_id: str = "test-client"
    client_secret: str = "test-secret"
    identity_id: str = "test-identity"
    token: str = "access-token-1"
    expires_in: int = 7200
    folders: dict[Folder, dict[str, str]] = field(default_factory=dict)
    answers: dict[tuple[str, str], Callable[[requests.PreparedRequest], requests.Response]] = field(
        default_factory=dict
    )
    """Replies a test sets for a (method, path), in place of the usual ones."""
    sent: list[Sent] = field(default_factory=list)

    def deliver(
        self, adapter: object, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
        del adapter
        raw = request.body
        body = json.loads(raw) if isinstance(raw, (str, bytes)) and raw else None
        headers = {name: str(value) for name, value in request.headers.items()}
        sent = Sent(request.method or "", request.url or "", headers, body, kwargs)
        self.sent.append(sent)
        override = self.answers.get((sent.method, sent.path))
        if override is not None:
            return override(request)
        return self._route(request, sent)

    def _route(self, request: requests.PreparedRequest, sent: Sent) -> requests.Response:
        parts = sent.path.strip("/").split("/")
        if sent.method == "POST" and parts[:3] == ["api", "v1", "auth"] and parts[3] in LOGINS:
            return self._login(request, parts[3], sent.body or {})
        if sent.headers.get("Authorization") != f"Bearer {self.token}":
            return reply(request, 401, {"message": "Token missing or invalid"})
        if parts[:4] == ["api", "v3", "secrets", "raw"]:
            return self._secrets(request, sent, parts[4] if len(parts) > 4 else None)
        if sent.method == "POST" and sent.path == "/api/v2/folders":
            return self._folder(request, sent.body)
        if sent.method == "POST" and sent.path == "/api/v4/secrets/batch":
            return self._batch(request, sent.body)
        if sent.method == "POST" and parts[:4] == ["api", "v1", "cert-manager", "certificates"]:
            return reply(request, 200, {"certificate": certificate(parts[4:])})
        return reply(request, 404, {"message": f"no route for {sent.method} {sent.path}"})

    def _login(
        self, request: requests.PreparedRequest, method: str, body: dict[str, Any]
    ) -> requests.Response:
        if method == "universal-auth":
            valid = (body.get("clientId"), body.get("clientSecret")) == (
                self.client_id,
                self.client_secret,
            )
        else:
            valid = body.get("identityId") == self.identity_id
        if not valid:
            return reply(request, 401, {"message": "Invalid credentials"})
        login = {
            "accessToken": self.token,
            "expiresIn": self.expires_in,
            "accessTokenMaxTTL": self.expires_in,
            "tokenType": "Bearer",
        }
        return reply(request, 200, login)

    def _secrets(
        self, request: requests.PreparedRequest, sent: Sent, name: str | None
    ) -> requests.Response:
        source = sent.params if sent.method == "GET" else (sent.body or {})
        project = source.get("workspaceId", "")
        environment = source.get("environment", "")
        path = source.get("secretPath", "/")
        folder = (project, environment, path)
        if name is None:
            recursive = sent.params.get("recursive") == "true"
            return self._listing(request, project, environment, path, recursive=recursive)
        if sent.method == "POST":
            self.folders.setdefault(folder, {})[name] = source["secretValue"]
        elif sent.method == "PATCH":
            if name not in self.folders.get(folder, {}):
                return reply(request, 404, {"message": f"Secret {name} not found"})
            self.folders[folder][name] = source["secretValue"]
        elif name not in self.folders.get(folder, {}):
            return reply(request, 404, {"message": f"Secret {name} not found"})
        return reply(request, 200, {"secret": secret(name, self.folders[folder][name], path)})

    def _listing(
        self,
        request: requests.PreparedRequest,
        project: str,
        environment: str,
        path: str,
        *,
        recursive: bool,
    ) -> requests.Response:
        if (project, environment, path) not in self.folders:
            return reply(request, 404, {"message": "Folder not found"})
        below = path.rstrip("/") + "/"
        listed = [
            secret(key, value, where)
            for (p, e, where), values in self.folders.items()
            if (p, e) == (project, environment)
            and (where == path or (recursive and where.startswith(below)))
            for key, value in values.items()
        ]
        return reply(request, 200, {"secrets": listed, "imports": []})

    def _folder(self, request: requests.PreparedRequest, body: dict[str, Any]) -> requests.Response:
        parent = body["path"].rstrip("/")
        path = f"{parent}/{body['name']}"
        folder = (body["projectId"], body["environment"], path)
        if folder in self.folders:
            return reply(request, 400, {"message": "Folder with this name already exists"})
        self.folders[folder] = {}
        created = {
            "id": f"folder-{len(self.folders)}",
            "name": body["name"],
            "createdAt": "2026-10-06T00:00:00Z",
            "updatedAt": "2026-10-06T00:00:00Z",
            "envId": body["environment"],
            "path": path,
        }
        return reply(request, 200, {"folder": created})

    def _batch(self, request: requests.PreparedRequest, body: dict[str, Any]) -> requests.Response:
        folder = (body["projectId"], body["environment"], body["secretPath"])
        created = self.folders.setdefault(folder, {})
        for each in body["secrets"]:
            created[each["secretKey"]] = each["secretValue"]
        listed = [secret(s["secretKey"], s["secretValue"], folder[2]) for s in body["secrets"]]
        return reply(request, 200, {"secrets": listed})


def secret(key: str, value: str, path: str) -> dict[str, Any]:
    """One secret as Infisical's raw API lists it."""
    return {
        "id": f"id-{key}",
        "_id": f"id-{key}",
        "workspace": "",
        "environment": "prod",
        "version": 1,
        "type": "shared",
        "secretKey": key,
        "secretValue": value,
        "secretComment": "",
        "secretPath": path,
        "createdAt": "2026-10-06T00:00:00Z",
        "updatedAt": "2026-10-06T00:00:00Z",
    }


def certificate(parts: list[str]) -> dict[str, str]:
    """A certificate as Infisical issues one, or renews ``parts[0]`` (``<id>/renew``)."""
    certificate_id = parts[0] if parts else "cert-1"
    return {
        "certificate": f"certificate of {certificate_id}",
        "certificateChain": "chain",
        "issuingCaCertificate": "issuing CA",
        "privateKey": f"key of {certificate_id}",
        "serialNumber": "01",
        "certificateId": certificate_id,
    }


def reply(
    request: requests.PreparedRequest,
    status: int,
    body: Any,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    """A response to ``request``, as requests builds one from the network."""
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response._content_consumed = True
    response.headers = CaseInsensitiveDict({"Content-Type": "application/json", **(headers or {})})
    response.url = request.url or ""
    response.request = request
    response.encoding = "utf-8"
    return response
