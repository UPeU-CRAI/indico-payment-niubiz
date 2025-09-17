"""Lightweight subset of the requests-mock API for testing purposes."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


class _MockResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: Any = None,
        text: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}
        if text is not None:
            self.text = text
        elif json_data is not None:
            self.text = json.dumps(json_data)
        else:
            self.text = ""

    def json(self) -> Any:
        if self._json_data is None:
            raise ValueError("No JSON data configured")
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


class Mocker:
    """Minimal mocker implementing the subset used in the tests."""

    def __init__(self) -> None:
        self._registry: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self._original_request = None
        self._original_session_request = None
        self.request_history: List[SimpleNamespace] = []

    def __enter__(self) -> "Mocker":
        self._original_request = requests.request
        self._original_session_request = requests.sessions.Session.request
        requests.request = self._handle_request  # type: ignore[assignment]
        requests.sessions.Session.request = self._handle_session_request  # type: ignore[assignment]
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        requests.request = self._original_request  # type: ignore[assignment]
        requests.sessions.Session.request = self._original_session_request  # type: ignore[assignment]
        self._registry.clear()
        self.request_history.clear()

    def get(self, url: str, response=None, **kwargs: Any) -> None:
        self._add("GET", url, response, **kwargs)

    def post(self, url: str, response=None, **kwargs: Any) -> None:
        self._add("POST", url, response, **kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _add(self, method: str, url: str, response, **kwargs: Any) -> None:
        key = (method.upper(), url)
        if isinstance(response, list):
            entries = [self._normalize(entry) for entry in response]
        elif response is not None and not kwargs:
            entries = [self._normalize(response)]
        else:
            merged = dict(kwargs)
            if isinstance(response, dict):
                merged.update(response)
            entries = [self._normalize(merged)]
        self._registry[key] = entries

    def _handle_request(self, method: str, url: str, **kwargs: Any) -> _MockResponse:
        return self._dispatch(method, url, **kwargs)

    def _handle_session_request(self, session, method: str, url: str, **kwargs: Any) -> _MockResponse:  # type: ignore[override]
        return self._dispatch(method, url, **kwargs)

    def _dispatch(self, method: str, url: str, **kwargs: Any) -> _MockResponse:
        key = (method.upper(), url)
        if key not in self._registry:
            raise AssertionError(f"Unexpected request: {method.upper()} {url}")

        queue = self._registry[key]
        if len(queue) > 1:
            config = queue.pop(0)
        else:
            config = queue[0]

        record = SimpleNamespace(
            method=method.upper(),
            url=url,
            headers=kwargs.get("headers") or {},
            json=kwargs.get("json"),
        )
        self.request_history.append(record)

        return _MockResponse(
            status_code=config.get("status_code", 200),
            json_data=config.get("json"),
            text=config.get("text"),
            headers=config.get("headers"),
        )

    @staticmethod
    def _normalize(config: Any) -> Dict[str, Any]:
        if isinstance(config, dict):
            return dict(config)
        raise TypeError("Unsupported response configuration")


__all__ = ["Mocker"]
