import json
import logging
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote

import requests


class SplunkKV:
    def __init__(
        self,
        base_url: str,
        app: str,
        owner: str = "nobody",
        token: Optional[str] = None,
        auth: Optional[Tuple[str, str]] = None,
        verify_tls: bool = True,
        timeout_s: int = 60,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.app = app
        self.owner = owner
        self.verify_tls = verify_tls
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

        if token:
            self.session.headers.update({"Authorization": f"Splunk {token}"})
        if auth:
            self.session.auth = auth

    def _should_retry(self, exc: Exception) -> bool:
        """Determine if an exception warrants a retry."""
        if isinstance(exc, requests.exceptions.ConnectionError):
            return True
        if isinstance(exc, requests.exceptions.Timeout):
            return True
        if isinstance(exc, requests.exceptions.HTTPError):
            # Retry on server errors (5xx) but not client errors (4xx)
            if hasattr(exc, "response") and exc.response is not None:
                return exc.response.status_code >= 500
        return False

    def _retry_request(self, operation: str, func, *args, **kwargs):
        """Execute a function with exponential backoff retry logic."""
        last_exception = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                last_exception = exc
                if attempt < self.max_retries and self._should_retry(exc):
                    delay = self.retry_delay * (2 ** (attempt - 1))
                    logging.warning(
                        f"{operation} failed (attempt {attempt}/{self.max_retries}): {exc}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)
                else:
                    break

        # All retries exhausted or non-retryable error
        if self._should_retry(last_exception):
            logging.error(f"{operation} failed after {self.max_retries} attempts: {last_exception}")
        raise last_exception

    def batch_save(self, collection: str, docs: List[Dict], chunk_size: int = 500) -> None:
        if not docs:
            return
        url = (
            f"{self.base_url}/servicesNS/{self.owner}/{self.app}/"
            f"storage/collections/data/{collection}/batch_save"
        )
        num_chunks = (len(docs) + chunk_size - 1) // chunk_size
        for i in range(0, len(docs), chunk_size):
            chunk = docs[i : i + chunk_size]
            chunk_num = (i // chunk_size) + 1
            logging.debug(f"Writing chunk {chunk_num}/{num_chunks} ({len(chunk)} docs) to {collection}")

            def _do_post():
                response = self.session.post(
                    url,
                    data=json.dumps(chunk),
                    verify=self.verify_tls,
                    timeout=self.timeout_s,
                )
                if not response.ok:
                    raise requests.exceptions.HTTPError(
                        f"HTTP {response.status_code}: {response.text}",
                        response=response,
                    )
                return response

            self._retry_request(
                f"batch_save to {collection} (chunk {chunk_num}/{num_chunks})",
                _do_post,
            )

    def list_keys(self, collection: str) -> Set[str]:
        url = (
            f"{self.base_url}/servicesNS/{self.owner}/{self.app}/"
            f"storage/collections/data/{collection}"
        )

        def _do_get():
            response = self.session.get(
                url,
                params={"count": 0, "fields": "_key"},
                verify=self.verify_tls,
                timeout=self.timeout_s,
            )
            if not response.ok:
                raise requests.exceptions.HTTPError(
                    f"HTTP {response.status_code}: {response.text}",
                    response=response,
                )
            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Invalid JSON response from {collection}") from exc

            keys: Set[str] = set()
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict) and "_key" in item:
                        keys.add(str(item["_key"]))
            return keys

        return self._retry_request(f"list_keys from {collection}", _do_get)

    def delete_keys(self, collection: str, keys: Iterable[str]) -> None:
        url = (
            f"{self.base_url}/servicesNS/{self.owner}/{self.app}/"
            f"storage/collections/data/{collection}"
        )
        keys_list = list(keys)
        for idx, key in enumerate(keys_list, 1):
            encoded_key = quote(str(key), safe="")
            logging.debug(f"Deleting key {idx}/{len(keys_list)} from {collection}: {key}")

            def _do_delete():
                response = self.session.delete(
                    f"{url}/{encoded_key}",
                    verify=self.verify_tls,
                    timeout=self.timeout_s,
                )
                if not response.ok:
                    raise requests.exceptions.HTTPError(
                        f"HTTP {response.status_code}: {response.text}",
                        response=response,
                    )
                return response

            self._retry_request(
                f"delete key {key} from {collection}",
                _do_delete,
            )
