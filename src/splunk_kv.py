import json
from typing import Dict, List, Optional, Tuple

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
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.app = app
        self.owner = owner
        self.verify_tls = verify_tls
        self.timeout_s = timeout_s

        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

        if token:
            self.session.headers.update({"Authorization": f"Splunk {token}"})
        if auth:
            self.session.auth = auth

    def batch_save(self, collection: str, docs: List[Dict], chunk_size: int = 500) -> None:
        if not docs:
            return
        url = (
            f"{self.base_url}/servicesNS/{self.owner}/{self.app}/"
            f"storage/collections/data/{collection}/batch_save"
        )
        for i in range(0, len(docs), chunk_size):
            chunk = docs[i : i + chunk_size]
            response = self.session.post(
                url,
                data=json.dumps(chunk),
                verify=self.verify_tls,
                timeout=self.timeout_s,
            )
            if not response.ok:
                raise RuntimeError(
                    f"batch_save failed for {collection}: HTTP {response.status_code} {response.text}"
                )
