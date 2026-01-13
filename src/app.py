import argparse
import os
import time
from typing import Callable, Dict, List, Optional, Tuple

from pfsense_extract import (
    build_dns_rows,
    build_interface_rows,
    build_rule_rows,
    load_config_xml,
    load_pfctl_lines,
    parse_enrichment_interfaces,
)
from splunk_kv import SplunkKV


def add_keys(rows: List[Dict[str, str]], key_fn: Callable[[Dict[str, str]], str]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for row in rows:
        doc = dict(row)
        doc["_key"] = key_fn(row)
        out.append(doc)
    return out


def env_required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        raise SystemExit(f"Missing required env var: {name}")
    return value


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name, "")
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise SystemExit(f"Invalid integer for {name}: {value}") from exc


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    value = value.strip().lower()
    if value in {"1", "true", "yes", "y"}:
        return True
    if value in {"0", "false", "no", "n"}:
        return False
    raise SystemExit(f"Invalid boolean for {name}: {value}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pull pfSense config and write lookups to Splunk KV store.",
    )
    parser.add_argument(
        "--mode",
        choices=["dns", "interfaces", "rules", "enrichment", "all"],
        default=os.environ.get("MODE", "all"),
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=int(os.environ.get("INTERVAL_SECONDS", "0")),
        help="0 = run once and exit; >0 = loop",
    )
    parser.add_argument("--config-xml", default=os.environ.get("PFSENSE_CONFIG_XML"))
    parser.add_argument("--pfctl-file", default=os.environ.get("PFSENSE_PFCTL_FILE"))
    return parser.parse_args()


def env_choice(name: str, allowed: Tuple[str, ...], default: str) -> str:
    value = os.environ.get(name, default).strip().lower()
    if value not in allowed:
        raise SystemExit(f"Invalid {name}={value}. Allowed: {', '.join(allowed)}")
    return value


def build_kv_client() -> Tuple[SplunkKV, int]:
    splunk_url = env_required("SPLUNK_URL")
    splunk_app = env_required("SPLUNK_APP")
    splunk_owner = os.environ.get("SPLUNK_OWNER", "nobody")
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", True)
    timeout_s = env_int("SPLUNK_TIMEOUT_S", 60)
    chunk_size = env_int("SPLUNK_CHUNK_SIZE", 500)

    token = os.environ.get("SPLUNK_TOKEN")
    user = os.environ.get("SPLUNK_USER")
    password = os.environ.get("SPLUNK_PASSWORD")
    auth = (user, password) if (user and password and not token) else None

    if not token and not auth:
        raise SystemExit("Set SPLUNK_TOKEN or SPLUNK_USER/SPLUNK_PASSWORD for auth.")

    return (
        SplunkKV(
            base_url=splunk_url,
            app=splunk_app,
            owner=splunk_owner,
            token=token,
            auth=auth,
            verify_tls=verify_tls,
            timeout_s=timeout_s,
        ),
        chunk_size,
    )


def run_once(
    mode: str,
    config_xml: Optional[str],
    pfctl_file: Optional[str],
    host: Optional[str],
    user: str,
    port: int,
    password: Optional[str],
    strict_host_key: str,
    known_hosts_file: Optional[str],
    kv: SplunkKV,
    chunk_size: int,
) -> None:
    root = load_config_xml(
        config_xml,
        host,
        user,
        port,
        password,
        strict_host_key=strict_host_key,
        known_hosts_file=known_hosts_file,
    )
    pfctl_lines: List[str] = []
    if mode in ("rules", "all"):
        pfctl_lines = load_pfctl_lines(
            pfctl_file,
            host,
            user,
            port,
            password,
            strict_host_key=strict_host_key,
            known_hosts_file=known_hosts_file,
        )

    if mode in ("dns", "all"):
        rows = build_dns_rows(root)
        docs = add_keys(rows, lambda r: f"{r['ip']}|{r['hostname']}")
        print(f"Writing {len(docs)} docs to pfsense_dns_hosts")
        kv.batch_save("pfsense_dns_hosts", docs, chunk_size=chunk_size)

    if mode in ("interfaces", "all"):
        rows = build_interface_rows(root)
        docs = add_keys(rows, lambda r: r["interface"])
        print(f"Writing {len(docs)} docs to pfsense_interface_map")
        kv.batch_save("pfsense_interface_map", docs, chunk_size=chunk_size)

    if mode in ("rules", "all"):
        rows = build_rule_rows(root, pfctl_lines)
        docs = add_keys(rows, lambda r: r["tracker_id"])
        print(f"Writing {len(docs)} docs to pfsense_filter_rule_map")
        kv.batch_save("pfsense_filter_rule_map", docs, chunk_size=chunk_size)

    if mode in ("enrichment", "all"):
        rows = parse_enrichment_interfaces(root)
        docs = add_keys(rows, lambda r: r["cidr"])
        print(f"Writing {len(docs)} docs to pfsense_zone_subnets")
        kv.batch_save("pfsense_zone_subnets", docs, chunk_size=chunk_size)


def main() -> None:
    args = parse_args()
    config_xml = args.config_xml
    pfctl_file = args.pfctl_file

    host = os.environ.get("PFSENSE_HOST")
    if not config_xml and not host:
        raise SystemExit("Set PFSENSE_HOST or PFSENSE_CONFIG_XML.")

    user = os.environ.get("PFSENSE_USER", "admin")
    port = env_int("PFSENSE_PORT", 22)
    password = os.environ.get("PFSENSE_PASSWORD")
    strict_host_key = env_choice(
        "PFSENSE_SSH_STRICT_HOST_KEY",
        ("yes", "no", "accept-new"),
        "accept-new",
    )
    known_hosts_file = os.environ.get("PFSENSE_SSH_KNOWN_HOSTS")

    kv, chunk_size = build_kv_client()

    while True:
        run_once(
            args.mode,
            config_xml,
            pfctl_file,
            host,
            user,
            port,
            password,
            strict_host_key,
            known_hosts_file,
            kv,
            chunk_size,
        )
        if args.interval_seconds <= 0:
            break
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    main()
