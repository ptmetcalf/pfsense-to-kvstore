import argparse
import logging
import os
import time
from dataclasses import dataclass
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


@dataclass
class SyncConfig:
    """Configuration for a sync operation."""

    mode: str
    config_xml: Optional[str]
    pfctl_file: Optional[str]
    host: Optional[str]
    user: str
    port: int
    password: Optional[str]
    strict_host_key: str
    known_hosts_file: Optional[str]
    kv: SplunkKV
    chunk_size: int
    remove_stale: bool


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


def env_float(name: str, default: float) -> float:
    value = os.environ.get(name, "")
    if not value:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise SystemExit(f"Invalid float for {name}: {value}") from exc


def build_kv_client() -> Tuple[SplunkKV, int]:
    splunk_url = env_required("SPLUNK_URL")
    splunk_app = env_required("SPLUNK_APP")
    splunk_owner = os.environ.get("SPLUNK_OWNER", "nobody")
    verify_tls = env_bool("SPLUNK_VERIFY_TLS", True)
    timeout_s = env_int("SPLUNK_TIMEOUT_S", 60)
    chunk_size = env_int("SPLUNK_CHUNK_SIZE", 500)
    max_retries = env_int("SPLUNK_MAX_RETRIES", 3)
    retry_delay = env_float("SPLUNK_RETRY_DELAY", 1.0)

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
            max_retries=max_retries,
            retry_delay=retry_delay,
        ),
        chunk_size,
    )


def get_sync_config(mode: Optional[str] = None, config_xml: Optional[str] = None, pfctl_file: Optional[str] = None) -> SyncConfig:
    """Build sync configuration from environment variables and optional overrides."""
    # Use environment defaults if not explicitly provided
    if mode is None:
        mode = os.environ.get("MODE", "all")
    if config_xml is None:
        config_xml = os.environ.get("PFSENSE_CONFIG_XML")
    if pfctl_file is None:
        pfctl_file = os.environ.get("PFSENSE_PFCTL_FILE")

    # pfSense connection config
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

    # Splunk config
    remove_stale = env_bool("SPLUNK_REMOVE_STALE", False)
    kv, chunk_size = build_kv_client()

    return SyncConfig(
        mode=mode,
        config_xml=config_xml,
        pfctl_file=pfctl_file,
        host=host,
        user=user,
        port=port,
        password=password,
        strict_host_key=strict_host_key,
        known_hosts_file=known_hosts_file,
        kv=kv,
        chunk_size=chunk_size,
        remove_stale=remove_stale,
    )


def sync_collection(
    kv: SplunkKV,
    collection: str,
    rows: List[Dict[str, str]],
    key_fn: Callable[[Dict[str, str]], str],
    chunk_size: int,
    remove_stale: bool,
) -> bool:
    """Sync a collection to Splunk KV store. Returns True on success, False on failure."""
    try:
        docs = add_keys(rows, key_fn)
        logging.info(f"Syncing {len(docs)} documents to collection '{collection}'")

        kv.batch_save(collection, docs, chunk_size=chunk_size)
        logging.info(f"Successfully wrote {len(docs)} documents to '{collection}'")

        if not remove_stale:
            logging.debug(f"Stale cleanup disabled for '{collection}'")
            return True

        logging.info(f"Checking for stale records in '{collection}'")
        current_keys = {doc["_key"] for doc in docs}
        existing_keys = kv.list_keys(collection)
        stale_keys = sorted(existing_keys - current_keys)

        if stale_keys:
            logging.info(f"Deleting {len(stale_keys)} stale documents from '{collection}'")
            kv.delete_keys(collection, stale_keys)
            logging.info(f"Successfully deleted {len(stale_keys)} stale documents from '{collection}'")
        else:
            logging.info(f"No stale documents found in '{collection}'")

        return True
    except Exception as exc:
        logging.error(f"Failed to sync collection '{collection}': {exc}", exc_info=True)
        return False


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
    remove_stale: bool,
) -> bool:
    """Run one sync cycle. Returns True if all operations succeeded, False otherwise."""
    logging.info("=" * 60)
    logging.info(f"Starting sync cycle (mode: {mode})")
    logging.info("=" * 60)

    success_count = 0
    failure_count = 0
    collections_attempted = []

    try:
        # Load pfSense config
        logging.info("Loading pfSense configuration...")
        source = f"file {config_xml}" if config_xml else f"SSH {user}@{host}:{port}"
        logging.info(f"Source: {source}")

        root = load_config_xml(
            config_xml,
            host,
            user,
            port,
            password,
            strict_host_key=strict_host_key,
            known_hosts_file=known_hosts_file,
        )
        logging.info("Successfully loaded pfSense configuration")

        # Load pfctl output if needed
        pfctl_lines: List[str] = []
        if mode in ("rules", "all"):
            logging.info("Loading pfctl output for firewall rules...")
            pfctl_lines = load_pfctl_lines(
                pfctl_file,
                host,
                user,
                port,
                password,
                strict_host_key=strict_host_key,
                known_hosts_file=known_hosts_file,
            )
            logging.info(f"Loaded {len(pfctl_lines)} lines from pfctl output")

    except Exception as exc:
        logging.error(f"Failed to load pfSense data: {exc}", exc_info=True)
        logging.error("Cannot proceed without pfSense data")
        return False

    # Sync DNS hosts
    if mode in ("dns", "all"):
        collections_attempted.append("pfsense_dns_hosts")
        logging.info("-" * 60)
        logging.info("Processing DNS hosts collection...")
        try:
            rows = build_dns_rows(root)
            logging.info(f"Extracted {len(rows)} DNS host records from pfSense")
            if sync_collection(
                kv,
                "pfsense_dns_hosts",
                rows,
                lambda r: f"{r['ip']}|{r['hostname']}",
                chunk_size,
                remove_stale,
            ):
                success_count += 1
            else:
                failure_count += 1
        except Exception as exc:
            logging.error(f"Failed to process DNS hosts: {exc}", exc_info=True)
            failure_count += 1

    # Sync interfaces
    if mode in ("interfaces", "all"):
        collections_attempted.append("pfsense_interface_map")
        logging.info("-" * 60)
        logging.info("Processing interface map collection...")
        try:
            rows = build_interface_rows(root)
            logging.info(f"Extracted {len(rows)} interface records from pfSense")
            if sync_collection(
                kv,
                "pfsense_interface_map",
                rows,
                lambda r: r["interface"],
                chunk_size,
                remove_stale,
            ):
                success_count += 1
            else:
                failure_count += 1
        except Exception as exc:
            logging.error(f"Failed to process interfaces: {exc}", exc_info=True)
            failure_count += 1

    # Sync firewall rules
    if mode in ("rules", "all"):
        collections_attempted.append("pfsense_filter_rule_map")
        logging.info("-" * 60)
        logging.info("Processing firewall rules collection...")
        try:
            rows = build_rule_rows(root, pfctl_lines)
            logging.info(f"Extracted {len(rows)} firewall rule records from pfSense")
            if sync_collection(
                kv,
                "pfsense_filter_rule_map",
                rows,
                lambda r: r["tracker_id"],
                chunk_size,
                remove_stale,
            ):
                success_count += 1
            else:
                failure_count += 1
        except Exception as exc:
            logging.error(f"Failed to process firewall rules: {exc}", exc_info=True)
            failure_count += 1

    # Sync enrichment/zone subnets
    if mode in ("enrichment", "all"):
        collections_attempted.append("pfsense_zone_subnets")
        logging.info("-" * 60)
        logging.info("Processing zone subnets collection...")
        try:
            rows = parse_enrichment_interfaces(root)
            logging.info(f"Extracted {len(rows)} subnet records from pfSense")
            if sync_collection(
                kv,
                "pfsense_zone_subnets",
                rows,
                lambda r: r["cidr"],
                chunk_size,
                remove_stale,
            ):
                success_count += 1
            else:
                failure_count += 1
        except Exception as exc:
            logging.error(f"Failed to process zone subnets: {exc}", exc_info=True)
            failure_count += 1

    # Summary
    logging.info("=" * 60)
    logging.info(f"Sync cycle completed: {success_count} succeeded, {failure_count} failed")
    logging.info(f"Collections attempted: {', '.join(collections_attempted)}")
    logging.info("=" * 60)

    return failure_count == 0


def main() -> None:
    logging.info("Starting pfSense to Splunk KV Store sync service")

    args = parse_args()

    # Build sync configuration
    try:
        config = get_sync_config(mode=args.mode, config_xml=args.config_xml, pfctl_file=args.pfctl_file)
        logging.info("Successfully initialized Splunk KV Store client")
        logging.info(f"Configuration: mode={config.mode}, interval={args.interval_seconds}s, remove_stale={config.remove_stale}")
    except Exception as exc:
        logging.error(f"Failed to initialize configuration: {exc}")
        raise SystemExit(f"Failed to initialize: {exc}")

    cycle = 0
    while True:
        cycle += 1
        if args.interval_seconds > 0:
            logging.info(f"Starting sync cycle #{cycle}")

        try:
            success = run_once(
                config.mode,
                config.config_xml,
                config.pfctl_file,
                config.host,
                config.user,
                config.port,
                config.password,
                config.strict_host_key,
                config.known_hosts_file,
                config.kv,
                config.chunk_size,
                config.remove_stale,
            )

            if not success:
                logging.warning("Sync cycle completed with failures")
            else:
                logging.info("Sync cycle completed successfully")

        except KeyboardInterrupt:
            logging.info("Received interrupt signal, shutting down gracefully")
            break
        except Exception as exc:
            logging.error(f"Unexpected error during sync cycle: {exc}", exc_info=True)
            if args.interval_seconds <= 0:
                logging.error("Exiting due to error in one-shot mode")
                raise SystemExit(1)
            logging.warning("Error occurred, will retry on next cycle")

        if args.interval_seconds <= 0:
            break

        logging.info(f"Waiting {args.interval_seconds} seconds until next sync cycle...")
        time.sleep(args.interval_seconds)

    logging.info("Shutdown complete")


if __name__ == "__main__":
    main()
