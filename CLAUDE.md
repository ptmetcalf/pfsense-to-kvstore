# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a containerized Python application that extracts configuration data from pfSense firewalls and synchronizes it to Splunk KV (Key-Value) store collections. It can run as a one-shot operation or in a continuous loop.

## Architecture

### Core Components

1. **app.py** - Main entry point and orchestrator
   - Parses CLI arguments and environment variables
   - Manages the sync loop (one-shot or continuous)
   - Coordinates data extraction and KV store synchronization
   - Handles four sync modes: dns, interfaces, rules, enrichment, or all

2. **pfsense_extract.py** - pfSense data extraction layer
   - `SshSession` class: Manages persistent SSH connections with ControlMaster for performance
   - `load_config_xml()`: Retrieves config.xml via SSH or reads from local file
   - `load_pfctl_lines()`: Executes `pfctl -sr` via SSH or reads from local file
   - `build_dns_rows()`: Extracts DNS entries from unbound/dnsmasq/DHCP static mappings
   - `build_interface_rows()`: Extracts interface definitions including VLANs and bridges
   - `build_rule_rows()`: Merges user-defined rules from config.xml with system-generated rules from pfctl output
   - `parse_enrichment_interfaces()`: Extracts interface subnets for zone enrichment

3. **splunk_kv.py** - Splunk KV store client
   - `SplunkKV` class: REST API client for Splunk KV store operations
   - `batch_save()`: Bulk upsert documents in chunks (default 500)
   - `list_keys()`: Retrieve all _key values from a collection
   - `delete_keys()`: Remove stale records no longer present in pfSense
   - `query_collection()`: Query collection with pagination
   - `count_documents()`: Get total document count
   - `delete_all()`: Wipe all documents from a collection

4. **state_manager.py** - State persistence and logging (Web Interface)
   - `StateManager` class: Manages sync state with SQLite + in-memory cache
   - Tracks sync history, current status, and logs
   - `StateLoggingHandler`: Custom logging handler to capture logs

5. **sync_service.py** - Background sync scheduler (Web Interface)
   - `SyncService` class: Manages background sync operations
   - Daemon thread for scheduled syncs
   - Manual sync triggers
   - Thread-safe state management

6. **web_app.py** - Flask web interface (Web Interface)
   - Dashboard with real-time status updates
   - Manual sync triggers for all modes
   - Live log viewer
   - KV store collection viewer with pagination
   - Collection wipe operations

### Data Flow

1. Extract data from pfSense (SSH or local files)
2. Parse XML and pfctl output into structured rows
3. Add `_key` field to each document based on collection-specific key function
4. Batch write to Splunk KV store collections
5. Optionally identify and delete stale records

### KV Store Collections

- **pfsense_dns_hosts**: DNS host overrides and aliases (key: `ip|hostname`)
- **pfsense_interface_map**: Interface names and descriptions (key: `interface`)
- **pfsense_filter_rule_map**: Firewall rules from config.xml and pfctl (key: `tracker_id`)
- **pfsense_zone_subnets**: Interface subnet/zone mappings for enrichment (key: `cidr`)

### Rule Extraction Logic

The rule extraction merges two sources:
- User-defined rules from `/pfsense/filter/rule` in config.xml
- System-generated rules from `pfctl -sr` output (identified by `ridentifier`)

Rules from pfctl that don't exist in config.xml are parsed and added with normalized descriptions. This ensures both user-configured and system rules are captured in the KV store.

## Commands

### Docker Build
```bash
docker build -t pfsense-kv-sync .
```

### Run One-Shot Sync
```bash
docker run --rm --env-file .env pfsense-kv-sync:latest --mode all
```

### Run Continuous Sync Loop
```bash
docker run --rm --env-file .env pfsense-kv-sync:latest --mode all --interval-seconds 3600
```

### Local File Testing
Mount local files instead of using SSH:
```bash
docker run --rm \
  -v "$PWD/data:/data:ro" \
  --env-file .env \
  -e PFSENSE_CONFIG_XML=/data/config.xml \
  -e PFSENSE_PFCTL_FILE=/data/pfctl.txt \
  pfsense-kv-sync:latest --mode all
```

### Run Web Interface
Start the Flask web dashboard with background sync scheduler:
```bash
docker run -p 5000:5000 --env-file .env pfsense-kv-sync:latest python -m web_app
```

Access the dashboard at http://localhost:5000

The web interface provides:
- Real-time sync status (auto-refreshes every 2s)
- Manual sync triggers for each mode
- Live log viewer
- Sync history
- KV store collection viewer with pagination
- Collection wipe operations

### Linting
```bash
pip install ruff
ruff check src
```

## Web Interface

The application includes a Flask-based web interface for monitoring and controlling sync operations.

### Features

- **Dashboard**: Real-time view of sync status, last run, next scheduled run
- **Manual Triggers**: Buttons to trigger syncs for specific modes (dns, interfaces, rules, enrichment, all)
- **Live Logs**: Auto-refreshing log viewer showing recent sync operations
- **Sync History**: Table of past sync runs with success/failure status
- **Collection Viewer**: Browse KV store data with pagination
- **Collection Wipe**: Delete all documents from a collection (with confirmation)

### Architecture

The web interface runs alongside the sync process using:
- **Flask**: Web server on port 5000
- **HTMX**: Dynamic UI updates without JavaScript frameworks
- **SQLite**: Persistent storage for sync history and logs
- **Threading**: Background sync scheduler in daemon thread
- **StateManager**: Thread-safe coordination between web UI and sync operations

### Running Modes

**Web Mode (Recommended):**
```bash
docker run -p 5000:5000 --env-file .env pfsense-kv-sync:latest python -m web_app --interval-seconds 3600
```

**CLI Mode (Original):**
```bash
docker run --env-file .env pfsense-kv-sync:latest --mode all --interval-seconds 3600
```

Both modes support the same configuration options via environment variables.

## Configuration

Configuration is via environment variables (see `.env.example`):

### pfSense Source
- `PFSENSE_HOST`: pfSense hostname/IP for SSH access
- `PFSENSE_USER`: SSH username (default: admin)
- `PFSENSE_PASSWORD`: SSH password
- `PFSENSE_PORT`: SSH port (default: 22)
- `PFSENSE_SSH_STRICT_HOST_KEY`: SSH host key checking (default: accept-new)
- `PFSENSE_CONFIG_XML`: Optional local path to config.xml for testing
- `PFSENSE_PFCTL_FILE`: Optional local path to pfctl output for testing

### Splunk Connection
- `SPLUNK_URL`: Splunk REST API URL (e.g., https://splunk.example:8089)
- `SPLUNK_APP`: Splunk app context (default: search)
- `SPLUNK_OWNER`: Splunk owner context (default: nobody)
- `SPLUNK_TOKEN`: Bearer token for authentication (preferred)
- `SPLUNK_USER` + `SPLUNK_PASSWORD`: Basic auth (alternative to token)
- `SPLUNK_VERIFY_TLS`: Verify TLS certificates (default: true)
- `SPLUNK_TIMEOUT_S`: Request timeout in seconds (default: 60)
- `SPLUNK_CHUNK_SIZE`: Batch size for bulk operations (default: 500)
- `SPLUNK_REMOVE_STALE`: Delete KV records not in current pfSense data (default: false)
- `SPLUNK_MAX_RETRIES`: Maximum retry attempts for Splunk API calls (default: 3)
- `SPLUNK_RETRY_DELAY`: Initial delay in seconds between retries, uses exponential backoff (default: 1.0)

### Runtime Modes
- `--mode`: Select data types to sync (dns, interfaces, rules, enrichment, or all)
- `--interval-seconds`: Continuous loop interval (0 = run once and exit)

### Web Interface Configuration
- `WEB_HOST`: Web server bind address (default: 0.0.0.0)
- `WEB_PORT`: Web server port (default: 5000)
- `WEB_DEBUG`: Enable Flask debug mode (default: false)
- `SYNC_INTERVAL_SECONDS`: Background sync interval for web mode (default: 3600)

## Logging and Error Handling

The application uses Python's standard logging module with timestamps and log levels:
- **INFO**: Normal operational messages (sync progress, counts, success/failure)
- **WARNING**: Non-fatal issues (pfctl failures, retries)
- **ERROR**: Failures that prevent operations (connection errors, sync failures)
- **DEBUG**: Detailed diagnostic information (SSH commands, chunk operations)

### Resilience Features

1. **Collection-level isolation**: If one collection fails to sync, others continue
2. **Automatic retries**: Splunk API calls retry with exponential backoff on:
   - Connection errors
   - Timeouts
   - Server errors (HTTP 5xx)
3. **Graceful degradation**: If pfctl fails, syncs continue with config.xml data only
4. **Loop mode resilience**: In continuous mode, errors don't crash the service

### Exit Behavior

- **One-shot mode** (`--interval-seconds 0`): Exits with code 1 on fatal errors
- **Loop mode** (`--interval-seconds > 0`): Logs errors and continues to next cycle

## Development Notes

- Python 3.12 is the target version
- Runtime dependencies: `requests==2.32.3`, `flask==3.0.0`
- SSH connections use ControlMaster for connection reuse across multiple commands
- All XML parsing uses `xml.etree.ElementTree`
- Dockerfile uses python:3.12-slim with openssh-client and sshpass
- CI pipeline (GitHub Actions) includes linting with ruff and Docker build/push to GHCR
