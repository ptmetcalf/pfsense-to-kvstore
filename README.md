# pfsense-to-kvstore

Containerized pfSense lookup extractor that writes directly to Splunk KV store.

## Build

```bash
docker build -t pfsense-kv-sync .
```

## Run (web interface with background sync - Recommended)

Runs the Flask web dashboard with automatic background syncs:

```bash
docker run -p 5000:5000 --env-file .env.example pfsense-kv-sync:latest --interval-seconds 3600
```

Access the dashboard at http://localhost:5000

The web interface provides:
- Real-time sync status and monitoring
- Manual sync triggers for each mode
- Live log viewer
- Sync history
- KV store collection viewer
- Collection wipe operations

## Run (CLI mode)

For headless operation without the web interface:

### One-shot sync
```bash
docker run --rm --env-file .env.example --entrypoint python pfsense-kv-sync:latest -m app --mode all
```

### Continuous loop
```bash
docker run --rm --env-file .env.example --entrypoint python pfsense-kv-sync:latest -m app --mode all --interval-seconds 3600
```

## Local file testing

Mount `config.xml` and optional `pfctl.txt` into the container and set paths:

```bash
docker run -p 5000:5000 \
  -v "$PWD/data:/data:ro" \
  --env-file .env.example \
  -e PFSENSE_CONFIG_XML=/data/config.xml \
  -e PFSENSE_PFCTL_FILE=/data/pfctl.txt \
  pfsense-kv-sync:latest --interval-seconds 3600
```

## SSH notes

If you hit host key prompts or verification errors inside the container, set
`PFSENSE_SSH_STRICT_HOST_KEY=accept-new` (default) or `no` in your `.env`.

## Stale cleanup

Set `SPLUNK_REMOVE_STALE=true` to delete KV records that are no longer present
in the latest pfSense pull.
