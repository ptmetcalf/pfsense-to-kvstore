# pfsense-to-kvstore

Containerized pfSense lookup extractor that writes directly to Splunk KV store.

## Build

```bash
docker build -t pfsense-kv-sync .
```

## Run (one-shot)

```bash
docker run --rm --env-file .env.example pfsense-kv-sync:latest --mode all
```

## Run (loop)

```bash
docker run --rm --env-file .env.example pfsense-kv-sync:latest --mode all --interval-seconds 3600
```

## Local file testing

Mount `config.xml` and optional `pfctl.txt` into the container and set paths:

```bash
docker run --rm \
  -v "$PWD/data:/data:ro" \
  --env-file .env.example \
  -e PFSENSE_CONFIG_XML=/data/config.xml \
  -e PFSENSE_PFCTL_FILE=/data/pfctl.txt \
  pfsense-kv-sync:latest --mode all
```

## SSH notes

If you hit host key prompts or verification errors inside the container, set
`PFSENSE_SSH_STRICT_HOST_KEY=accept-new` (default) or `no` in your `.env`.

## Stale cleanup

Set `SPLUNK_REMOVE_STALE=true` to delete KV records that are no longer present
in the latest pfSense pull.
