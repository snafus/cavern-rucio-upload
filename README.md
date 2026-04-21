# cavern-rucio-upload

A lightweight Python utility for uploading files from a [CANFAR](https://www.canfar.net/) Cavern POSIX filesystem to a Rucio WebDAV RSE and registering replicas — no `gfal2` required.

Designed for use in CANFAR interactive sessions (Jupyter notebooks or terminal), where `gfal2` is unavailable but `rucio-clients` and `requests` are present.

---

## Requirements

- Python 3.10+
- [`rucio-clients`](https://rucio.readthedocs.io/en/latest/installing_clients.html)
- [`requests`](https://docs.python-requests.org/)
- A valid Rucio configuration at `~/.rucio/rucio.cfg`
- An active OIDC session (`rucio whoami` should succeed before running)

---

## Installation

```bash
# Clone into your CANFAR session
git clone https://github.com/snafus/cavern-rucio-upload.git
cd cavern-rucio-upload
```

No package installation needed — run the script directly.

---

## Authentication

### Rucio API

The script uses the Rucio Python client, which reads `~/.rucio/rucio.cfg` and manages its own token. Run `rucio whoami` once to complete the OIDC browser flow before using this script.

### Storage endpoint (WebDAV)

The token used for the HTTP PUT to the WebDAV RSE is controlled separately via one of four providers. If no flag is given, the script reuses the Rucio client's token — this works when the storage endpoint trusts the same OIDC token as the Rucio server.

| Flag | Token source |
|---|---|
| *(none)* | Rucio client's current auth token (default) |
| `--storage-token-env VAR` | Environment variable `VAR` |
| `--storage-token-file PATH` | Raw token string in a file |
| `--wlcg-token-discovery` | WLCG discovery order: `$BEARER_TOKEN` → `$BEARER_TOKEN_FILE` → `/tmp/bt_u<uid>` |

---

## Usage

```
python cavern_rucio_upload.py [OPTIONS] FILE [FILE ...]

Required:
  FILE               One or more source files to upload
  --scope SCOPE      Rucio scope applied to all files
  --rse RSE          Destination RSE name

Optional:
  --name NAME        Override the Rucio logical filename (single file only)
  --dataset SCOPE:NAME
                     Attach successful uploads to this dataset.
                     The dataset is created automatically if it does not exist.
  --dry-run          Print planned actions without transferring or registering
  --verbose, -v      Enable debug logging

Storage token (mutually exclusive):
  --storage-token-env VAR
  --storage-token-file PATH
  --wlcg-token-discovery
```

---

## Examples

### Upload a single file

```bash
python cavern_rucio_upload.py \
    --scope myvo \
    --rse CANFAR_DISK \
    /arc/projects/myproject/obs_2024_01.fits
```

### Upload multiple files using shell globbing

```bash
python cavern_rucio_upload.py \
    --scope myvo \
    --rse CANFAR_DISK \
    /arc/projects/myproject/*.fits
```

### Upload and attach to a dataset (created if absent)

```bash
python cavern_rucio_upload.py \
    --scope myvo \
    --rse CANFAR_DISK \
    --dataset myvo:observation_run_2024 \
    /arc/projects/myproject/*.fits
```

### Dry run — preview what would happen without transferring anything

```bash
python cavern_rucio_upload.py \
    --scope myvo \
    --rse CANFAR_DISK \
    --dataset myvo:observation_run_2024 \
    --dry-run \
    /arc/projects/myproject/*.fits
```

### Upload with a separate storage token from a file

Useful when the WebDAV endpoint requires a token from a different issuer than the Rucio server.

```bash
python cavern_rucio_upload.py \
    --scope myvo \
    --rse CANFAR_DISK \
    --storage-token-file /tmp/storage_token \
    /arc/projects/myproject/obs.fits
```

### Upload with WLCG bearer token discovery

```bash
python cavern_rucio_upload.py \
    --scope myvo \
    --rse CANFAR_DISK \
    --wlcg-token-discovery \
    /arc/projects/myproject/obs.fits
```

### Override the logical filename (single file)

```bash
python cavern_rucio_upload.py \
    --scope myvo \
    --rse CANFAR_DISK \
    --name my_canonical_filename.fits \
    /arc/projects/myproject/local_working_copy.fits
```

---

## How it works

1. **Resolve RSE protocol** — queries the Rucio RSE for its write-capable `davs`/`https` protocol and prefix.
2. **Compute metadata** — streams each file to compute its size and adler32 checksum without loading it into memory.
3. **Build PFN** — constructs the deterministic destination path using Rucio's standard algorithm: `MD5(scope:name)` → `prefix/scope/xx/yy/name`.
4. **HTTP PUT** — uploads the file to the WebDAV endpoint with a bearer token in the `Authorization` header.
5. **Register replica** — calls `ReplicaClient.add_replicas()` only after a confirmed HTTP 2xx response. A failed transfer never results in a registered replica.
6. **Attach to dataset** — if `--dataset` is given, attaches all successfully uploaded DIDs to the dataset after the upload loop completes.

---

## Error handling

- A failed PUT skips replica registration for that file and logs the error.
- If replica registration fails after a successful PUT (orphaned file), the script logs the PFN, size, and checksum at `ERROR` level so the file can be manually registered or cleaned up.
- If dataset creation or resolution fails at startup, the script aborts before uploading anything.
- The script exits non-zero if any file fails, making it safe to use in shell pipelines.

---

## Limitations

- Requires a **deterministic** RSE. Non-deterministic RSEs (where the storage path is not derived from the logical filename) are not supported and will produce an error.
- Does not create WebDAV collection paths on the storage server. If the destination directory tree does not exist, some WebDAV implementations will return `409 Conflict`. Contact your storage administrator to pre-create the prefix directory.
- Does not verify the checksum after upload (no GET + compare). This would require gfal2 or storage-specific support.
- No built-in retry logic. Re-run the script for failed files; already-registered replicas will cause a Rucio `Duplicate` error but the file on storage will be intact.
