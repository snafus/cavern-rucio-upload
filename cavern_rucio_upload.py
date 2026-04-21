#!/usr/bin/env python3
"""
cavern_rucio_upload.py

Upload files from a CANFAR/Cavern POSIX filesystem to a Rucio WebDAV RSE
and register replicas, without gfal2.

Usage examples:
  # Single file
  python cavern_rucio_upload.py --scope myvo --rse CANFAR_DISK file.fits

  # Multiple files, attach to dataset (create if absent)
  python cavern_rucio_upload.py --scope myvo --rse CANFAR_DISK --dataset myvo:obs2024 *.fits

  # Dry run with explicit storage token file
  python cavern_rucio_upload.py --scope myvo --rse CANFAR_DISK --dry-run \
      --storage-token-file /tmp/mytoken file.fits
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
import zlib
from abc import ABC, abstractmethod
from pathlib import Path

import requests

from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.rseclient import RSEClient
from rucio.client.ruleclient import RuleClient
from rucio.common.exception import DataIdentifierAlreadyExists, DuplicateRule

log = logging.getLogger(__name__)

CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB


# ---------------------------------------------------------------------------
# Token providers
# ---------------------------------------------------------------------------

class TokenProvider(ABC):
    """Abstract bearer token source for WebDAV storage endpoint auth."""

    @abstractmethod
    def get_token(self) -> str:
        """Return a current bearer token string. Called before each PUT."""
        ...


class RucioClientTokenProvider(TokenProvider):
    """Re-reads the Rucio client's current auth token on each call."""

    def __init__(self, client: Client):
        self._client = client

    def get_token(self) -> str:
        token = self._client.auth_token
        if not token:
            raise RuntimeError("Rucio client has no auth token; run 'rucio whoami' first")
        return token


class EnvTokenProvider(TokenProvider):
    """Reads a bearer token from an environment variable."""

    def __init__(self, var_name: str = "BEARER_TOKEN"):
        self._var = var_name

    def get_token(self) -> str:
        token = os.environ.get(self._var)
        if not token:
            raise RuntimeError(f"Environment variable {self._var!r} is not set or empty")
        return token.strip()


class FileTokenProvider(TokenProvider):
    """Reads a raw bearer token from a file (one token per file)."""

    def __init__(self, path: str | Path):
        self._path = Path(path)

    def get_token(self) -> str:
        if not self._path.exists():
            raise RuntimeError(f"Token file not found: {self._path}")
        return self._path.read_text().strip()


class WLCGDiscoveryTokenProvider(TokenProvider):
    """
    Discovers a bearer token using the WLCG Bearer Token Discovery order:
      1. $BEARER_TOKEN env var (raw token string)
      2. $BEARER_TOKEN_FILE env var (path to token file)
      3. /tmp/bt_u{uid} (standard per-user token location)
    """

    def get_token(self) -> str:
        token = os.environ.get("BEARER_TOKEN")
        if token:
            return token.strip()

        path = os.environ.get("BEARER_TOKEN_FILE")
        if path:
            return Path(path).read_text().strip()

        default = Path(f"/tmp/bt_u{os.getuid()}")
        if default.exists():
            return default.read_text().strip()

        raise RuntimeError(
            "WLCG token discovery failed: set $BEARER_TOKEN, $BEARER_TOKEN_FILE, "
            f"or place a token at /tmp/bt_u{os.getuid()}"
        )


def build_token_provider(args: argparse.Namespace, rucio_client: Client) -> TokenProvider:
    """Select the storage endpoint token provider from CLI args."""
    if args.storage_token_env:
        return EnvTokenProvider(args.storage_token_env)
    if args.storage_token_file:
        return FileTokenProvider(args.storage_token_file)
    if args.wlcg_token_discovery:
        return WLCGDiscoveryTokenProvider()
    return RucioClientTokenProvider(rucio_client)


# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------

def compute_metadata(path: Path) -> dict:
    """Return size (bytes) and adler32 checksum (8-char hex) for a file."""
    checksum = 1  # adler32 seed value
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            checksum = zlib.adler32(chunk, checksum)
            size += len(chunk)
    return {
        "size": size,
        "adler32": f"{checksum & 0xFFFFFFFF:08x}",
    }


# ---------------------------------------------------------------------------
# RSE protocol and PFN construction
# ---------------------------------------------------------------------------

def get_webdav_protocol(rse_name: str, rse_client: RSEClient) -> dict:
    """
    Query RSE protocols and return the first write-capable davs/https entry.
    Raises ValueError if none found or RSE is non-deterministic.
    """
    rse_info = rse_client.get_rse(rse_name)
    if not rse_info.get("deterministic", True):
        raise ValueError(
            f"RSE {rse_name!r} is non-deterministic; automatic PFN construction is not "
            "supported. Register replicas manually or use a deterministic RSE."
        )

    protocols = rse_client.get_protocols(rse_name, operation="write")
    for proto in protocols:
        if proto.get("scheme") in ("davs", "https"):
            return proto

    schemes = [p.get("scheme") for p in protocols]
    raise ValueError(
        f"RSE {rse_name!r} has no write-capable davs/https protocol. "
        f"Available schemes: {schemes}"
    )


def resolve_pfns(
    rse_name: str,
    scope: str,
    names: list[str],
    protocol: dict,
) -> dict[str, str]:
    """
    Construct deterministic PFNs for a list of logical filenames.

    Uses Rucio's standard deterministic path algorithm:
      MD5(scope:name) → prefix/scope/xx/yy/name

    RSEClient.lfns2pfns() exists for this purpose but iterates over dict keys
    rather than values in some client versions, producing malformed query strings.
    The deterministic algorithm is stable and well-defined; since get_webdav_protocol()
    already verifies the RSE is deterministic, this is safe to apply directly.
    """
    scheme = protocol["scheme"]
    hostname = protocol["hostname"]
    port = protocol.get("port", 443)
    prefix = protocol["prefix"].rstrip("/")

    result = {}
    for name in names:
        digest = hashlib.md5(f"{scope}:{name}".encode()).hexdigest()
        path = f"{prefix}/{scope}/{digest[0:2]}/{digest[2:4]}/{name}"
        result[f"{scope}:{name}"] = f"{scheme}://{hostname}:{port}{path}"
    return result


# ---------------------------------------------------------------------------
# Transfer
# ---------------------------------------------------------------------------

def put_file(
    local_path: Path,
    pfn: str,
    token: str,
    dry_run: bool = False,
) -> bool:
    """
    HTTP PUT local_path to pfn with bearer token auth.
    Returns True on HTTP 2xx, False on any error.

    Note: if the WebDAV collection path does not exist on the server,
    some implementations require a prior MKCOL request. If you see 409
    Conflict responses, the storage admin may need to pre-create the
    prefix directory tree.
    """
    if dry_run:
        log.info("[dry-run] PUT %s → %s", local_path, pfn)
        return True

    size = local_path.stat().st_size
    # requests has no adapter for davs://; it is plain HTTPS under the hood
    put_url = pfn.replace("davs://", "https://", 1)
    try:
        with open(local_path, "rb") as fh:
            resp = requests.put(
                put_url,
                data=fh,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Length": str(size),
                },
                verify=True,
                timeout=300,
            )
    except requests.RequestException as exc:
        log.error("PUT network error for %s: %s", local_path.name, exc)
        return False

    if resp.status_code in (200, 201, 204):
        return True

    log.error(
        "PUT failed for %s: HTTP %s — %s",
        local_path.name, resp.status_code, resp.text[:300],
    )
    return False


# ---------------------------------------------------------------------------
# Replica registration
# ---------------------------------------------------------------------------

def register_replica(
    rse_name: str,
    scope: str,
    name: str,
    pfn: str,
    meta: dict,
    replica_client: ReplicaClient,
    dry_run: bool = False,
) -> bool:
    """
    Register a file replica in Rucio. Only called after a confirmed PUT success.

    On failure, logs the full PFN and metadata so the operator can manually
    register or clean up the orphaned file on storage.
    """
    if dry_run:
        log.info("[dry-run] register replica %s:%s on %s → %s", scope, name, rse_name, pfn)
        return True

    try:
        replica_client.add_replicas(
            rse=rse_name,
            files=[{
                "scope": scope,
                "name": name,
                "bytes": meta["size"],
                "adler32": meta["adler32"],
                "pfn": pfn,
            }],
        )
        return True
    except Exception as exc:
        log.error(
            "Replica registration failed for %s:%s — %s\n"
            "  ORPHANED FILE on storage — manual action required:\n"
            "    pfn=%s\n    size=%s  adler32=%s",
            scope, name, exc, pfn, meta["size"], meta["adler32"],
        )
        return False


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

def ensure_dataset(
    scope: str,
    name: str,
    did_client: DIDClient,
    dry_run: bool = False,
    **kwargs,
) -> None:
    """Create dataset scope:name if it does not already exist."""
    if dry_run:
        log.info("[dry-run] ensure dataset %s:%s exists", scope, name)
        return
    try:
        did_client.add_dataset(scope=scope, name=name, **kwargs)
        log.info("Created dataset %s:%s", scope, name)
    except DataIdentifierAlreadyExists:
        log.debug("Dataset %s:%s already exists", scope, name)


def attach_to_dataset(
    dataset_scope: str,
    dataset_name: str,
    dids: list[dict],
    did_client: DIDClient,
    dry_run: bool = False,
) -> None:
    if not dids:
        return
    if dry_run:
        log.info("[dry-run] attach %d DID(s) to %s:%s", len(dids), dataset_scope, dataset_name)
        return
    did_client.attach_dids(
        scope=dataset_scope,
        name=dataset_name,
        dids=dids,
    )
    log.info("Attached %d DID(s) to %s:%s", len(dids), dataset_scope, dataset_name)


# ---------------------------------------------------------------------------
# Replication rules
# ---------------------------------------------------------------------------

_SECONDS_PER_DAY = 86_400


def add_rule(
    scope: str,
    name: str,
    rse_expression: str,
    rule_client: RuleClient,
    copies: int = 1,
    lifetime_days: float | None = None,
    dry_run: bool = False,
    **kwargs,
) -> str | None:
    """
    Add a replication rule on DID scope:name targeting rse_expression.

    lifetime_days is converted to whole seconds (1 day = 86 400 s).
    Returns the rule ID on success, None on failure.

    A DuplicateRule is treated as a non-fatal warning — Rucio already has
    an equivalent rule in place, so the data is protected.
    """
    lifetime_seconds: int | None = None
    if lifetime_days is not None:
        lifetime_seconds = int(lifetime_days * _SECONDS_PER_DAY)

    if dry_run:
        lifetime_str = f"{lifetime_seconds}s ({lifetime_days}d)" if lifetime_seconds else "permanent"
        log.info(
            "[dry-run] add rule: %s:%s → %s  copies=%d  lifetime=%s",
            scope, name, rse_expression, copies, lifetime_str,
        )
        return None

    try:
        rule_ids = rule_client.add_replication_rule(
            dids=[{"scope": scope, "name": name}],
            copies=copies,
            rse_expression=rse_expression,
            lifetime=lifetime_seconds,
            **kwargs,
        )
        rule_id = rule_ids[0]
        log.info(
            "Added rule %s: %s:%s → %s  copies=%d  lifetime=%s",
            rule_id, scope, name, rse_expression, copies,
            f"{lifetime_seconds}s ({lifetime_days}d)" if lifetime_seconds else "permanent",
        )
        return rule_id
    except DuplicateRule:
        log.warning(
            "Rule already exists for %s:%s → %s (skipping)",
            scope, name, rse_expression,
        )
        return None
    except Exception as exc:
        log.error("Failed to add rule for %s:%s → %s: %s", scope, name, rse_expression, exc)
        return None


# ---------------------------------------------------------------------------
# Input expansion
# ---------------------------------------------------------------------------

def expand_inputs(paths: list[Path], include_top_dir: bool = True) -> list[tuple[Path, str]]:
    """
    Expand a mixed list of files and directories into (local_path, logical_name) pairs.

    - File: logical_name is the bare filename.
    - Directory: recurses and builds logical_name from the path relative to the
      directory's *parent*, so the directory name itself is included by default.

      include_top_dir=True  (default):
        input /data/obs/, file /data/obs/2024/jan/file.fits
        → logical_name = "obs/2024/jan/file.fits"

      include_top_dir=False:
        → logical_name = "2024/jan/file.fits"
    """
    result = []
    for path in paths:
        if path.is_file():
            result.append((path, path.name))
        elif path.is_dir():
            files = sorted(f for f in path.rglob("*") if f.is_file())
            if not files:
                log.warning("Directory is empty, skipping: %s", path)
                continue
            base = path.parent if include_top_dir else path
            for file in files:
                result.append((file, str(file.relative_to(base))))
        else:
            log.error("Path does not exist or is not a file/directory: %s", path)
    return result


# ---------------------------------------------------------------------------
# Per-file orchestrator
# ---------------------------------------------------------------------------

def upload_and_register(
    local_path: Path,
    scope: str,
    name: str,
    rse_name: str,
    pfn: str,
    token_provider: TokenProvider,
    replica_client: ReplicaClient,
    dry_run: bool = False,
) -> bool:
    """
    Full pipeline for one file: metadata → PUT → register.
    PFN is pre-computed by the caller via resolve_pfns().
    Returns True only if both PUT and registration succeed.
    Registration is skipped (and returns False) if the PUT fails.
    """
    log.info("Processing %s → %s:%s", local_path, scope, name)
    log.debug("  pfn=%s", pfn)

    if dry_run:
        log.info("[dry-run] would PUT %s → %s", local_path, pfn)
        log.info("[dry-run] would register replica %s:%s on %s", scope, name, rse_name)
        return True

    meta = compute_metadata(local_path)
    log.debug("  size=%s  adler32=%s", meta["size"], meta["adler32"])

    token = token_provider.get_token()
    if not put_file(local_path, pfn, token, dry_run):
        return False

    return register_replica(rse_name, scope, name, pfn, meta, replica_client, dry_run)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Upload files from Cavern to a Rucio WebDAV RSE and register replicas.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("files", nargs="+", type=Path, metavar="PATH",
                   help="Source file(s) or directory/ies to upload. "
                        "Directories are walked recursively; subdirectory structure "
                        "is preserved as part of the Rucio logical name.")
    p.add_argument("--scope", required=True,
                   help="Rucio scope applied to all files")
    p.add_argument("--rse", required=True,
                   help="Destination RSE name")
    p.add_argument("--name", metavar="LOGICAL_NAME",
                   help="Override the Rucio logical filename (single-file uploads only)")
    p.add_argument("--name-prefix", metavar="PREFIX",
                   help="Prepend a fixed string to every logical DID name "
                        "(e.g. 'newdata/' → 'newdata/obs/file.fits')")
    p.add_argument("--dataset", metavar="SCOPE:NAME",
                   help="Attach successful uploads to this dataset; created if it does not exist")
    p.add_argument("--no-top-dir", action="store_true",
                   help="Exclude the top-level directory name from the Rucio logical name "
                        "when uploading a directory. By default the directory name is included.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print planned actions without transferring or registering anything")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable debug logging")

    rule = p.add_argument_group("replication rule")
    rule.add_argument("--add-rule", action="store_true",
                      help="Add a Rucio replication rule on the dataset DID after upload. "
                           "Requires --dataset.")
    rule.add_argument("--rule-rse-expression", metavar="EXPR",
                      help="RSE expression for the rule (default: the upload RSE). "
                           "Set to a different RSE to trigger an automatic transfer there; "
                           "Rucio will lock the source replica until the transfer completes.")
    rule.add_argument("--rule-copies", type=int, default=1, metavar="N",
                      help="Number of copies the rule should enforce (default: 1)")
    rule.add_argument("--rule-lifetime", type=float, default=None, metavar="DAYS",
                      help="Rule lifetime in days. Omit for a permanent rule. "
                           "Fractional days are accepted (e.g. 0.5 = 12 hours). "
                           "Converted to seconds internally (1 day = 86 400 s).")

    tok = p.add_mutually_exclusive_group()
    tok.add_argument("--storage-token-env", metavar="VAR",
                     help="Read storage bearer token from this environment variable")
    tok.add_argument("--storage-token-file", metavar="PATH",
                     help="Read storage bearer token from this file")
    tok.add_argument("--wlcg-token-discovery", action="store_true",
                     help=(
                         "Discover storage token via WLCG order: "
                         "$BEARER_TOKEN → $BEARER_TOKEN_FILE → /tmp/bt_u<uid>"
                     ))

    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if args.name and (len(args.files) > 1 or args.files[0].is_dir()):
        log.error("--name can only be used with a single input file, not a directory or multiple paths")
        sys.exit(1)

    if args.add_rule and not args.dataset:
        log.error("--add-rule requires --dataset")
        sys.exit(1)

    # Rucio clients — share one auth context
    rucio_client = Client()
    rse_client = RSEClient()
    replica_client = ReplicaClient()
    did_client = DIDClient()
    rule_client = RuleClient()

    # Storage endpoint token provider
    token_provider = build_token_provider(args, rucio_client)

    # Resolve RSE WebDAV protocol — needed for PFN construction and davs→https rewrite on PUT
    try:
        protocol = get_webdav_protocol(args.rse, rse_client)
        log.debug("Using protocol: %s://%s:%s%s",
                  protocol["scheme"], protocol["hostname"],
                  protocol.get("port", 443), protocol["prefix"])
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)

    # Ensure dataset exists before uploading anything
    dataset_scope = dataset_name = None
    if args.dataset:
        if ":" not in args.dataset:
            log.error("--dataset must be in SCOPE:NAME format, got: %r", args.dataset)
            sys.exit(1)
        dataset_scope, dataset_name = args.dataset.split(":", 1)
        try:
            ensure_dataset(dataset_scope, dataset_name, did_client, args.dry_run)
        except Exception as exc:
            log.error("Failed to ensure dataset %s: %s", args.dataset, exc)
            sys.exit(1)

    # Expand files/directories into (path, logical_name) pairs
    inputs = expand_inputs(args.files, include_top_dir=not args.no_top_dir)
    if args.name:
        # --name is only valid for a single file; guard above ensures this
        inputs = [(inputs[0][0], args.name)]

    if args.name_prefix:
        prefix = args.name_prefix.rstrip("/") + "/"
        inputs = [(p, prefix + n) for p, n in inputs]

    if not inputs:
        log.error("No files found to upload")
        sys.exit(1)

    log.info("Found %d file(s) to upload", len(inputs))

    # Resolve all PFNs in one batch call before transferring anything
    names = [name for _, name in inputs]
    try:
        pfn_map = resolve_pfns(args.rse, args.scope, names, protocol)
    except Exception as exc:
        log.error("Failed to resolve PFNs from Rucio: %s", exc)
        sys.exit(1)

    # Upload loop
    succeeded: list[dict] = []
    failed: list[Path] = []

    for path, logical_name in inputs:
        pfn = pfn_map.get(f"{args.scope}:{logical_name}")
        if not pfn:
            log.error("No PFN returned for %s:%s — skipping", args.scope, logical_name)
            failed.append(path)
            continue

        ok = upload_and_register(
            local_path=path,
            scope=args.scope,
            name=logical_name,
            rse_name=args.rse,
            pfn=pfn,
            token_provider=token_provider,
            replica_client=replica_client,
            dry_run=args.dry_run,
        )

        if ok:
            succeeded.append({"scope": args.scope, "name": logical_name})
        else:
            failed.append(path)  # type: ignore[arg-type]

    # Attach successful uploads to dataset
    if dataset_scope and succeeded:
        try:
            attach_to_dataset(dataset_scope, dataset_name, succeeded, did_client, args.dry_run)
        except Exception as exc:
            log.error(
                "Failed to attach DIDs to dataset %s:%s — %s",
                dataset_scope, dataset_name, exc,
            )

    # Add replication rule on the dataset DID
    if args.add_rule and dataset_scope and succeeded:
        rse_expr = args.rule_rse_expression or args.rse
        add_rule(
            scope=dataset_scope,
            name=dataset_name,
            rse_expression=rse_expr,
            rule_client=rule_client,
            copies=args.rule_copies,
            lifetime_days=args.rule_lifetime,
            dry_run=args.dry_run,
        )

    log.info("Done: %d succeeded, %d failed", len(succeeded), len(failed))
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
