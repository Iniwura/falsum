"""Fetch public OSV records safely to immutable, digest-pinned source snapshots.

Never accept caller-chosen URLs: this client only constructs the official OSV
/v1/vulns/<validated CVE/GHSA id> endpoint. No redirects, small size cap,
HTTPS certificate verification through Python's default TLS stack.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .osv import ADVISORY, MAX_BYTES, SourceError, parse_osv, verify_snapshot


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise SourceError(f"OSV HTTP redirect rejected ({code})")


def fetch_osv(advisory_id: str, directory: Path, *, opener=None) -> Path:
    """Fetch, verify identity, and persist with immutable metadata; no overwrite."""
    if not isinstance(advisory_id, str) or not ADVISORY.fullmatch(advisory_id):
        raise SourceError('unsupported CVE/GHSA advisory ID')
    target_dir = Path(directory)
    url = f'https://api.osv.dev/v1/vulns/{advisory_id}'
    path = target_dir / f'{advisory_id}.json'
    meta_path = target_dir / f'{advisory_id}.meta.json'
    if path.exists() or meta_path.exists():
        if not (path.exists() and meta_path.exists()):
            raise SourceError('partial snapshot exists; refusing overwrite')
        verify_snapshot(path, advisory_id)
        return path  # preserve original retrieved_at and exact original source bytes
    request = Request(url, headers={'Accept': 'application/json', 'User-Agent': 'falsum-evidence/0.2'})
    client = opener or build_opener(NoRedirects())
    try:
        with client.open(request, timeout=15) as response:
            if response.geturl() != url:
                raise SourceError('unexpected source URL')
            raw = response.read(MAX_BYTES + 1)
    except (HTTPError, URLError, TimeoutError) as e:
        raise SourceError(f'OSV fetch failed: {e}') from e
    record = parse_osv(raw, advisory_id)
    metadata = {
        'schema_version': 1, 'source': 'OSV', 'source_url': url,
        'requested_id': advisory_id, 'canonical_id': record['id'],
        'sha256': hashlib.sha256(raw).hexdigest(), 'byte_size': len(raw),
        'retrieved_at': datetime.now(timezone.utc).isoformat(),
    }
    target_dir.mkdir(parents=True, exist_ok=True)
    # Exclusive writes, and cleanup if any step fails: never silently replace evidence.
    try:
        with path.open('xb') as out:
            out.write(raw)
        with meta_path.open('x', encoding='utf-8') as out:
            out.write(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    verify_snapshot(path, advisory_id)
    return path
