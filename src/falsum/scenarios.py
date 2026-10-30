"""Fail-closed validation for *draft* application-security comparison cases.

A guidance link is NOT an immutable source snapshot or a human fact check.
No entry in this casebook can be submitted directly as eligible Telegraph data.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from .ledger import _similarity

CATEGORIES = frozenset({'configuration', 'secret_handling', 'request_boundary', 'workflow_permissions', 'tls_validation'})
SPLITS = frozenset({'train', 'validation', 'holdout'})
EXPECTED = frozenset({'finding', 'no_confirmed_finding', 'conditional'})
SOURCE_STATES = frozenset({'linked_unpinned', 'pinned'})
SHA256 = re.compile(r'^[0-9a-f]{64}$')
CRED = re.compile(r'(?i)(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{16,})')


class ScenarioError(ValueError):
    pass


def _https(s: object) -> bool:
    if not isinstance(s, str):
        return False
    try:
        p = urlsplit(s)
        return p.scheme == 'https' and bool(p.hostname) and '.' in p.hostname and not p.username and not p.password and not p.fragment
    except ValueError:
        return False


def _text(x: object) -> str:
    return x.strip() if isinstance(x, str) else ''


def validate_casebook(data: object) -> list[str]:
    """Structural/shortcut checks only. Never asserts that case labels are true."""
    errors = []
    if not isinstance(data, dict) or data.get('schema_version') != 1:
        return ['root: expected schema_version=1 object']
    sources, cases = data.get('sources'), data.get('cases')
    if not isinstance(sources, list) or not isinstance(cases, list):
        return ['root: sources and cases must be arrays']
    if not cases:
        errors.append('root: empty casebook')
    source_by_id = {}
    for i, src in enumerate(sources):
        tag = f'sources[{i}]'
        if not isinstance(src, dict):
            errors.append(f'{tag}: expected object'); continue
        sid = _text(src.get('id'))
        if not sid or sid in source_by_id:
            errors.append(f'{tag}: missing/duplicate source id')
        else:
            source_by_id[sid] = src
        if not _text(src.get('publisher')) or not _https(src.get('url')):
            errors.append(f'{tag}: publisher and HTTPS URL required')
        if src.get('state') not in SOURCE_STATES:
            errors.append(f'{tag}: invalid source state')
        if src.get('state') == 'pinned':
            if not SHA256.fullmatch(_text(src.get('sha256'))):
                errors.append(f'{tag}: pinned source needs a real snapshot checksum')
            if not _text(src.get('snapshot_path')):
                errors.append(f'{tag}: pinned source needs an archived snapshot path')
        if src.get('state') == 'linked_unpinned' and src.get('sha256'):
            errors.append(f'{tag}: linked unpinned source must not claim a checksum')

    seen_ids, seen_negative, seen_prompts = set(), set(), []
    source_splits, group_splits = defaultdict(set), defaultdict(set)
    label_distribution, split_distribution = Counter(), Counter()
    for i, row in enumerate(cases):
        tag = f'cases[{i}]'
        if not isinstance(row, dict):
            errors.append(f'{tag}: expected object'); continue
        rid, cat, split = _text(row.get('id')), row.get('category'), row.get('split')
        if not rid or rid in seen_ids:
            errors.append(f'{tag}: missing/duplicate case id')
        seen_ids.add(rid)
        if cat not in CATEGORIES:
            errors.append(f'{tag}: unsupported category')
        if split not in SPLITS:
            errors.append(f'{tag}: invalid split')
        if row.get('intent_id') != 'SECURITY_REVIEW_GENERAL':
            errors.append(f'{tag}: wrong child Intent')
        if row.get('review_status') not in ('draft', 'reviewed'):
            errors.append(f'{tag}: review_status must be draft or reviewed')
        if row.get('expected_outcome') not in EXPECTED:
            errors.append(f'{tag}: invalid expected outcome')
        label_distribution[str(row.get('expected_outcome'))] += 1
        split_distribution[str(split)] += 1
        group = _text(row.get('rule_family'))
        if not group:
            errors.append(f'{tag}: missing rule family')
        elif split in SPLITS:
            group_splits[group].add(split)
        prompt, chosen, rejected = [_text(row.get(k)) for k in ('prompt', 'chosen', 'rejected')]
        if min(map(len, (prompt, chosen, rejected))) < 60:
            errors.append(f'{tag}: task and answers must each have at least 60 characters')
        if chosen.casefold() == rejected.casefold():
            errors.append(f'{tag}: identical answers')
        if chosen and rejected:
            a, b = len(chosen.split()), len(rejected.split())
            ratio = a / max(1, b)
            if not 0.72 <= ratio <= 1.39:
                errors.append(f'{tag}: answer-length ratio {ratio:.2f} is a shortcut')
            digest = hashlib.sha256(rejected.casefold().encode()).hexdigest()
            if digest in seen_negative:
                errors.append(f'{tag}: repeated negative')
            seen_negative.add(digest)
        for prev_id, prev_prompt in seen_prompts:
            if prompt and _similarity(prompt, prev_prompt) >= 0.85:
                errors.append(f'{tag}: too similar to {prev_id}')
        seen_prompts.append((rid, prompt))
        refs = row.get('source_ids')
        if not isinstance(refs, list) or not refs or any(not isinstance(x, str) for x in refs) or len(refs) != len(set(refs)):
            errors.append(f'{tag}: source_ids must be nonempty unique strings')
        else:
            for src in refs:
                if src not in source_by_id:
                    errors.append(f'{tag}: unknown source {src}')
                elif split in SPLITS:
                    source_splits[src].add(split)
        for field in ('context', 'precondition', 'review_note'):
            if len(_text(row.get(field))) < 12:
                errors.append(f'{tag}: missing specific {field}')
        if CRED.search('\n'.join((prompt, chosen, rejected, _text(row.get('context'))))):
            errors.append(f'{tag}: possible real credential in public casebook')
        if row.get('review_status') == 'reviewed':
            if not _text(row.get('reviewer')) or not _text(row.get('reviewed_on')):
                errors.append(f'{tag}: missing human reviewer evidence')
            else:
                try:
                    date.fromisoformat(row['reviewed_on'])
                except ValueError:
                    errors.append(f'{tag}: reviewed_on must be a real ISO date')
            for src in refs if isinstance(refs, list) else []:
                if src in source_by_id and source_by_id[src].get('state') != 'pinned':
                    errors.append(f'{tag}: reviewed case references unpinned guidance')
    for group, splits in group_splits.items():
        if len(splits) > 1:
            errors.append(f'leakage: rule family {group} crosses splits {sorted(splits)}')
    for src, splits in source_splits.items():
        if len(splits) > 1:
            errors.append(f'leakage: source {src} crosses splits {sorted(splits)}')
    return errors


def read_casebook(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    errors = validate_casebook(data)
    if errors:
        raise ScenarioError('\n'.join(errors))
    return data


def readiness_report(book: dict, *, base_dir: str | Path | None = None) -> dict:
    """Local export-readiness only; never infer Telegraph network eligibility."""
    errors = validate_casebook(book)
    if errors:
        raise ScenarioError('\n'.join(errors))
    cases = book['cases']
    all_reviewed = bool(cases) and all(x['review_status'] == 'reviewed' for x in cases)
    all_pinned = bool(book['sources']) and all(x['state'] == 'pinned' for x in book['sources'])
    issues = verify_source_snapshots(book, base_dir) if base_dir is not None else ['source snapshots not audited']
    return {
        'count': len(cases),
        'by_category': dict(sorted(Counter(x['category'] for x in cases).items())),
        'by_split': dict(sorted(Counter(x['split'] for x in cases).items())),
        'by_outcome': dict(sorted(Counter(x['expected_outcome'] for x in cases).items())),
        'reviewed': sum(x['review_status'] == 'reviewed' for x in cases),
        'pinned_sources': sum(x['state'] == 'pinned' for x in book['sources']),
        'source_integrity_ok': not issues,
        'source_integrity_errors': issues,
        'local_export_ready': all_reviewed and all_pinned and not issues,
        'submission_ready': False,
        'network_eligibility': 'unverified',
    }


def verify_source_snapshots(book: dict, base_dir: str | Path) -> list[str]:
    """Check actual archived source bytes, not merely sha256 metadata strings."""
    errors = []
    base = Path(base_dir).resolve()
    for src in book.get('sources', []):
        if not isinstance(src, dict) or src.get('state') != 'pinned':
            errors.append(f"{src.get('id', '?') if isinstance(src, dict) else '?'}: source is not pinned")
            continue
        name = src.get('snapshot_path')
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{src.get('id')}: missing source snapshot")
            continue
        try:
            target = (base / name).resolve()
            if not target.is_relative_to(base) or not target.is_file():
                raise OSError('missing or path escapes casebook directory')
            if target.stat().st_size > 3_000_000:
                raise OSError('oversized source snapshot')
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if digest != src.get('sha256'):
                raise OSError('source snapshot SHA-256 mismatch')
            if str(name).endswith('.excerpt.json'):
                try:
                    body = json.loads(target.read_text(encoding='utf-8'))
                except (UnicodeError, ValueError) as exc:
                    raise OSError('invalid excerpt JSON') from exc
                if (not isinstance(body, dict)
                        or body.get('format') != 'falsum_upstream_excerpt_v1'
                        or body.get('source_id') != src.get('id')
                        or body.get('immutable_url') != src.get('url')
                        or not isinstance(body.get('upstream'), dict)
                        or body['upstream'].get('commit') != src.get('source_commit')
                        or not isinstance(body.get('excerpts'), list)
                        or not body['excerpts']
                        or any(not isinstance(x, dict) or not x.get('quote') for x in body['excerpts'])):
                    raise OSError('excerpt provenance mismatch')
        except OSError as exc:
            errors.append(f"{src.get('id')}: {exc}")
    return errors


def export_reviewed(book: dict, split: str, *, base_dir: str | Path | None = None) -> str:
    errors = validate_casebook(book)
    if errors:
        raise ScenarioError('\n'.join(errors))
    if split not in SPLITS:
        raise ScenarioError('invalid split')
    rows = [x for x in book['cases'] if x['split'] == split]
    if not rows or any(x['review_status'] != 'reviewed' for x in rows):
        raise ScenarioError(f'{split} has unreviewed or absent cases; export blocked')
    if base_dir is None:
        raise ScenarioError('local source snapshot directory required before export')
    snapshot_errors = verify_source_snapshots(book, base_dir)
    if snapshot_errors:
        raise ScenarioError('source integrity gate failed: ' + '; '.join(snapshot_errors))
    return ''.join(json.dumps({k: x[k] for k in ('prompt','chosen','rejected')}, sort_keys=True) + '\n' for x in rows)
