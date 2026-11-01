"""Patched aiohttp runtime with variable option: static analyzer must abstain."""
from pathlib import Path
from aiohttp import web

FOLLOW_STATIC_SYMLINKS = False
app = web.Application()
app.router.add_static("/assets", str(Path(__file__).parent / "assets"), follow_symlinks=FOLLOW_STATIC_SYMLINKS)
