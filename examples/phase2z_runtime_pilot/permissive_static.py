"""Patched aiohttp runtime, explicit True call site: not an exploit claim."""
from pathlib import Path
from aiohttp import web

app = web.Application()
app.router.add_static("/assets", str(Path(__file__).parent / "assets"), follow_symlinks=True)
