"""Patched aiohttp runtime, explicit False call site."""
from pathlib import Path
from aiohttp import web

app = web.Application()
app.router.add_static("/assets", str(Path(__file__).parent / "assets"), follow_symlinks=False)
