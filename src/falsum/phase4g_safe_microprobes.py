"""Safe source-derived microprobes, NOT upstream integration tests or actual exploits.

These isolated checks reproduce narrow control flow from seven pinned PUBLIC
patches. They make research hypotheses falsifiable but DO NOT show installed
upstream versions executing, production exposure, expert validation or a model
scoring improvement.
"""
import inspect
import os
from pathlib import Path
import re
import tempfile


def prepared_proxy_header(scheme: str, username="test", password="pass") -> bool:
    """Equivalent to the pinned requests rebuild_proxies header decision."""
    return not scheme.startswith("https") and bool(username and password)


def jinja_attr_lookup_policy(obj: object, name: str) -> str:
    """Only checks which lookup *branch* patched do_attr invokes."""
    try:
        inspect.getattr_static(obj, name)
    except AttributeError:
        if not hasattr(obj, name):
            return "undefined_without_environment_getattr"
    return "environment_getattr"


def static_containment(sibling: bool) -> tuple[bool, bool]:
    """Realpath/commonprefix/commonpath comparison on temporary local paths."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "static"
        root.mkdir()
        outside = Path(td) / "static_private"
        outside.mkdir()
        candidate = outside / "info" if sibling else root / "index.html"
        candidate.write_text("safe synthetic probe")
        path = os.path.realpath(candidate)
        base = os.path.realpath(root)
        old = os.path.commonprefix([path, base]) == base
        new = os.path.commonpath([path, base]) == base
        return old, new


def redirected_headers(source: dict, removal_list=("Authorization",)) -> dict:
    """Cross-host branch only, mirroring pinned urllib3 header-key comparison."""
    normalized = frozenset(x.lower() for x in removal_list)
    remaining = dict(source)
    for key in list(remaining):
        if key.lower() in normalized:
            del remaining[key]
    return remaining


def django_intcomma_original(value: str) -> str:
    """Small reproduced pre-fix recursion; call only with controlled benign strings."""
    updated = re.sub(r"^(-?\d+)(\d{3})", r"\g<1>,\g<2>", str(value))
    return updated if updated == value else django_intcomma_original(updated)


def django_intcomma_patched(value: str) -> str:
    """Exactly the relevant historic nonlocalization string operations."""
    result = str(value)
    match = re.match(r"-?\d+", result)
    if match:
        prefix = match[0]
        formatted = re.sub(r"\d{3}", r"\g<0>,", prefix[::-1])[::-1]
        result = formatted + result[len(prefix):]
    return result


def run_py_probes() -> dict:
    """Return isolated source-logic facts; never claim upstream package execution."""
    assert prepared_proxy_header("https") is False
    assert prepared_proxy_header("http") is True
    class Example:
        present = "member"
    assert jinja_attr_lookup_policy(Example(), "missing") == "undefined_without_environment_getattr"
    assert jinja_attr_lookup_policy(Example(), "present") == "environment_getattr"
    assert static_containment(True) == (True, False)
    assert static_containment(False) == (True, True)
    assert "authorization" not in redirected_headers({"authorization":"demo"})
    assert redirected_headers({"authorization":"demo","x-api-secret":"opaque"},
                              ["X-API-Secret"]) == {"authorization":"demo"}
    try:
        django_intcomma_original("1" * 3600)
        raise AssertionError("old recursive long numeric format did not hit recursion limit")
    except RecursionError:
        pass
    assert django_intcomma_patched("1" * 3600).count(",") > 1000
    assert django_intcomma_patched("123") == ",123"
    return {
        "status": "PHASE4G_SAFE_SOURCE_DERIVED_PY_MICROPROBE_NOT_UPSTREAM_EXECUTION",
        "isolated_behavior_checks": 10,
        "source_packages_actually_installed_and_tested": 0,
        "production_app_exploits": 0,
        "independent_expert_gold_labels": 0,
        "trained_model_accuracy": None,
    }

if __name__ == "__main__":
    import json
    print(json.dumps(run_py_probes(),indent=2))
