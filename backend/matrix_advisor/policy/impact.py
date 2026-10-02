"""Impact analysis for changes to a contract shared by several cells."""

from __future__ import annotations

from .matrix import Matrix


def impact_of_change(
    matrix: Matrix,
    sgacl_id: str,
    new_content: str,
    observed: dict[tuple[str, str], list[dict]],
    exclude: tuple[str, str] | None = None,
) -> list[dict]:
    """Observed traffic of *other* pairs that is permitted today and would be denied
    if SGACL ``sgacl_id`` were replaced by ``new_content``.

    ``observed`` maps (src, dst) -> [{"spec": "TCP/443", "flows": 123}, ...].
    """
    impacts: list[dict] = []
    for pair in matrix.contract_users(sgacl_id):
        if pair == exclude:
            continue
        src, dst = pair
        for port in observed.get(pair, []):
            spec = port["spec"]
            if matrix.evaluate(src, dst, spec) and not matrix.evaluate(src, dst, spec, {sgacl_id: new_content}):
                impacts.append({"src": src, "dst": dst, "spec": spec, "flows": port.get("flows", 0)})
    return impacts


def clone_name(prefix: str, base: str, src: str, existing: set[str]) -> str:
    stem = base if base.startswith(prefix) else prefix + base
    name = f"{stem}_{src}"
    n = 2
    while name in existing:
        name = f"{stem}_{src}_{n}"
        n += 1
    return name


def new_contract_name(prefix: str, src: str, dst: str, existing: set[str]) -> str:
    name = f"{prefix}{src}_to_{dst}"
    n = 2
    candidate = name
    while candidate in existing:
        candidate = f"{name}_{n}"
        n += 1
    return candidate
