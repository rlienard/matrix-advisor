"""Human decisions on proposals and the corresponding writes to ISE.

Safety rules implemented here:
* the cell is re-read from ISE right before writing; if it changed since the proposal was
  made, nothing is written and a conflict is returned (unless the operator asks to merge);
* an existing contract is modified in place only when no observed traffic of another pair
  using it would be denied; otherwise a clone is created and only this cell points to it;
* new and cloned SGACLs carry the configured prefix; cells are written in MONITOR status
  unless ``ise.write_mode`` is ``enforce``.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from ..config import ConfigStore
from ..ise.client import ISEError
from ..ise.service import ISEService
from ..policy import acl
from ..policy.impact import clone_name, impact_of_change, new_contract_name
from ..policy.matrix import NO_CELL_FINGERPRINT
from ..store import Store, utcnow
from .advisor import Advisor

log = logging.getLogger(__name__)


class ActionError(Exception):
    def __init__(self, message: str, status: int = 400, details: dict | None = None):
        super().__init__(message)
        self.status = status
        self.details = details or {}


def _norm(text: str | None) -> str:
    return acl.to_ise(text or "")


class Actions:
    def __init__(self, config: ConfigStore, store: Store, ise: ISEService, advisor: Advisor):
        self.config = config
        self.store = store
        self.ise = ise
        self.advisor = advisor

    def _get(self, pid: str) -> dict:
        p = self.store.proposal(pid)
        if not p:
            raise ActionError("Proposition introuvable.", 404)
        return p

    def _pending(self, pid: str) -> dict:
        p = self._get(pid)
        if p["status"] != "pending":
            raise ActionError(f"Proposition déjà traitée ({p['status']}).", 409)
        return p

    # ------------------------------------------------------------ analysis
    def analyse(self, p: dict, text: str | None = None) -> dict:
        """Validation, shared-contract impact and write mode for a (possibly edited) proposal."""
        m = self.ise.matrix
        final = text if text is not None else (p.get("edited_acl") or p["proposed_acl"])
        validation = acl.validate(final, p["specs"]) if p["kind"] != "external" else \
            {"errors": [], "warns": [], "infos": []}
        edited = _norm(final) != _norm(p["proposed_acl"])
        base = m.sgacls.get(p.get("base_sgacl_id") or "") if p.get("base_sgacl_id") else None
        changes_base = bool(base) and not validation["errors"] and _norm(final) != _norm(base.content)
        pair = (p["src"], p["dst"])
        others = [k for k in m.contract_users(base.id) if k != pair] if base else []
        impacts: list[dict] = []
        if changes_base:
            observed = self.advisor.observed_ports(utcnow() - timedelta(days=7))
            impacts = impact_of_change(m, base.id, _norm(final), observed, exclude=pair)
        names = {a.name for a in m.sgacls.values()}
        prefix = self.config.settings.ise.sgacl_prefix
        default_mode = "clone" if others else "inplace"
        return {
            "acl": final,
            "validation": validation,
            "edited": edited,
            "changes_base": changes_base,
            "base_contract": base.name if base else p.get("base_contract"),
            "others": [{"src": s, "dst": d} for s, d in others],
            "impacts": impacts,
            "default_mode": default_mode,
            "inplace_allowed": not impacts,
            "clone_name": clone_name(prefix, base.name, p["src"], names) if base else None,
            "new_name": new_contract_name(prefix, p["src"], p["dst"], names),
            "write_mode": self.config.settings.ise.write_mode,
        }

    # ------------------------------------------------------------ edits
    def save_edit(self, pid: str, text: str | None) -> dict:
        p = self._pending(pid)
        if text is not None:
            res = acl.parse(text)
            if res.errors:
                raise ActionError("La SGACL contient des erreurs.", 400, {"errors": res.errors})
        edited = None if text is None or _norm(text) == _norm(p["proposed_acl"]) else text
        return self.store.save_proposal({**p, "edited_acl": edited})

    def set_mode(self, pid: str, mode: str) -> dict:
        if mode not in ("clone", "inplace"):
            raise ActionError("Mode inconnu.")
        p = self._pending(pid)
        return self.store.save_proposal({**p, "mode": mode})

    # ------------------------------------------------------------ decisions
    def reject(self, pid: str, actor: str) -> dict:
        p = self._pending(pid)
        p = self.store.save_proposal({**p, "status": "rejected", "decided_at": utcnow(), "decided_by": actor})
        self.store.audit(actor, "reject", {"proposal": pid, "pair": f"{p['src']} -> {p['dst']}"})
        return p

    def reopen(self, pid: str, actor: str) -> dict:
        p = self._get(pid)
        if p["status"] != "rejected":
            raise ActionError("Seule une proposition rejetée peut être rouverte.", 409)
        p = self.store.save_proposal({**p, "status": "pending", "decided_at": None, "decided_by": None})
        self.store.audit(actor, "reopen", {"proposal": pid})
        return p

    async def approve(self, pid: str, actor: str, text: str | None = None, mode: str | None = None,
                      merge: bool = False) -> dict:
        p = self._pending(pid)
        if p["kind"] == "external":
            raise ActionError("Source ou destination sans SGT : aucune cellule TrustSec ne peut porter ce contrat. "
                              "Traitez ce flux sur le pare-feu de sortie, ou rejetez la proposition.", 422)
        info = self.analyse(p, text)
        if info["validation"]["errors"]:
            raise ActionError("La SGACL contient des erreurs.", 400, {"errors": info["validation"]["errors"]})
        mode = mode or p.get("mode") or info["default_mode"]
        if info["changes_base"] and mode == "inplace" and not info["inplace_allowed"]:
            raise ActionError("Modification sur place refusée : elle bloquerait du trafic d’autres paires.", 409,
                              {"impacts": info["impacts"]})
        ise_cfg = self.config.settings.ise
        status = "MONITOR" if ise_cfg.write_mode == "monitor" else "ENABLED"
        final = _norm(info["acl"])
        desc = f"Matrix Advisor · {p['src']} -> {p['dst']} · proposition {pid}"

        async with self.ise.write_lock:
            m = self.ise.matrix
            src, dst = m.sgt_by_name(p["src"]), m.sgt_by_name(p["dst"])
            if not src or not dst:
                raise ActionError("SGT inconnu dans ISE : resynchronisez la matrice.", 409)
            client = self.ise.client
            try:
                fresh = await client.fresh_cell(m, p["src"], p["dst"])
            except ISEError as e:
                raise ActionError(f"Lecture de la cellule impossible : {e}", 502) from e
            fp = fresh.fingerprint() if fresh else NO_CELL_FINGERPRINT
            if fp != p["cell_fingerprint"] and not merge:
                names = []
                for sid in (fresh.sgacl_ids if fresh else []):
                    sg = m.sgacls.get(sid)
                    if sg is None:
                        try:
                            sg = await client.fresh_sgacl(sid)
                        except ISEError:
                            pass
                    names.append(sg.name if sg else sid)
                raise ActionError(
                    "La cellule a été modifiée dans ISE depuis la proposition. Rien n’a été écrit.", 409,
                    {"conflict": True, "current_contracts": names,
                     "current_status": fresh.status if fresh else None},
                )
            existing = list(fresh.sgacl_ids) if fresh else []
            # An existing cell keeps its status: never downgrade an enforced cell to monitor.
            cell_status = fresh.status if fresh else status
            base = m.sgacls.get(p.get("base_sgacl_id") or "")
            result: dict = {"cell_status": cell_status}
            try:
                if p["kind"] == "new":
                    name = info["new_name"]
                    sid = await client.create_sgacl(name, final, desc)
                    ids = existing + [sid]
                    result.update(action="create", sgacl=name)
                elif not info["changes_base"]:  # reuse unchanged
                    ids = existing + ([base.id] if base.id not in existing else [])
                    result.update(action="assign", sgacl=base.name)
                elif mode == "clone":
                    name = info["clone_name"]
                    sid = await client.create_sgacl(name, final, f"{desc} · cloné à partir de {base.name}")
                    ids = [sid if i == base.id else i for i in existing] if base.id in existing else existing + [sid]
                    result.update(action="clone", sgacl=name, cloned_from=base.name)
                else:
                    current = await client.fresh_sgacl(base.id)
                    if _norm(current.content) != _norm(base.content):
                        raise ActionError(f"{base.name} a été modifié dans ISE depuis la proposition.", 409,
                                          {"conflict": True})
                    await client.update_sgacl(current, final)
                    ids = existing + ([base.id] if base.id not in existing else [])
                    result.update(action="update", sgacl=base.name)
                cell_id = await client.upsert_cell(fresh, src.id, dst.id, ids, cell_status, desc)
                result["cell_id"] = cell_id
            except ISEError as e:
                raise ActionError(f"Écriture refusée par ISE : {e}", 502) from e
            try:
                await self.ise.reconcile()
            except ISEError:
                self.ise.request_reconcile()

        p = self.store.save_proposal({
            **p, "status": "approved", "decided_at": utcnow(), "decided_by": actor, "mode": mode,
            "edited_acl": info["acl"] if info["edited"] else None, "result": result,
        })
        self.store.audit(actor, "approve", {"proposal": pid, "pair": f"{p['src']} -> {p['dst']}", **result,
                                            "edited": info["edited"], "merge": merge})
        log.info("approved %s: %s", pid, result)
        return p
