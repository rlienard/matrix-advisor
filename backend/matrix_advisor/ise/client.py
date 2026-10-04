"""Cisco ISE REST client: ERS (TrustSec objects) and OpenAPI (deployment).

Endpoints used (ISE 3.x):
  GET/POST/PUT  /ers/config/sgt[/{id}]
  GET/POST/PUT  /ers/config/sgacl[/{id}]
  GET/POST/PUT  /ers/config/egressmatrixcell[/{id}]
  GET           /api/v1/deployment/node
  POST          /api/v1/certs/trusted-certificate/import   (only on an explicit request from the UI)
The API account needs the ERS Admin role (read/write) and ERS must be enabled on the PAN.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import UTC, datetime

import httpx

from ..config import ISEConfig
from ..i18n import Message
from ..policy.matrix import Cell, Matrix, Sgacl, Sgt

log = logging.getLogger(__name__)

PAGE = 100
CONCURRENCY = 8


class ISEError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _verify(verify_tls: bool, ca_cert: str) -> ssl.SSLContext | bool:
    if not verify_tls:
        return False
    if ca_cert:
        return ssl.create_default_context(cafile=ca_cert)
    return True


class ISEClient:
    def __init__(self, cfg: ISEConfig):
        self.cfg = cfg
        o = cfg.openapi
        base = o.base_url.rstrip("/") if o.base_url else f"https://{cfg.pan}:{o.port}"
        self.http = httpx.AsyncClient(
            base_url=base,
            auth=(o.username, o.password),
            verify=_verify(cfg.verify_tls, cfg.ca_cert),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=httpx.Timeout(20.0, connect=5.0),
        )
        self._sem = asyncio.Semaphore(CONCURRENCY)

    async def close(self) -> None:
        await self.http.aclose()

    # ------------------------------------------------------------ low level
    async def _request(self, method: str, url: str, **kw) -> httpx.Response:
        async with self._sem:
            try:
                r = await self.http.request(method, url, **kw)
            except httpx.HTTPError as e:
                raise ISEError(f"{method} {url}: {e.__class__.__name__}: {e}") from e
        if r.status_code == 401:
            raise ISEError(Message("ise_auth_refused"), 401)
        if r.status_code >= 400:
            detail = r.text[:300]
            raise ISEError(f"{method} {url} -> HTTP {r.status_code}: {detail}", r.status_code)
        return r

    async def _list(self, resource: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        page = 1
        while True:
            q = {"size": PAGE, "page": page, **(params or {})}
            data = (await self._request("GET", f"/ers/config/{resource}", params=q)).json()
            res = data.get("SearchResult", {})
            out.extend(res.get("resources", []))
            if not res.get("nextPage") or len(out) >= res.get("total", 0):
                return out
            page += 1

    async def _get(self, resource: str, oid: str, key: str) -> dict:
        data = (await self._request("GET", f"/ers/config/{resource}/{oid}")).json()
        return data.get(key, data)

    async def _create(self, resource: str, key: str, body: dict) -> str:
        r = await self._request("POST", f"/ers/config/{resource}", json={key: body})
        location = r.headers.get("Location", "")
        if location:
            return location.rstrip("/").rsplit("/", 1)[-1]
        data = r.json() if r.content else {}
        return data.get(key, {}).get("id", "")

    async def _update(self, resource: str, key: str, oid: str, body: dict) -> None:
        await self._request("PUT", f"/ers/config/{resource}/{oid}", json={key: {"id": oid, **body}})

    # ------------------------------------------------------------ reads
    async def ping(self) -> dict:
        data = (await self._request("GET", "/ers/config/sgt", params={"size": 1})).json()
        return {"sgt_total": data.get("SearchResult", {}).get("total", 0)}

    async def deployment_nodes(self) -> list[dict]:
        data = (await self._request("GET", "/api/v1/deployment/node")).json()
        nodes = data.get("response", data if isinstance(data, list) else [])
        out = []
        for n in nodes:
            services = n.get("services") or []
            roles = n.get("roles") or []
            out.append({
                "fqdn": n.get("fqdn") or n.get("hostname"),
                "hostname": n.get("hostname"),
                "ip": n.get("ipAddress", ""),
                "roles": roles,
                "services": services,
                "status": n.get("nodeStatus", ""),
                "pxgrid": any("pxgrid" in str(s).lower() for s in services) or any("pxgrid" in str(r).lower() for r in roles),
            })
        return out

    async def import_trusted_certificate(self, name: str, pem: str, description: str) -> dict:
        """Add a certificate to the ISE trusted store, trusted for client authentication (pxGrid).

        Field names follow the ISE 3.x OpenAPI (TrustedCertificateImport); to check against the
        Swagger of the target version. Needs an account with rights on certificates.
        """
        r = await self._request("POST", "/api/v1/certs/trusted-certificate/import", json={
            "name": name, "description": description, "data": pem,
            "trustForClientAuth": True, "allowBasicConstraintCAFalse": True,
            "trustForIseAuth": False, "trustForCertificateBasedAdminAuth": False,
            "trustForCiscoServicesAuth": False, "allowOutOfDateCert": False, "allowSHA1Certificates": False,
            "validateCertificateExtensions": False,
        })
        data = r.json() if r.content else {}
        return data.get("response", data) if isinstance(data, dict) else {}

    async def read_matrix(self, default: str = "deny") -> Matrix:
        sgt_items, acl_items, cell_items = await asyncio.gather(
            self._list("sgt"), self._list("sgacl"), self._list("egressmatrixcell")
        )
        sgts_raw = await asyncio.gather(*(self._get("sgt", i["id"], "Sgt") for i in sgt_items))
        acls_raw = await asyncio.gather(*(self._get("sgacl", i["id"], "Sgacl") for i in acl_items))
        cells_raw = await asyncio.gather(*(self._get("egressmatrixcell", i["id"], "EgressMatrixCell") for i in cell_items))

        m = Matrix(default=default, synced_at=datetime.now(UTC).replace(tzinfo=None))
        for s in sgts_raw:
            m.sgts[s["id"]] = Sgt(s["id"], s["name"], int(s.get("value", -1)), s.get("description", ""))
        for a in acls_raw:
            m.sgacls[a["id"]] = Sgacl(
                a["id"], a["name"], a.get("aclcontent", ""), a.get("description", ""),
                str(a.get("generationId", "")), bool(a.get("readOnly", False)),
            )
        for c in cells_raw:
            src, dst = m.sgts.get(c.get("sourceSgtId")), m.sgts.get(c.get("destinationSgtId"))
            if not src or not dst:
                continue
            m.cells[(src.name, dst.name)] = self._cell(c)
        return m

    @staticmethod
    def _cell(c: dict) -> Cell:
        return Cell(
            id=c["id"], src_id=c.get("sourceSgtId", ""), dst_id=c.get("destinationSgtId", ""),
            status=c.get("matrixCellStatus", "ENABLED"), default_rule=c.get("defaultRule", "NONE"),
            sgacl_ids=list(c.get("sgacls") or []), name=c.get("name", ""), description=c.get("description", ""),
        )

    async def fresh_cell(self, matrix: Matrix, src: str, dst: str) -> Cell | None:
        """Re-read the cell for (src, dst) directly from ISE, bypassing the cache."""
        cached = matrix.cells.get((src, dst))
        if cached:
            try:
                return self._cell(await self._get("egressmatrixcell", cached.id, "EgressMatrixCell"))
            except ISEError as e:
                if e.status != 404:
                    raise
        s, d = matrix.sgt_by_name(src), matrix.sgt_by_name(dst)
        if not s or not d:
            return None
        items = await self._list("egressmatrixcell")
        for it in items:
            c = await self._get("egressmatrixcell", it["id"], "EgressMatrixCell")
            if c.get("sourceSgtId") == s.id and c.get("destinationSgtId") == d.id:
                return self._cell(c)
        return None

    async def fresh_sgacl(self, sgacl_id: str) -> Sgacl:
        a = await self._get("sgacl", sgacl_id, "Sgacl")
        return Sgacl(a["id"], a["name"], a.get("aclcontent", ""), a.get("description", ""),
                     str(a.get("generationId", "")), bool(a.get("readOnly", False)))

    # ------------------------------------------------------------ writes
    async def create_sgacl(self, name: str, content: str, description: str) -> str:
        return await self._create("sgacl", "Sgacl", {
            "name": name, "description": description, "ipVersion": "IPV4", "aclcontent": content,
        })

    async def update_sgacl(self, sg: Sgacl, content: str, description: str | None = None) -> None:
        body = {"name": sg.name, "description": description if description is not None else sg.description,
                "ipVersion": "IPV4", "aclcontent": content}
        if sg.generation_id:
            body["generationId"] = sg.generation_id
        await self._update("sgacl", "Sgacl", sg.id, body)

    async def upsert_cell(self, existing: Cell | None, src_id: str, dst_id: str, sgacl_ids: list[str],
                          status: str, description: str) -> str:
        body = {
            "sourceSgtId": src_id, "destinationSgtId": dst_id, "matrixCellStatus": status,
            "defaultRule": existing.default_rule if existing else "NONE", "sgacls": sgacl_ids,
            "description": description,
        }
        if existing:
            await self._update("egressmatrixcell", "EgressMatrixCell", existing.id, body)
            return existing.id
        return await self._create("egressmatrixcell", "EgressMatrixCell", body)
