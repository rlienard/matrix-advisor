"""Application entry point: wiring, background workers and the HTTP server."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import secrets
import shutil
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .agent.actions import Actions
from .agent.advisor import Advisor, LLMHolder
from .api.routes import router
from .config import ConfigStore, default_config_path
from .ingest.pipeline import IngestPipeline
from .ingest.resolver import SGTResolver
from .ise.service import ISEService
from .ops import Backups, metrics_text
from .store import Store

log = logging.getLogger("matrix_advisor")


@dataclass
class Context:
    config: ConfigStore
    store: Store
    resolver: SGTResolver
    ise: ISEService
    llm: LLMHolder
    advisor: Advisor
    actions: Actions
    pipeline: IngestPipeline


def build_context(config_path: str | None = None, store_path: str | None = None) -> Context:
    path = Path(config_path or default_config_path())
    template = os.environ.get("MA_CONFIG_TEMPLATE")
    if not path.exists() and template and Path(template).exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(template, path)
        log.warning("No configuration found: initialised %s from %s", path, template)
    config = ConfigStore(path)
    _first_run_secrets(config)
    col = config.settings.collector
    store = Store(store_path or col.duckdb_path, parquet_dir=col.parquet_dir)
    resolver = SGTResolver()
    ise = ISEService(config, resolver)
    llm = LLMHolder(config)
    advisor = Advisor(config, store, ise, llm)
    actions = Actions(config, store, ise, advisor)
    # Flows wait for the SGT table (tags exported in flow records) and the endpoint context (pxGrid).
    pipeline = IngestPipeline(config, store, resolver,
                              ready=lambda: ise.context_ready and bool(ise.matrix.sgts))
    return Context(config, store, resolver, ise, llm, advisor, actions, pipeline)


def _first_run_secrets(config: ConfigStore) -> None:
    if not config.settings.server.session_secret:
        config.ensure_secret("server.session_secret", secrets.token_urlsafe(32))
    if not config.settings.server.admin_password:
        password = secrets.token_urlsafe(12)
        config.ensure_secret("server.admin_password", password)
        target = config.path.with_name("initial-admin-password")
        target.write_text(password + "\n")
        os.chmod(target, 0o600)
        log.warning("No admin password configured. Generated one, stored in %s", target)


def create_app(context: Context | None = None, start_workers: bool = True) -> FastAPI:
    ctx = context or build_context()
    backups = Backups.from_env(ctx)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks = []
        if start_workers:
            tasks = [
                asyncio.create_task(ctx.pipeline.run(), name="ingest"),
                asyncio.create_task(ctx.ise.run(), name="ise"),
                asyncio.create_task(ctx.llm.run(), name="llm"),
                asyncio.create_task(ctx.advisor.run(), name="advisor"),
            ]
            if backups:
                tasks.append(asyncio.create_task(backups.run(), name="backups"))
        yield
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        ctx.store.flush_parquet()
        ctx.store.close()

    app = FastAPI(title="Matrix Advisor", version=__version__, lifespan=lifespan)
    app.state.ctx = ctx
    app.state.backups = backups
    origins = ctx.config.settings.server.cors_origins
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True,
                           allow_methods=["*"], allow_headers=["*"])
    app.include_router(router)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/metrics", include_in_schema=False)
    def metrics(request: Request):
        # Off unless MA_METRICS_TOKEN is set; then a bearer token is required (Prometheus authorization).
        token = os.environ.get("MA_METRICS_TOKEN", "")
        if not token:
            raise HTTPException(status_code=404)
        given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(given.encode(), token.encode()):
            raise HTTPException(status_code=401)
        return PlainTextResponse(metrics_text(ctx, backups), media_type="text/plain; version=0.0.4")

    static = os.environ.get("MA_STATIC_DIR")
    if static and Path(static, "index.html").exists():
        app.mount("/assets", StaticFiles(directory=Path(static, "assets")), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            candidate = Path(static, path)
            if path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(Path(static, "index.html"))

    return app


def run() -> None:
    import uvicorn

    logging.basicConfig(level=os.environ.get("MA_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    # Behind the HTTPS reverse proxy, trust its X-Forwarded-Proto so that the session cookie is marked Secure.
    uvicorn.run(create_app(), host=os.environ.get("MA_HOST", "0.0.0.0"), port=int(os.environ.get("MA_PORT", "8000")),
                log_level=os.environ.get("MA_LOG_LEVEL", "info").lower(), proxy_headers=True,
                forwarded_allow_ips=os.environ.get("MA_FORWARDED_ALLOW_IPS", "127.0.0.1"))


if __name__ == "__main__":
    run()
