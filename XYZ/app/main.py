import asyncio
import secrets as stdsecrets
from contextlib import asynccontextmanager
from typing import Literal
from fastapi import FastAPI, HTTPException, Header, Depends, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from app.config import Settings, ROOT
from app.auth import Authentication, Principal
from app.models import Envelope, User, Agent, Input, ToolProposal, finding
from app.policy.loader import PolicyLoader
from app.controls.signatures import SignatureLoader
from app.controls.budget import BudgetEngine
from app.controls.memory_guard import MemoryGuard, MemoryWrite
from app.audit.database import Database
from app.audit.logger import AuditLogger
from app.metrics.collector import Metrics
from app.providers.ollama import Ollama
from app.semantic.analyzer import SemanticAnalyzer
from app.tools.real_tools import RealTools
from app.tools.registry import WebSearch, schemas
from app.gateway import Gateway


class SearchRequest(WebSearch):
    mode: Literal["quick", "google"] = "quick"


def create_app(settings=None):
    settings = settings or Settings.from_env()
    authentication = Authentication(settings)
    db = Database(settings.database_path)
    audit = AuditLogger(db)
    policy = PolicyLoader(settings.policy_path, lambda v: audit.record(None, finding("configuration", "POLICY_RELOADED", "Validated policy activated", "ALLOW", "info", 0), v))
    feed = SignatureLoader(settings.signature_path, lambda v: audit.record(None, finding("configuration", "SIGNATURES_RELOADED", "Validated signature feed activated", "ALLOW", "info", 0), policy.version, details={"signature_version": v}))
    budgets, metrics = BudgetEngine(db), Metrics(db)
    provider = Ollama(settings, metrics)
    semantic = SemanticAnalyzer(provider)
    tools, memory = RealTools(db, settings), MemoryGuard(db)
    gateway = Gateway(policy, feed, budgets, audit, metrics, tools, provider, semantic, settings)

    @asynccontextmanager
    async def lifespan(app):
        async def watcher():
            while True:
                await asyncio.sleep(.5)
                try:
                    policy.reload()
                    feed.reload()
                    app.state.reload_error = None
                except Exception:
                    app.state.reload_error = "Configuration activation audit failed"
        task = asyncio.create_task(watcher())
        yield
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    app = FastAPI(title="AEGIS", version="2.0.0", lifespan=lifespan)
    app.state.gateway, app.state.memory, app.state.settings = gateway, memory, settings
    app.state.reload_error = None
    app.mount("/static", StaticFiles(directory=ROOT / "app/dashboard/static"), name="static")

    async def admin(x_admin_token: str | None = Header(default=None)):
        if not settings.admin_token or not stdsecrets.compare_digest((x_admin_token or "").encode(), settings.admin_token.encode()):
            raise HTTPException(401, "Valid X-Admin-Token required")

    def trusted_context(ctx, principal):
        bound = authentication.bind(ctx, principal)
        if "model" not in ctx.model_fields_set:
            bound = bound.model_copy(update={"model": settings.ollama_model})
        return bound

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI's default error body echoes invalid inputs, potentially leaking credentials.
        return JSONResponse(status_code=422, content={"detail": [{"loc": list(e["loc"]), "type": e["type"], "msg": "Invalid request field"} for e in exc.errors()]})

    @app.get("/")
    def dashboard():
        return FileResponse(ROOT / "app/dashboard/templates/index.html")

    @app.get("/health")
    def health():
        with db.connect() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok", "database": "ready", "policy_version": policy.version}

    @app.get("/api/me")
    def me(principal: Principal = Depends(authentication.authenticate)):
        return {"user": principal.user().model_dump(), "agents": principal.agents}

    @app.get("/api/status", dependencies=[Depends(authentication.authenticate)])
    async def status():
        state = await provider.status()
        policy.snapshot()
        feed.snapshot()
        guard = "ACTIVE" if state["model"] == "AVAILABLE" and settings.semantic_enabled and policy.active.semantic.enabled else "FALLBACK"
        posture = "WARNING" if policy.error or feed.error or app.state.reload_error or not policy.active.controls.secrets.enabled or not policy.active.controls.prompt_injection.enabled else "PROTECTED"
        return {**state, "semantic_guard": guard, "last_semantic_state": semantic.state, "model_name": settings.ollama_model,
                "posture": posture, "policy_version": policy.version, "signature_version": feed.version,
                "policy_error": policy.error, "signature_error": feed.error, "reload_error": app.state.reload_error,
                "identity_mode": "api-key", "simulated_tools": False, "management_auth": bool(settings.admin_token),
                "tools_mode": "live", "authenticated_principals": len(authentication.keys)}

    @app.post("/api/evaluate")
    async def evaluate(ctx: Envelope, principal: Principal = Depends(authentication.authenticate)):
        return await gateway.process(trusted_context(ctx, principal))

    @app.post("/api/chat")
    async def chat(ctx: Envelope, principal: Principal = Depends(authentication.authenticate)):
        return await gateway.process(trusted_context(ctx, principal), "chat")

    @app.post("/api/tool/evaluate")
    async def tool_evaluate(ctx: Envelope, principal: Principal = Depends(authentication.authenticate)):
        if not ctx.tool:
            raise HTTPException(422, "Tool proposal required")
        return await gateway.process(trusted_context(ctx, principal), "evaluate")

    @app.post("/api/tool/execute")
    async def tool_execute(ctx: Envelope, principal: Principal = Depends(authentication.authenticate)):
        if not ctx.tool:
            raise HTTPException(422, "Tool proposal required")
        return await gateway.process(trusted_context(ctx, principal), "execute")

    @app.post("/api/search")
    async def search(request: SearchRequest, principal: Principal = Depends(authentication.authenticate)):
        # The broker owns query sanitization; avoid echoing an encoded raw query
        # separately through the general input/audit fields.
        ctx = Envelope(input=Input(text="Search public information"), agent=Agent(id=principal.agents[0]),
                       tool=ToolProposal(name="web.search", arguments={"query": request.query}))
        mode = "execute" if request.mode == "quick" else "search_link"
        return await gateway.process(trusted_context(ctx, principal), mode)

    @app.get("/api/tools", dependencies=[Depends(authentication.authenticate)])
    def tool_schemas():
        return schemas()

    @app.get("/api/events", dependencies=[Depends(admin)])
    def events(limit: int = Query(100, ge=1, le=500), decision: str | None = None,
               severity: str | None = None, control: str | None = None, user: str | None = None):
        return audit.recent(limit, decision=decision, severity=severity, control=control, user_id=user)

    @app.get("/api/metrics", dependencies=[Depends(admin)])
    def get_metrics():
        return metrics.snapshot(policy.version, feed.version)

    @app.get("/api/policy", dependencies=[Depends(admin)])
    def get_policy():
        active, version = policy.snapshot()
        return {"active_version": version, "error": policy.error, "policy": active.model_dump(by_alias=True)}

    @app.post("/api/policy/reload", dependencies=[Depends(admin)])
    def reload_policy():
        changed = policy.reload(force=True)
        return {"changed": changed, "active_version": policy.version, "error": policy.error}

    @app.get("/api/budgets", dependencies=[Depends(admin)])
    def get_budgets():
        return {**budgets.snapshot(), "limits": policy.active.budgets.model_dump(by_alias=True)}

    @app.post("/api/budgets/reset", dependencies=[Depends(admin)])
    def reset_budgets():
        audit.record(None, finding("budget", "BUDGET_RESET", "Budget counters reset by authenticated operator", "ALLOW", "info", 0), policy.version)
        budgets.reset()
        return {"reset": True}

    @app.get("/api/signatures", dependencies=[Depends(admin)])
    def get_signatures():
        active, version = feed.snapshot()
        return {"active_version": version, "error": feed.error, "feed": active.model_dump()}

    @app.post("/api/signatures/reload", dependencies=[Depends(admin)])
    def reload_signatures():
        changed = feed.reload(force=True)
        return {"changed": changed, "active_version": feed.version, "error": feed.error}

    @app.post("/api/memory")
    def write_memory(request: MemoryWrite, principal: Principal = Depends(authentication.authenticate)):
        request = authentication.bind(request, principal)
        active, version = policy.snapshot()
        active_feed, _ = feed.snapshot()
        result = memory.write(request, active, active_feed)
        ctx = Envelope(user=request.user, agent=request.agent)
        audit.record(ctx, finding("memory", "MEMORY_QUARANTINED" if result["quarantined"] else "MEMORY_WRITTEN",
                                 "Memory quarantined" if result["quarantined"] else "Untrusted memory stored with provenance", result["decision"]),
                     version, details={"provenance": result["provenance"], "memory_id": result["id"]})
        return result

    @app.post("/api/memory/{record_id}/read")
    def read_memory(record_id: str, ctx: Envelope, principal: Principal = Depends(authentication.authenticate)):
        ctx = trusted_context(ctx, principal)
        result = memory.read(record_id, ctx.user, ctx.agent)
        allowed = result is not None
        audit.record(ctx, finding("memory", "MEMORY_READ" if allowed else "MEMORY_ACCESS_DENIED", "Memory ownership/provenance enforced", "ALLOW" if allowed else "BLOCK"), policy.version, details={"memory_id": record_id})
        if not allowed:
            raise HTTPException(403, "Memory absent, quarantined, or belongs to another identity")
        return result

    return app


app = create_app()
