"""FastAPI web app — serves the attack graph dashboard."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).parent / "static"


def create_app(results_dir: Path) -> FastAPI:
    app = FastAPI(title="Cannon", docs_url=None, redoc_url=None)

    # ── API ───────────────────────────────────────────────────────────

    def _find_all_json() -> list[Path]:
        """Find all cannon graph JSON files in results dir and subdirs."""
        if not results_dir.is_dir():
            return []
        return sorted(results_dir.rglob("cannon_*.json"), reverse=True)

    def _find_json(run_id: str) -> Path | None:
        for f in results_dir.rglob(f"{run_id}.json"):
            return f
        return None

    @app.get("/api/runs")
    def list_runs() -> list[dict]:
        runs = []
        for f in _find_all_json():
            try:
                data = json.loads(f.read_text())
                runs.append({
                    "id": data.get("id", f.stem),
                    "target": data.get("target", ""),
                    "scope": data.get("scope", ""),
                    "started_at": data.get("started_at", ""),
                    "finished_at": data.get("finished_at", ""),
                    "status": data.get("status", "unknown"),
                    "stats": data.get("stats", {}),
                    "prompt": data.get("prompt", ""),
                })
            except (json.JSONDecodeError, KeyError):
                continue
        return runs

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict:
        path = _find_json(run_id)
        if not path:
            raise HTTPException(404, f"Run '{run_id}' not found")
        return json.loads(path.read_text())

    # ── Frontend ──────────────────────────────────────────────────────

    @app.get("/")
    def index() -> HTMLResponse:
        html = (STATIC_DIR / "index.html").read_text()
        return HTMLResponse(html)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    return app
