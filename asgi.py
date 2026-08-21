"""
asgi.py -- Application assembly for VulnAdvisor.

This is the ONLY file that imports from both api/ and web/. It joins the two
independent layers into a single ASGI app without coupling them to each other.
api/main.py knows nothing about web/; web/routes.py knows nothing about api/.

Run with:  uvicorn asgi:app --reload
           make run-api
"""

from pathlib import Path

from fastapi.staticfiles import StaticFiles

from api.main import app
from web.routes import router as web_router

# Mount the web UI router here, not in api/main.py.
# This keeps api/ and web/ independent -- neither imports from the other.
app.include_router(web_router, tags=["Web UI"])

# Mount the static file directory so /static/* requests are served from
# web/static/. This is done here (in asgi.py) rather than api/main.py to
# keep the api/ layer free of web concerns -- same separation-of-concerns
# principle that keeps web/routes.py out of api/main.py.
_static_dir = Path(__file__).parent / "web" / "static"
_static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
