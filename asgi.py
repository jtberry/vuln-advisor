"""
asgi.py -- Application assembly for VulnAdvisor.

This is the ONLY file that imports from both api/ and web/. It joins the two
independent layers into a single ASGI app without coupling them to each other.
api/main.py knows nothing about web/; web/routes.py knows nothing about api/.

Run with:  uvicorn asgi:app --reload
           make run-api
"""

from api.main import app
from web.routes import router as web_router

# Mount the web UI router here, not in api/main.py.
# This keeps api/ and web/ independent -- neither imports from the other.
app.include_router(web_router, tags=["Web UI"])
