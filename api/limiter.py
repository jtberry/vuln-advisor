"""
api/limiter.py -- Shared slowapi rate limiter instance.

Import this in both api/main.py (to mount as middleware) and
api/routes/v1/cve.py (to apply per-route limits with @limiter.limit()).

Using a single shared instance ensures all routes share the same in-memory
counter store. If this were instantiated in each module separately, each
module would get its own isolated counter and rate limits would never trigger.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
