from .auth_endpoints import router as auth_router
from .user_endpoints import router as user_router
from .health_endpoints import router as health_router
from .middleware import setup_middleware

__all__ = [
    "auth_router",
    "user_router", 
    "health_router",
    "setup_middleware",
]