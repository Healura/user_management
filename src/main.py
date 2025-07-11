"""Application entry point - imports the configured FastAPI app."""

from .api.main import app

# running: uvicorn src.main:app
__all__ = ["app"]