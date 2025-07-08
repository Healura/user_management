"""Main FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.auth_settings import auth_settings
from src.health import health_router
from src.database.database import init_db, check_database_connection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle events.
    """
    # Startup
    logger.info("Starting user management service...")
    
    # Check database connection
    if not check_database_connection():
        logger.error("Failed to connect to database")
        # In production, you might want to exit here
    else:
        logger.info("Database connection successful")
    
    # Initialize database tables (in production, use migrations)
    # init_db()
    
    yield
    
    # Shutdown
    logger.info("Shutting down user management service...")


# Create FastAPI application
app = FastAPI(
    title="Voice Biomarker User Management Service",
    description="User management microservice for voice biomarker healthcare application",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=auth_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health_router)

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Voice Biomarker User Management Service",
        "version": "1.0.0",
        "status": "operational"
    }

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handle unexpected exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An unexpected error occurred. Please try again later."
        }
    )