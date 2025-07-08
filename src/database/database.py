"""Database connection and session management."""

import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event, pool
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError

from config.database_config import database_config, get_database_url
from .models import Base

# Configure logging
logger = logging.getLogger(__name__)

# Create database engine with AWS RDS optimizations
engine = create_engine(
    get_database_url(),
    pool_size=database_config.db_pool_size,
    max_overflow=database_config.db_max_overflow,
    pool_timeout=database_config.db_pool_timeout,
    pool_recycle=database_config.db_pool_recycle,
    pool_pre_ping=True,  # Verify connections before using
    echo=database_config.db_echo,
    connect_args={
        "sslmode": database_config.db_ssl_mode,
        "connect_timeout": 10,
        "options": "-c statement_timeout=30000"  # 30 second statement timeout
    }
)

# Configure session factory
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False
)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency to get database session.
    
    Yields:
        Database session
    """
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as e:
        logger.error(f"Database error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Context manager for database sessions.
    
    Usage:
        with get_db_context() as db:
            # Use db session
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except SQLAlchemyError as e:
        logger.error(f"Database error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    """Initialize database tables."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except SQLAlchemyError as e:
        logger.error(f"Error creating database tables: {e}")
        raise


def check_database_connection() -> bool:
    """
    Check if database connection is working.
    
    Returns:
        True if connection is successful, False otherwise
    """
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        return True
    except SQLAlchemyError as e:
        logger.error(f"Database connection failed: {e}")
        return False


# Event listeners for connection pooling
@event.listens_for(pool.Pool, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Set connection parameters when a new connection is created."""
    # This is called for each new connection
    # Add any connection-specific settings here
    pass


@event.listens_for(pool.Pool, "checkout")
def ping_connection(dbapi_conn, connection_record, connection_proxy):
    """Verify connection is still valid when checking out from pool."""
    # The pool_pre_ping parameter handles this automatically
    pass