"""Database configuration and connection settings."""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr


class DatabaseConfig(BaseSettings):
    """Database configuration with AWS RDS settings."""
    
    # RDS Connection
    rds_endpoint: str = Field(
        default="voice-biomarker-users-db.cnq0agmieipg.eu-central-1.rds.amazonaws.com",
        env="RDS_ENDPOINT"
    )
    rds_port: int = Field(default=5432, env="RDS_PORT")
    rds_db_name: str = Field(default="voice_biomarker_users", env="RDS_DB_NAME")
    rds_username: str = Field(default="postgres", env="RDS_USERNAME")
    rds_password: Optional[SecretStr] = Field(default=None, env="RDS_PASSWORD")
    
    # Connection Pool Settings
    db_pool_size: int = Field(default=5, env="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=10, env="DB_MAX_OVERFLOW")
    db_pool_timeout: int = Field(default=30, env="DB_POOL_TIMEOUT")
    db_pool_recycle: int = Field(default=3600, env="DB_POOL_RECYCLE")
    
    # SSL Configuration
    db_ssl_mode: str = Field(default="require", env="DB_SSL_MODE")
    
    # Echo SQL queries (for debugging)
    db_echo: bool = Field(default=False, env="DB_ECHO")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # Allow extra fields in .env file


def get_database_url(config: Optional[DatabaseConfig] = None) -> str:
    """
    Construct the database URL from configuration.
    
    Args:
        config: DatabaseConfig instance. If None, creates a new instance.
        
    Returns:
        PostgreSQL connection URL with SSL parameters
    """
    if config is None:
        config = DatabaseConfig()
    
    # Construct base URL
    if config.rds_password is None:
        raise ValueError("RDS_PASSWORD environment variable is required")
    
    password = config.rds_password.get_secret_value()
    base_url = (
        f"postgresql+psycopg2://{config.rds_username}:{password}"
        f"@{config.rds_endpoint}:{config.rds_port}/{config.rds_db_name}"
    )
    
    # Add SSL parameters for AWS RDS
    ssl_params = f"?sslmode={config.db_ssl_mode}"
    
    return f"{base_url}{ssl_params}"


# Create a singleton instance
database_config = DatabaseConfig()