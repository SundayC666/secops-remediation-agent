"""
Configuration settings using Pydantic
Loads environment variables from .env file
"""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings"""

    # Server configuration
    HOST: str = Field(default="0.0.0.0", description="Server host")
    PORT: int = Field(default=8000, description="Server port")
    DEBUG: bool = Field(default=False, description="Debug mode")

    # Ollama configuration
    OLLAMA_HOST: str = Field(default="http://localhost:11434", description="Ollama server URL")
    OLLAMA_MODEL: str = Field(default="llama3.2:3b-instruct-q4_K_M", description="LLM model name")

    # Data configuration
    CVE_CACHE_FILE: str = Field(default="data/cve_cache.json", description="CVE cache file path")
    CVE_CACHE_TTL_HOURS: int = Field(default=6, description="CVE cache time-to-live in hours")
    CVE_LOOKBACK_DAYS: int = Field(default=30, description="Number of days to fetch CVEs")
    CVE_MAX_RESULTS: int = Field(default=50, description="Maximum number of CVEs to fetch")

    # Vector database configuration
    LANCEDB_PATH: str = Field(default="lancedb", description="LanceDB storage path")
    EMBEDDING_MODEL: str = Field(default="sentence-transformers/all-MiniLM-L6-v2", description="Embedding model name")
    VECTOR_DIM: int = Field(default=384, description="Vector dimension")

    # API configuration
    NVD_API_KEY: Optional[str] = Field(default=None, description="NIST NVD API key (optional)")

    @property
    def SERVER_URL(self) -> str:
        """Get the server URL"""
        return f"http://{self.HOST if self.HOST != '0.0.0.0' else 'localhost'}:{self.PORT}"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"  # Ignore extra fields in .env file


# Global settings instance
settings = Settings()
