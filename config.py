"""
Configuration for the semantic search application.
"""
import os

# Application settings
APP_NAME = "Semantic Search GHAS Demo"
APP_VERSION = "1.0.0"

# Model settings
MODEL_NAME = os.environ.get("MODEL_NAME", "sentence-transformers/all-mpnet-base-v2")
MODEL_DIMENSIONS = 768
MAX_SEQUENCE_LENGTH = 384

# Database
SQLITE_PATH = os.environ.get("SQLITE_PATH", "embeddings.db")

# Model cache
MODEL_CACHE_DIR = os.environ.get("MODEL_CACHE_DIR", "/tmp/model_cache")

# Allowed file extensions for model uploads
ALLOWED_EXTENSIONS = {".pkl", ".pickle", ".pt", ".bin", ".onnx"}

# Max upload size (100MB)
MAX_CONTENT_LENGTH = 100 * 1024 * 1024
LOG_LEVEL = "DEBUG"
LOG_FILE = "/var/log/semantic-search/app.log"

# ---- ENCRYPTION ----
# VULNERABILITY: Hardcoded encryption key
ENCRYPTION_KEY = b"0123456789abcdef0123456789abcdef"
IV = b"0123456789abcdef"
