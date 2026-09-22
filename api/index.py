"""
ULPF Serverless Entrypoint for Vercel Deployment.
Exposes the FastAPI ASGI application instance ('app') for Vercel serverless execution.
"""
import sys
import os
from pathlib import Path

# Add project root and src/ to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Ensure Vercel serverless environment defaults
os.environ.setdefault("VERCEL", "1")
os.environ.setdefault("ULPF_DATA_DIR", "/tmp/ulpf_data")
os.environ.setdefault("ULPF_DEPLOYMENT_MODE", "internet")

# Import the pre-configured FastAPI app
from ulpf.ui.app import app
