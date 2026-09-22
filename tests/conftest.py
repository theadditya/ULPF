"""
Pytest configuration and environment fixtures for ULPF.
Ensures src directory is automatically in the Python path regardless of execution environment.
"""

import sys
import os

# Automatically add src directory to sys.path
src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
