"""
conftest.py — placed at the project root.
Inserts backend/ into sys.path so `import app` works
from any pytest invocation directory.
"""
import sys
import os

# Ensure backend/ is on the path regardless of where pytest is invoked
BACKEND = os.path.join(os.path.dirname(__file__), "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)
