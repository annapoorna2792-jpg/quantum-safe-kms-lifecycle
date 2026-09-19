"""
tests/conftest.py — fallback path fix.
Ensures backend/ is on sys.path even when pytest is invoked from tests/.
"""
import sys, os

BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")
BACKEND = os.path.abspath(BACKEND)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)
