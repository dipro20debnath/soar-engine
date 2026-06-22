"""SOAR Engine - Test Configuration

Sets STORE_MODE=memory for all tests so they use the in-memory store
instead of SQLite (avoids test database pollution).
"""

import os

# Force in-memory store for all tests
os.environ["STORE_MODE"] = "memory"
