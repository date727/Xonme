"""Create C2Sherlock's application tables in the configured MySQL database.

Run from backend/ after configuring .env:
    python scripts/init_database.py
"""

from pathlib import Path
import sys

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

load_dotenv(BACKEND_ROOT / ".env")

from app.database import check_database_connection, initialise_database  # noqa: E402


if __name__ == "__main__":
    initialise_database()
    if not check_database_connection():
        raise SystemExit("Tables may have been created, but the database connection check failed.")
    print("Database connection verified. Tables users and analysis_records are ready.")
