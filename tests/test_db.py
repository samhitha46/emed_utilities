"""DB connection tests — skipped when no real database is available."""
import pytest

from emed_utilities.db.connection import check_connection


@pytest.mark.integration
def test_check_connection():
    assert check_connection(), "Could not reach the database"
