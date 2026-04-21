import pytest
from pydantic import ValidationError

from emed_utilities.config.settings import Settings


def test_db_url_format():
    s = Settings(db_name="testdb", db_user="user", db_password="pass")
    assert s.db_url.startswith("mysql+pymysql://user:pass@")
    assert "testdb" in s.db_url


def test_missing_required_fields_raises():
    with pytest.raises(ValidationError):
        Settings()  # db_name, db_user, db_password have no defaults
