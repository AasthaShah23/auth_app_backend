from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.main import app


@pytest.fixture(scope="module")
def db_session() -> Generator[Session, None, None]:
    """Provide a database session for direct model queries in tests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def client() -> Generator[TestClient, None, None]:
    """Provide a TestClient for making HTTP requests against the FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client
