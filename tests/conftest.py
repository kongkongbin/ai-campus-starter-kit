import os
import sys
import tempfile

import pytest

# main.py는 import 시점에 환경변수를 읽고 DB를 초기화하므로, import 전에 테스트용 값을 설정
_TEST_DIR = tempfile.mkdtemp(prefix="board_test_")
os.environ["DB_FILE"] = os.path.join(_TEST_DIR, "test.db")
os.environ["ADMIN_PASSWORD"] = "test-admin-password"
os.environ.pop("ADMIN_TOKEN", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


@pytest.fixture(autouse=True)
def clean_db():
    conn = main.get_db_connection()
    conn.execute("DELETE FROM posts")
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM items")
    conn.commit()
    conn.close()


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def admin_token(client):
    res = client.post("/admin/login", json={"password": ADMIN_PASSWORD})
    assert res.status_code == 200
    return res.json()["token"]
