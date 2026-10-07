import concurrent.futures

import main


def create_post(client, **fields):
    payload = {"title": "기본 제목", **fields}
    res = client.post("/posts", json=payload)
    assert res.status_code == 200, res.text
    return res.json()["post_id"]


# =====================================================================
# 기본 CRUD
# =====================================================================
def test_health_check(client):
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_create_and_list_posts(client):
    create_post(client, title="중간고사 족보", content="자료구조 기출", tags="study", author="컴공21")
    create_post(client, title="학식 메뉴")

    res = client.get("/posts")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 2
    # 최신 글이 먼저 + author 기본값은 '익명'
    assert body["posts"][0]["title"] == "학식 메뉴"
    assert body["posts"][0]["author"] == "익명"
    assert body["posts"][1]["author"] == "컴공21"


def test_search_posts_by_title_and_content(client):
    create_post(client, title="도서관 자리", content="3층 창가")
    create_post(client, title="동아리 모집", content="AI 스터디 족보 공유")
    create_post(client, title="학식")

    assert client.get("/posts/search", params={"q": "도서관"}).json()["total"] == 1
    assert client.get("/posts/search", params={"q": "족보"}).json()["total"] == 1
    assert client.get("/posts/search", params={"q": "없는키워드"}).json()["total"] == 0


def test_filtered_posts_exclude_blocked_tags(client):
    create_post(client, title="정상 글", tags="study,exam")
    create_post(client, title="스포 글", tags="movie, Spoiler")
    create_post(client, title="비방 글", tags="hate")
    create_post(client, title="태그 없음")

    titles = {p["title"] for p in client.get("/posts/filtered").json()["posts"]}
    assert titles == {"정상 글", "태그 없음"}


# =====================================================================
# 보안: SQL Injection
# =====================================================================
def test_sql_injection_in_search_is_neutralized(client):
    create_post(client, title="비밀 아닌 글")

    res = client.get("/posts/search", params={"q": "zzz' OR 1=1 --"})
    assert res.status_code == 200
    assert res.json()["total"] == 0


def test_sql_injection_payload_is_stored_as_plain_text(client):
    payload = "x'); DROP TABLE posts; --"
    create_post(client, title=payload, content="it's O'Reilly")

    posts = client.get("/posts").json()["posts"]
    assert len(posts) == 1
    assert posts[0]["title"] == payload
    assert posts[0]["content"] == "it's O'Reilly"


def test_sql_injection_in_login_is_rejected(client):
    client.post("/api/auth/register", json={"username": "kim", "password": "pw1234"})
    res = client.post("/api/auth/login", json={"username": "kim' --", "password": "anything"})
    assert res.status_code == 401


# =====================================================================
# 보안: 관리자 인증
# =====================================================================
def test_admin_login_rejects_wrong_password(client):
    res = client.post("/admin/login", json={"password": "wrong"})
    assert res.status_code == 401


def test_admin_delete_requires_valid_token(client, admin_token):
    post_id = create_post(client, title="삭제 대상")

    assert client.delete(f"/admin/posts/{post_id}").status_code == 403
    assert client.delete(f"/admin/posts/{post_id}", headers={"X-Admin-Token": "forged"}).status_code == 403

    res = client.delete(f"/admin/posts/{post_id}", headers={"X-Admin-Token": admin_token})
    assert res.status_code == 200
    assert client.get("/posts").json()["total"] == 0


def test_admin_delete_missing_post_returns_404(client, admin_token):
    res = client.delete("/admin/posts/99999", headers={"X-Admin-Token": admin_token})
    assert res.status_code == 404


def test_user_login_does_not_leak_admin_token(client):
    client.post("/api/auth/register", json={"username": "lee", "password": "secret"})
    res = client.post("/api/auth/login", json={"username": "lee", "password": "secret"})

    assert res.status_code == 200
    body = res.json()
    assert "token" not in body
    assert "password_hash" not in body["user"]
    assert body["user"]["role"] == "user"


def test_register_duplicate_and_wrong_password(client):
    assert client.post("/api/auth/register", json={"username": "park", "password": "pw"}).status_code == 200
    assert client.post("/api/auth/register", json={"username": "park", "password": "pw2"}).status_code == 400
    assert client.post("/api/auth/login", json={"username": "park", "password": "nope"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "ghost", "password": "pw"}).status_code == 401


def test_items_require_admin_token(client, admin_token):
    assert client.post("/api/items", json={"title": "공지"}).status_code == 403

    res = client.post("/api/items", json={"title": "공지", "content": "시험 일정"}, headers={"X-Auth-Token": admin_token})
    assert res.status_code == 200
    assert client.get("/api/items", params={"keyword": "시험"}).json()["total"] == 1
    assert client.get("/api/items").json()["total"] == 1


# =====================================================================
# 입력값 검증
# =====================================================================
def test_empty_or_blank_title_is_rejected(client):
    assert client.post("/posts", json={"title": ""}).status_code == 422
    assert client.post("/posts", json={"title": "   "}).status_code == 422
    assert client.post("/posts", json={}).status_code == 422
    assert client.get("/posts").json()["total"] == 0


def test_invalid_post_fields_are_rejected(client):
    assert client.post("/posts", json={"title": "ok", "likes": -1}).status_code == 422
    assert client.post("/posts", json={"title": "ok", "author": "  "}).status_code == 422
    assert client.post("/posts", json={"title": "x" * 201}).status_code == 422


# =====================================================================
# 유틸리티 & 동시성
# =====================================================================
def test_password_hash_is_salted_and_verifiable():
    h1 = main.hash_credential("same-password")
    h2 = main.hash_credential("same-password")

    assert h1 != h2  # 랜덤 salt
    assert main.verify_credential("same-password", h1)
    assert not main.verify_credential("other-password", h1)


def test_deduplicate_records_keeps_first_occurrence_order():
    records = [{"id": 2, "v": "a"}, {"id": 1}, {"id": 2, "v": "b"}, {"id": 3}]
    assert main.deduplicate_records(records) == [{"id": 2, "v": "a"}, {"id": 1}, {"id": 3}]


def test_database_uses_wal_mode():
    conn = main.get_db_connection()
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert mode.lower() == "wal"


def test_concurrent_writes_do_not_lock(client):
    def write(i):
        return client.post("/posts", json={"title": f"동시 쓰기 {i}", "tags": "loadtest"}).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        statuses = list(pool.map(write, range(100)))

    assert statuses.count(200) == 100
    assert client.get("/posts").json()["total"] == 100
