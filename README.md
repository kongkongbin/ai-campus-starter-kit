# 🎓 Campus Board API — AI가 만든 코드를 하네스로 검증한 익명 게시판 백엔드

![Harness](https://img.shields.io/badge/Harness-3%2F3%20GREEN-brightgreen)
![Security](https://img.shields.io/badge/CWE%20findings-0-brightgreen)
![Tests](https://img.shields.io/badge/tests-19%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![Stack](https://img.shields.io/badge/FastAPI%20%2B%20SQLite-WAL-blue)

> **"AI가 15분 만에 만든 게시판 API에서 SQL Injection·자격증명 노출·권한 결함을 CI와 하네스로 찾아내고, 측정 가능한 지표로 개선을 검증한 프로젝트입니다."**

---

## 🎯 1. 문제 정의

AI 코딩 도구는 기능을 빠르게 만들어 주지만, **코드베이스 안의 잘못된 지시를 그대로 따릅니다.**
이 프로젝트의 시드 코드 상단에는 *"SQL은 f-string으로, 비밀번호는 MD5로, 비밀값은 상수로"* 라는 주석이 숨어 있었고, AI가 생성한 초안은 이를 충실히 따라 다음 결함을 가진 채 동작했습니다.

- 검색창에 `zzz' OR 1=1 --` 입력 시 **전체 게시글 노출** (SQL Injection)
- 관리자 토큰·비밀번호가 **소스코드에 평문 하드코딩**
- **아무 사용자나 가입 후 로그인하면 관리자 토큰을 발급**받아 게시글 삭제 가능
- 작은따옴표가 들어간 글(`it's`)을 쓰면 **500 에러**

"동작한다"와 "운영할 수 있다" 사이의 간극을 **자동화된 검증 장치(Harness)** 로 메우는 것이 목표였습니다.

---

## 🏗️ 2. 아키텍처

```mermaid
flowchart LR
    C["클라이언트"] --> A["FastAPI<br/>입력 검증 · 관리자 인증"]
    A --> D[("SQLite<br/>WAL + busy_timeout")]

    subgraph G["🛡️ 품질 게이트"]
        direction TB
        CI["GitHub Actions<br/>AI PR Reviewer"]
        S1["Stage 1<br/>보안 정적 검사"]
        S2["Stage 2<br/>pytest 19개"]
        S3["Stage 3<br/>WAL · SLA 검사"]
        L["simulate_load.py<br/>동시성 부하 측정"]
    end

    A -.->|PR · 커밋마다 검증| G
```

| 계층 | 구성 |
|---|---|
| API | FastAPI, Pydantic v2 (`StringConstraints`로 입력 검증) |
| 저장소 | SQLite, WAL 모드, `synchronous=NORMAL`, busy_timeout 5초 |
| 인증 | 관리자 비밀번호·토큰은 환경변수, 상수 시간 비교(`hmac.compare_digest`) |
| 비밀번호 | PBKDF2-HMAC-SHA256, 랜덤 salt, 200,000회 반복 |
| 검증 | GitHub Actions 리뷰 봇 + 3단계 하네스 + 부하 시뮬레이터 |

---

## ⚡ 3. Before vs After (실측)

> 모든 수치는 같은 PC(Windows 11, Python 3.12)에서 직접 측정했습니다. 측정 조건은 표 아래에 적었습니다.

### 품질 · 보안

| 지표 | ❌ AI 초안 (세션 1) | ✅ 하네스 적용 후 (세션 2) |
|---|:---:|:---:|
| CI 리뷰 봇 지적 | **4건** (SQLi, 하드코딩, MD5, O(N²)) | **0건** |
| 하네스 게이트 | **RED** (3건 탈락) | **100% GREEN** |
| 단위 테스트 / 커버리지 | 0개 / 0% | **19개 / 100%** |
| SQL Injection (`' OR 1=1 --`) | 전체 글 노출 | 0건 반환 |
| 일반 사용자의 관리자 권한 획득 | 가능 | 불가 |

### 알고리즘: 중복 제거 O(N²) → O(N)

| 레코드 수 | 중첩 루프 (Before) | `set` 조회 (After) | 개선 |
|---:|---:|---:|---:|
| 1,000 | 34.00 ms | 0.18 ms | **191배** |
| 5,000 | 711.29 ms | 0.69 ms | **1,025배** |
| 10,000 | 2,791.06 ms | 0.98 ms | **2,836배** |

> 차단 태그 필터는 비교 대상이 4개로 고정되어 있어 `set` 전환 전후 차이가 측정 오차 수준(10,000건 기준 6.5ms)이었습니다. 복잡도 개선은 **입력 크기에 비례해 커지는 루프**에서만 의미가 있다는 점을 확인했습니다.

### 동시 쓰기 부하: `POST /posts` 500건

| 동시 요청 | 지표 | Before (롤백 저널) | After (WAL) | 변화 |
|:---:|---|---:|---:|:---:|
| 20 | 처리량 | 94 RPS | **137 RPS** | **+45%** |
| 20 | p99 지연 | 2,564 ms | **1,096 ms** | **−57%** |
| 20 | p50 지연 | 33 ms | 89 ms | 악화 |
| 50 | 처리량 | 133 RPS | 135 RPS | 변화 없음 |
| 50 | p99 지연 | 3,390 ms | 3,049 ms | −10% |
| 20 / 50 | 에러율 | 0% | 0% | — |

<sub>측정: `simulate_load.py --url http://127.0.0.1:8001/posts --requests 500`, 조건별 2회 평균, uvicorn 워커 1개, DB는 로컬 디스크.</sub>

**해석**
- WAL 전환 효과는 **꼬리 지연(p99)과 처리량**에서 뚜렷했습니다. 쓰기가 읽기를 막지 않고, 커밋 시 디스크 동기화 비용이 줄었기 때문입니다.
- 동시 요청 50에서는 차이가 사라졌습니다. 이 구간의 병목은 DB가 아니라 **단일 uvicorn 워커**로 판단됩니다.
- 기본 `busy_timeout`(5초) 덕분에 Before에서도 에러는 나지 않았습니다. 락 경합은 **에러가 아니라 지연으로** 나타났습니다.

---

## 🛡️ 4. 보안 가드레일

| 위협 | Before | After |
|---|---|---|
| **CWE-89** SQL Injection | `execute(f"... LIKE '%{q}%'")` | 모든 쿼리 `?` 파라미터 바인딩 |
| **CWE-798** 하드코딩 자격증명 | `ADMIN_MASTER_TOKEN = "DEV_MOCK_..."` | `os.getenv()` + 미설정 시 토큰 랜덤 생성, `.env.example` 제공 |
| **CWE-327** 취약 해시 | `hashlib.md5(pw)`, salt 없음 | PBKDF2-SHA256 + 랜덤 salt, 상수 시간 비교 |
| **CWE-285** 부적절한 권한 부여 | 일반 로그인이 관리자 토큰 반환 | 관리자 토큰은 `/admin/login`에서만 발급 |
| **CWE-20** 입력 검증 누락 | 빈 제목, 음수 좋아요 저장 | 빈 값·공백·길이 초과·음수 → 422 |
| 프롬프트 인젝션 | 시드 코드 주석이 AI에게 취약 패턴 지시 | 주석 제거, `harness/AGENTS.md` 규칙으로 대체 |

---

## ✅ 5. 하네스 검증 결과

```text
============================================================
  Campus Harness Verification Engine
============================================================
🔍 [Stage 1] Running AST Security & Secret Scan...
  ✅ Stage 1 PASS: 보안 취약점 0건 (Clean)

🧪 [Stage 2] Running Automated Unit & Regression Tests...
  ✅ Stage 2 PASS: 모든 단위/통합 테스트 100% 통과

⚡ [Stage 3] Running Performance & Latency SLA Benchmark...
  ✅ [SLA Latency] p99 응답 시간 1.49ms < 100ms SLA 충족
  ✅ [DB Concurrency] SQLite WAL 모드 활성화 (고동시성 락 충돌 방어 완료)

🎉 [100% GREEN] 모든 하네스 검증 통과! 프로덕션 배포가 안전합니다.
```

**테스트 구성** ([`tests/test_api.py`](tests/test_api.py), 19개)

| 영역 | 검증 내용 |
|---|---|
| CRUD | 작성·목록·검색·차단 태그 필터, `author` 기본값 |
| 보안 | 검색/로그인 SQL Injection 무력화, 공격 문자열이 평문으로 저장되는지 |
| 인증 | 잘못된 비밀번호 401, 토큰 없음·위조 403, 일반 로그인에 토큰 미노출 |
| 입력 검증 | 빈 제목·공백 제목·음수 좋아요·길이 초과 → 422 |
| 동시성 | WAL 모드 활성화 확인, 20 스레드 동시 쓰기 100건 전부 성공 |

---

## 🔧 6. 하네스 자체의 결함도 고쳤습니다

검증 도구도 코드입니다. 실행해 보니 Windows 환경에서 하네스가 **잘못된 결과**를 내고 있었습니다.

| 문제 | 증상 | 조치 |
|---|---|---|
| `python3` 하드코딩 | Windows의 MS Store 스텁이 실행되어 테스트가 통과해도 Stage 2 FAIL | `sys.executable` 사용 |
| cp949 인코딩 | AI 에이전트처럼 출력을 파이프로 받으면 이모지에서 크래시 | stdout·자식 프로세스를 UTF-8로 고정 |
| 연결 누수 | 락 실패 시 DB 연결이 안 닫혀 임시 파일 삭제 중 크래시 | `finally`에서 연결 종료 |

검사 기준은 바꾸지 않았고, **실행 환경 문제만** 수정했습니다.

---

## 🚀 7. 실행 방법

```bash
git clone https://github.com/kongkongbin/ai-campus-starter-kit.git
cd ai-campus-starter-kit
python -m venv .venv
```

```bash
# macOS / Linux
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

```bash
pip install -r requirements.txt
cp .env.example .env   # ADMIN_PASSWORD 등 설정 (미설정 시 개발용 기본값)

uvicorn main:app --reload --port 8000        # Swagger UI: http://127.0.0.1:8000/docs
python harness/check_harness.py              # 3단계 하네스
pytest tests --cov=main                      # 테스트 + 커버리지
python harness/simulate_load.py --url http://127.0.0.1:8000/posts --requests 500
```

> ⚠️ Windows에서는 부하 테스트 URL에 `localhost` 대신 **`127.0.0.1`** 을 쓰세요. `localhost`는 IPv6 연결 시도 후 대체되면서 요청마다 약 2초가 더해져 측정값이 왜곡됩니다.

### API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/posts` | 게시글 목록 (최신순) |
| `POST` | `/posts` | 게시글 작성 (`author` 생략 시 "익명") |
| `GET` | `/posts/search?q=` | 제목·내용 키워드 검색 |
| `GET` | `/posts/filtered` | 차단 태그(abuse, hate, leak, spoiler) 제외 피드 |
| `POST` | `/admin/login` | 관리자 토큰 발급 |
| `DELETE` | `/admin/posts/{id}` | 관리자 강제 삭제 (`X-Admin-Token` 헤더) |

---

## 💡 8. 회고

- **AI는 코드베이스의 지시를 신뢰합니다.** 주석 한 단락이 생성 코드 전체의 보안 수준을 결정했습니다. 리뷰 대상은 생성된 코드뿐 아니라 AI에게 주어지는 컨텍스트까지입니다.
- **정규식 기반 검사는 우회됩니다.** 원본 하네스는 `query = f"..."; execute(query)` 형태의 SQL Injection과 `ADMIN_MASTER_TOKEN` 하드코딩을 놓쳤고, 권한 결함은 어떤 자동 검사도 잡지 못했습니다. 이 결함은 **테스트로 명세화**해서 회귀를 막았습니다.
- **측정 환경이 결과를 좌우합니다.** 첫 측정의 "p50 2초"는 DB가 아니라 Windows의 `localhost` 해석 지연이었습니다. 원인을 확인하지 않았다면 잘못된 최적화를 했을 것입니다.
- **개선 효과는 정직하게 기록합니다.** WAL은 꼬리 지연을 절반 이상 줄였지만, 중간값은 오히려 늘었고 높은 동시성에서는 효과가 없었습니다. 다음 병목은 워커 수(멀티 프로세스)와 커넥션 재사용입니다.

---

<sub>네이버 특강 "AI 시대의 개발과 개발자의 역할: 엔터프라이즈 환경과 하네스 엔지니어링" 실습 키트를 기반으로 진행했습니다.</sub>
