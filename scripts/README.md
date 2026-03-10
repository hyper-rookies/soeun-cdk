# scripts/

AWS 인프라 초기화 및 데이터 적재용 스크립트 모음입니다.

---

## 실행 순서

### 1. `1_create_glue_tables.py` — Glue 테이블 스키마 생성

Athena에서 쿼리할 수 있도록 Glue 카탈로그에 테이블을 생성합니다.

```bash
python 1_create_glue_tables.py
```

생성 테이블:
- `se_report_db.google_ad_performance`
- `se_report_db.kakao_ad_performance`

> ⚠️ 기존 테이블이 있으면 삭제 후 재생성합니다.

---

### 2. `2_upload_to_s3.py` — CSV → S3 업로드

CSV 파일을 Parquet으로 변환하여 S3에 저장하고, Glue 파티션을 등록합니다.

```bash
python 2_upload_to_s3.py
```

실행 전 스크립트 하단 경로 수정 필요:
```python
process_google(r'경로/google_keyword.csv')
process_kakao(r'경로/kakao_keyword.csv', r'경로/kakao_keyword_master.csv')
```

저장 경로:
```
s3://se-report-ad-data/raw/google/year=YYYY/month=MM/day=DD/data.parquet
s3://se-report-ad-data/raw/kakao/year=YYYY/month=MM/day=DD/data.parquet
```

---

### 3. `3_report_trigger_lambda.py` — 주간 리포트 Lambda 함수

EventBridge(매주 월요일 08:00 KST)가 트리거하는 Lambda 함수 코드입니다.
백엔드의 `/api/chat/report`를 호출해 주간 리포트를 자동 생성합니다.

Lambda 환경변수 설정:

| 변수명 | 설명 |
|--------|------|
| `BACKEND_URL` | Spring Boot 서버 주소 |
| `INTERNAL_API_KEY` | 내부 API 인증키 |

EventBridge Cron: `cron(0 23 ? * SUN *)` (UTC 일 23시 = KST 월 08시)

---

## 사전 조건

- AWS CLI 설정 완료 (`ap-northeast-2`)
- Python 패키지: `boto3`, `pandas`, `pyarrow`
- S3 버킷: `se-report-ad-data` 생성 완료
- Glue 데이터베이스: `se_report_db` 생성 완료