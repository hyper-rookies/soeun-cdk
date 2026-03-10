# SE Report CDK

AWS CDK(TypeScript)로 정의된 과제 B 인프라입니다.

## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `npx cdk deploy`  deploy this stack to your default AWS account/region
* `npx cdk diff`    compare deployed stack with current state
* `npx cdk synth`   emits the synthesized CloudFormation template

---

## 🏗️ AWS 아키텍처

### 배치 파이프라인 (데이터 수집)

**운영 환경 (Lambda 자동 수집)**
```
EventBridge Scheduler (매일 03:00 KST)
  → SQS (se-batch-queue) — 재시도 최대 3회
  → Lambda (se-batch-lambda)
  → Google Ads API / Kakao Keyword API 호출
  → S3 (raw/google/, raw/kakao/) — Parquet + Snappy 압축
  → Glue 파티션 등록 (year/month_p/day)
  → Athena 쿼리 가능 상태
  
  실패 시: DLQ (se-batch-dlq) → DLQ Lambda → CloudWatch 로그
```

**초기 데이터 적재 (수동 스크립트)**
```
CSV 원본 데이터
  → scripts/2_upload_to_s3.py (로컬 실행)
  → S3 (raw/google/, raw/kakao/) — Parquet + Snappy 압축
  → Glue 파티션 등록 (year/month_p/day)
  → Athena 쿼리 가능 상태
```

### 채팅 / AI 리포트
```
사용자 질문 (Next.js)
  → Spring Boot (EC2/Docker)
  → Amazon Bedrock (Claude) — Tool Use 패턴
  → Athena → S3 쿼리 실행
  → SSE 스트리밍으로 응답 반환
```

### 주간 리포트 자동화
```
EventBridge Scheduler (매주 월 08:00 KST = UTC 일 23:00)
  → Lambda (se-report-lambda)
  → Amazon Bedrock (Claude) — 지난주 성과 자동 분석
  → DynamoDB (se_reports) 저장
  → 공유 링크 발급 (JWT, 30일 만료)
```

---

## 🚀 초기 설정 및 실행 방법

### 사전 조건
- AWS CLI 설정 (`ap-northeast-2`)
- Node.js 18+, `npm install`
- Python 3.9+, `boto3`, `pandas`, `pyarrow` 설치
- `.env` 파일에 아래 환경변수 설정:

```
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_DEVELOPER_TOKEN=
GOOGLE_REFRESH_TOKEN=
GOOGLE_CUSTOMER_ID=
KAKAO_REST_API_KEY=
KAKAO_CLIENT_SECRET=
KAKAO_REFRESH_TOKEN=
```

### 1단계 — CDK 배포

```bash
npx cdk deploy
```

생성되는 주요 리소스:
- VPC, EC2 (Spring Boot 서버)
- ECR (se-report-server)
- S3 (se-report-ad-data)
- DynamoDB 4개 테이블 (se_ad_accounts, se_conversations, se_messages, se_reports)
- Cognito User Pool (Google OAuth2)
- Glue DB + 테이블 2개 (google_ad_performance, kakao_ad_performance)
- Athena 워크그룹 (se-report-workgroup)
- Lambda 3개 (se-auth-lambda, se-batch-lambda, se-report-lambda)
- SQS 2개 (se-batch-queue, se-batch-dlq)
- EventBridge Scheduler 3개 (배치 google/kakao, 주간 리포트)

### 2단계 — 초기 데이터 적재 (수동, 최초 1회)

과거 데이터를 CSV로 보유하고 있는 경우 수동으로 S3에 적재합니다.

```bash
python scripts/2_upload_to_s3.py
```

스크립트 내 경로 수정 필요:
```python
process_google(r'경로/google_keyword.csv')
process_kakao(r'경로/kakao_keyword.csv', r'경로/kakao_keyword_master.csv')
```

수행 작업:
- CSV → Parquet 변환 (Snappy 압축)
- S3 파티션 경로로 저장: `raw/{platform}/year=YYYY/month_p=MM/day=DD/data.parquet`
- Glue 파티션 자동 등록

> 데이터는 기본적으로 Lambda가 매일 자동 수집합니다.

---

## 🗄️ 데이터 스키마

### Google (`google_ad_performance`)

| 컬럼 | 타입 | 설명 |
|------|------|------|
| `camp_name` | string | 캠페인명 |
| `agroup_name` | string | 광고그룹명 |
| `keyword_text` | string | 키워드 |
| `date` | string | 날짜 |
| `impressions` | bigint | 노출수 |
| `clicks` | bigint | 클릭수 |
| `cost_micros` | double | 비용 (micro 단위, ÷1,000,000 = 원) |
| `conversions` | bigint | 전환수 |
| `conversions_value` | double | 전환 매출 |
| `ctr` | double | 클릭률 |
| `average_cpc` | double | 평균 CPC |

파티션: `year` / `month_p` / `day`

### Kakao (`kakao_ad_performance`)

| 컬럼 | 타입 | 설명 |
|------|------|------|
| `camp_name` | string | 캠페인명 |
| `agroup_name` | string | 광고그룹명 |
| `kwd_name` | string | 키워드 |
| `basic_date` | string | 날짜 |
| `imp` | bigint | 노출수 |
| `click` | bigint | 클릭수 |
| `spending` | double | 비용 (원) |
| `conv_purchase_1d` | bigint | 1일 구매 전환수 |
| `ctr` | double | 클릭률 |
| `ppc` | double | 평균 CPC |

파티션: `year` / `month_p` / `day`

---

## 🛠️ 기술 스택

**프론트엔드**
- Next.js 14 (App Router), TypeScript, Tailwind CSS
- Recharts, Zustand, Axios

**백엔드**
- Spring Boot 3, Java 17
- Amazon Bedrock (Claude), AWS Athena, DynamoDB
- Docker, EC2

**인프라**
- S3, Glue, Athena, Lambda, EventBridge Scheduler
- SQS (배치 큐 + DLQ)
- Amazon Cognito (Google OAuth2)
- Vercel (프론트엔드), ECR + EC2 (백엔드)

---

## ⚠️ 참고 사항

- Google Ads API / 카카오 API 실제 연동 권한 미보유로 **CSV 기반 임시 데이터** 사용 (운영 환경에서는 Lambda가 자동 수집)
- 프론트(Vercel HTTPS) ↔ 백엔드(EC2 HTTP) 통신은 **Next.js API Route 프록시**로 처리
- `cost_micros` → 원화 변환: `cost_micros / 1,000,000`