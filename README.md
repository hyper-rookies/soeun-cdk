# 과제 B - 이소은
- [백엔드 레포지토리](https://github.com/hyper-rookies/soeun-chat)
- [프론트엔드 레포지토리](https://github.com/hyper-rookies/soeun-report-frontend)
- [인프라 레포지토리](https://github.com/hyper-rookies/soeun-cdk)
---

# 🏗️ AWS 아키텍처

### 광고 API 자동 수집
**EventBridge Scheduler**
```
EventBridge Scheduler (매일 03:00 KST)
  → SQS (se-batch-queue) — 재시도 최대 3회
  → Lambda (se-batch-lambda)
  → Google Ads API / Kakao Keyword API 호출
  → S3 (raw/google/, raw/kakao/) — Parquet + Snappy 압축
  → Glue 파티션 등록 (year/month_p/day)
  → Athena 쿼리 가능 상태
  → 실패 시: DLQ (se-batch-dlq)
```

**초기 데이터 적재 (수동 스크립트 사용)**
```
CSV 원본 데이터 (카카오 키워드, 구글 Ads)
  → scripts/2_upload_to_s3.py (로컬 실행)
  → S3 (raw/google/, raw/kakao/) — Parquet + Snappy 압축
  → Glue 파티션 등록 (year/month_p/day)
  → Athena 쿼리 가능 상태
```

### AI 채팅
```
사용자 질문 (Next.js)
  → Spring Boot (EC2/Docker)
  → Amazon Bedrock (Claude) — Tool Use 패턴, API 호출 방식 (Spring Boot에서 Loop최대 5회)
  → Athena → S3 쿼리 실행
  → SSE 스트리밍으로 응답 반환
```

### 주간 리포트 자동화
```
EventBridge Scheduler (매주 월 08:00 KST = UTC 일 23:00)
  → Lambda (se-report-lambda)
  → Amazon Bedrock (Claude) — Tool Use, 지난주 성과 자동 분석
  → DynamoDB (se_reports) 저장
  → 공유 링크 발급 (JWT, 30일 만료)

Excel로 내보내기
→ EC2에서 요청이 들어올 때 Lambda 호출
→ Lambda (se- report-excel-report)
→ S3 Presigned URL 발급 및 저장
```

## 🛠️ 기술 스택

**프론트엔드**
- Next.js 14 (App Router), TypeScript, Tailwind CSS
- Recharts, Zustand, Axios

**백엔드**
- Spring Boot 3, Java 17
- Amazon Bedrock (Claude), AWS Athena, DynamoDB, Elasticache (Redis)
- Docker, EC2

**인프라**
- VPC, VPC Gateway Endpoint, Internet Gateway
- S3, Glue, Athena, Lambda, EventBridge Scheduler
- SQS (배치 큐 + DLQ)
- Amazon Cognito (Google OAuth2)
- Vercel (프론트엔드), ECR + EC2 (백엔드) + Github Actions

---

### 인증 JWT (Cognito ID Token)
| 구분 | 내용 |
|------|------|
| **발급** | Cognito가 직접 발급 (Spring이 만들지 않음) |
| **서명** | Cognito RSA256 키쌍 (JWKS로 검증) |
| **만료** | Cognito 설정값 따름 (기본 1시간) |
| **저장** | localStorage + 쿠키 동기화 (middleware용) |
| **갱신** | refreshToken으로 /api/auth/refresh 호출 |

### 공유링크 JWT (읽기 전용 링크)

| 구분 | 항목 | 내용 |
|------|------|------|
| **발급** | 발급 주체 | Spring ShareService가 직접 생성, 로그인한 사용자만 발급 가능 |
| **서명** | 알고리즘 | share.jwt-secret (HMAC SHA256, 대칭키) |
| **만료** | 만료 기간 | 30일 (share.expiration-days) |
| **저장** | 저장 위치 | URL에 포함 (/shared/{token}) |
| **갱신** | 갱신 정책 | 없음 (만료 시 재발급 필요) |
| **외부 사용자 (비로그인)** | 유효한 링크 | 정상 조회 |
| | 만료된 링크 | "링크가 만료되었습니다" 안내 페이지 |
| **로그인 사용자 + 본인 대화** | 유효한 링크 | 정상 조회 |
| | 만료된 링크 | 자동으로 새 링크 발급 + 새 URL로 리다이렉트 |
| **로그인 사용자 + 타인 대화** | 유효한 링크 | 정상 조회 |
| | 만료된 링크 | "링크가 만료되었습니다" 안내 페이지 |
  
---

### **VPC Gateway 엔드포인트 추가**

EC2 → S3/DynamoDB 트래픽 경로를 공인 인터넷에서 AWS 내부망으로 전환했습니다.
- S3 인터넷 데이터 전송 비용 제거 (Gateway 엔드포인트 무료)
- 트래픽이 공인 인터넷에 노출되지 않아 보안 강화
- AWS 내부망 사용으로 레이턴시 감소

### **ElastiCache Redis 도입 (Private Subnet)**

기존 Caffeine(JVM 로컬 캐시)에서 ElastiCache Redis로 전환했습니다.

| 항목 | Caffeine (변경 전) | ElastiCache (변경 후) |
|------|------|------|
| 캐시 위치 | EC2 JVM 메모리 | 독립 Redis 서버 |
| EC2 재시작 시 | 캐시 초기화 | 캐시 유지 |
| 스케일 아웃 시 | 인스턴스마다 캐시 불일치 | 캐시 공유 |
| EC2 메모리 영향 | 힙 메모리 사용 | 영향 없음 |

> 현재는 EC2 단일 인스턴스로 Caffeine으로도 충분하나, 향후 ECS 전환 가능성을 고려해 선제적으로 전환했습니다.

---

### S3 Lifecycle 정책

스토리지 비용 최적화 및 불필요한 데이터 누적 방지를 위한 수명 주기 규칙을 추가했습니다.

| 경로 | 규칙 | 이유 |
|------|------|------|
| `excel/` | 1일 후 삭제 | presigned URL 1시간 만료 후 불필요 |
| `athena-results/` | 7일 후 삭제 | Athena 내부 동작용 임시 파일, 재사용 없음 |
| `reports/` | 90일 → Standard-IA, 365일 → Glacier Instant Retrieval | 오래된 리포트는 조회 빈도 낮으나 보존 필요 |

> `reports/`는 주간리포트 과거 이력 조회 기능을 고려해 삭제 대신 아카이빙으로 처리했습니다. Glacier Instant Retrieval은 즉시 접근이 가능하여 사용자 경험에 영향이 없습니다.
---

## ETC
- Google Ads API / 카카오 API 실제 연동 권한 미보유로 **CSV 기반 임시 데이터** 사용 (운영 환경에서는 Lambda가 자동 수집)
- 프론트(Vercel HTTPS) ↔ 백엔드(EC2 HTTP) 통신은 **Next.js API Route 프록시**로 처리
- `cost_micros` → 원화 변환: `cost_micros / 1,000,000`


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


