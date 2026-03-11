# 과제 B - 이소은
- [백엔드 레포지토리](https://github.com/hyper-rookies/soeun-chat)
- [프론트엔드 레포지토리](https://github.com/hyper-rookies/soeun-report-frontend)
- [인프라 레포지토리](https://github.com/hyper-rookies/soeun-cdk)


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

# 👨‍💻 화면
<details> 
  <summary> 🚩 로그인 </summary>
  
  <img width="2559" height="1345" alt="fe-auth" src="https://github.com/user-attachments/assets/18f04b5d-be8b-4bfc-af1f-3e7a38df605d" />
  
  - 구글 로그인을 지원합니다. 
  - 로그인한 사용자만 채팅에 참여할 수 있습니다.
  
  <br>
  <img width="2553" height="1298" alt="login-progress" src="https://github.com/user-attachments/assets/ef8bd357-6e99-4864-ba2b-2e306243b634" />
  
  - 로그인 진행중일 시, 프로그레스 바가 표시됩니다.
  - 프로그레스 바가 이동하며, 시간별로 TIP을 제공하는 문구가 표시됩니다.
  - 예시) TIP! 주간리포트 엑셀로 내보내기 기능을 활용해보세요.

</details>

<details>
<summary> 🚩 홈  </summary>

<img width="2559" height="1349" alt="login-home-접음" src="https://github.com/user-attachments/assets/f4c8f5aa-5bd4-4d10-87be-03fd21a85433" />

- 좌측의 사이드바를 접고 펼 수 있습니다.
- 사이드바의 메뉴는 hover시 툴팁을 제공합니다. 
- 오전/오후/저녁/새벽 시간대에 따라서 '사용자명 + 시간대별 문구'를 제공합니다.
- 제공되는 3개의 질문을 선택하면 채팅방으로 이동되며, input 창에 선택 질문이 자동 입력됩니다.
- '직접 질문하기' 또는 '사이드바 > 새 채팅'을 클릭하여 새로운 채팅방을 열 수 있습니다.
<br>
<br>
</details>

<details> 
  <summary> 🚩 채팅 </summary>

<img width="2554" height="1339" alt="fe-chat-loading" src="https://github.com/user-attachments/assets/6407d096-a519-4583-9f6f-9b92dde889f7" />

- 채팅을 입력하면, AI 의 답변을 기다리는동안 상태를 알리는 문구가 출력됩니다.
<br>
<img width="2559" height="1344" alt="fe-chat-answer1" src="https://github.com/user-attachments/assets/71c49b9e-d0c3-462e-a468-30ae2513eb55" />
<img width="2557" height="1298" alt="fe-chat-answer2" src="https://github.com/user-attachments/assets/795bc759-4098-4ae5-be17-893e25b027b5" />

- 질문을 자연어로 전송하면 답변이 스트리밍 방식으로 한 글자씩 출력됩니다.
- SSE로 받은 텍스트를 타이핑 애니메이션 효과를 주면서 출력합니다.
- 받은 청크 단위의 텍스트를 바로 화면에 노출시키지 않고, 16MS 타이머가 돌면서 누적했다가 한 글자씩 출력합니다. 이를 통해 네트워크 속도와 무관하게 일정한 타이핑 속도처럼 보이도록 합니다.
- 단, 답변 속도 향상을 위해 SSE 스트림이 끝나면 타이핑 애니메이션을 멈추고 답변 전체를 즉시 반환합니다. 이를 통해 스트림이 다 왔는데 타이머가 한 글자씩 따라가느라 사용자를 기다리게 하는 상황을 방지합니다.
- 최소로딩 시간을 5000MS로 지정합니다. 첫 청크가 도착해도 5초가 지나지 않았다면 로딩 스피너를 유지합니다. 이를 통해 서버에서 AI를 활용해 DB를 조회하는 시간동안 텍스트가 거의 오지 않다가 갑자기 확 쏟아지는 경우를 방지합니다. 즉, 사용자에게 DB 조회 시간이 단축된 것처럼 보이게 합니다.
<br>
<img width="2555" height="1305" alt="fe- chat-answer-chart" src="https://github.com/user-attachments/assets/7685b9be-dfde-4da6-85d3-dc1bcd994d50" />

- 표 형태 뿐만 아니라, 차트 형태도 표현할 수 있습니다.
- AI가 사용자의 질문에 따라 어떤 형식(표/차트/없음 중 선택)으로 답변을 제공할 지 의사결정을 내립니다.

<br>

<img width="2557" height="1297" alt="fe-chat-greeting" src="https://github.com/user-attachments/assets/6f03db84-db64-440c-9f7b-f96ce135354d" />
<img width="2555" height="1300" alt="fe-chat-greeting2" src="https://github.com/user-attachments/assets/19515ff9-6515-4cc6-a5c4-927cf99b9a4f" />

- 광고와 무관한 질문에도 답변할 수 있으나, 광고와 아무런 상관이 없는 질문을 한 경우나 개인정보를 입력한 경우 광고 분야로의 질문을 자연스럽게 유도합니다.

<br>
<br>
</details>

<details>
  <summary> 🚩 사이드바 메뉴 </summary>

<img width="2554" height="1339" alt="sidebar-tool-menu" src="https://github.com/user-attachments/assets/469d1cfb-93d2-45e4-af4f-18f86361d2bc" />

- 사이드바에서는 여러가지 메뉴를 제공합니다.

<br>
<br>
</details>

<details>
  <summary> 🚩 채팅방 이름 수정 </summary>

<img width="2548" height="1341" alt="fe-sidebar-revise" src="https://github.com/user-attachments/assets/78781620-ef63-4c4d-87a0-6f3df122b5de" />

- 채팅방 이름은 첫 질문으로 자동 생성되지만, 이름을 수정할 수 있습니다.

<br>

<img width="2552" height="1347" alt="fe-sidebar-delete" src="https://github.com/user-attachments/assets/b15e72b1-ccca-427c-8c62-6006c1f0e17f" />

- 채팅방은 삭제할 수 있으며, 삭제 후에는 완료되었다는 토스트 메시지가 제공됩니다.

<br>
<br>
</details>

<details>
<summary> 🚩 채팅방 공유 링크 생성 </summary>

<img width="2556" height="1298" alt="fe-sidebar-share" src="https://github.com/user-attachments/assets/e2cf4c5a-218b-4516-9ee7-5c06348f4a90" />
<img width="2554" height="1304" alt="fe-sidebar-share-green" src="https://github.com/user-attachments/assets/d9c417ed-e6ea-4c2f-9e34-6d3955339ecd" />

- 채팅방에 대해 공유 링크(유효기간 30일)를 생성할 수 있으며, 클릭을 통해 클립보드에 간편하게 복사할 수 있습니다.
- '유효기간'은 사용자가 공유 링크를 조회한 순간으로부터 30일을 의미합니다.
  
<br>

<img width="2557" height="1345" alt="fe-sidebar-search" src="https://github.com/user-attachments/assets/ebf0c209-d328-40a0-a8ec-5d88076cce8e" />

- 로그인하지 않은 사용자도 공유 링크를 통해 채팅방을 조회할 수 있습니다.
- 읽기 전용 모드이며, 각종 기능이 제한됩니다.

<br>
<br>

</details>


<details>
  <summary> 🚩 대화 검색 </summary>

<img width="2557" height="1345" alt="fe-sidebar-search" src="https://github.com/user-attachments/assets/368b40de-559c-4fac-b867-00f7937cfef8" />

- 사이드바는 대화 검색 기능을 제공합니다.
- 채팅방 이름을 기준으로 검색할 수 있습니다.

<br>
<br>

</details>

<details> 
  <summary> 🚩 대시보드 </summary>


<img width="2554" height="1343" alt="fe-dashboard" src="https://github.com/user-attachments/assets/61c0c175-10de-407b-890e-69d4972c6304" />
<img width="2553" height="1347" alt="fe-dashboard-hover" src="https://github.com/user-attachments/assets/48131e95-185a-48ce-8810-b9cd51a3d303" />

- 대시보드를 통해 광고 현황을 한 눈에 확인할 수 있습니다. 
- 오늘의 광고비, 이번 주 광고비, ROAS, CPC, CTR, 매체별 광고비 비충, 최근 7일 전환 추이 등이 제공됩니다.
- 그래프에 hover 시, 상세 수치를 확인할 수 있습니다.
- 대시보드 데이터는 캐싱되며, 2회 이상 접근 시 조회 성능이 향상됩니다.

<br>
<br>

</details>

<details> 
  <summary> 🚩 주간 리포트 </summary>


<img width="2552" height="1343" alt="fe-sidebar-report-hover" src="https://github.com/user-attachments/assets/58f2f1e5-9982-4576-aa89-0a1f804f6754" />

- 사이드바를 통해 주간 리포트 목록을 확인할 수 있습니다.
- 사이드바를 펼친 채 주간 리포트 버튼에 hover할 시, 주간리포트 생성 시간이 툴팁을 통해 표시됩니다.

<br>

<img width="2556" height="1353" alt="fe-report-hover" src="https://github.com/user-attachments/assets/74c9ff52-1df2-4f84-b86d-ac238d6fa8d1" />

- 그래프에 hover 시, 상세 수치를 확인할 수 있습니다.

<br>

<img width="2553" height="1351" alt="fe-report-filtering" src="https://github.com/user-attachments/assets/e0ee0e14-acc9-48fb-979b-664019ed43d3" />

- 매체와 기간을 선택하여 그래프를 조회할 수 있습니다.

<br>

<img width="2552" height="1291" alt="fe-report-2" src="https://github.com/user-attachments/assets/acb6f9a6-676c-4962-8330-9c1779b85905" />

<img width="2556" height="1302" alt="fe-report-3" src="https://github.com/user-attachments/assets/4209814f-4196-4dee-bfb6-c30a3e85096c" />

- 일별 상세 지표, 성과 요약, 주요 인사이트, 개선 제안을 제공합니다.

<br>

<img width="2553" height="1343" alt="fe-rerpot-3-filter" src="https://github.com/user-attachments/assets/81b98a76-a7d5-4853-8485-b2dac7ae326d" />

- 상세 데이터는 정렬/검색 기능을 제공합니다.

<br>

<img width="1900" height="1016" alt="excel1" src="https://github.com/user-attachments/assets/bc1bbe34-9cc0-4c70-86e2-5207d972d767" />

- 주간리포트는 Excel로 내보내기 기능이 제공됩니다.
- 총 4개의 시트가 생성됩니다. (요약, 일별추이, 구글상세, 카카오 상세)
- 필터링과 차트를 자동 제공합니다. 이를 통해, 사용자는 raw 데이터를 직접 가공하고 Excel 함수를 작성할 필요가 없습니다.

<br>

<img width="274" height="242" alt="sidebar-report-1" src="https://github.com/user-attachments/assets/cc0470cb-18dc-4990-aae3-036f3a2186c8" />
<img width="272" height="295" alt="sidebar-report-2" src="https://github.com/user-attachments/assets/984a9df6-1c6a-4366-9bb2-be000ee84b0d" />

- 주간 리포트는 사이드바를 통해 월별로 조회할 수 있습니다.
- 년도를 선택하면, 월 선택 화면으로 이동합니다.

<br>
<br>
</details>

---
# 🏗️ 아키텍처

<img width="4261" height="2274" alt="1차과제-아키텍처-20260311" src="https://github.com/user-attachments/assets/c68e6fbc-62f8-4502-9a90-28d3e8544748" />

### [광고 API 자동 수집]
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

### [AI 채팅]
```
사용자 질문 (Next.js)
  → Spring Boot (EC2/Docker)
  → Amazon Bedrock (Claude) — Tool Use 패턴, API 호출 방식 (Spring Boot에서 Loop최대 5회)
  → Athena → S3 쿼리 실행
  → SSE 스트리밍으로 응답 반환
```

### [주간 리포트 자동화]
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

---

### [인증 JWT (Cognito ID Token)]
| 구분 | 내용 |
|------|------|
| **발급** | Cognito가 직접 발급 (Spring이 만들지 않음) |
| **서명** | Cognito RSA256 키쌍 (JWKS로 검증) |
| **만료** | Cognito 설정값 따름 (기본 1시간) |
| **저장** | localStorage + 쿠키 동기화 (middleware용) |
| **갱신** | refreshToken으로 /api/auth/refresh 호출 |

### [공유링크 JWT (읽기 전용 링크)]

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

### [**VPC Gateway 엔드포인트**]

EC2 → S3/DynamoDB 트래픽 경로를 공인 인터넷에서 AWS 내부망으로 전환했습니다.
- S3 인터넷 데이터 전송 비용 제거 (Gateway 엔드포인트 무료)
- 트래픽이 공인 인터넷에 노출되지 않아 보안 강화
- AWS 내부망 사용으로 레이턴시 감소

### [**ElastiCache Redis(Private Subnet)**]

기존 Caffeine(JVM 로컬 캐시)에서 ElastiCache Redis로 전환했습니다.

| 항목 | Caffeine (변경 전) | ElastiCache (변경 후) |
|------|------|------|
| 캐시 위치 | EC2 JVM 메모리 | 독립 Redis 서버 |
| EC2 재시작 시 | 캐시 초기화 | 캐시 유지 |
| 스케일 아웃 시 | 인스턴스마다 캐시 불일치 | 캐시 공유 |
| EC2 메모리 영향 | 힙 메모리 사용 | 영향 없음 |

> 현재는 EC2 단일 인스턴스로 Caffeine으로도 충분하나, 향후 ECS 전환 가능성을 고려해 선제적으로 전환했습니다.

---

### [S3 Lifecycle 정책]

스토리지 비용 최적화 및 불필요한 데이터 누적 방지를 위한 수명 주기 규칙을 추가했습니다.

| 경로 | 규칙 | 이유 |
|------|------|------|
| `excel/` | 1일 후 삭제 | presigned URL 1시간 만료 후 불필요 |
| `athena-results/` | 7일 후 삭제 | Athena 내부 동작용 임시 파일, 재사용 없음 |
| `reports/` | 90일 → Standard-IA, 365일 → Glacier Instant Retrieval | 오래된 리포트는 조회 빈도 낮으나 보존 필요 |

> `reports/`는 주간리포트 과거 이력 조회 기능을 고려해 삭제 대신 아카이빙으로 처리했습니다. Glacier Instant Retrieval은 즉시 접근이 가능하여 사용자 경험에 영향이 없습니다.
---

### ETC
- Google Ads API / 카카오 API 실제 연동 권한 미보유로 **CSV 기반 임시 데이터** 사용 (운영 환경에서는 Lambda가 자동 수집)
- 프론트(Vercel HTTPS) ↔ 백엔드(EC2 HTTP) 통신은 **Next.js API Route 프록시**로 처리


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


