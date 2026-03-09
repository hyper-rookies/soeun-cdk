import os
import json
import uuid
import boto3
import time
from datetime import datetime, timedelta

# 환경변수
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-5-sonnet-20241022-v2:0')
DYNAMODB_REPORTS_TABLE = os.environ.get('DYNAMODB_REPORTS_TABLE', 'se_reports')
ATHENA_DATABASE = os.environ.get('ATHENA_DATABASE', 'se_report_db')
ATHENA_WORKGROUP = os.environ.get('ATHENA_WORKGROUP', 'se-report-workgroup')
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME')

athena = boto3.client('athena', region_name='ap-northeast-2')
bedrock = boto3.client('bedrock-runtime', region_name='ap-northeast-2')
dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
reports_table = dynamodb.Table(DYNAMODB_REPORTS_TABLE)


# ───────────────────────────────
# Athena 쿼리 유틸
# ───────────────────────────────

def run_athena_query(sql: str) -> list[dict]:
    """Athena 쿼리 실행 후 결과를 dict 리스트로 반환"""
    response = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={'Database': ATHENA_DATABASE},
        WorkGroup=ATHENA_WORKGROUP,
    )
    execution_id = response['QueryExecutionId']

    # 완료 대기 (최대 60초)
    for _ in range(60):
        status = athena.get_query_execution(QueryExecutionId=execution_id)
        state = status['QueryExecution']['Status']['State']
        if state == 'SUCCEEDED':
            break
        if state in ('FAILED', 'CANCELLED'):
            reason = status['QueryExecution']['Status'].get('StateChangeReason', '')
            raise RuntimeError(f"Athena 쿼리 실패: {state} - {reason}")
        time.sleep(1)
    else:
        raise RuntimeError("Athena 쿼리 타임아웃 (60초)")

    # 결과 파싱
    results = athena.get_query_results(QueryExecutionId=execution_id)
    rows = results['ResultSet']['Rows']
    if len(rows) <= 1:
        return []

    headers = [col['VarCharValue'] for col in rows[0]['Data']]
    return [
        {headers[i]: col.get('VarCharValue', '') for i, col in enumerate(row['Data'])}
        for row in rows[1:]
    ]


# ───────────────────────────────
# 지난주 날짜 범위 계산
# ───────────────────────────────

def get_last_week_range() -> dict:
    today = datetime.now()
    last_monday = today - timedelta(days=today.weekday() + 7)
    last_sunday = last_monday + timedelta(days=6)
    return {
        'start': last_monday.strftime('%Y%m%d'),
        'end': last_sunday.strftime('%Y%m%d'),
        'start_display': last_monday.strftime('%Y년 %m월 %d일'),
        'end_display': last_sunday.strftime('%Y년 %m월 %d일'),
    }


# ───────────────────────────────
# 데이터 수집
# ───────────────────────────────

def fetch_google_summary(date_range: dict) -> list[dict]:
    sql = f"""
        SELECT
            camp_name AS "캠페인명",
            SUM(impressions) AS "노출수",
            SUM(clicks) AS "클릭수",
            ROUND(SUM(clicks) * 100.0 / NULLIF(SUM(impressions), 0), 2) AS "CTR",
            ROUND(SUM(cost_micros) / 1000000.0, 0) AS "광고비",
            SUM(conversions) AS "전환수",
            ROUND(SUM(conversions_value), 0) AS "전환가치",
            ROUND(SUM(cost_micros) / 1000000.0 / NULLIF(SUM(conversions), 0), 0) AS "전환당비용"
        FROM google_ad_performance
        WHERE basic_date BETWEEN '{date_range['start']}' AND '{date_range['end']}'
        GROUP BY camp_name
        ORDER BY "전환가치" DESC
        LIMIT 10
    """
    try:
        return run_athena_query(sql)
    except Exception as e:
        print(f"Google 데이터 조회 실패: {e}")
        return []


def fetch_kakao_summary(date_range: dict) -> list[dict]:
    sql = f"""
        SELECT
            camp_name AS "캠페인명",
            SUM(imp) AS "노출수",
            SUM(click) AS "클릭수",
            ROUND(SUM(click) * 100.0 / NULLIF(SUM(imp), 0), 2) AS "CTR",
            ROUND(SUM(spending), 0) AS "광고비",
            SUM(conv_purchase_1d) AS "전환수(1일)",
            SUM(conv_purchase_7d) AS "전환수(7일)"
        FROM kakao_ad_performance
        WHERE basic_date BETWEEN '{date_range['start']}' AND '{date_range['end']}'
        GROUP BY camp_name
        ORDER BY "광고비" DESC
        LIMIT 10
    """
    try:
        return run_athena_query(sql)
    except Exception as e:
        print(f"Kakao 데이터 조회 실패: {e}")
        return []


def fetch_overall_summary(date_range: dict) -> dict:
    """전체 요약 지표"""
    google_sql = f"""
        SELECT
            SUM(impressions) AS impressions,
            SUM(clicks) AS clicks,
            ROUND(SUM(cost_micros) / 1000000.0, 0) AS cost,
            SUM(conversions) AS conversions,
            ROUND(SUM(conversions_value), 0) AS conversions_value
        FROM google_ad_performance
        WHERE basic_date BETWEEN '{date_range['start']}' AND '{date_range['end']}'
    """
    kakao_sql = f"""
        SELECT
            SUM(imp) AS impressions,
            SUM(click) AS clicks,
            ROUND(SUM(spending), 0) AS cost,
            SUM(conv_purchase_7d) AS conversions
        FROM kakao_ad_performance
        WHERE basic_date BETWEEN '{date_range['start']}' AND '{date_range['end']}'
    """
    try:
        google = run_athena_query(google_sql)
        kakao = run_athena_query(kakao_sql)
        return {
            'google': google[0] if google else {},
            'kakao': kakao[0] if kakao else {},
        }
    except Exception as e:
        print(f"전체 요약 조회 실패: {e}")
        return {'google': {}, 'kakao': {}}


# ───────────────────────────────
# Bedrock 성과 요약 생성
# ───────────────────────────────

def generate_report_with_bedrock(date_range: dict, overall: dict, google_data: list, kakao_data: list) -> str:
    prompt = f"""당신은 디지털 광고 성과 분석 전문가입니다.
아래 데이터를 바탕으로 {date_range['start_display']} ~ {date_range['end_display']} 주간 광고 성과 리포트를 작성해주세요.

## 전체 요약
### Google Ads
{json.dumps(overall.get('google', {}), ensure_ascii=False, indent=2)}

### Kakao 키워드
{json.dumps(overall.get('kakao', {}), ensure_ascii=False, indent=2)}

## Google Ads 캠페인별 성과 (전환가치 TOP 10)
{json.dumps(google_data, ensure_ascii=False, indent=2)}

## Kakao 캠페인별 성과 (광고비 TOP 10)
{json.dumps(kakao_data, ensure_ascii=False, indent=2)}

## 리포트 작성 요구사항
1. **주간 성과 요약**: 두 매체의 핵심 지표(노출, 클릭, CTR, 광고비, 전환) 비교
2. **잘된 점**: 성과가 좋았던 캠페인/지표와 이유 분석
3. **개선 필요**: 성과가 부진했던 항목과 원인 추정
4. **다음 주 액션 아이템**: 구체적인 개선 방향 3가지
5. 마크다운 형식으로 작성
6. 수치는 반드시 포함하여 근거 있는 분석 작성
"""

    response = bedrock.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        body=json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 2000,
            'messages': [
                {'role': 'user', 'content': prompt}
            ],
        }),
        contentType='application/json',
        accept='application/json',
    )

    result = json.loads(response['body'].read())
    return result['content'][0]['text']


# ───────────────────────────────
# DynamoDB 저장
# ───────────────────────────────

def save_report(date_range: dict, content: str) -> str:
    report_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(days=90)).isoformat()

    reports_table.put_item(Item={
        'reportId': report_id,
        'type': 'weekly',
        'periodStart': date_range['start'],
        'periodEnd': date_range['end'],
        'content': content,
        'createdAt': now,
        'expiresAt': expires_at,
    })

    print(f"리포트 저장 완료: reportId={report_id}")
    return report_id


# ───────────────────────────────
# Lambda Handler
# ───────────────────────────────

def lambda_handler(event, context):
    print(f"리포트 생성 Lambda 시작: {json.dumps(event)}")

    report_type = event.get('type', 'weekly_report')
    if report_type != 'weekly_report':
        print(f"알 수 없는 report_type: {report_type}")
        return {'statusCode': 400, 'body': f'Unknown type: {report_type}'}

    try:
        # 1. 날짜 범위 계산
        date_range = get_last_week_range()
        print(f"분석 기간: {date_range['start']} ~ {date_range['end']}")

        # 2. 데이터 수집
        print("Athena 데이터 수집 중...")
        overall = fetch_overall_summary(date_range)
        google_data = fetch_google_summary(date_range)
        kakao_data = fetch_kakao_summary(date_range)
        print(f"Google: {len(google_data)}개 캠페인, Kakao: {len(kakao_data)}개 캠페인")

        # 3. Bedrock 리포트 생성
        print("Bedrock 리포트 생성 중...")
        report_content = generate_report_with_bedrock(date_range, overall, google_data, kakao_data)
        print(f"리포트 생성 완료: {len(report_content)}자")

        # 4. DynamoDB 저장
        report_id = save_report(date_range, report_content)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'reportId': report_id,
                'period': f"{date_range['start']} ~ {date_range['end']}",
                'contentLength': len(report_content),
            }, ensure_ascii=False)
        }

    except Exception as e:
        print(f"리포트 생성 실패: {str(e)}")
        raise e