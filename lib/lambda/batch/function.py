import os
import json
import boto3
import requests
import pandas as pd
from datetime import datetime, timedelta
from io import BytesIO

# 환경변수
GOOGLE_DEVELOPER_TOKEN = os.environ['GOOGLE_DEVELOPER_TOKEN']
GOOGLE_CLIENT_ID = os.environ['GOOGLE_CLIENT_ID']
GOOGLE_CLIENT_SECRET = os.environ['GOOGLE_CLIENT_SECRET']
GOOGLE_REFRESH_TOKEN = os.environ['GOOGLE_REFRESH_TOKEN']
GOOGLE_CUSTOMER_ID = os.environ['GOOGLE_CUSTOMER_ID']
KAKAO_REST_API_KEY = os.environ['KAKAO_REST_API_KEY']
KAKAO_CLIENT_SECRET = os.environ['KAKAO_CLIENT_SECRET']
KAKAO_REFRESH_TOKEN = os.environ['KAKAO_REFRESH_TOKEN']
S3_BUCKET_NAME = os.environ['S3_BUCKET_NAME']

s3 = boto3.client('s3')
glue = boto3.client('glue')

KAKAO_BASE_URL = 'https://apis.moment.kakao.com/openapi/v4'

# ───────────────────────────────
# 공통 유틸
# ───────────────────────────────

def get_yesterday():
    yesterday = datetime.now() - timedelta(days=1)
    return {
        'date': yesterday.strftime('%Y-%m-%d'),
        'year': yesterday.strftime('%Y'),
        'month': yesterday.strftime('%m'),
        'day': yesterday.strftime('%d'),
    }

def save_to_s3_and_register_partition(df, platform, table_name, date_info):
    """Parquet으로 변환 후 S3 저장 + Glue 파티션 등록"""
    key = (
        f"raw/{platform}/"
        f"year={date_info['year']}/" 
        f"month_p={date_info['month']}/"
        f"day={date_info['day']}/"
        f"data.parquet"
    )
    s3_location = (
        f"s3://{S3_BUCKET_NAME}/raw/{platform}/"
        f"year={date_info['year']}/month_p={date_info['month']}/day={date_info['day']}/"
    )

    # Parquet 변환 후 S3 저장
    buffer = BytesIO()
    df.to_parquet(buffer, index=False, compression='snappy')
    buffer.seek(0)
    s3.put_object(Bucket=S3_BUCKET_NAME, Key=key, Body=buffer.getvalue())
    print(f"S3 저장 완료: s3://{S3_BUCKET_NAME}/{key}")

    # Glue 파티션 등록
    try:
        glue.create_partition(
            DatabaseName='se_report_db',
            TableName=table_name,
            PartitionInput={
                'Values': [date_info['year'], date_info['month'], date_info['day']],
                'StorageDescriptor': {
                    'Location': s3_location,
                    'InputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
                    'OutputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
                    'SerdeInfo': {
                        'SerializationLibrary': 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe',
                        'Parameters': {'parquet.compression': 'SNAPPY'}
                    }
                }
            }
        )
        print(f"Glue 파티션 등록 완료: {table_name}/{date_info['year']}/{date_info['month']}/{date_info['day']}")
    except glue.exceptions.AlreadyExistsException:
        print(f"Glue 파티션 이미 존재 (덮어쓰기): {table_name}/{date_info['year']}/{date_info['month']}/{date_info['day']}")

# ───────────────────────────────
# Google Ads
# ───────────────────────────────

def get_google_access_token():
    res = requests.post('https://oauth2.googleapis.com/token', data={
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'refresh_token': GOOGLE_REFRESH_TOKEN,
        'grant_type': 'refresh_token',
    })
    res.raise_for_status()
    return res.json()['access_token']

def fetch_google_ads(date_info):
    access_token = get_google_access_token()
    customer_id = GOOGLE_CUSTOMER_ID.replace('-', '')

    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            campaign.advertising_channel_type,
            campaign.status,
            ad_group.id,
            ad_group.name,
            ad_group.type,
            ad_group_criterion.criterion_id,
            ad_group_criterion.keyword.text,
            ad_group_criterion.keyword.match_type,
            segments.device,
            segments.network,
            segments.date,
            segments.quarter,
            segments.year,
            segments.day_of_week,
            segments.month,
            segments.week,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.video_views,
            metrics.all_conversions,
            metrics.conversions,
            metrics.conversions_value,
            metrics.all_conversions_value,
            metrics.value_per_conversion,
            metrics.cost_per_conversion,
            metrics.conversions_from_interactions_rate,
            metrics.video_quartile_p25_rate,
            metrics.video_quartile_p50_rate,
            metrics.video_quartile_p75_rate,
            metrics.video_quartile_p100_rate
        FROM keyword_view
        WHERE segments.date = '{date_info['date']}'
    """

    res = requests.post(
        f'https://googleads.googleapis.com/v23/customers/{customer_id}/googleAds:search',
        headers={
            'Authorization': f'Bearer {access_token}',
            'developer-token': GOOGLE_DEVELOPER_TOKEN,
            'Content-Type': 'application/json',
        },
        json={'query': query}
    )
    print(f"Google Ads API 응답 코드: {res.status_code}")
    res.raise_for_status()
    results = res.json().get('results', [])

    rows = []
    for r in results:
        seg = r.get('segments', {})
        metrics = r.get('metrics', {})
        campaign = r.get('campaign', {})
        ad_group = r.get('adGroup', {})
        criterion = r.get('adGroupCriterion', {})
        keyword = criterion.get('keyword', {})

        rows.append({
            'camp_id': str(campaign.get('id', '')),
            'camp_name': campaign.get('name', ''),
            'camp_advertising_channel_type': campaign.get('advertisingChannelType', ''),
            'camp_status': campaign.get('status', ''),
            'agroup_id': str(ad_group.get('id', '')),
            'agroup_name': ad_group.get('name', ''),
            'agroup_type': ad_group.get('type', ''),
            'keyword_id': str(criterion.get('criterionId', '')),
            'keyword_text': keyword.get('text', ''),
            'keyword_match_type': keyword.get('matchType', ''),
            'device': seg.get('device', ''),
            'network_type': seg.get('network', ''),
            'date': seg.get('date', ''),
            'quarter': seg.get('quarter', ''),
            'day_of_week': seg.get('dayOfWeek', ''),
            'week': seg.get('week', ''),
            'basic_date': date_info['date'].replace('-', ''),
            'adv_id': customer_id,
            'impressions': int(metrics.get('impressions', 0)),
            'clicks': int(metrics.get('clicks', 0)),
            'video_views': int(metrics.get('videoViews', 0)),
            'all_conversions': int(metrics.get('allConversions', 0)),
            'conversions': int(metrics.get('conversions', 0)),
            'cost_micros': float(metrics.get('costMicros', 0)),
            'ctr': float(metrics.get('ctr', 0)),
            'average_cpc': float(metrics.get('averageCpc', 0)),
            'all_conversions_value': float(metrics.get('allConversionsValue', 0)),
            'conversions_value': float(metrics.get('conversionsValue', 0)),
            'value_per_conversion': float(metrics.get('valuePerConversion', 0)),
            'cost_per_conversion': float(metrics.get('costPerConversion', 0)),
            'conversions_from_interactions_rate': float(metrics.get('conversionsFromInteractionsRate', 0)),
            'video_quartile_p25_rate': float(metrics.get('videoQuartileP25Rate', 0)),
            'video_quartile_p50_rate': float(metrics.get('videoQuartileP50Rate', 0)),
            'video_quartile_p75_rate': float(metrics.get('videoQuartileP75Rate', 0)),
            'video_quartile_p100_rate': float(metrics.get('videoQuartileP100Rate', 0)),
        })

    return pd.DataFrame(rows)

# ───────────────────────────────
# Kakao Keyword
# ───────────────────────────────

def get_kakao_access_token():
    res = requests.post('https://kauth.kakao.com/oauth/token', data={
        'grant_type': 'refresh_token',
        'client_id': KAKAO_REST_API_KEY,
        'client_secret': KAKAO_CLIENT_SECRET,
        'refresh_token': KAKAO_REFRESH_TOKEN,
    })
    print(f"카카오 토큰 발급 응답 코드: {res.status_code}")
    res.raise_for_status()
    return res.json()['access_token']

def fetch_kakao_ad_accounts(access_token):
    res = requests.get(
        f'{KAKAO_BASE_URL}/adAccounts/pages',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
        }
    )
    print(f"카카오 계정 목록 응답 코드: {res.status_code}")
    res.raise_for_status()
    return res.json().get('adAccounts', [])

def fetch_kakao_keyword_report(access_token, account_id, date_info):
    res = requests.get(
        f'{KAKAO_BASE_URL}/adAccounts/{account_id}/keywords/report',
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
        },
        params={
            'startDate': date_info['date'],
            'endDate': date_info['date'],
            'metricsGroups': 'BASIC',
        }
    )
    print(f"카카오 키워드 리포트 응답 코드 (account: {account_id}): {res.status_code}")
    return res

def fetch_kakao_keyword(date_info):
    access_token = get_kakao_access_token()
    accounts = fetch_kakao_ad_accounts(access_token)

    if not accounts:
        print("카카오 광고 계정이 없습니다.")
        return pd.DataFrame()

    rows = []
    for account in accounts:
        account_id = account['id']
        res = fetch_kakao_keyword_report(access_token, account_id, date_info)

        if not res.ok:
            print(f"키워드 리포트 조회 실패 (account: {account_id}) → 건너뜀")
            continue

        for item in res.json().get('data', []):
            metrics = item.get('metrics', {})
            rows.append({
                'kwd_id': str(item.get('keywordId', '')),
                'agroup_id': str(item.get('adGroupId', '')),
                'basic_date': date_info['date'].replace('-', ''),
                'adv_id': str(account_id),
                'imp': int(metrics.get('imp', 0)),
                'click': int(metrics.get('click', 0)),
                'spending': float(metrics.get('spending', 0)),
                'ctr': float(metrics.get('ctr', 0)),
                'rimp': int(metrics.get('rimp', 0)),
                'ppc': float(metrics.get('ppc', 0)),
                'rank': int(metrics.get('rank', 0)),
                'conv_cmpt_reg_1d': int(metrics.get('convCmptReg1d', 0)),
                'conv_cmpt_reg_7d': int(metrics.get('convCmptReg7d', 0)),
                'conv_view_cart_1d': int(metrics.get('convViewCart1d', 0)),
                'conv_view_cart_7d': int(metrics.get('convViewCart7d', 0)),
                'conv_purchase_1d': int(metrics.get('convPurchase1d', 0)),
                'conv_purchase_7d': int(metrics.get('convPurchase7d', 0)),
                'conv_purchase_p_1d': float(metrics.get('convPurchaseP1d', 0)),
                'conv_purchase_p_7d': float(metrics.get('convPurchaseP7d', 0)),
                'conv_participation_1d': int(metrics.get('convParticipation1d', 0)),
                'conv_participation_7d': int(metrics.get('convParticipation7d', 0)),
                'conv_signup_1d': int(metrics.get('convSignup1d', 0)),
                'conv_signup_7d': int(metrics.get('convSignup7d', 0)),
                'conv_app_install_1d': int(metrics.get('convAppInstall1d', 0)),
                'conv_app_install_7d': int(metrics.get('convAppInstall7d', 0)),
            })

    return pd.DataFrame(rows)

# ───────────────────────────────
# Handler
# ───────────────────────────────

def lambda_handler(event, context):
    date_info = get_yesterday()
    print(f"수집 날짜: {date_info['date']}")

    for record in event.get('Records', []):
        body = json.loads(record['body'])
        platform = body.get('platform')
        print(f"처리 platform: {platform}")

        try:
            if platform == 'google':
                print("Google Ads 수집 시작")
                df = fetch_google_ads(date_info)
                if df.empty:
                    print("Google Ads: 수집된 데이터 없음, 저장 생략")
                    continue
                save_to_s3_and_register_partition(df, 'google', 'google_ad_performance', date_info)
                print(f"Google Ads 수집 완료: {len(df)}건")

            elif platform == 'kakao':
                print("Kakao Keyword 수집 시작")
                df = fetch_kakao_keyword(date_info)
                if df.empty:
                    print("Kakao Keyword: 수집된 데이터 없음, 저장 생략")
                    continue
                save_to_s3_and_register_partition(df, 'kakao', 'kakao_ad_performance', date_info)
                print(f"Kakao Keyword 수집 완료: {len(df)}건")

            else:
                print(f"알 수 없는 platform: {platform}")

        except Exception as e:
            print(f"{platform} 수집 실패: {str(e)}")
            raise e

    return {'statusCode': 200, 'body': 'success'}