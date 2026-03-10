import boto3

glue = boto3.client('glue', region_name='ap-northeast-2')
S3_BUCKET = 'se-report-ad-data'
DATABASE = 'se_report_db'

# ───────────────────────────────
# Google 테이블 스키마
# ───────────────────────────────
GOOGLE_COLUMNS = [
    # 캠페인/광고그룹/키워드 메타
    {'Name': 'camp_id', 'Type': 'string'},
    {'Name': 'camp_name', 'Type': 'string'},
    {'Name': 'camp_advertising_channel_type', 'Type': 'string'},
    {'Name': 'camp_status', 'Type': 'string'},
    {'Name': 'agroup_id', 'Type': 'string'},
    {'Name': 'agroup_name', 'Type': 'string'},
    {'Name': 'agroup_type', 'Type': 'string'},
    {'Name': 'creation_id', 'Type': 'string'},
    {'Name': 'creation_name', 'Type': 'string'},
    {'Name': 'creation_type', 'Type': 'string'},
    {'Name': 'creation_status', 'Type': 'string'},
    {'Name': 'creation_final_urls', 'Type': 'string'},
    {'Name': 'keyword_id', 'Type': 'string'},
    {'Name': 'keyword_text', 'Type': 'string'},
    {'Name': 'keyword_match_type', 'Type': 'string'},
    {'Name': 'device', 'Type': 'string'},
    {'Name': 'network_type', 'Type': 'string'},
    {'Name': 'basic_date', 'Type': 'string'},
    {'Name': 'adv_id', 'Type': 'string'},
    # 날짜 관련
    {'Name': 'date', 'Type': 'string'},
    {'Name': 'quarter', 'Type': 'string'},
    {'Name': 'day_of_week', 'Type': 'string'},
    {'Name': 'week', 'Type': 'string'},
    # 성과 지표 (bigint)
    {'Name': 'impressions', 'Type': 'bigint'},
    {'Name': 'clicks', 'Type': 'bigint'},
    {'Name': 'video_views', 'Type': 'bigint'},
    {'Name': 'all_conversions', 'Type': 'bigint'},
    {'Name': 'conversions', 'Type': 'bigint'},
    # 성과 지표 (double)
    {'Name': 'cost_micros', 'Type': 'double'},
    {'Name': 'ctr', 'Type': 'double'},
    {'Name': 'average_cpc', 'Type': 'double'},
    {'Name': 'all_conversions_value', 'Type': 'double'},
    {'Name': 'conversions_value', 'Type': 'double'},
    {'Name': 'value_per_conversion', 'Type': 'double'},
    {'Name': 'cost_per_conversion', 'Type': 'double'},
    {'Name': 'conversions_from_interactions_rate', 'Type': 'double'},
    {'Name': 'video_quartile_p25_rate', 'Type': 'double'},
    {'Name': 'video_quartile_p50_rate', 'Type': 'double'},
    {'Name': 'video_quartile_p75_rate', 'Type': 'double'},
    {'Name': 'video_quartile_p100_rate', 'Type': 'double'},
]

# ───────────────────────────────
# Kakao 테이블 스키마 (keyword + master 조인)
# ───────────────────────────────
KAKAO_COLUMNS = [
    # 키워드 메타 (master)
    {'Name': 'kwd_id', 'Type': 'string'},
    {'Name': 'kwd_name', 'Type': 'string'},
    {'Name': 'kwd_config', 'Type': 'string'},
    {'Name': 'kwd_url', 'Type': 'string'},
    {'Name': 'kwd_bid_type', 'Type': 'string'},
    {'Name': 'kwd_bid_amount', 'Type': 'bigint'},
    {'Name': 'agroup_id', 'Type': 'string'},
    {'Name': 'agroup_name', 'Type': 'string'},
    {'Name': 'camp_id', 'Type': 'string'},
    {'Name': 'camp_name', 'Type': 'string'},
    {'Name': 'camp_type', 'Type': 'string'},
    {'Name': 'biz_id', 'Type': 'string'},
    {'Name': 'biz_name', 'Type': 'string'},
    {'Name': 'lu_pc', 'Type': 'string'},
    {'Name': 'lu_mobile', 'Type': 'string'},
    {'Name': 'basic_date', 'Type': 'string'},
    {'Name': 'adv_id', 'Type': 'string'},
    # 성과 지표 (bigint)
    {'Name': 'imp', 'Type': 'bigint'},
    {'Name': 'click', 'Type': 'bigint'},
    {'Name': 'rimp', 'Type': 'bigint'},
    {'Name': 'rank', 'Type': 'bigint'},
    {'Name': 'conv_cmpt_reg_1d', 'Type': 'bigint'},
    {'Name': 'conv_cmpt_reg_7d', 'Type': 'bigint'},
    {'Name': 'conv_view_cart_1d', 'Type': 'bigint'},
    {'Name': 'conv_view_cart_7d', 'Type': 'bigint'},
    {'Name': 'conv_purchase_1d', 'Type': 'bigint'},
    {'Name': 'conv_purchase_7d', 'Type': 'bigint'},
    {'Name': 'conv_participation_1d', 'Type': 'bigint'},
    {'Name': 'conv_participation_7d', 'Type': 'bigint'},
    {'Name': 'conv_signup_1d', 'Type': 'bigint'},
    {'Name': 'conv_signup_7d', 'Type': 'bigint'},
    {'Name': 'conv_app_install_1d', 'Type': 'bigint'},
    {'Name': 'conv_app_install_7d', 'Type': 'bigint'},
    # 성과 지표 (double)
    {'Name': 'spending', 'Type': 'double'},
    {'Name': 'ctr', 'Type': 'double'},
    {'Name': 'ppc', 'Type': 'double'},
    {'Name': 'conv_purchase_p_1d', 'Type': 'double'},
    {'Name': 'conv_purchase_p_7d', 'Type': 'double'},
]

PARTITION_KEYS = [
    {'Name': 'year', 'Type': 'string'},
    {'Name': 'month_p', 'Type': 'string'},
    {'Name': 'day', 'Type': 'string'},
]

def get_storage_descriptor(columns, s3_location):
    return {
        'Columns': columns,
        'Location': s3_location,
        'InputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
        'OutputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat',
        'SerdeInfo': {
            'SerializationLibrary': 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe',
            'Parameters': {'parquet.compression': 'SNAPPY'}
        }
    }

def delete_table_if_exists(table_name):
    try:
        glue.delete_table(DatabaseName=DATABASE, Name=table_name)
        print(f"  🗑️ 기존 테이블 삭제: {table_name}")
    except glue.exceptions.EntityNotFoundException:
        print(f"  ℹ️ 테이블 없음 (새로 생성): {table_name}")

def create_table(table_name, columns, s3_prefix):
    s3_location = f"s3://{S3_BUCKET}/raw/{s3_prefix}/"
    glue.create_table(
        DatabaseName=DATABASE,
        TableInput={
            'Name': table_name,
            'TableType': 'EXTERNAL_TABLE',
            'StorageDescriptor': get_storage_descriptor(columns, s3_location),
            'PartitionKeys': PARTITION_KEYS,
            'Parameters': {
                'classification': 'parquet',
                'parquet.compression': 'SNAPPY',
            }
        }
    )
    print(f"  ✅ 테이블 생성: {DATABASE}.{table_name} ({len(columns)}개 컬럼)")

if __name__ == '__main__':
    print("=== 기존 테이블 삭제 ===")
    delete_table_if_exists('se_ad_performance_parquet')
    delete_table_if_exists('google_ad_performance')
    delete_table_if_exists('kakao_ad_performance')

    print("\n=== 새 테이블 생성 ===")
    create_table('google_ad_performance', GOOGLE_COLUMNS, 'google')
    create_table('kakao_ad_performance', KAKAO_COLUMNS, 'kakao')

    print("\n🎉 완료!")