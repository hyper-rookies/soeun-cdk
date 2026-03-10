import boto3
import pandas as pd
from io import BytesIO

S3_BUCKET = 'se-report-ad-data'
DATABASE = 'se_report_db'

s3 = boto3.client('s3', region_name='ap-northeast-2')
glue = boto3.client('glue', region_name='ap-northeast-2')


def read_csv(filepath):
    for encoding in ['utf-8', 'cp949', 'euc-kr', 'utf-8-sig']:
        try:
            df = pd.read_csv(filepath, sep=None, engine='python', dtype=str, encoding=encoding)
            print(f"  인코딩: {encoding}, {len(df)}건, {len(df.columns)}개 컬럼")
            return df
        except UnicodeDecodeError:
            continue
    raise ValueError(f"인코딩 감지 실패: {filepath}")


def save_to_s3_and_register_partition(df, platform, table_name, year, month, day):
    key = f"raw/{platform}/year={year}/month_p={month}/day={day}/data.parquet"
    s3_location = f"s3://{S3_BUCKET}/raw/{platform}/year={year}/month_p={month}/day={day}/"

    # Parquet 변환 후 S3 저장
    buffer = BytesIO()
    df.to_parquet(buffer, index=False, compression='snappy')
    buffer.seek(0)
    s3.put_object(Bucket=S3_BUCKET, Key=key, Body=buffer.getvalue())
    print(f"  ✅ S3 저장: s3://{S3_BUCKET}/{key} ({len(df)}건)")

    # Glue 파티션 등록
    try:
        glue.create_partition(
            DatabaseName=DATABASE,
            TableName=table_name,
            PartitionInput={
                'Values': [year, month, day],
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
        print(f"  ✅ Glue 파티션 등록: {table_name}/year={year}/month_p={month}/day={day}")
    except glue.exceptions.AlreadyExistsException:
        print(f"  ⚠️ Glue 파티션 이미 존재: {table_name}/year={year}/month_p={month}/day={day}")


def process_google(filepath):
    print(f"\n{'='*50}")
    print("처리 중: GOOGLE")
    df = read_csv(filepath)

    # bigint 컬럼
    for col in ['impressions', 'clicks', 'video_views', 'all_conversions', 'conversions']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').astype('float64').round().astype('Int64')

    # double 컬럼
    for col in ['cost_micros', 'ctr', 'average_cpc', 'all_conversions_value', 'conversions_value',
                'value_per_conversion', 'cost_per_conversion', 'conversions_from_interactions_rate',
                'video_quartile_p25_rate', 'video_quartile_p50_rate',
                'video_quartile_p75_rate', 'video_quartile_p100_rate']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').astype('float64')

    # 파티션 키 추출 (date 컬럼 기준)
    date_series = pd.to_datetime(df['date'], errors='coerce')
    df['year'] = date_series.dt.strftime('%Y')
    df['month_p'] = date_series.dt.strftime('%m')
    df['day'] = date_series.dt.strftime('%d')

    for (year, month_p, day), group in df.groupby(['year', 'month_p', 'day']):
        save_cols = [c for c in group.columns if c not in ['year', 'month_p', 'day']]
        save_to_s3_and_register_partition(
            group[save_cols], 'google', 'google_ad_performance', year, month_p, day
        )

    print(f"GOOGLE 완료: 총 {len(df)}건")


def process_kakao(keyword_path, master_path):
    print(f"\n{'='*50}")
    print("처리 중: KAKAO")

    keyword_df = read_csv(keyword_path)
    master_df = read_csv(master_path)

    print(f"  keyword: {len(keyword_df)}건 / master: {len(master_df)}건")

    # kwd_id 타입 통일 (string)
    keyword_df['kwd_id'] = keyword_df['kwd_id'].astype(str).str.strip()
    master_df['kwd_id'] = master_df['kwd_id'].astype(str).str.strip()

    # master 중복 제거 (kwd_id 기준 최신 1개)
    master_df = master_df.drop_duplicates(subset=['kwd_id'], keep='last')

    # LEFT JOIN
    df = keyword_df.merge(
        master_df.drop(columns=['adv_id', 'basic_date', 'agroup_id'], errors='ignore'),
        on='kwd_id',
        how='left'
    )
    print(f"  조인 후: {len(df)}건")

    # bigint 컬럼
    for col in ['imp', 'click', 'rimp', 'rank', 'kwd_bid_amount',
                'conv_cmpt_reg_1d', 'conv_cmpt_reg_7d',
                'conv_view_cart_1d', 'conv_view_cart_7d',
                'conv_purchase_1d', 'conv_purchase_7d',
                'conv_participation_1d', 'conv_participation_7d',
                'conv_signup_1d', 'conv_signup_7d',
                'conv_app_install_1d', 'conv_app_install_7d']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').astype('float64').round().astype('Int64')

    # double 컬럼
    for col in ['spending', 'ctr', 'ppc', 'conv_purchase_p_1d', 'conv_purchase_p_7d']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').astype('float64')

    # basic_date 파싱 (20221013 → 2022-10-13)
    df['basic_date'] = pd.to_datetime(
        df['basic_date'].astype(str), format='%Y%m%d', errors='coerce'
    ).dt.strftime('%Y-%m-%d')

    # 파티션 키 추출
    date_series = pd.to_datetime(df['basic_date'], errors='coerce')
    df['year'] = date_series.dt.strftime('%Y')
    df['month_p'] = date_series.dt.strftime('%m')
    df['day'] = date_series.dt.strftime('%d')

    for (year, month_p, day), group in df.groupby(['year', 'month_p', 'day']):
        save_cols = [c for c in group.columns if c not in ['year', 'month_p', 'day']]
        save_to_s3_and_register_partition(
            group[save_cols], 'kakao', 'kakao_ad_performance', year, month_p, day
        )

    print(f"KAKAO 완료: 총 {len(df)}건")


if __name__ == '__main__':
    process_google(r'C:\Users\NHN\Downloads\google_keyword.csv')
    process_kakao(
        r'C:\Users\NHN\Downloads\kakao_keyword.csv',
        r'C:\Users\NHN\Downloads\kakao_keyword_master.csv'
    )
    print("\n🎉 전체 완료!")