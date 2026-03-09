import json
import boto3
from datetime import datetime

cloudwatch = boto3.client('cloudwatch')

def lambda_handler(event, context):
    print(f"DLQ 메시지 수신: {len(event.get('Records', []))}건")

    for record in event.get('Records', []):
        try:
            body = json.loads(record['body'])
        except Exception:
            body = record['body']

        # 실패 원인 추출
        attributes = record.get('attributes', {})
        approximate_receive_count = attributes.get('ApproximateReceiveCount', 'unknown')
        sent_timestamp = attributes.get('SentTimestamp')
        sent_time = (
            datetime.fromtimestamp(int(sent_timestamp) / 1000).strftime('%Y-%m-%d %H:%M:%S')
            if sent_timestamp else 'unknown'
        )

        # CloudWatch 에러 로그 기록
        print(f"[DLQ ERROR] 처리 실패 메시지")
        print(f"  - platform : {body.get('platform', 'unknown') if isinstance(body, dict) else body}")
        print(f"  - 최초 전송 시각 : {sent_time}")
        print(f"  - 수신 횟수 : {approximate_receive_count}회 (재시도 후 최종 실패)")
        print(f"  - 메시지 원문 : {json.dumps(body, ensure_ascii=False)}")

        # CloudWatch 커스텀 메트릭 기록 (알람 연동 시 활용 가능)
        cloudwatch.put_metric_data(
            Namespace='SEReport/BatchPipeline',
            MetricData=[
                {
                    'MetricName': 'DLQMessageCount',
                    'Value': 1,
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'Platform',
                            'Value': body.get('platform', 'unknown') if isinstance(body, dict) else 'unknown'
                        }
                    ]
                }
            ]
        )

    return {'statusCode': 200, 'body': 'DLQ 처리 완료'}