import json
import urllib.request
import urllib.error
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    backend_url = os.environ.get('BACKEND_URL')
    internal_key = os.environ.get('INTERNAL_API_KEY')

    if not backend_url or not internal_key:
        logger.error("환경변수 누락: BACKEND_URL 또는 INTERNAL_API_KEY")
        return {"statusCode": 500, "body": "환경변수 누락"}

    url = f"{backend_url}/api/chat/report"
    payload = json.dumps({"reportType": "weekly"}).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Internal-Key": internal_key
        },
        method='POST'
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as response:
            body = response.read().decode('utf-8')
            result = json.loads(body)
            logger.info(f"리포트 생성 성공: {result}")

            share_token = result.get('data', {}).get('shareToken', '')
            logger.info(f"공유 링크: {backend_url}/shared/{share_token}")

            return {
                "statusCode": 200,
                "body": json.dumps(result, ensure_ascii=False)
            }
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        logger.error(f"HTTP 에러 {e.code}: {error_body}")
        return {"statusCode": e.code, "body": error_body}
    except Exception as e:
        logger.error(f"Lambda 실행 실패: {str(e)}")
        return {"statusCode": 500, "body": str(e)}
