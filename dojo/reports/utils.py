import logging
logger = logging.getLogger(__name__)


def get_url_presigned(session,
                      key,
                      bucket,
                      expires_in=3600):
    url = session.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket, 'Key': key},
        ExpiresIn=expires_in
    )
    logger.debug(f"REPORT FINDING: {url}")
    return url


def upload_s3(session_s3, buffer, bucket, key):
    try:
        response = session_s3.put_object(Bucket=bucket, Key=key, Body=buffer.getvalue())
        logger.info(f"REPORT FINDING: Upload successful: {response}")
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            return response
        else:
            logger.error(f"REPORT FINDING: Upload failed with status code: {response['ResponseMetadata']['HTTPStatusCode']}")
            raise Exception(response["ResponseMetadata"]["HTTPStatusCode"], "Failed to upload to S3")
    except Exception as e:
        logger.error(f"REPORT FINDING: Error uploading to S3: {e}")
        raise Exception("Failed to upload to S3 after multiple attempts due to expired token.")