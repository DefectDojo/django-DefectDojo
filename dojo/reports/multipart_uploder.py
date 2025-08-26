import logging
logger = logging.getLogger(__name__)

class S3MultipartUploader:
    def __init__(self, session_s3, bucket, key):
        self.session_s3 = session_s3
        self.bucket = bucket
        self.key = key
        self.upload_id = None
        self.parts = []
        self.part_number = 1
    
    def start_upload(self):
        """Init multipart upload"""
        response = self.session_s3.create_multipart_upload(
            Bucket=self.bucket,
            Key=self.key
        )
        self.upload_id = response['UploadId']
        logger.info(f"MULTIPART: Started upload {self.upload_id} for {self.key}")
        return self.upload_id
    
    def upload_part(self, buffer_content):
        """upload a part to S3"""
        if not self.upload_id:
            raise Exception("Multipart upload not started")
        
        response = self.session_s3.upload_part(
            Bucket=self.bucket,
            Key=self.key,
            PartNumber=self.part_number,
            UploadId=self.upload_id,
            Body=buffer_content.encode('utf-8') if isinstance(buffer_content, str) else buffer_content
        )
        
        self.parts.append({
            'ETag': response['ETag'],
            'PartNumber': self.part_number
        })
        
        logger.info(f"MULTIPART: Uploaded part {self.part_number}, size: {len(buffer_content)} chars")
        self.part_number += 1
        return response
    
    def complete_upload(self):
        """Complete multipart upload"""
        if not self.upload_id:
            raise Exception("Multipart upload not started")
        
        response = self.session_s3.complete_multipart_upload(
            Bucket=self.bucket,
            Key=self.key,
            UploadId=self.upload_id,
            MultipartUpload={'Parts': self.parts}
        )
        
        logger.info(f"MULTIPART: Completed upload {self.upload_id}")
        return response
    
    def abort_upload(self):
        """Abort multipart upload in case of error"""
        if self.upload_id:
            self.session_s3.abort_multipart_upload(
                Bucket=self.bucket,
                Key=self.key,
                UploadId=self.upload_id
            )
            logger.info(f"MULTIPART: Aborted upload {self.upload_id}")
