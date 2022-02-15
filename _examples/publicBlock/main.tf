resource "aws_s3_bucket" "dodgyBucket" {
   
   bucket = "mybucket"
   
   acl    = "authenticated-read"

   server_side_encryption_configuration {
     rule {
       apply_server_side_encryption_by_default {
         kms_master_key_id = "arn"
         sse_algorithm     = "aws:kms"
       }
     }
   }
   
   logging {
        target_bucket = "target-bucket"
   }
   
   versioning {
        enabled = true
   }
 }

resource "aws_s3_bucket_public_access_block" "dodgyBucketPublicAccessBlock" {

    bucket = aws_s3_bucket.dodgyBucket.id

    ignore_public_acls = true
    block_public_acls = false
}