The aws checks listed below have been implemented, for more information about each check, see the wiki link provided.

| Code  | Description | Wiki link |
|:-------|:-------------|:----------|
|AWS001|S3 Bucket has an ACL defined which allows public access.|[AWS001](https://github.com/tfsec/tfsec/wiki/AWS001)|
|AWS002|S3 Bucket does not have logging enabled.|[AWS002](https://github.com/tfsec/tfsec/wiki/AWS002)|
|AWS003|AWS Classic resource usage.|[AWS003](https://github.com/tfsec/tfsec/wiki/AWS003)|
|AWS004|Use of plain HTTP.|[AWS004](https://github.com/tfsec/tfsec/wiki/AWS004)|
|AWS005|Load balancer is exposed to the internet.|[AWS005](https://github.com/tfsec/tfsec/wiki/AWS005)|
|AWS006|An ingress security group rule allows traffic from `/0`.|[AWS006](https://github.com/tfsec/tfsec/wiki/AWS006)|
|AWS007|An egress security group rule allows traffic to `/0`.|[AWS007](https://github.com/tfsec/tfsec/wiki/AWS007)|
|AWS008|An inline ingress security group rule allows traffic from `/0`.|[AWS008](https://github.com/tfsec/tfsec/wiki/AWS008)|
|AWS009|An inline egress security group rule allows traffic to `/0`.|[AWS009](https://github.com/tfsec/tfsec/wiki/AWS009)|
|AWS010|An outdated SSL policy is in use by a load balancer.|[AWS010](https://github.com/tfsec/tfsec/wiki/AWS010)|
|AWS011|A resource is marked as publicly accessible.|[AWS011](https://github.com/tfsec/tfsec/wiki/AWS011)|
|AWS012|A resource has a public IP address.|[AWS012](https://github.com/tfsec/tfsec/wiki/AWS012)|
|AWS013|Task definition defines sensitive environment variable(s).|[AWS013](https://github.com/tfsec/tfsec/wiki/AWS013)|
|AWS014|Launch configuration with unencrypted block device.|[AWS014](https://github.com/tfsec/tfsec/wiki/AWS014)|
|AWS015|Unencrypted SQS queue.|[AWS015](https://github.com/tfsec/tfsec/wiki/AWS015)|
|AWS016|Unencrypted SNS topic.|[AWS016](https://github.com/tfsec/tfsec/wiki/AWS016)|
|AWS017|Unencrypted S3 bucket.|[AWS017](https://github.com/tfsec/tfsec/wiki/AWS017)|
|AWS018|Missing description for security group/security group rule.|[AWS018](https://github.com/tfsec/tfsec/wiki/AWS018)|
|AWS019|A KMS key is not configured to auto-rotate.|[AWS019](https://github.com/tfsec/tfsec/wiki/AWS019)|
|AWS020|CloudFront distribution allows unencrypted (HTTP) communications.|[AWS020](https://github.com/tfsec/tfsec/wiki/AWS020)|
|AWS021|CloudFront distribution uses outdated SSL/TSL protocols.|[AWS021](https://github.com/tfsec/tfsec/wiki/AWS021)|
|AWS022|A MSK cluster allows unencrypted data in transit.|[AWS022](https://github.com/tfsec/tfsec/wiki/AWS022)|
|AWS023|ECR repository has image scans disabled.|[AWS023](https://github.com/tfsec/tfsec/wiki/AWS023)|
|AWS024|Kinesis stream is unencrypted.|[AWS024](https://github.com/tfsec/tfsec/wiki/AWS024)|
|AWS025|API Gateway domain name uses outdated SSL/TLS protocols.|[AWS025](https://github.com/tfsec/tfsec/wiki/AWS025)|
|AWS031|Elasticsearch domain isn't encrypted at rest.|[AWS031](https://github.com/tfsec/tfsec/wiki/AWS031)|
|AWS032|Elasticsearch domain uses plaintext traffic for node to node communication.|[AWS032](https://github.com/tfsec/tfsec/wiki/AWS032)|
|AWS033|Elasticsearch doesn't enforce HTTPS traffic.|[AWS033](https://github.com/tfsec/tfsec/wiki/AWS033)|
|AWS034|Elasticsearch domain endpoint is using outdated TLS policy.|[AWS034](https://github.com/tfsec/tfsec/wiki/AWS034)|
|AWS035|Unencrypted Elasticache Replication Group.|[AWS035](https://github.com/tfsec/tfsec/wiki/AWS035)|
|AWS036|Elasticache Replication Group uses unencrypted traffic.|[AWS036](https://github.com/tfsec/tfsec/wiki/AWS036)|
|AWS037|IAM Password policy should prevent password reuse.|[AWS037](https://github.com/tfsec/tfsec/wiki/AWS037)|
|AWS038|IAM Password policy should have expiry greater than or equal to 90 days.|[AWS038](https://github.com/tfsec/tfsec/wiki/AWS038)|
|AWS039|IAM Password policy should have minimum password length of 14 or more characters.|[AWS039](https://github.com/tfsec/tfsec/wiki/AWS039)|
|AWS040|IAM Password policy should have requirement for at least one symbol in the password.|[AWS040](https://github.com/tfsec/tfsec/wiki/AWS040)|
|AWS041|IAM Password policy should have requirement for at least one number in the password.|[AWS041](https://github.com/tfsec/tfsec/wiki/AWS041)|
|AWS042|IAM Password policy should have requirement for at least one lowercase character.|[AWS042](https://github.com/tfsec/tfsec/wiki/AWS042)|
|AWS043|IAM Password policy should have requirement for at least one uppercase character.|[AWS043](https://github.com/tfsec/tfsec/wiki/AWS043)|
|AWS044|AWS provider has access credentials specified.|[AWS044](https://github.com/tfsec/tfsec/wiki/AWS044)|
|AWS045|CloudFront distribution does not have a WAF in front.|[AWS045](https://github.com/tfsec/tfsec/wiki/AWS045)|
|AWS046|AWS IAM policy document has wildcard action statement.|[AWS046](https://github.com/tfsec/tfsec/wiki/AWS046)|

